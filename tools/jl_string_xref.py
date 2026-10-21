#!/usr/bin/env python3
"""Resolve base+offset string references and callers in a JieLi (JL) app.bin.

Why this exists: JL firmware does not reference rodata by absolute pointer.
The compiler emits `mov rB,#0x06xxxxxx` followed by `add rX,rB,#imm`, so
literal-pointer searches and load-imm scans find nothing, and Ghidra's
getReferencesTo() is empty because the SLEIGH spec emits no reference for the
computed address.

This scans raw bytes (no disassembler needed), matches EVERY SUFFIX of each
anchor string, and keeps only hits where the base load and the `add` fall in the
same function. Function entries are derived from call targets, so no prior
analysis is required.

IMPORTANT — runtime base: JL images map at **0x06000100 + file_offset**, not
0x06000000. (Proof: the startup stub's `mov r1,#0x60d0ae8` sits at file offset
0xd09e8.) Override with --base if a different device proves otherwise.

Usage:
    python jl_string_xref.py app.bin 0x2ffa2 0x302db     # string xref
    python jl_string_xref.py app.bin --callers 0x75450   # who calls this fn
    python jl_string_xref.py app.bin --callers 0x75450 --base 0x6000000

Offsets are app.bin-relative file offsets. Extract app.bin from a .ufw first
with tools/jl_ufw.py (or your normal JLFS tooling); this script only needs the
raw app.bin payload.

pi32v2 encodings used:
  mov rA,#imm32      iword 0xFFC0|regA, then imm1631 (LE16), imm3247 (LE16)
  add rX,rB,#imm12   iword 0xE100|regX, hw = imm12 | eregB<<12
  add rX,rB,imm12p4096  iword 0xE110|regX
  add rX,rB,#imm14   iword 0xE120|regX, imm = (imm0405<<12)|imm1627
  add rX,rB,#imm12s  iword 0xE130|regX
  call rel16         iword 0xEABF (bytes bf ea), target = (off+4) + rel*2
  call rel32         iword 0xFF80 (bytes 80 ff), target = (off+6) + simm32
"""
import bisect
import struct
import sys

CONST_BASE = 0x06000100


def ascii_at(buf, off, maxlen=64):
    out = []
    for i in range(maxlen):
        if off + i >= len(buf):
            break
        b = buf[off + i]
        if b < 0x20 or b > 0x7E:
            break
        out.append(chr(b))
    return "".join(out)


def call_sites(buf):
    """Yield (site, target) for every direct call encoding."""
    n = len(buf)
    for off in range(0, n - 6, 2):
        if buf[off] == 0xBF and buf[off + 1] == 0xEA:
            rel = struct.unpack_from("<h", buf, off + 2)[0]
            yield off, (off + 4) + rel * 2
        elif buf[off] == 0x80 and buf[off + 1] == 0xFF:
            rel = struct.unpack_from("<i", buf, off + 2)[0]
            yield off, (off + 6) + rel


def call_targets(buf):
    """Function entries, harvested from direct call encodings."""
    n = len(buf)
    targets = set()
    for _, t in call_sites(buf):
        if 0 <= t < n:
            targets.add(t)
    return sorted(targets)


def base_loads(buf, base=CONST_BASE):
    """imm32 -> [(addr, reg)] for every load of a 0x06xxxxxx base."""
    n = len(buf)
    out = {}
    for off in range(0, n - 6, 2):
        if (buf[off] & 0xF0) == 0xC0 and buf[off + 1] == 0xFF:
            imm = struct.unpack_from("<I", buf, off + 2)[0]
            if base <= imm < base + n:
                out.setdefault(imm, []).append((off, buf[off] & 0x0F))
    return out


def add_sites(buf):
    """Yield (addr, regX, regB, imm) for every base+imm add form."""
    n = len(buf)
    for p in range(0, n - 4):
        if buf[p + 1] != 0xE1:
            continue
        b0 = buf[p]
        hw = struct.unpack_from("<H", buf, p + 2)[0]
        imm12 = hw & 0xFFF
        ereg = hw >> 12
        reg_x = b0 & 0x0F
        kind = b0 & 0xF0
        if kind == 0x00:
            imm = imm12
        elif kind == 0x10:
            imm = imm12 << 12
        elif kind == 0x20:
            imm = ((b0 & 0x30) << 8) | imm12
        elif kind == 0x30:
            imm = imm12 - 0x1000 if imm12 & 0x800 else imm12
        else:
            continue
        yield p, reg_x, ereg, imm


def main():
    argv = sys.argv[1:]
    if not argv:
        sys.exit(__doc__)
    base = CONST_BASE
    if "--base" in argv:
        i = argv.index("--base")
        base = int(argv[i + 1], 0)
        del argv[i:i + 2]
    callers_of = None
    if "--callers" in argv:
        i = argv.index("--callers")
        callers_of = int(argv[i + 1], 0)
        del argv[i:i + 2]

    buf = open(argv[0], "rb").read()
    entries = call_targets(buf)

    def func_start(a):
        i = bisect.bisect_right(entries, a) - 1
        return entries[i] if i >= 0 else 0

    if callers_of is not None:
        print(f"app.bin {len(buf)} bytes, {len(entries)} function entries, "
              f"base {base:#x}")
        found = [(site, func_start(site)) for site, tgt in call_sites(buf)
                 if tgt == callers_of]
        print(f"\ncallers of 0x{callers_of:06x}: {len(found)}")
        for site, f in sorted(found):
            print(f"  call @0x{site:06x}   inside function 0x{f:06x}")
        if not found:
            print("  none - the target may be reached via a function pointer "
                  "table, a computed call, or a RAM-resident copy")
        return

    anchors = [int(a, 0) for a in argv[1:]]
    if not anchors:
        sys.exit("give at least one anchor offset, e.g. 0x2ffa2, or --callers 0x75450")

    wanted = {}
    for a in anchors:
        text = ascii_at(buf, a)
        for i in range(len(text) or 1):
            wanted[base + a + i] = (a, text[i:] or text)

    loads = base_loads(buf, base)
    hits = {}
    for p, reg_x, reg_b, imm in add_sites(buf):
        for tgt, (anchor, suffix) in wanted.items():
            base_addr = tgt - imm
            for maddr, mreg in loads.get(base_addr, ()):
                if maddr < p and func_start(maddr) == func_start(p):
                    hits.setdefault(anchor, set()).add((p, maddr, func_start(p)))

    print(f"app.bin {len(buf)} bytes, {len(entries)} function entries, "
          f"{len(loads)} base constants (base {base:#x})")
    for a in anchors:
        print(f"\n0x{a:06x}  {ascii_at(buf, a)!r}")
        got = sorted(hits.get(a, ()))
        if not got:
            print("  no base+offset reference found "
                  "(base likely passed as an argument or loaded from RAM)")
            continue
        for p, maddr, f in got[:12]:
            print(f"  add @0x{p:06x}  base load @0x{maddr:06x}  func 0x{f:06x}")


if __name__ == "__main__":
    main()
