"""Pinned-stock, offline-only TT201M2 dual-bank UFW validation.

Independent parser/CRC/ciphers: imports no old builder or vendor helper.
Unknown outer CRC semantics and virtual partition data CRCs are NOT certified.
They must remain byte-exact to the SHA-pinned stock image.
"""
from __future__ import annotations

import binascii
import hashlib
import struct
from dataclasses import dataclass

# Optional integrity pin. Pass --expect-sha on the CLI to refuse any input that
# is not the exact stock image you audited. Leave None to accept any stock.
STOCK_SHA256 = None
UNKNOWN_OUTER = frozenset(('uboot.version', 'isd_config.ini', 'v_ota.bin', 'farg.cfg', 'blimit.bin'))
BANK_NAMES = ('flash.bin', 'flash2.bin')


class Invalid(ValueError):
    """Fail-closed input/format/integrity error."""


def need(condition, message):
    if not condition:
        raise Invalid(message)


def span(data, offset, size):
    need(type(offset) is int and type(size) is int and offset >= 0 and size >= 0
         and offset <= len(data) and size <= len(data) - offset,
         f'out-of-bounds span offset={offset} size={size} length={len(data)}')
    return data[offset:offset + size]


def crc(data):
    return binascii.crc_hqx(data, 0)


def crypt(data, key=0xffff):
    result = bytearray(data)
    for i in range(len(result)):
        result[i] ^= key & 255
        key = ((key << 1) ^ (0x1021 if key & 0x8000 else 0)) & 65535
    return bytes(result)


def check_crc(stored, data, label):
    calculated = crc(data)
    need(stored == calculated,
         f'{label}: stored={stored:04x} calculated={calculated:04x}')


def name_of(data):
    try:
        return bytes(data).split(b'\0', 1)[0].decode('ascii')
    except UnicodeDecodeError as exc:
        raise Invalid('non-ASCII entry name') from exc


@dataclass
class Entry:
    name: str
    header: bytes
    header_offset: int
    offset: int
    size: int


@dataclass
class Node:
    name: str
    header_offset: int
    offset: int
    size: int
    flags: int
    end: int
    stored_crc: int


@dataclass
class Bank:
    entry: Entry
    plain: bytes
    nodes: list[Node]
    top_offsets: list[int]
    appbase: int
    sfc_end: int
    key: int

    def named(self, name):
        found = [n for n in self.nodes if n.name == name]
        need(len(found) == 1, f'{self.entry.name}: expected unique {name}')
        return found[0]


def parse_bank(raw, entry):
    plain = bytearray(span(raw, entry.offset, entry.size))
    plain[:32] = crypt(span(plain, 0, 32))
    check_crc(struct.unpack_from('<H', plain)[0], plain[2:32], entry.name + '/flash header')
    nodes = []
    top_offsets = []

    def node(at, base=0, chained=False):
        h = bytes(span(plain, at, 32))
        hc, dc, off, size, flags, _, end, nb = struct.unpack('<HHIIBBH16s', h)
        name = name_of(nb)
        check_crc(hc, h[2:], entry.name + '/' + name + ' header')
        if chained:
            need(size >= 32, 'chained size below header size')
            off, size = at + 32, size - 32
        else:
            off += base
        n = Node(name, at, off, size, flags, end, dc)
        nodes.append(n)
        return n

    at = 32
    for _ in range(len(plain) // 32):
        plain[at:at + 32] = crypt(span(plain, at, 32))
        top_offsets.append(at)
        n = node(at)
        if n.end:
            break
        at += 32
    else:
        raise Invalid('unterminated top directory')
    configs = [n for n in nodes if n.name == 'isd_config.ini']
    dirs = [n for n in nodes if n.name == 'app_dir_head']
    need(len(configs) == len(dirs) == 1, 'missing/duplicate configuration or app directory')
    config = span(plain, configs[0].offset, configs[0].size)
    keydata = span(config, 0, 32)
    check_crc(struct.unpack('<H', span(config, 32, 2))[0], keydata, 'chipkey')
    threshold = sum(keydata[:16]) & 255
    threshold = 0xaa if threshold >= 0xe0 else 0x55 if threshold <= 0x10 else threshold
    key = sum(1 << i for i in range(16) if keydata[16+i] ^ keydata[15-i] < threshold)
    appbase = dirs[0].offset
    need(appbase % 32 == 0, 'unaligned SFC base')
    decrypted = appbase

    def decode_to(end):
        nonlocal decrypted
        span(plain, decrypted, end - decrypted)
        for p in range(decrypted, end, 32):
            length = min(32, end - p)
            plain[p:p+length] = crypt(plain[p:p+length], key ^ ((p-appbase) >> 2))
        decrypted = end

    def children(parent, depth=0):
        need(depth < 8, 'directory nesting exceeds limit')
        at = parent.offset
        stop = parent.offset + parent.size
        for _ in range(parent.size // 32):
            need(at + 32 <= stop, 'child header outside parent')
            child = node(at, parent.header_offset)
            if child.stored_crc != 0xffff:
                need(child.offset >= parent.offset and child.offset + child.size <= stop,
                     'child payload outside parent')
            if child.flags == 0x83 and child.stored_crc != 0xffff:
                children(child, depth + 1)
            if child.end:
                return
            at += 32
        raise Invalid('unterminated child directory')

    at = appbase
    for _ in range(len(plain) // 32):
        target = (at + 63) & ~31
        if target > decrypted:
            decode_to(target)
        parent = node(at, chained=True)
        end = parent.offset + parent.size
        need(end > at, 'non-progressing app directory')
        target = end if parent.end else (end + 63) & ~31
        if target > decrypted:
            decode_to(target)
        if parent.flags == 0x83:
            children(parent)
        if parent.end:
            break
        at = end
    else:
        raise Invalid('unterminated app directory')

    for n in nodes:
        if n.stored_crc == 0xffff:
            continue  # virtual partition descriptor; stock comparison is mandatory
        data = bytes(span(plain, n.offset, n.size))
        if n.name == 'uboot.boot':
            # Two independent ENC streams: 16-byte boot header, then body.
            data = crypt(span(data, 0, 16)) + crypt(span(data, 16, len(data)-16))
        check_crc(n.stored_crc, data, entry.name + '/' + n.name + ' data')
    return Bank(entry, bytes(plain), nodes, top_offsets, appbase, decrypted, key)


def parse(raw):
    header = crypt(span(raw, 0, 64))
    hc, lc, size, count = struct.unpack_from('<HHIH', header)
    need(size == len(raw), 'image length differs from declared length')
    check_crc(hc, header[2:], 'UFW header')
    table = span(raw, 64, count * 80)
    check_crc(lc, table, 'UFW entry table')
    entries = []
    used = []
    for i in range(count):
        h = crypt(table[i*80:(i+1)*80])
        _, _, dc, _, offset, size, _, _, nb = struct.unpack('<HHHHIII44s16s', h)
        name = name_of(nb)
        need(name not in [e.name for e in entries], 'duplicate outer name')
        payload = span(raw, offset, size)
        need(offset >= 64 + count*80, 'outer payload overlaps table')
        if size:
            need(all(offset+size <= lo or offset >= hi for lo, hi in used), 'overlapping outer payloads')
            used.append((offset, offset+size))
        if name not in UNKNOWN_OUTER:
            check_crc(dc, payload, 'UFW ' + name)
        entries.append(Entry(name, h, 64+i*80, offset, size))
    need(UNKNOWN_OUTER <= {e.name for e in entries}, 'missing preserved nonstandard entries')
    banks = [parse_bank(raw, e) for e in entries if e.name in BANK_NAMES]
    need(tuple(b.entry.name for b in banks) == BANK_NAMES, 'expected both independent banks')
    return header, entries, banks


def pinned(stock, expect=None):
    expect = expect or STOCK_SHA256
    if expect:
        need(hashlib.sha256(stock).hexdigest() == expect, 'stock SHA-256 mismatch')
    result = parse(stock)
    apps = [bytes(span(b.plain, b.named('app.bin').offset, b.named('app.bin').size)) for b in result[2]]
    need(apps[0] == apps[1], 'stock apps differ between banks')
    return result


def encode_bank(bank, plain):
    need(len(plain) == len(bank.plain), 'bank length changed')
    out = bytearray(plain)
    out[:32] = crypt(out[:32])
    for at in bank.top_offsets:
        out[at:at+32] = crypt(out[at:at+32])
    for at in range(bank.appbase, bank.sfc_end, 32):
        end = min(at + 32, bank.sfc_end)
        out[at:end] = crypt(out[at:end], bank.key ^ ((at-bank.appbase) >> 2))
    return bytes(out)


def patches_for(manifest, banks):
    need(type(manifest) is dict and set(manifest) == {'patches'}, 'manifest requires only patches')
    need(type(manifest['patches']) is list, 'patches must be a list')
    patches = []
    for item in manifest['patches']:
        need(type(item) is dict and set(item) == {'offset', 'expected_hex', 'replacement_hex'},
             'each patch requires offset, expected_hex, replacement_hex only')
        offset = item['offset']
        need(type(offset) is int and offset >= 0, 'patch offset must be a nonnegative integer')
        for field in ('expected_hex', 'replacement_hex'):
            text = item[field]
            need(type(text) is str and len(text) > 0 and len(text) % 2 == 0
                 and all(c in '0123456789abcdefABCDEF' for c in text), 'invalid exact hex bytes')
        expected = bytes.fromhex(item['expected_hex'])
        replacement = bytes.fromhex(item['replacement_hex'])
        need(len(expected) == len(replacement), 'patch length changes are prohibited')
        end = offset + len(expected)
        need(all(end <= lo or offset >= lo + len(old) for lo, old, _ in patches), 'overlapping patches')
        for b in banks:
            app = b.named('app.bin')
            data = span(b.plain, app.offset, app.size)
            need(bytes(span(data, offset, len(expected))) == expected,
                 b.entry.name + ': exact expected bytes mismatch')
        patches.append((offset, expected, replacement))
    return patches


def diff_ranges(before, after):
    need(len(before) == len(after), 'image length changed')
    ranges = []
    start = None
    for i, (a, b) in enumerate(zip(before, after)):
        if a != b and start is None:
            start = i
        elif a == b and start is not None:
            ranges.append([start, i])
            start = None
    if start is not None:
        ranges.append([start, len(before)])
    return ranges


def verify(candidate, stock, manifest, expect=None):
    _, entries, banks = pinned(stock, expect)
    patches = patches_for(manifest, banks)
    need(len(candidate) == len(stock), 'image length changed')
    allowed = bytearray(len(stock))

    def permit(offset, length):
        span(allowed, offset, length)
        allowed[offset:offset+length] = b'\1' * length

    if patches:
        permit(0, 4)  # independent stream cipher keeps CRC bytes at identical offsets
        for b in banks:
            permit(b.entry.header_offset + 4, 2)
            for name in ('app.bin', 'app_area_head'):
                permit(b.entry.offset + b.named(name).header_offset, 4)
            app = b.named('app.bin')
            for offset, expected, _ in patches:
                permit(b.entry.offset + app.offset + offset, len(expected))
    changes = diff_ranges(stock, candidate)
    for lo, hi in changes:
        need(all(allowed[lo:hi]), f'change outside full-image allowlist at [{lo:#x},{hi:#x})')
    # Decode and validate candidate independently. Never compare to builder output.
    _, _, verified = parse(candidate)
    for b in verified:
        app = b.named('app.bin')
        for offset, _, replacement in patches:
            need(bytes(span(b.plain, app.offset+offset, len(replacement))) == replacement,
                 b.entry.name + ': replacement bytes mismatch')
    for e in entries:
        if e.name in UNKNOWN_OUTER:
            need(span(candidate, e.header_offset, 80) == span(stock, e.header_offset, 80)
                 and span(candidate, e.offset, e.size) == span(stock, e.offset, e.size),
                 'nonstandard entry not preserved: ' + e.name)
    return {'status': 'verified_with_preserved_unknown_semantics',
            'sha256': hashlib.sha256(candidate).hexdigest(),
            'stock_sha256': hashlib.sha256(stock).hexdigest(), 'length': len(candidate),
            'changed_bytes': sum(hi-lo for lo, hi in changes), 'diff_ranges': changes,
            'banks': [{'name': b.entry.name,
                       'header_crcs_verified': len(b.nodes) + 1,
                       'data_crcs_verified': sum(n.stored_crc != 0xffff for n in b.nodes),
                       'app_crc': f'{b.named("app.bin").stored_crc:04x}',
                       'parent_crc': f'{b.named("app_area_head").stored_crc:04x}',
                       'preserved_virtual_data_crc_semantics_unknown':
                       [n.name for n in b.nodes if n.stored_crc == 0xffff]} for b in verified],
            'preserved_outer_unknown': sorted(UNKNOWN_OUTER),
            'warning': 'Preserved unknown CRC semantics are not verified CRCs; offline integrity is not device safety.'}


def build(stock, manifest, expect=None):
    header, entries, banks = pinned(stock, expect)
    patches = patches_for(manifest, banks)
    out = bytearray(stock)
    for bank in banks:
        plain = bytearray(bank.plain)
        app = bank.named('app.bin')
        for offset, _, replacement in patches:
            plain[app.offset+offset:app.offset+offset+len(replacement)] = replacement
        if patches:
            # Each bank uses its OWN descriptors. Leaf first, then encompassing parent.
            for n in (app, bank.named('app_area_head')):
                struct.pack_into('<H', plain, n.header_offset+2, crc(span(plain, n.offset, n.size)))
                struct.pack_into('<H', plain, n.header_offset, crc(span(plain, n.header_offset+2, 30)))
        encoded = encode_bank(bank, plain)
        out[bank.entry.offset:bank.entry.offset+bank.entry.size] = encoded
        eh = bytearray(bank.entry.header)
        struct.pack_into('<H', eh, 4, crc(encoded))
        out[bank.entry.header_offset:bank.entry.header_offset+80] = crypt(eh)
    h = bytearray(header)
    struct.pack_into('<H', h, 2, crc(span(out, 64, len(entries)*80)))
    struct.pack_into('<H', h, 0, crc(h[2:]))
    out[:64] = crypt(h)
    result = bytes(out)
    verify(result, stock, manifest, expect)
    return result


def main(argv=None):
    """CLI JSON: [{"offset": 217604, "expected": "hex", "replacement": "hex"}].

    Offsets are decimal JSON integers relative to decrypted app.bin, applied
    independently to BOTH banks. Hex is nonempty, contiguous, even length;
    expected/replacement lengths must match. [] is the byte-exact roundtrip.
    """
    import argparse
    import json
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__ + '\n' + main.__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('build', 'verify'):
        sub = commands.add_parser(command)
        sub.add_argument('--stock', type=Path, required=True)
        sub.add_argument('--manifest', type=Path, required=True)
        sub.add_argument('--expect-sha', default=None,
                         help='refuse any stock image whose sha256 differs')
        sub.add_argument('--output' if command == 'build' else '--image',
                         type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.manifest.read_text(encoding='utf-8'))
        need(type(document) is list, 'CLI manifest must be a JSON list')
        for item in document:
            need(type(item) is dict and set(item) == {'offset', 'expected', 'replacement'},
                 'CLI patch requires offset, expected, replacement only')
        manifest = {'patches': [{'offset': p['offset'], 'expected_hex': p['expected'],
                                'replacement_hex': p['replacement']} for p in document]}
        stock = args.stock.read_bytes()
        if args.command == 'build':
            result = build(stock, manifest, args.expect_sha)
            # Exclusive creation: never overwrite stock, old images, or any file.
            with args.output.open('xb') as stream:
                stream.write(result)
            candidate = args.output.read_bytes()
        else:
            candidate = args.image.read_bytes()
        print(json.dumps(verify(candidate, stock, manifest, args.expect_sha), indent=2))
        return 0
    except (Invalid, OSError, ValueError) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
