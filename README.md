# jl-rfkill — permanently kill a JieLi device's radios, keep it wired

A recipe, a verified toolset, and one fully documented case study
(BlueAnt Soundblade / TT201M2) for **permanently disabling the Bluetooth/WiFi
radios of a JieLi (JL) SoC device by patching its own firmware**, while keeping
its wired function (USB audio, AUX, HID) working.

Written for two audiences:

- **People reducing EMF** — a device that "has Bluetooth off" in its menu is
  usually still powered, still beaconing, still radiating. This removes the RF
  bring-up from the firmware instead of trusting a UI toggle.
- **AI agents** picking this task up — read the **Fast path** and the
  **Pitfalls** below first. Both exist because the naive route costs days.

> ## Read this before you flash anything
>
> 1. **It is a one-way door over the air.** The patch removes the radio, which
>    removes the OTA service. If the image does not boot, there is **no
>    wireless recovery** — you need a hardware path (JL `USB_KEY` dongle or
>    UART pads). Have that dongle **before** you start, or you are gambling the
>    device.
> 2. **Offsets are per-firmware, not per-chip.** The same SoC with a different
>    firmware revision or a different vendor's board has different bytes. The
>    tools here **fail closed**: every patch must match the expected original
>    bytes exactly, or the build refuses. Never hand-edit around that check.
> 3. **This is firmware modification.** It voids warranties and may violate
>    your vendor's terms. Modifying firmware you own is generally lawful for
>    repair/interoperability in the US; **redistributing vendor firmware
>    images is copyright infringement** — which is why this repo contains no
>    binaries (see *What is not here*).
> 4. **No health claims.** This reduces RF emissions. It is not a medical
>    device, a treatment, or a cure for electromagnetic hypersensitivity.
> 5. **Do not run this against a device you do not own.** The OTA channel is
>    authenticated to the device, not to you — anyone in BLE range with the
>    right tooling can flash a unit they can reach. Keep it physical-possession
>    work.

---

## Fast path (for a JieLi device you own)

```
0. Identify the SoC           USB VID 0x4C4A = JieLi. Check for a vendor OTA app.
1. Obtain the stock .ufw      vendor app / support / update file. Keep it, hash it.
2. Reproduce it byte-exactly  python tools/jl_ufw.py build --stock stock.ufw \
                                --manifest empty.json --output rt.ufw
                              cmp rt.ufw stock.ufw   → must be identical
3. Find the RF bring-up       docs/RECIPE.md §3 (string xref + call graph)
4. Patch the caller, not the
   function entry             one same-length instruction, see §4
5. Build + verify             tools/jl_ufw.py build --manifest your.json ...
6. Flash                      tools/serve_ota.py (two passes, app then loader)
7. Verify, do not assume      tools/verify_rf.py --name ... --vid ... --edr ...
```

Step 2 is not optional. If the repacker cannot reproduce its own input
byte-for-byte, it does not understand the container well enough to patch it.

**Worked example with every address and byte:** `docs/SOUNDBLADE-TT201M2.md`.

---

## Pitfalls that cost the most time (read these, they are measured)

1. **The runtime base is `0x06000100 + file_offset`, not `0x06000000 + off`.**
   Off by 256 bytes, every "unresolvable" string pointer resolves, and every
   "dead code" conclusion was wrong.
2. **Do not stub a function entry.** JL firmware exits via `pop {pc,…}` — an
   early return skips the epilogue and corrupts the stack. Replace the *call*
   with a same-length "return a value" instruction.
3. **Scan for the string's suffix, not its start.** The compiler often emits a
   full `mov rX,#0x06xxxxxx` pointing *into* a log string (e.g. at `">RF_init"`
   inside `">>>>>>>>>>RF_init"`).
4. **A loader that rejects every image is usually losing blocks, not resuming.**
   This one cost nine failed attempts. The loader replays the *same* full sweep
   every time and aborts at a **random** depth (1, 4, 10, 148, 230, 242 blocks)
   with identical image bytes. Random depth = transport: one lost BLE
   notification truncates a 4 KiB block and the loader reports a generic "bad
   update file". **Never poll status, disconnect, or stop mid-transfer.** Serve
   every requested offset and let it run (~18–20 min for a 345-block bank).
5. **E4 (exit update mode) and E7 (reboot) are silently ignored** by the OTA
   loader — no response, any payload. Do not burn attempts on them.
6. **The success code is not the kill.** A clean flash says the write landed.
   The kill is proven only by measurement: zero advertisers, classic link down,
   wired function alive. `tools/verify_rf.py` does exactly that.
7. **You cannot read a firmware marker back after a successful kill** — the
   radio is gone by design. That is expected. The loader's own `E6=0x00`
   already proves the flashed bank matches your patched image.

---

## Repo map

| path | what |
|---|---|
| `tools/jl_ufw.py` | strict `.ufw` parser / dual-bank patcher / verifier (CLI) |
| `tools/serve_ota.py` | BLE RCSP OTA serve loop (pass 2, device-driven) |
| `tools/verify_rf.py` | proves radios dead + wired function alive |
| `tools/jl_string_xref.py` | resolves base+offset string references in a JL `app.bin` |
| `examples/manifest.soundblade.json` | the actual TT201M2 patch manifest |
| `docs/RECIPE.md` | the generalized 10-step procedure |
| `docs/RCSP-OTA-NOTES.md` | OTA protocol: opcodes, two-pass flow, why it breaks |
| `docs/SOUNDBLADE-TT201M2.md` | complete case study with addresses and bytes |

Requirements: Python 3.10+. `jl_ufw.py` and `verify_rf.py` are stdlib-only
(`verify_rf.py` additionally uses `bleak` and PowerShell for USB enumeration).
`serve_ota.py` needs `bleak` plus the **qix-ble** RCSP transport/auth package
from the public JieLi badge research project:

```
pip install bleak
pip install "git+https://github.com/ElectronicCats/jieli-ble-badge-research#subdirectory=tools/qix-ble"
```

## What is not here

- **No firmware images.** Neither stock nor patched `.ufw` files. You supply
  your own legally obtained stock image; the manifest describes the diff.
- **No auth keys or device secrets.** The RCSP auth lives in the upstream
  qix-ble project; use theirs.
- **No turnkey flasher.** Deliberate: flashing requires the user's own image
  and an explicit, verified build step.

## Scope

Verified on **BlueAnt Soundblade (TT201M2)**, app/loader firmware 1.8.16.10,
2026-10-21. The method generalizes to other JieLi devices; the *bytes* do not.
Single-bank (non-dual-bank) `.ufw` layouts need a small adaptation in
`jl_ufw.py` — it currently requires both `flash.bin` and `flash2.bin`.

## License

MIT for the code and documentation in this repo. Vendor firmware is not
included and remains the vendor's property.
