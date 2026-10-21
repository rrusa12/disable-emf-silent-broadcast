# 🔇 emf-rfkill

**Permanently silence the Bluetooth/WiFi radios of a JieLi (JL) device — by patching its own firmware. Wired audio keeps working.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Verified](https://img.shields.io/badge/verified-TT201M2-brightgreen.svg)
![No binaries](https://img.shields.io/badge/firmware%20included-none-lightgrey.svg)

> A device that says "Bluetooth off" in its menu usually still powers the radio,
> still beacons, and can still be woken over the air. This removes the RF
> bring-up from the firmware itself, so the radio is never calibrated or
> powered — instead of trusting a UI toggle.
>
> Built for EMF-conscious users, and for anyone who wants a "wired-only" device
> that is actually wired-only.

**Verified result (BlueAnt Soundblade TT201M2, 2026-10-21):** 0 BLE
advertisements across active scans, classic link down, USB audio + HID still
enumerating. No case opening, no dongle, no soldering.

---

## Contents

- [What this is — and isn't](#what-this-is--and-isnt)
- [Read before you flash ⚠️](#read-before-you-flash)
- [How it works in 30 seconds](#how-it-works-in-30-seconds)
- [Quick start — humans](#quick-start--humans)
- [Quick start — AI agents](#quick-start--ai-agents)
- [The pitfalls that cost days](#the-pitfalls-that-cost-days)
- [Repository map](#repository-map)
- [Requirements](#requirements)
- [What is not here](#what-is-not-here)
- [Verified results](#verified-results)
- [License](#license)

---

## What this is — and isn't

| ✅ This is | ❌ This is not |
|---|---|
| A firmware patch that stops RF from ever powering up | A UI setting, a pairing-mode trick, or "turn off Bluetooth" |
| A fail-closed toolchain: SHA-pinned stock, exact-byte patch match, full CRC verification | A one-click flasher you can point at any device |
| A recipe that generalizes to other JieLi devices | A list of offsets that work on other devices (they don't) |
| A measured verification method | A progress bar that says "success" |

---

## Read before you flash ⚠️

| # | Rule | Why |
|---|---|---|
| 1 | **It is a one-way door over the air.** | The patch removes the radio — which is also the OTA service. A bad image means **hardware recovery** (JL `USB_KEY` dongle or UART pads). Have that before you start. |
| 2 | **Offsets are per-firmware, not per-chip.** | Same SoC ≠ same binary. The tools refuse any patch whose expected bytes don't match — never edit around that. |
| 3 | **Reproduce stock byte-for-byte first.** | If the repacker can't rebuild its own input exactly, it doesn't understand the container well enough to patch it. |
| 4 | **Firmware modification voids warranties.** | Modifying firmware you own is generally lawful for repair/interoperability in the US. **Redistributing vendor firmware is copyright infringement** — which is why no binaries live here. |
| 5 | **No health claims.** | This reduces RF emissions. It is not a medical device, a treatment, or a cure for EMF hypersensitivity. |
| 6 | **Own the device.** | The OTA channel authenticates the device, not you. Anyone in range with tooling can flash a unit they can reach — keep this physical-possession work. |

---

## How it works in 30 seconds

```
app.bin                          patched app.bin
  BT controller task (0x76958)      BT controller task
    └─ bring-up (0x76848)             └─ bring-up
         └─ call RF_init  ──────►          └─ [ nop'd call ]   ← RF never runs
              powers RF block                 rest of bring-up still runs
```

```
pass 1  app running      E1 → E2 → E3 → serve pulls → E6=0x80  (loader staged)
        ↓ device relinks to the loader and reboots
pass 2  loader running   E3 only → serve pulls → [0,0] → E6=0x00 (bank verified)
```

Two instructions, same length as the call they replace:

```
80 ff ec eb ff ff   →   40 e0 06 00 00 16     # call RF_init → movz r0,#6 ; mov r0,r0
```

Because the length is identical, no offset anywhere else in the image shifts.

---

## Quick start — humans

```bash
# 0. identify: USB VID 0x4C4A = JieLi
# 1. obtain your own stock .ufw, then hash it
sha256sum stock.ufw

# 2. prove the repacker (must print BYTE-EXACT)
echo '[]' > empty.json
python tools/jl_ufw.py build --stock stock.ufw --manifest empty.json --output rt.ufw
cmp rt.ufw stock.ufw && echo BYTE-EXACT

# 3. locate the RF bring-up and its single caller
python tools/jl_string_xref.py app.bin 0x<rf_init_string_offset>
python tools/jl_string_xref.py app.bin --callers 0x<rf_init_func_offset>

# 4. build with your manifest
python tools/jl_ufw.py build --stock stock.ufw --expect-sha <sha256> \
       --manifest manifest.json --output patched.ufw

# 5. flash: pass 1 against the app, pass 2 against the loader
python tools/serve_ota.py --mac <app-mac>    --image patched.ufw
python tools/serve_ota.py --mac <loader-mac> --image patched.ufw --skip-e1e2 --reboot

# 6. verify by measurement
python tools/verify_rf.py --name <NAME> --vid 4C4A --edr <classic-mac>
```

Full procedure, including porting to another device: **[`docs/RECIPE.md`](docs/RECIPE.md)**.
Worked example with every address and byte: **[`docs/SOUNDBLADE-TT201M2.md`](docs/SOUNDBLADE-TT201M2.md)**.

---

## Quick start — AI agents

If you are an agent asked to "kill the radios" on a device with USB `VID_4C4A`:

1. Read **[`AGENTS.md`](AGENTS.md)** — it is the short, directive version of this page.
2. Confirm the user owns the device and accepts a one-way, non-reversible-over-air change.
3. Get their stock `.ufw`, SHA-pin it, and prove the roundtrip **before** anything else.
4. Follow `docs/RECIPE.md` in order. Do not improvise around a failed byte match.

---

## The pitfalls that cost days

These are measured, not theorized — each one cost a real failed attempt.

| Pitfall | What actually happens |
|---|---|
| Wrong runtime base | `runtime = 0x06000100 + file_offset`, **not** `0x06000000`. Off by 256 bytes, every "unresolvable" pointer resolves and every "dead code" verdict is wrong. |
| Stubbing a function entry | JL functions exit via `pop {pc,…}`. An early return skips the epilogue and corrupts the stack. **Patch the call.** |
| Scanning for a string's start | The compiler often points *into* a string (`">RF_init"` inside `">>>>>>>>>>RF_init"`). Scan every suffix. |
| "The loader's state is corrupt" | It replays the **same** full sweep every attempt and aborts at a **random** depth (1, 4, 10, 148, 230, 242 blocks) with identical bytes. Random depth = transport. One lost BLE notification truncates a 4 KiB block → `E6=0x04` for the whole transfer. |
| Polling status mid-transfer | Never poll `E6`, disconnect, or stop early. A full bank is ~345 blocks × ~3.2 s ≈ **18–20 min**. Let it run. |
| Retrying `E4` / `E7` | The OTA loader **silently ignores** both — no response frame, any payload. |
| Trusting the progress bar | A clean flash proves the write landed, not that the radio died. `verify_rf.py` decides. |
| Expecting a marker readback afterwards | After a successful kill the radio is gone, so there is no RCSP channel. That's the point. The loader's `E6=0x00` is the content proof. |

---

## Repository map

| Path | What it does |
|---|---|
| [`tools/jl_ufw.py`](tools/jl_ufw.py) | Strict `.ufw` parser / dual-bank patcher / verifier (CLI: `build`, `verify`) |
| [`tools/serve_ota.py`](tools/serve_ota.py) | BLE RCSP OTA serve loop (device-driven, pass 1 or pass 2) |
| [`tools/verify_rf.py`](tools/verify_rf.py) | Proves radios dead **and** wired function alive |
| [`tools/jl_string_xref.py`](tools/jl_string_xref.py) | Base+offset string xref and caller finder for a JL `app.bin` |
| [`examples/manifest.soundblade.json`](examples/manifest.soundblade.json) | The actual TT201M2 patch manifest |
| [`docs/RECIPE.md`](docs/RECIPE.md) | Generalized 10-step procedure |
| [`docs/RCSP-OTA-NOTES.md`](docs/RCSP-OTA-NOTES.md) | OTA protocol: opcodes, two-pass flow, failure modes |
| [`docs/SOUNDBLADE-TT201M2.md`](docs/SOUNDBLADE-TT201M2.md) | Complete case study: addresses, bytes, timings, results |
| [`AGENTS.md`](AGENTS.md) | Directive instructions for AI agents |

---

## Requirements

- **Python 3.10+**
- `jl_ufw.py` and `jl_string_xref.py`: stdlib only
- `verify_rf.py`: `bleak` + PowerShell (USB enumeration)
- `serve_ota.py`: `bleak` + the **qix-ble** RCSP transport/auth package

```bash
pip install bleak
pip install "git+https://github.com/ElectronicCats/jieli-ble-badge-research#subdirectory=tools/qix-ble"
```

## What is not here

| Missing | Why |
|---|---|
| Stock or patched `.ufw` images | Vendor firmware is copyrighted. You supply your own; the manifest describes only the diff. |
| Auth keys / device secrets | They live in the upstream qix-ble project — use theirs. |
| A turnkey MAC-in / image-out flasher | Flashing requires the user's own image and an explicit, verified build step. |

## Verified results

| Check | Result |
|---|---|
| BLE active scans (10 s ×3 + 30 s ×1) | **0 advertisements at all** — no app address, no loader address |
| Classic BR/EDR | `connected=False`, `remembered=True`, `last_seen` two days before the patch |
| Wired function | USB audio (MEDIA) + HID consumer control still enumerate |
| Loader `E6` | `0x00` — flashed bank CRC matched the patched image |

## Scope

Verified on **BlueAnt Soundblade (TT201M2)**, app/loader firmware `1.8.16.10`,
2026-10-21. The *method* generalizes to other JieLi devices; the *bytes* do not.
Single-bank `.ufw` layouts need a small adaptation — `jl_ufw.py` currently
requires both `flash.bin` and `flash2.bin`.

## License

MIT for the code and documentation. Vendor firmware is not included and remains
the vendor's property. See [LICENSE](LICENSE).
