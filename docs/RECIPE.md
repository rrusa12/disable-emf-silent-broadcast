# RECIPE — kill the radios on a JieLi (JL) device via its own firmware

This is the generalized procedure. The concrete worked example (every address,
every byte) is in `SOUNDBLADE-TT201M2.md`; read it alongside this file.

Time budget honestly: **the RE is a day, the flash is 20 minutes.** Most of the
time goes into steps 3–5. Steps 1–2 are where people lose the plot by flashing
before they can reproduce the stock image byte-for-byte.

---

## 0. Decide the goal first

"Kill the radios" means **the RF block is never calibrated or powered**, not
"the UI says off" and not "advertising is disabled". A device with BT off in its
menu still powers the controller and can still be woken over the air.

Two valid kill points:

| point | what it buys | risk |
|---|---|---|
| **RF bring-up never runs** (recommended) | no RF block power-up, no calibration, no advertising; rest of the controller bring-up still runs so the app is not left on half-built state | low |
| controller task never starts | nothing BT-related exists | higher — the app may dereference uninitialised BT state later |

Prefer the first.

---

## 1. Identify the SoC and get the stock firmware

```powershell
Get-PnpDevice -PresentOnly | ? { $_.FriendlyName -match '<device>' }   # -> InstanceId
Get-PnpDevice -InstanceId 'USB\VID_xxxx*'                              # all functions/MI_N
```

`VID_4C4A` = JieLi. The device will be a USB composite: audio + HID, usually.

Get the **official update file (`.ufw`)** — vendor app, vendor support, or the
update file bundled with the companion app. Record:

```
sha256sum stock.ufw
```

That hash is your fail-closed pin for every later build (`--expect-sha`).

**Back it up twice.** It is the only way back.

---

## 2. Reproduce the container byte-exactly (do not skip)

```bash
echo '[]' > empty.json
python tools/jl_ufw.py build --stock stock.ufw --manifest empty.json --output rt.ufw
cmp rt.ufw stock.ufw && echo BYTE-EXACT
```

If this fails, stop and fix the parser. A patcher that cannot reproduce its own
input does not understand the format.

What `jl_ufw.py` handles, and what it means:

- outer UFW header (CRC-CCITT/XModem `crc_hqx`, key `0xffff` stream cipher)
- outer entry table: `flash.bin`, `flash2.bin` (the two banks) + preserved
  vendor entries (`ota.bin`, `tail.bin`, `isd_config.ini`, …) that must stay
  byte-identical
- per-bank: encrypted 32-byte header, top directory, `app_dir_head`, chipkey
  derivation, SFC stream decryption over the app area
- per-record `dcrc` (data CRC) and `hcrc` (header CRC)
- repair order **leaf → parent**: `app.bin` first, then `app_area_head`, then
  the outer `flash.bin` dcrc, then the entry-table CRC, then the header CRC

**Both banks must be patched and repaired independently.** Mirroring patch bytes
into the second bank without recomputing *its* CRCs produces an image that
verifies offline and fails on the device — a real, previously shipped bug.

---

## 3. Locate the RF bring-up

```bash
python tools/jl_string_xref.py app.bin        # string references at the right base
```

Rules that matter on JL images:

1. **Runtime base is `0x06000100 + file_offset`.** Not `0x06000000`. Off by 256
   bytes, and every "unresolvable pointer" resolves.
2. **Scan every substring start.** Strings are materialised as full-address
   `mov rX,#0x06xxxxxx` (`iword 0xFFC0|reg` + imm32 LE), and the pointer often
   lands on a *suffix* (`">RF_init"` at `0x060300a2`, not the string start).
3. **Call encodings** (verify against two known-good sites before trusting):

   | bytes | form | target |
   |---|---|---|
   | 6-byte, `80 ff …` | PC-relative | `ins_addr + 6 + simm32` |
   | 4-byte, `bf ea` | PC-relative | `ins_addr + 4 + simm16*2` |

4. **Ghidra function boundaries on raw blobs are unreliable** (6–0x16-byte
   fragments). Find prologues by scanning back for `?? 04` push patterns, and
   confirm any global the decompiler names against the raw bytes.

Walk from the log string to its function (`RF_init` in our case), then find
**who calls it**:

```bash
python tools/jl_string_xref.py app.bin --callers 0x75450
```

The kill site is the **call**, and there should ideally be exactly one.

Also worth checking before you patch: is the radio brought up *earlier* than
the app (bootloader/maskrom), with the app only attaching to an already-running
controller? If so, app-side patching is dead weight and you need to patch the
bring-up itself.

---

## 4. Patch the caller, not the function

Replace the call with a same-length instruction that returns a plausible
"already done / not supported" value:

```
80 ff ec eb ff ff   →   40 e0 06 00 00 16     # movz r0,#6 ; mov r0,r0
```

Both are 6 bytes, so no offset shifts anywhere in the image.

**Never** overwrite the first instruction of the function to return early — JL
functions frequently have no `rts` and exit via `pop {pc,…}`; skipping the
epilogue corrupts the stack. That is the brick-shaped mistake.

Pick a return value the caller tolerates (in our case `6`; the caller logs and
continues). If you do not know what the caller does with the result, decompile
the caller first.

---

## 5. Prove the patch is LIVE (before you commit to it)

Add a **marker**: rewrite a string the firmware hands back over its normal
status channel, at *identical length* so nothing shifts.

```
"MP1MP2MP3WMAWAVFLATMP"  (21 bytes)  →  "RFKILL_V2_LIVE_OK_21!"  (21 bytes)
```

Flash it and read it back. Then:

- marker changed → patches are live; if the radio still works, the **target was
  wrong**, not the flash.
- marker original → the bootloader is booting the **other bank**; fix the
  bank/dual-image logic before any more RE.

Do this once, early. It is what separates "the patch did nothing" from "the
patch was never executed".

Caveat for RF kills: once the kill works, the app no longer advertises, so you
**cannot** read the marker back afterwards. Use the marker on an intermediate
build (radio still alive) to validate the flash path, then ship the kill build.
After a successful kill the loader's own `E6=0x00` is your proof that the
flashed bank equals the patched image.

---

## 6. Build

```bash
python tools/jl_ufw.py build \
  --stock stock.ufw \
  --expect-sha <your-stock-sha256> \
  --manifest your-manifest.json \
  --output patched.ufw
```

Manifest format (offsets are **decrypted `app.bin`** offsets, applied to both
banks):

```json
[
  {"offset": 485470,
   "expected": "80ffecebffff",
   "replacement": "40e006000016"}
]
```

The builder refuses if: the stock hash differs, any `expected` byte does not
match, a patch changes length, patches overlap, or the rebuilt image's
plaintext diff contains anything outside the declared manifest.

Read the JSON report it prints. `status: verified_with_preserved_unknown_semantics`
is the success line; `changed_bytes` should equal your manifest size plus the
recomputed CRC bytes.

---

## 7. Flash

Two passes. The app downloads the loader and reboots into it; the loader then
pulls the real image.

```bash
# pass 1 — app is running and advertising
python tools/serve_ota.py --mac <app-mac> --image patched.ufw
#   ... E6=0x80 → device relinks (often to a different address) and reboots

# pass 2 — against the loader
python tools/serve_ota.py --mac <loader-mac> --image patched.ufw --skip-e1e2 --reboot
```

Rules:

- **Do not interrupt.** No status polling, no disconnect, no "it looks stuck".
  A single lost BLE notification truncates a 4 KiB block and the loader aborts
  the whole transfer.
- Budget ~3.2 s per 4 KiB block on a 200 ms connection interval → a 345-block
  bank is ~18–20 min. Set `--max-seconds 1700` and walk away.
- A run that stops early looks exactly like a rejection. It usually is not —
  re-run it cleanly before concluding anything about the loader or the image.
- `E6=0x00` = success. `0x04` = "bad update file" = one block arrived wrong.

---

## 8. Verify — measure, never assume

```bash
python tools/verify_rf.py --name <device-name> --vid 4C4A --edr <classic-mac>
```

Three independent signals, all required:

1. **BLE** — active scans, several passes; report *all* advertisers seen, not
   just the target (0 total on a quiet desk is normal and proves the scan runs).
2. **Classic BR/EDR** — the local radio's view of the device: `connected=False`,
   old `last_seen`.
3. **Wired function** — the USB device must still enumerate (audio + HID).

Success is `RADIO DEAD: True` **and** `WIRED FUNCTION ALIVE: True`. A progress
bar is not a kill.

Test in the device's maximum-transmission state (pairing mode), not standby.

---

## 9. Recovery plan (have it before step 7)

Once the kill is live there is no wireless recovery: the OTA service is the
radio. Options, in order of preference:

| path | cost | notes |
|---|---|---|
| JL `USB_KEY` dongle → UBOOT | ~$10–15 | plugs into the device's USB port, bit-bangs `0x16EF` on D+/D− during boot, then `jl-uboot-tool` writes flash directly. No case opening. |
| ESP32-S3 + MOSFET USB mux | ~$10–15 DIY | same trick, open sketch (`vatidaniel/jieli-usbkey`) |
| UART pads on the board | ~$2 USB-TTL | needs the case open; JL uboot has a `0xC0..0xC5` UART/HID upgrade protocol |

Note that USB **HID** is usually not a recovery path: consumer-control
collections (usage page `0x000C`) have no output/feature reports, so there is
no vendor command channel. Check with a HID caps probe before counting on it.

---

## 10. Generalising to another JieLi device

The method transfers; the addresses do not. For each new device:

1. Get its own stock `.ufw` and re-do step 2 (roundtrip) before anything else.
2. Re-derive the base: find the startup stub's `mov rX,#<full address>` and
   subtract the file offset of the same bytes. Do not assume `0x6000100`.
3. Re-run step 3 on *its* `app.bin` — the RF init string and call site move.
4. Keep the marker discipline: identical-length string, read it back on an
   intermediate build.
5. If the device is **single-bank**, `jl_ufw.py` needs adaptation (it requires
   `flash.bin` and `flash2.bin`). The CRC repair order still applies, minus the
   second bank.

If the vendor firmware is not a `.ufw` (raw `app.bin`, SD-card image, USB-ISP
package), the patch/build steps change but the locate/patch/verify discipline
does not.
