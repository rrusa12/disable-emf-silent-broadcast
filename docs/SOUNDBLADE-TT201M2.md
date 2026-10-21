# Case study — BlueAnt Soundblade (TT201M2)

Everything below was measured on one unit on 2026-10-21. **Treat these as
evidence, not as a universal recipe**: the method generalizes, the addresses do
not. If your `.ufw` is not byte-identical to the stock hash below, none of these
offsets apply.

## Device

| | |
|---|---|
| product | BlueAnt Soundblade, model TT201M2 |
| SoC | JieLi (USB `VID_4C4A`, `PID_4155`) — composite: USB audio + consumer HID |
| app / loader firmware | 1.8.16.10 (`fw_version` attr `0108100a`, `mtu_alt=264`) |
| power | mains / USB-PSU — **no battery**. Unplugging the USB-C *data* cable does nothing; the power lead is the real power cycle. |
| radios | BLE address `9D:D9:74:40:CB:5A` (app), `…CB:5B` (OTA loader); classic BR/EDR `9D:D9:74:FE:D7:60` |
| wired | USB audio, AUX, HDMI — unaffected by the patch |

## Stock image

```
TT201M2_stock.ufw   3 023 744 bytes
sha256              a12c51ea7b3d4e1cdf84eca1a396fc493ec086735c61ec186ecc4cec04c0e756
```

Container layout (outer entries, offsets into the `.ufw`):

| entry | offset | size |
|---|---:|---:|
| `uboot.version` | 1024 | 32 |
| `isd_config.ini` | 1056 | 1045 |
| `v_ota.bin` | 2112 | 64 |
| `ota.bin` | 2176 | 195 578 |
| `flash.bin` (bank A) | 197 760 | 1 413 120 |
| `flash2.bin` (bank B) | 1 610 880 | 1 412 608 |
| `farg.cfg` / `blimit.bin` / `tail.bin` | 3 023 488… | 5 / 144 / 64 |

Per-bank JLFS tree (identical node names in both banks, offsets differ):

| node | offset | size | note |
|---|---:|---:|---|
| `uboot.boot` | 160 | 3795 | stage-1; two independent ENC streams (16-byte header, then body) |
| `isd_config.ini` | 3955 | 88 | holds the chipkey material |
| `app_dir_head` | 4096 | 0xFFFFFFFF | virtual root |
| `app_area_head` | 4128 | 914 744 | parent record, `flags=0x83` |
| `app.bin` | 4352 | 914 520 | the code — **this is what we patch** |
| `VM`, `PRCT`, `BTIF`, `EXIF` | — | — | virtual partitions (`dcrc=0xffff`, semantics unknown — preserved byte-exact) |
| `tone`, `*.mp3`, `*.wts` | 918 904… | — | voice prompts |

Bank B's parent CRC legitimately differs from bank A's (`app_area_head`
`0x36d2` vs `0x963c`) because its VM/PRCT descriptors differ. A builder that
copies bank A's CRCs into bank B produces an image that verifies offline and
fails on the device.

## Address mapping

**`runtime = 0x06000100 + file_offset`** — not `0x06000000`.

Three independent confirmations:

| evidence | check |
|---|---|
| startup stub `mov r1,#0x60d0ae8` | file `0xd09e8` → `0x6000100 + 0xd09e8 = 0x60d0ae8` ✓ |
| startup stub `mov r0,#0x6012ee4` (main) | file `0x12ee4` → `0x6012ee4` ✓ |
| 443 const pointers land on string starts at delta −256 vs 104 at delta 0 | `jl_string_xref.py` |

## The RF bring-up chain

```
0x76958  BT controller task entry (invoked via function pointer at 0x761ac)
  └─ 0x76848  controller bring-up
       ├─ 0x75450  RF_init        ← logs ">>>>>>>>>>>>>>RF_init" (string @ 0x060300a2)
       │     or [0x00fe2200],#1   ← RF/analog power gate
       │     ~40 writes into the RF register block 0x00f0fc08
       ├─ list heads 0x10bba4 / 0x10bba8
       ├─ registered callbacks from 0x118814
       └─ 0x11d448 (RAM-resident), 0x9abc8, 0x9ad6a, 0x94090, 0x7ffae
```

`RF_init` has **exactly one caller**:

```
$ python tools/jl_string_xref.py app.bin --callers 0x75450
callers of 0x075450: 1
  call @0x07685e   inside function 0x076848
```

## The patch

Neutralise the call at `0x7685e` — 6-byte PC-relative call, replaced by a
same-length two-instruction sequence that returns `6`:

```
80 ff ec eb ff ff   →   40 e0 06 00 00 16
call 0x75450 (+0x6+0xffffebec)      movz r0,#6 ; mov r0,r0
```

Plus a liveness marker at `app.bin 0x35204`, 21 bytes, identical length:

```
MP1MP2MP3WMAWAVFLATMP   →   RFKILL_V2_LIVE_OK_21!
```

`examples/manifest.soundblade.json`:

```json
[
  {"offset": 217604,
   "expected": "4d50314d50324d5033574d41574156464c41544d50",
   "replacement": "52464b494c4c5f56325f4c4956455f4f4b5f323121"},
  {"offset": 485470,
   "expected": "80ffecebffff",
   "replacement": "40e006000016"}
]
```

`217604 = 0x35204`, `485470 = 0x7685e`. Offsets are **decrypted `app.bin`**
offsets and are applied to both banks.

Build result: `sha256 f9e18e7184baecc767650584e79b34d53257a1f6211458269196f459d2300cfb`,
35 differing plaintext bytes per bank (8 CRC bytes + 21 marker + 6 patch), no
unexpected diffs, byte-exact roundtrip proven first.

## Flashing

Two passes over BLE RCSP. Pass 1 runs against the app, which downloads the
loader and reboots into it; pass 2 serves the image to the loader.

```
pass 1  E1→E2→E3 … E6 = 0x80      (loader staged, device relinks …CB:5B)
pass 2  E3 only → device pulls     E6 = 0x00
```

Successful pass 2 transcript (`serve_ota.py`):

```
image 3023744
E3 sent → E3 ack
E8 notify-size=1409024
13 header reads: 0/512, 512/512, 197760/512, 197760/32, 197760/512,
                 201715/88, 201856/32, then off=1 len=16 ×5
345 × 4096-byte blocks, descending 1606784 → 197760
[1102.5 s] DONE-SIGNAL → E6 payload 00 → code 0x00
```

Timing: ~3.2 s per 4 KiB block (MTU 264, 16 fragments per block, ~200 ms
connection interval). Full bank ≈ 18 min.

### The failure that cost nine attempts

Every earlier attempt replayed the *same* sweep from `1606784` and aborted at a
random depth:

| attempt | image | blocks served | abort at |
|---|---|---:|---:|
| 1 | v2 | 230 | 780 s |
| 2 | v2 | 1 | 8.6 s |
| 3 | v2 | 4 | 18.6 s |
| 4 | v2 (altered E2 mark) | 59 | — |
| 5 | v2 (after power cycle) | 1 | — |
| 6 | v3 | 242 | 807 s |
| 7 | v3 | 10 | 25.6 s |
| 8 | v4 | 148 | 534 s |
| 9 | v5 | 2 | 11.1 s |
| 10 | **stock** | 2 | 11.1 s |

Stock failing identically was the tell: the image was never the problem. Random
abort depth with identical bytes = **transport**. One lost BLE notification
truncates a 4 KiB block and the loader reports E6=0x04 ("bad update file") for
the whole transfer.

The successful run differed only in being left completely alone.

## Verification (measured twice, ~10 min apart)

| check | result |
|---|---|
| USB `VID_4C4A&PID_4155` | present: MEDIA "BLUEANT SOUNDBLADE", USB Composite, HID Input, HID consumer control |
| BLE active scans (10 s ×3, 30 s ×1) | **0 advertisements at all** — no `CB:5A`, no `CB:5B` |
| classic `9D:D9:74:FE:D7:60` | `connected=False`, `remembered=True`, `last_seen=2026-10-19 16:51` |
| loader `E6` | `0x00` → flashed bank CRC == patched image |

The `RFKILL_V2_LIVE_OK_21!` marker cannot be read back afterwards: the radio is
dead by design, so there is no RCSP channel. That is expected; `E6=0x00` is the
proof that the flashed content matches the patched image.

USB HID exposes only a consumer-control collection (usage page `0x000C`,
3-byte input, no output/feature reports) — **no vendor channel**, so USB is not
a recovery path on this unit.

## Notes for anyone repeating this on the same model

- **Mains powered.** Pull the power lead for a real power cycle.
- The loader answers `0x03` (sysinfo), `E1`, `E2`, `E3`, `E8`, `E5`, `E6` and
  `0x0B`. It **silently ignores `E4` and `E7`** — no response frame at all, with
  any payload.
- The loader asks for `ufw[1:17]` five times just after `E8`. That is its
  file-id read (it contains the encrypted entry-table CRC, so it changes with
  the image). It is harmless; answer it from the file and keep going.
- **No over-the-air restore remains** after a successful kill: the app does not
  advertise, the loader does not run. Restoring stock needs a hardware path
  (JL `USB_KEY` dongle → UBOOT, or UART pads).
