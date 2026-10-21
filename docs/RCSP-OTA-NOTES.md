# RCSP OTA notes (JieLi, BLE)

Protocol observations from driving the TT201M2 loader. Useful if you are
adapting this to another JL device, or writing your own client.

The framing, auth handshake and BLE transport are implemented in the public
**qix-ble** package (JieLi badge research). This repo only adds the serve loop
and the failure analysis; it does not re-host auth material.

## Transport

- GATT service `0000ae00-0000-1000-8000-00805f9b34fb`
  - `AE01` = write (write-without-response), phone → device
  - `AE02` = notify, device → phone
- An auth handshake must complete before OTA opcodes are accepted (random
  challenge / encrypted response / device challenge).
- MTU matters: observed `mtu_alt=264` → 261-byte fragments. A 4096-byte block is
  16 fragments; at a ~200 ms connection interval that is ~3.2 s per block.

## Opcodes

| op | name | direction | payload |
|---|---|---|---|
| `0xE1` | get update file info offset | phone → dev | empty |
| `0xE1` | response | dev → phone | `offset:u32be`, `len:u16be` |
| `0xE2` | inquire can update | phone → dev | the "mark" block (`len` bytes from `offset`) |
| `0xE2` | response | dev → phone | `status:u8` |
| `0xE3` | enter update mode | phone → dev | empty |
| `0xE4` | exit update mode | phone → dev | empty (accepted, no effect on this loader) |
| `0xE5` | send/request fw block | **dev → phone** | `offset:u32be`, `len:u16be` |
| `0xE5` | response | phone → dev | `status:u8` + `data[len]` |
| `0xE6` | get refresh fw status | phone → dev | empty |
| `0xE6` | response | dev → phone | `result:u8` |
| `0xE7` | set device reboot | phone → dev | (ignored by this loader) |
| `0xE8` | notify content size | dev → phone | `size:u32be` |
| `0x0B` | switch communication way | phone → dev | `way:u8`, `reconnect:u8` |
| `0x03` | get target info | phone → dev | TLV attrs (attr 9 byte0 = mandatory_upgrade_flag) |

Note the direction: **the device pulls**. After `E3` the phone is a passive
responder answering `E5` with the bytes at the requested offset. There is no
push mode in this firmware.

## Two-pass update

```
pass 1 (app running)
  E1 → E2(0x00) → E3 → serve E5 pulls → E6 = 0x80
  0x0B {0x00, 0x01} → device drops the link itself and reboots into the loader
pass 2 (loader running, different address)
  E3 only → serve E5 pulls → [0,0] → E6 = 0x00
```

`E6 = 0x80` means "loader downloaded" — the transfer is not finished. The
reference master does **not** disconnect after pass 1; it sends `0x0B` and waits
for the *device* to drop the link. Disconnecting yourself is what leaves units
half-updated.

Pass 2 deliberately skips `E1`/`E2`: the loader already has the staged file
identity from pass 1.

## `E6` result codes

| code | meaning |
|---|---|
| `0x00` | success — bank written and verified |
| `0x01` | verify failed |
| `0x02` | update failed |
| `0x03` | key mismatch |
| `0x04` | **bad update file** — one block arrived wrong (the common one) |
| `0x05` | uboot mismatch |
| `0x06` | length error |
| `0x07` | flash read/write failed |
| `0x08` | command timeout |
| `0x80` | loader staged (pass 1 done, retransfer needed) |

## `E2` can-update codes

| code | meaning |
|---|---|
| `0x00` | OK |
| `0x01` | low battery (device refuses OTA on low power) |
| `0x02` | firmware-info error (bad/incompatible header) |
| `0x03` | same version |
| `0x04`/`0x05` | TWS not connected / not in charge store |
| `0x06` | an update is already in progress |
| `0x07` | multiple BT devices connected |

## What the loader actually asks for

A bank update is not a linear stream. Observed request sequence:

```
0/512        512/512      ← outer UFW header
197760/512   197760/32   197760/512   201715/88   201856/32   ← bank header + directory
E8 notify-size=1409024
1/16 × 5      ← file-id read (offset 1, 16 bytes) — retried, harmless
1606784/4096  ← last 4 KiB block of the content
1602688/4096 … 197760/4096   ← descending, 345 blocks total
0/0           ← done-signal
```

The descending order is the loader's own design. Do not reorder it, do not
batch it, do not "optimise" it.

## Why an interrupted transfer is fatal

`E6 = 0x04` is reported for the **whole transfer** as soon as one 4 KiB block
arrives truncated. On a weak link (−82…−94 dBm) a single lost notification is
enough. Signature: the loader replays the identical sweep from the identical
start offset and dies at a **random** depth.

Rules:

1. Never poll `E6` mid-transfer. Poll only after the `[0,0]` done-signal.
2. Never disconnect or stop early "because it looks stuck".
3. Budget ~18–20 min and let it finish.
4. A short run is not a rejection. Re-run cleanly before concluding anything
   about the loader or the image.
5. Serve the file bytes verbatim at the requested offsets — including the
   `offset=1, len=16` requests, which are the loader's file-id probe.

## Recovery when it does fail

If the bank was partially written, the next attempt rewrites it from the same
start. There is no erase command in this protocol; the loader erases as it
writes. A run that never completes leaves the unit in the loader, still
advertising — which is why the "one-way door" warning exists.
