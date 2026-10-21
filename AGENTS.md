# AGENTS.md — instructions for AI agents picking up this task

If a user asks you to "kill the Bluetooth/WiFi on this speaker / soundbar /
badge so it stops radiating", and the device has USB `VID_4C4A` (JieLi), you are
in the right place. Do not start from a blank RE session — this repo is the
distilled path, including the mistakes that cost days.

## Hard rules before you touch anything

1. **Confirm the user owns the device** and wants a permanent, one-way change.
   Ask explicitly. The patch removes the radio, which removes the OTA recovery
   service — a bad image means hardware recovery.
2. **Get the stock `.ufw` and hash it.** Never flash a build whose stock input
   is not SHA-pinned (`--expect-sha`).
3. **Prove the repacker first.** `jl_ufw.py build` with `[]` must reproduce the
   stock image byte-for-byte. If it does not, stop; do not "work around" it.
4. **Never edit around a failed `expected` byte match.** That check is what
   stops you bricking the device with another model's offsets.

## The path (do these in order)

```bash
# 1. extract app.bin from the stock .ufw (your JLFS tooling) and locate RF init
python tools/jl_string_xref.py app.bin 0x<rf_init_string_off>
python tools/jl_string_xref.py app.bin --callers 0x<rf_init_func_off>

# 2. patch the CALLER, not the function entry (same-length instruction)
#    manifest.json: [{"offset":..., "expected":"...", "replacement":"..."}]

# 3. build + verify
python tools/jl_ufw.py build --stock stock.ufw --expect-sha <sha> \
       --manifest manifest.json --output patched.ufw

# 4. flash: pass 1 against the app, pass 2 against the loader
python tools/serve_ota.py --mac <app-mac> --image patched.ufw
python tools/serve_ota.py --mac <loader-mac> --image patched.ufw --skip-e1e2 --reboot

# 5. verify by measurement, not by the progress bar
python tools/verify_rf.py --name <NAME> --vid 4C4A --edr <classic-mac>
```

## Things that will waste your time if you ignore them

- Runtime base is **`0x06000100 + file_offset`**, not `0x06000000`.
- Do **not** stub a function entry: JL functions exit via `pop {pc,…}`, so an
  early return skips the epilogue and corrupts the stack. Patch the call.
- Strings are referenced at a **suffix**, not the start (`">RF_init"` inside
  `">>>>>>>>>>RF_init"`).
- `E4` and `E7` are **silently ignored** by the OTA loader. Do not retry them.
- **Never poll `E6`, disconnect, or stop mid-transfer.** A single lost BLE
  notification truncates a 4 KiB block and the loader aborts the whole
  transfer with `0x04`. A short run is not a rejection — re-run it cleanly.
  A full bank is ~345 blocks at ~3.2 s each (~18–20 min).
- A clean flash is not a kill. The verdict comes from `verify_rf.py`: zero
  advertisers, classic link down, wired function alive.
- After a successful kill you **cannot** read a firmware marker back (no radio).
  That is expected; the loader's `E6=0x00` is the content proof.

## Where the details live

| need | file |
|---|---|
| generalized procedure, step by step | `docs/RECIPE.md` |
| protocol opcodes, two-pass flow, failure modes | `docs/RCSP-OTA-NOTES.md` |
| worked example, every address and byte | `docs/SOUNDBLADE-TT201M2.md` |

## What not to do

- Do not redistribute vendor `.ufw` files (not in this repo, keep it that way).
- Do not build a turnkey flasher that takes a MAC address and an image: the
  user must supply their own stock image and pass the build gate.
- Do not make health claims. This reduces RF emissions; it is not a treatment.
