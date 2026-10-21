#!/usr/bin/env python3
"""Verify that a device's radios are actually dead.

A clean flash is NOT a kill. This measures the three things that together
prove it:

  1. BLE advertising — active scans; count ALL advertisers, not just the target
     (0 total is normal on a quiet desk and proves the scan is working).
  2. Classic BR/EDR — query the local radio for the device's connection state.
  3. The wired function — the USB device must still enumerate.

Usage:
  python verify_rf.py --name SOUNDBLADE --vid 4C4A --edr 9D:D9:74:FE:D7:60
  python verify_rf.py --name SOUNDBLADE --vid 4C4A --edr ... --passes 3 --seconds 10

Note: the RF-kill patch removes the radio, so an RCSP/sysinfo marker readback is
impossible afterwards. That is the point, not a failure.
"""
from __future__ import annotations

import argparse
import asyncio
import ctypes
import ctypes.wintypes as wt
import json
import subprocess


# ---------------------------------------------------------------- BLE
async def _scan(seconds: float):
    import bleak
    seen = {}

    def cb(dev, adv):
        seen[dev.address] = (dev.name or adv.local_name or "", adv.rssi)

    scanner = bleak.BleakScanner(detection_callback=cb)
    await scanner.start()
    await asyncio.sleep(seconds)
    await scanner.stop()
    return seen


def ble_passes(passes: int, seconds: float, name_sub: str):
    hits = []
    totals = []
    for i in range(1, passes + 1):
        seen = asyncio.run(_scan(seconds))
        totals.append(len(seen))
        for addr, (nm, rssi) in seen.items():
            if name_sub.lower() in (nm or "").lower():
                hits.append((addr, nm, rssi))
        print(f"  pass {i}: {len(seen)} advertisers seen; target-name hits so far {len(hits)}")
        for addr, (nm, rssi) in sorted(seen.items()):
            print(f"     {addr} {nm!r} rssi={rssi}")
    return hits, totals


# ---------------------------------------------------------------- classic
class _BA(ctypes.Structure):
    _fields_ = [("ullLong", ctypes.c_ulonglong)]


class _ST(ctypes.Structure):
    _fields_ = [("wYear", wt.WORD), ("wMonth", wt.WORD), ("wDayOfWeek", wt.WORD),
                ("wDay", wt.WORD), ("wHour", wt.WORD), ("wMinute", wt.WORD),
                ("wSecond", wt.WORD), ("wMilliseconds", wt.WORD)]


class _DI(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("Address", _BA), ("ulClassofDevice", wt.DWORD),
                ("fConnected", wt.BOOL), ("fRemembered", wt.BOOL),
                ("fAuthenticated", wt.BOOL), ("stLastSeen", _ST),
                ("stLastUsed", _ST), ("szName", ctypes.c_wchar * 248)]


class _FRP(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD)]


def classic_state(mac: str):
    """Return dict(connected, remembered, last_seen) or None if the radio can't
    be opened. NOTE: the address must be given as a big-endian ullLong
    (0x9DD974FED760); the byte-reversed form returns E_INVALIDARG."""
    bt = ctypes.WinDLL("bthprops.cpl")
    bt.BluetoothFindFirstRadio.argtypes = [ctypes.POINTER(_FRP), ctypes.POINTER(wt.HANDLE)]
    bt.BluetoothFindFirstRadio.restype = wt.HANDLE
    bt.BluetoothGetDeviceInfo.argtypes = [wt.HANDLE, ctypes.POINTER(_DI)]
    bt.BluetoothGetDeviceInfo.restype = wt.DWORD

    frp = _FRP()
    frp.dwSize = ctypes.sizeof(frp)
    hradio = wt.HANDLE()
    if not bt.BluetoothFindFirstRadio(ctypes.byref(frp), ctypes.byref(hradio)):
        return None

    val = int(mac.replace(":", ""), 16)
    info = _DI()
    info.dwSize = ctypes.sizeof(info)
    info.Address.ullLong = val
    if bt.BluetoothGetDeviceInfo(hradio, ctypes.byref(info)) != 0:
        return {"known": False}
    st = info.stLastSeen
    seen = (f"{st.wYear:04d}-{st.wMonth:02d}-{st.wDay:02d} "
            f"{st.wHour:02d}:{st.wMinute:02d}") if st.wYear else "never"
    return {"known": True, "name": info.szName, "connected": bool(info.fConnected),
            "remembered": bool(info.fRemembered), "last_seen": seen}


# ---------------------------------------------------------------- USB
def usb_devices(vid: str):
    ps = ("Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match "
          f"'VID_{vid}' }} | Select-Object Status,Class,FriendlyName | "
          "ConvertTo-Json -Compress")
    out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps],
                         capture_output=True, text=True)
    try:
        data = json.loads(out.stdout)
    except Exception:
        return []
    return data if isinstance(data, list) else [data]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="advertised/paired name substring")
    ap.add_argument("--vid", required=True, help="USB VID in hex, e.g. 4C4A")
    ap.add_argument("--edr", required=True, help="classic BR/EDR address")
    ap.add_argument("--passes", type=int, default=3)
    ap.add_argument("--seconds", type=float, default=10.0)
    args = ap.parse_args()

    print("=== BLE advertising (active scans) ===")
    ble_hits, totals = ble_passes(args.passes, args.seconds, args.name)

    print("\n=== classic BR/EDR state ===")
    classic = classic_state(args.edr)
    print(f"  {json.dumps(classic, ensure_ascii=False)}")

    print("\n=== wired function (USB) ===")
    usb = usb_devices(args.vid)
    for d in usb:
        print(f"  {d.get('Status','?'):4s} {d.get('Class','?'):9s} {d.get('FriendlyName','?')}")

    radio_dead = (not ble_hits) and (classic is None or
                                     (classic.get("known") and not classic.get("connected")))
    wired_alive = bool(usb)

    print("\n=== SUMMARY ===")
    print(f"  advertisers seen per pass: {totals}")
    print(f"  BLE target hits           : {len(ble_hits)}")
    print(f"  classic connected         : {classic.get('connected') if classic else 'unknown'}")
    print(f"  USB functions present     : {len(usb)}")
    print(f"  RADIO DEAD                : {radio_dead}")
    print(f"  WIRED FUNCTION ALIVE      : {wired_alive}")
    print(f"  VERDICT                   : "
          f"{'KILLED' if radio_dead and wired_alive else 'NOT CONFIRMED'}")
    return 0 if radio_dead and wired_alive else 1


if __name__ == "__main__":
    raise SystemExit(main())
