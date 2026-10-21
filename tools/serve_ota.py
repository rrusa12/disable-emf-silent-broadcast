#!/usr/bin/env python3
"""Serve a JieLi .ufw image to an RCSP OTA loader over BLE (pass 2).

The device drives the transfer: after E3 it pulls blocks with E5
(offset:u32be + len:u16be) and we answer each one with the bytes at that
offset. It ends with a [0,0] request; then we query E6 for the result.

DO NOT interrupt this. A single lost BLE notification truncates a 4 KiB block
and the loader aborts the whole transfer with E6=0x04 ("bad update file").
Do not poll E6 mid-transfer, do not disconnect, do not stop early.

Usage:
  python serve_ota.py --mac AA:BB:CC:DD:EE:FF --image firmware.ufw
  python serve_ota.py ... --reboot          # send E7 after E6==0x00
  python serve_ota.py ... --skip-e1e2       # pass 2 against a loader

Requires: pip install bleak   (and the qix_ble package for auth/transport)
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from qix_ble.transport import QixTransport
from qix_ble.auth import AuthSession
from qix_ble.rcsp_ota import (
    RcspOtaUpdater, OP_SEND_FW_UPDATE_BLOCK, OP_NOTIFY_CONTENT_SIZE,
    OP_ENTER_UPDATE_MODE, OP_GET_REFRESH_FW_STATUS, OP_SET_DEVICE_REBOOT,
    E6_RESULT,
)
from qix_ble.rcsp_session import _parse_inner
from qix_ble.errors import TimeoutError as QixTimeoutError


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mac", required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--skip-e1e2", action="store_true",
                    help="pass 2: send E3 only (the reference master does this "
                         "once its relink latch is set)")
    ap.add_argument("--reboot", action="store_true",
                    help="send E7 when E6 reports success")
    ap.add_argument("--max-seconds", type=float, default=1700.0,
                    help="hard stop; a full 345-block bank needs ~18-20 min")
    ap.add_argument("--max-chunks", type=int, default=400)
    ap.add_argument("--log", default="serve_ota.log")
    args = ap.parse_args()

    ufw = open(args.image, "rb").read()
    print(f"image {args.image}: {len(ufw)} bytes", flush=True)

    events = []
    t0 = time.monotonic()

    def note(**kw):
        kw["t"] = round(time.monotonic() - t0, 2)
        events.append(kw)

    rc = 1
    with QixTransport(args.mac) as t:
        AuthSession(t, step_timeout=20.0).do_handshake()
        print("auth OK", flush=True)
        up = RcspOtaUpdater(t)

        if not args.skip_e1e2:
            off, ln = up._e1_get_offset(15.0)
            print(f"E1 -> off={off} len={ln}", flush=True)
            note(kind="E1", off=off, ln=ln)
            mark = ufw[off:off + ln] if ln else b"\x00"
            cu = up._e2_inquire(mark, 15.0)
            print(f"E2 -> can_update=0x{cu:02x}", flush=True)
            if cu != 0x00:
                print("device refused the update (see E2_CAN_UPDATE table)", flush=True)
                return 2

        up._send_command(OP_ENTER_UPDATE_MODE)
        print("E3 sent — entering device-driven loop; do not interrupt", flush=True)

        chunks = 0
        blocks = []
        while time.monotonic() - t0 < args.max_seconds and chunks < args.max_chunks:
            try:
                frame = t.recv_rcsp_frame(timeout=25.0)
            except QixTimeoutError:
                print(f"[{time.monotonic()-t0:7.1f}s] 25 s silence — device stopped "
                      f"asking; polling E6 once", flush=True)
                break
            inner = _parse_inner(frame)
            note(kind="rx", cmd=frame.cmd, flag=frame.flag, is_cmd=inner.is_command,
                 plen=len(inner.payload))

            if inner.is_command and frame.cmd == OP_SEND_FW_UPDATE_BLOCK and len(inner.payload) >= 6:
                o = int.from_bytes(inner.payload[0:4], "big")
                ln = int.from_bytes(inner.payload[4:6], "big")
                if o == 0 and ln == 0:
                    print(f"[{time.monotonic()-t0:7.1f}s] DONE-SIGNAL after {chunks} chunks",
                          flush=True)
                    up._send_response(OP_SEND_FW_UPDATE_BLOCK, inner.op_code_sn, 0x00, b"")
                    time.sleep(0.5)
                    break
                up._send_response(OP_SEND_FW_UPDATE_BLOCK, inner.op_code_sn, 0x00,
                                  ufw[o:o + ln])
                chunks += 1
                if ln == 4096:
                    blocks.append(o)
                if chunks <= 20 or chunks % 25 == 0:
                    print(f"[{time.monotonic()-t0:7.1f}s] #{chunks} off={o} len={ln}",
                          flush=True)

            elif inner.is_command and frame.cmd == OP_NOTIFY_CONTENT_SIZE:
                size = int.from_bytes(inner.payload[0:4], "big") if len(inner.payload) >= 4 else 0
                print(f"[{time.monotonic()-t0:7.1f}s] E8 notify-size={size}", flush=True)
                up._send_response(OP_NOTIFY_CONTENT_SIZE, inner.op_code_sn, 0x00, b"")

            elif not inner.is_command and frame.cmd == OP_ENTER_UPDATE_MODE:
                print(f"[{time.monotonic()-t0:7.1f}s] E3 ack", flush=True)

            elif not inner.is_command and frame.cmd == OP_GET_REFRESH_FW_STATUS:
                code = inner.payload[0] if inner.payload else 0xFF
                print(f"[{time.monotonic()-t0:7.1f}s] E6 pushed: 0x{code:02x} "
                      f"({E6_RESULT.get(code, 'unknown')})", flush=True)
                rc = 0 if code == 0x00 else 1
                break
            else:
                print(f"[{time.monotonic()-t0:7.1f}s] other cmd=0x{frame.cmd:02x} "
                      f"payload={inner.payload.hex()[:64]}", flush=True)

        try:
            code = up._e6_query_status(20.0)
            print(f"E6 = 0x{code:02x} ({E6_RESULT.get(code, 'unknown')})", flush=True)
            note(kind="E6", code=code)
            rc = 0 if code == 0x00 else 1
            if code == 0x00 and args.reboot:
                print("E6=0x00 → sending E7 reboot", flush=True)
                up._e7_reboot(10.0)
        except Exception as exc:
            print(f"E6 failed: {type(exc).__name__}: {exc}", flush=True)
            rc = 1

        print(f"chunks={chunks} 4k_blocks={len(blocks)}", flush=True)
        if blocks:
            print(f"first 4k offsets: {blocks[:6]}")
            print(f"last 4k offsets: {blocks[-6:]}")
            print(f"duplicate requests: {len(blocks) - len(set(blocks))}")

    with open(args.log, "w", encoding="utf-8") as fh:
        json.dump({"image": args.image, "events": events}, fh, indent=1)
    print(f"log written to {args.log}", flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
