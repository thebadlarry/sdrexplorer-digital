#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""Deterministically replay a recorded IQ file through op25 (no HackRF needed).

The point of this tool: decode-chain testing free of live-RF variance. Record
once (strong signal), then replay as many times as you like while tuning params.

Record a capture from the HackRF (native signed int8 I/Q) — tune the hardware
OFFSET(=300k) BELOW the channel so the signal dodges the DC spike, matching our
default center:
    hackrf_transfer -r cap.iq -f $((CHAN_HZ-300000)) -s 2400000 -n 72000000 \
        -a 1 -l 40 -g 24
(-n 72e6 samples @ 2.4Msps ~= 30 s.)  Then decode it:
    ./run_replay.sh cap.iq 482662500 P25
or point at a file from another SDR (give its actual center with --center, and
its format with --iq-size/--iq-signed; e.g. RTL-SDR cs8 = int8 signed = size 1).

Run under the op25 env (see run_replay.sh); logs decode lines to stdout.
"""
import argparse
import json
import os
import subprocess
import sys

_SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _SRC)                                            # this module's src/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(_SRC)), "sdrexplorer"))   # the core beside it
from sdrexplorer_digital.monitor import build_iq_config, multi_rx, op25_apps, SUPPORTED_MODES  # noqa: E402
from sdrexplorer.api import paths  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Replay an IQ file through op25")
    ap.add_argument("iq_file")
    ap.add_argument("chan_hz", type=int, nargs="?", default=None,
                    help="channel frequency in Hz (default: from sidecar .json)")
    ap.add_argument("mode", choices=SUPPORTED_MODES + ["P25P2"], nargs="?",
                    default=None)
    ap.add_argument("--center", type=int, default=None,
                    help="recording center freq (default: sidecar, else chan-300k)")
    ap.add_argument("--rate", type=int, default=None)
    ap.add_argument("--iq-size", type=int, default=None, choices=[1, 2, 4],
                    help="1=int8, 2=int16 (GUI recordings), 4=float32")
    ap.add_argument("--iq-signed", type=lambda s: s.lower() != "false",
                    default=None)
    ap.add_argument("-v", "--verbosity", type=int, default=10)
    args = ap.parse_args()

    if not os.path.exists(args.iq_file):
        sys.exit(f"no such file: {args.iq_file}")

    # A GUI recording ships a sidecar (<file>.json) describing center/chan/rate/
    # format — read it so `run_replay.sh cap.cs16` just works, with CLI overrides.
    side = {}
    sidecar = args.iq_file + ".json"
    if os.path.exists(sidecar):
        try:
            side = json.load(open(sidecar))
        except (OSError, ValueError):
            side = {}

    chan_hz = args.chan_hz or side.get("chan_hz")
    if chan_hz is None:
        sys.exit("need chan_hz (positional) or a sidecar .json with chan_hz")
    mode = args.mode or side.get("mode") or "P25"
    if mode not in SUPPORTED_MODES + ["P25P2"]:
        mode = "P25"                       # analog mode in sidecar -> default P25
    cfg = build_iq_config(
        os.path.abspath(args.iq_file), int(chan_hz), mode,
        center_hz=args.center if args.center is not None else side.get("center_hz"),
        samp_rate=args.rate or side.get("samp_rate", 2_400_000),
        iq_size=args.iq_size or side.get("iq_size", 2),
        iq_signed=args.iq_signed if args.iq_signed is not None
        else side.get("iq_signed", True))
    sys.stderr.write("replay config: %s\n" % json.dumps(cfg["devices"][0]))
    if multi_rx() is None:
        sys.exit("op25 not found (paths keys op25 / op25_apps: python3 -m sdrexplorer.paths)")
    proc = subprocess.Popen(
        [sys.executable, multi_rx(), "-v", str(args.verbosity), "-c", "-"],
        cwd=op25_apps(), stdin=subprocess.PIPE, env=paths.tool_env("op25", "op25_apps"))
    proc.communicate((json.dumps(cfg) + "\n").encode())
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
