#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
# Replay a recorded IQ file through op25, decoupled from the HackRF. op25 is found
# the same way the app finds it (python3 -m sdrexplorer.paths). Usage:
#   ./run_replay.sh cap.iq 482662500 P25 [extra op25_replay.py args...]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec "${PYTHON:-python3}" "$HERE/op25_replay.py" "$@"
