# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""The external builds this module uses, as sdrexplorer path keys (``python3 -m sdrexplorer.paths`` lists
them once the module has loaded). Resolved like the core's: SDREXPLORER_<KEY>, paths.json,
<install>/ext/<key>, the system."""
from __future__ import annotations

import os

from sdrexplorer.api import paths as _paths

KEYS = {
    "op25": "op25 install prefix (P25 / DMR / SmartNet decode, P25 / DMR TX)",
    "op25_apps": "op25's gr-op25_repeater/apps directory",
    "dsd_fme": "dsd-fme install prefix (NXDN, EDACS, decoder proofs)",
}


def register_paths():
    if "dsd_fme" in _paths.KEYS and "op25_apps" in _paths.KEYS:
        return
    _paths.register("op25", KEYS["op25"], legacy_env=("OP25_PREFIX",))
    _paths.register("op25_apps", KEYS["op25_apps"], legacy_env=("OP25_APPS",), py_dirs=(".", "tx"),
                    default=lambda: os.path.join(_paths.get("op25") or "", "apps"))
    _paths.register("dsd_fme", KEYS["dsd_fme"], program=True)
