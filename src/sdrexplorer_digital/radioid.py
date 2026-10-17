# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""Resolve a DMR radio ID to its registered callsign via radioid.net's public
user database (the registry most ham DMR networks -- BrandMeister, TGIF,
NewEngTRBO, etc. -- require registration against). Used to label a decoded
DMR SRC value with an actual callsign instead of a bare numeric ID.

Lookups are cached to disk (dmr_id_cache.json) since a radio ID never changes
identity and repeat lookups would otherwise hit the network on every call.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Optional

from sdrexplorer.api import paths as _paths

API = "https://radioid.net/api/dmr/user/?id={id}"
_UA = "sdrexplorer/0.1 (HackRF scanner; DMR ID lookup)"

def _cache_path():
    return _paths.memory_file("dmr_id_cache.json")


def load_cache() -> dict:
    try:
        with open(_cache_path()) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_cache(cache: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_cache_path()), exist_ok=True)
        with open(_cache_path(), "w") as fh:
            json.dump(cache, fh, indent=2)
    except OSError:
        pass


def lookup(dmr_id: int, timeout: float = 8.0) -> Optional[dict]:
    """{'callsign', 'name', 'city', 'state', 'country'} for a registered DMR
    ID, or None if unregistered or the lookup failed. Network call -- run off
    the UI thread."""
    req = urllib.request.Request(API.format(id=int(dmr_id)),
                                  headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception:
        return None
    results = data.get("results") or []
    if not results:
        return None
    hit = results[0]
    callsign = (hit.get("callsign") or "").strip()
    if not callsign:
        return None
    return {
        "callsign": callsign,
        "name": (hit.get("fname") or hit.get("name") or "").strip(),
        "city": (hit.get("city") or "").strip(),
        "state": (hit.get("state") or "").strip(),
        "country": (hit.get("country") or "").strip(),
    }


try:                                    # the Qt worker (not needed by headless callers)
    from PyQt5 import QtCore

    class DmrIdWorker(QtCore.QThread):
        """Resolve a DMR radio ID to its registered callsign (radioid.net) off
        the UI thread, so a burst of new SRCs on a busy talkgroup can't stall
        the decode log."""

        done = QtCore.pyqtSignal(int, object)   # dmr_id, info dict or None

        def __init__(self, dmr_id, parent=None):
            super().__init__(parent)
            self.dmr_id = dmr_id

        def run(self):
            try:
                info = lookup(self.dmr_id)
            except Exception:                             # network / parse
                info = None
            self.done.emit(self.dmr_id, info)
except ImportError:                     # pragma: no cover
    DmrIdWorker = None
