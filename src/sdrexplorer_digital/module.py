# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""The digital module: op25 (P25, DMR, SmartNet, P25 / DMR TX) and dsd-fme (NXDN48 / NXDN96, EDACS) on the
core's channel tap, decoding in parallel with whatever analog mode is picked.

- A "Digital" tab in the decode strip: which decoder runs on the op25 slot / dsd-fme (P25, DMR, NXDN,
  EDACS; SmartNet always runs), the lock light, Keys..., Digital only, the dsd-fme status, data bursts.
- Decodes go to the core's decode log / recording labels as api.Decode records; LRRP and NXDN GPS fixes
  to the map as api.Position; DATA bursts to the payload pane (pcap-exportable, raw IP).
- A decoder with a lock claims the speaker (analog muted; the meter shows the protocol) and its voice
  plays through the core's audio chain (voice.py). A hang time keeps the claim through short sync drops.
- decodes(): other modules (the classifier's auto mode) and bank channels hand over P25 / DMR / NXDN /
  EDACS signals by label.
- P25 and DMR transmit modes for the core's PTT (tx.py).
"""
from __future__ import annotations

import itertools
import re
import time
from datetime import datetime

from PyQt5 import QtCore, QtWidgets

from sdrexplorer.api import Decode, MenuEntry, Module, Panel, Position, TxModeSpec, paths
from sdrexplorer.api import radio as api_radio

from . import __version__
from . import branches as B
from . import dialogs as D
from . import dsdfme as _dsd
from . import radioid, smartnet
from . import tx as TX
from . import dmr_ms_tx as MSTX
from .monitor import (DigitalMonitor, Op25DataCapture, describe_data_frame, ip_radio_id, p25_algid_name,
                      parse_lrrp)
from .pathkeys import KEYS, register_paths

LINKTYPE_RAW = 101                   # pcap: raw IP (DMR / P25 data bursts carry IP packets)
LINKTYPE_EDACS = 147                 # pcap: LINKTYPE_USER0 -- EDACS MSG_1 + MSG_2, 4 bytes each (28-bit words)
LINKTYPE_P25_LCW = 148               # pcap: LINKTYPE_USER1 -- a P25 Phase 1 link control word (9 bytes)

# labels another module or a bank channel can hand over -> (decoder, NXDN96?)
_REFS = itertools.count(1)          # Decode.ref: ties a burst's log lines to its payload

LABELS = {"P25-P1": ("P25", None), "P25": ("P25", None), "DMR": ("DMR", None), "NXDN": ("NXDN", None),
          "NXDN96": ("NXDN", True), "NXDN48": ("NXDN", False), "EDACS": ("EDACS", None),
          "DMR-MS": ("DMR-MS", None),
          "SmartNet": (None, None)}
# store labels shown (and their recordings folders named) under another name
ALIASES = {"P25-P1": "P25"}

# Fields that carry actual identity/content. A frame that sets none of these (e.g. DMR SLOT_ESB, or
# CACH_CSBK -- op25 frame types not parsed into fields) is a bare "still here" ping with nothing new.
_DECODE_INFO_FIELDS = ("nac", "duid", "tgid", "src", "csbko", "freq_mhz",
                       "sysid", "dst", "lcn", "cc", "encrypted")
# Below this many seconds since the same content was last SEEN (not last logged), an identical decode is
# folded into the same on-air "session" and stays silent. Time-based rather than tied to op25's lock /
# timeout signal: op25's own sync-timeout timer fires once a SECOND whenever it isn't holding a full
# voice-slot lock (p25p1_fdma.cc TIMEOUT_THRESHOLD), which is normal for content that only rides the CACH.
REPEAT_GAP_S = 5.0
HANG_MS = 2000                       # the claim outlives a lost lock by this much
STALE_MS = 3000                      # an op25 lock with no frame for this long is lost (SmartNet / DMR say
#                                      "locked" with every frame but seldom "lost": one late frame after a
#                                      retune used to keep analog muted on the next channel indefinitely)
_TS_RE = re.compile(r"^\d{2}:\d{2}:\d{2}\s+")
_EDACS_MSG_RE = re.compile(r"^Sync:\s*[+-]EDACS\s+MSG_1 \[[0-9A-F]+\] MSG_2 \[[0-9A-F]+\]\s+\([^)]*\)\s*")
_EDACS_WORDS_RE = re.compile(r"MSG_1 \[([0-9A-F]+)\] MSG_2 \[([0-9A-F]+)\]\s+\(([^)]*)\)")
_EDACS_GRANT_LCN_RE = re.compile(r"(?<!CC )\bLCN \[(\d+)\]")
_NXDN_SYNC_RE = re.compile(r"\bSync:\s*(NXDN(?:48|96))\b", re.I)
_RAN_RE = re.compile(r"\bRAN[:=]?\s*(\d+)", re.I)
_SYS_RE = re.compile(r"\bSys Code:\s*(\d+)", re.I)
_SITE_RE = re.compile(r"\bSite Code\s*(\d+)", re.I)
_LOC_RE = re.compile(r"\bLocation ID \[([0-9A-F]+)\]", re.I)

# state the core kept at the top of state.json before this was a module (taken over once)
LEGACY_KEYS = ("digital_mode", "digital_only", "smartnet_bandplan", "dmr_bandplan", "edacs",
               "payload_hex", "dmr_tx_cc", "dmr_tx_tgid", "dmr_tx_radio_id")


class DigitalModule(Module):
    name = "digital"
    title = "Digital voice: op25 + dsd-fme"
    version = __version__
    api = ">=1.0,<2.0"
    paths = dict(KEYS)
    min_frames = 5

    def __init__(self):
        super().__init__()
        self.ui = None
        self.br = None                      # branches.DigitalBranches
        self.monitor = None                 # DigitalMonitor on op25's message queue
        self.voice = None                   # voice.VoiceReceiver
        self.capture = None                 # Op25DataCapture while "Data bursts" is on
        self.mode = "P25"                   # the picked decoder
        self.nxdn96 = True
        self.digital_only = False
        self.capture_data = False
        self.smartnet_bandplan = smartnet.DEFAULT_BANDPLAN
        self.dmr_bandplan = []              # [{lcn, freq_mhz}]
        self.edacs = {"variant": _dsd.EDACS_DEFAULT_VARIANT, "afs": "", "lcns": []}
        self.dmr_tx = {"cc": TX.DMR_DEFAULT_CC, "tgid": TX.DMR_DEFAULT_TGID, "radio_id": TX.DMR_DEFAULT_RADIO_ID}
        self.p25_tx = {"nac": TX.P25_DEFAULT_NAC, "tgid": TX.P25_DEFAULT_TGID, "src": TX.P25_DEFAULT_SRC}
        self.dmr_ms_tx = {"cc": MSTX.MS_DEFAULT_CC, "tgid": MSTX.MS_DEFAULT_TGID, "src": MSTX.MS_DEFAULT_SRC}
        self.crypt_keys = []
        self.locked = False                 # some decoder holds the speaker (a lock, or its hang)
        self._locks = {"op25": False, "dsd": False}   # each decoder's own sync state
        self.encrypted = False
        self.nac = None
        self.proto = None                   # the protocol last decoded on this channel (the claim's label)
        self._seen = {}                     # op25 dedup: content key -> last seen
        self._dsd_seen = {}                 # dsd-fme dedup: line -> last seen
        self._edacs_raw_seen = {}           # EDACS payload dedup: message words -> last seen
        self._lcw_seen = {}                 # P25 GPS link control dedup: word -> last seen
        self._p25_src = None                # the last P25 source unit (op25's call metadata)
        self._ess_unknown = None            # (algid, keyid) of an ESS naming an unregistered algorithm
        self._dmr_kind = ""                 # DMR bursts dsd-fme sees now: "BS", "MS" (mobile / direct mode) or ""
        self._p25_gps_pending = None        # a GPS report waiting for its call's unit id
        self._dsd_group = None              # dsd-fme's current frame / data call (Decode.ref of its lines)
        self._last_payload = None
        self._edacs_site = None
        self._bridge_ref = None
        self._dmr_id_cache, self._dmr_id_pending, self._dmr_id_workers = {}, set(), []
        self._smartnet_dialog = self._dmr_bandplan_dialog = self._edacs_dialog = None
        self._hang = None
        self._w = {}                        # the Digital tab's widgets
        # every TX setting field -> the spin/hex widgets bound to it (submenu AND the main-screen quick
        # widget), so _sync_tx_widgets() refreshes them all from the dicts after load_state. Each entry:
        # (settings_dict, key, widget, kind) where kind is "spin" (QSpinBox) or "hex" (QLineEdit, hex).
        self._tx_fields = []

    # -- lifecycle ------------------------------------------------------------------------------------
    def probe(self):
        register_paths()
        if not B.OP25_AVAILABLE and not _dsd.dsd_fme_available():
            return False, ("neither op25 nor dsd-fme found (paths keys op25 / op25_apps / dsd_fme; "
                           "see the sdrexplorer-digital README)")
        return True, ""

    def attach_radio(self, radio, taps):
        super().attach_radio(radio, taps)
        self.taps = taps
        self.br = B.DigitalBranches(radio, taps)
        self.br.audio_port = B.OP25_AUDIO_PORT
        api_radio.on_retune(radio, lambda _off: self.br.flush())

    def attach_ui(self, app, ui):
        super().attach_ui(app, ui)
        self.ui = ui
        for label, shown in ALIASES.items():
            ui.label_alias(label, shown)
        self._hang = QtCore.QTimer()
        self._hang.setSingleShot(True)
        self._hang.timeout.connect(self._release)
        self._stale = QtCore.QTimer()
        self._stale.setSingleShot(True)
        self._stale.timeout.connect(lambda: self._set_lock("op25", False))
        self.crypt_keys = D.load_crypt_keys()
        self._dmr_id_cache = radioid.load_cache()
        try:
            from .voice import VoiceReceiver
            self.voice = VoiceReceiver(ui.audio.open_input(self.name, 8000), B.OP25_AUDIO_PORT)
        except OSError as e:
            print(f"[digital] no decoded voice (UDP {B.OP25_AUDIO_PORT}: {e})")
            self.voice = None
            self.br.audio_port = None
        if self.br.rx_q is not None:
            self.monitor = DigitalMonitor(self.br.rx_q)
            self.monitor.lock_changed.connect(lambda on: self._set_lock("op25", on))
            self.monitor.decoded.connect(self._on_decoded)
            self.monitor.set_smartnet_bandplan(self.smartnet_bandplan)
            self.monitor.start()
        self.br.start()
        self._apply_crypt_keys()
        ui.bus.subscribe("tuned", self._on_tuned)
        ui.bus.subscribe("scan", self._on_scan)
        # a replayed file jumped or started over: don't decode across the gap
        ui.bus.subscribe("replay_seek", self._on_replay_jump)
        ui.bus.subscribe("replay_wrap", self._on_replay_jump)

    def menu_entries(self):
        return [MenuEntry("Settings", "Smart&Net bandplan…", triggered=lambda: D.open_smartnet_settings(self, self.app)),
                MenuEntry("Settings", "&DMR bandplan (LCN)…", triggered=lambda: D.open_dmr_bandplan(self, self.app)),
                MenuEntry("Settings", "&EDACS…", triggered=lambda: D.open_edacs_settings(self, self.app))]

    def panels(self):
        return [Panel("Digital", self._make_panel)]

    def decodes(self):
        return {label: self._take for label in LABELS}

    def tx_modes(self):
        return [TxModeSpec("P25", TX.build_p25, available=TX.p25_available,
                           settings=self.p25_tx, settings_widget=self._p25_tx_widget,
                           quick_widget=self._p25_tx_quick,
                           channel_tone=lambda: f"{self.p25_tx['nac']:X} NAC",
                           apply_tone=self._apply_p25_tone,
                           tooltip="P25 Phase 1 digital voice (op25's IMBE encoder, clear voice only)"),
                TxModeSpec("DMR", TX.build_dmr, cleanup=TX.cleanup_dmr, available=TX.dmr_available,
                           settings=self.dmr_tx, settings_widget=self._dmr_tx_widget,
                           quick_widget=self._dmr_tx_quick,
                           channel_tone=lambda: f"CC {self.dmr_tx['cc']} TG {self.dmr_tx['tgid']}",
                           apply_tone=self._apply_dmr_tone,
                           tooltip="DMR digital voice, base-station bursts (op25 dmr_bs_tx_bb) — for "
                                   "direct/simplex RX, not a repeater input"),
                TxModeSpec("DMR-MS", MSTX.build_dmr_ms, cleanup=MSTX.cleanup_dmr_ms,
                           available=MSTX.ms_tx_available,
                           settings=self.dmr_ms_tx, settings_widget=self._dmr_ms_tx_widget,
                           quick_widget=self._dmr_ms_tx_quick,
                           channel_tone=lambda: f"CC {self.dmr_ms_tx['cc']} TG {self.dmr_ms_tx['tgid']}",
                           apply_tone=self._apply_dmr_ms_tone,
                           tooltip="DMR mobile-station voice — keys a repeater INPUT (MS sync, voice LC "
                                   "header + embedded LC + terminator, single logical channel)")]

    def load_state(self, d):
        if not d:
            d = self._legacy_state()
        mode = d.get("digital_mode", d.get("mode", "P25"))
        self.mode = mode if mode in B.DIGITAL_MODES else "P25"
        self.nxdn96 = bool(d.get("nxdn96", True))
        self.digital_only = bool(d.get("digital_only", False))
        self.capture_data = bool(d.get("payload_hex", d.get("capture_data", False)))
        sb = d.get("smartnet_bandplan")
        if sb in smartnet.BANDPLANS:
            self.smartnet_bandplan = sb
        self.dmr_bandplan = [e for e in (d.get("dmr_bandplan") or []) if isinstance(e, dict)]
        ed = d.get("edacs") or {}
        if isinstance(ed, dict):
            v = ed.get("variant")
            self.edacs = {"variant": v if v in _dsd.EDACS_VARIANTS else _dsd.EDACS_DEFAULT_VARIANT,
                          "afs": str(ed.get("afs") or ""), "lcns": list(ed.get("lcns") or [])}
        tx = d.get("dmr_tx") or {k: d[o] for k, o in (("cc", "dmr_tx_cc"), ("tgid", "dmr_tx_tgid"),
                                                       ("radio_id", "dmr_tx_radio_id")) if o in d}
        for k in ("cc", "tgid", "radio_id"):
            if k in tx:
                self.dmr_tx[k] = int(tx[k])
        ptx = d.get("p25_tx") or {}
        for k in ("nac", "tgid", "src"):
            if k in ptx:
                self.p25_tx[k] = int(ptx[k])
        mtx = d.get("dmr_ms_tx") or {}
        for k in ("cc", "tgid", "src"):
            if k in mtx:
                self.dmr_ms_tx[k] = int(mtx[k])
        if self.monitor is not None:
            self.monitor.set_smartnet_bandplan(self.smartnet_bandplan)
            self.monitor.set_dmr_bandplan(D.dmr_lcn_freq_hz(self.dmr_bandplan))
        self.br.edacs_flags = D.edacs_flags(self.edacs)
        self._sync_tx_widgets()         # the TX widgets were built from defaults before this load
        self._sync_panel()
        self._set_mode(self.mode, self.nxdn96)
        self.ui.audio.analog_off = self.digital_only
        if self.capture_data:
            self._set_capture(True)

    def _legacy_state(self):
        try:
            import json
            with open(paths.memory_file("state.json")) as fh:
                st = json.load(fh)
        except (OSError, ValueError):
            return {}
        return {k: st[k] for k in LEGACY_KEYS if k in st}

    def save_state(self):
        return {"mode": self.mode, "nxdn96": self.nxdn96, "digital_only": self.digital_only,
                "capture_data": self.capture_data, "smartnet_bandplan": self.smartnet_bandplan,
                "dmr_bandplan": self.dmr_bandplan, "edacs": self.edacs, "dmr_tx": dict(self.dmr_tx),
                "p25_tx": dict(self.p25_tx), "dmr_ms_tx": dict(self.dmr_ms_tx)}

    def shutdown(self):
        for t in (self._hang, getattr(self, "_stale", None)):
            if t is not None:
                t.stop()
        self._set_capture(False)
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor.wait(1000)
            self.monitor = None
        if self.br is not None:
            self.br.stop_bridge()
        if self.voice is not None:
            self.voice.stop()
            self.voice = None
        for w in list(self._dmr_id_workers):
            w.wait(2000)

    # -- picking the decoder --------------------------------------------------------------------------
    def _take(self, freq_hz, label, info):
        """request_decode: a label handed over by another module or a bank channel's mode. During a scan
        sweep only a channel's own mode is taken (the scan applies it before it parks there)."""
        mode, nxdn96 = LABELS[label]
        if self.ui.is_scanning() and (info or {}).get("source") != "channel":
            return False
        if mode is None:                    # SmartNet decodes all the time
            return B.OP25_AVAILABLE
        if mode in B.DSD_MODES and not _dsd.dsd_fme_available():
            return False
        if mode not in B.DSD_MODES and not B.OP25_AVAILABLE:
            return False
        self._set_mode(mode, nxdn96 if nxdn96 is not None else self.nxdn96)
        return True

    def _set_mode(self, mode, nxdn96=None):
        if nxdn96 is not None:
            self.nxdn96 = bool(nxdn96)
        self.mode = mode
        self.br.set_mode(mode, self.nxdn96)
        self._sync_bridge()
        self._apply_voice_pref()
        c = self._w.get("mode")
        if c is not None and c.currentText() != self._mode_text():
            c.blockSignals(True)
            c.setCurrentText(self._mode_text())
            c.blockSignals(False)

    def _mode_text(self):
        if self.mode == "NXDN":
            return "NXDN96" if self.nxdn96 else "NXDN48"
        return self.mode

    def _on_mode_picked(self, text):
        if text.startswith("NXDN"):
            self._set_mode("NXDN", text != "NXDN48")
        else:
            self._set_mode(text)

    # -- the dsd-fme bridge -----------------------------------------------------------------------------
    def _bridge_signals(self, b):
        return ((b.raw_line, self._on_dsd_line), (b.decoded, self._on_dsd_decoded), (b.lock_changed, self._on_dsd_lock),
                *([(b.group, self._on_dsd_group)] if hasattr(b, "group") else []),
                *([(b.kind_changed, self._on_dmr_kind)] if hasattr(b, "kind_changed") else []),
                (b.data, self._on_dsd_data), (b.position, self._on_nxdn_position))

    def _sync_bridge(self):
        """Connect to whichever dsd-fme bridge runs now (after anything that may have started, stopped or
        restarted it)."""
        old, new = self._bridge_ref, self.br.bridge
        if new is old:
            return
        if old is not None:
            for sig, slot in self._bridge_signals(old):
                try:
                    sig.disconnect(slot)
                except TypeError:
                    pass
            self._set_lock("dsd", False)     # a stopped bridge never says it lost its lock
        self._bridge_ref = new
        self._dmr_kind = getattr(new, "kind", "")
        self._apply_voice_pref()
        if new is not None:
            self._dsd_seen.clear()
            for sig, slot in self._bridge_signals(new):
                sig.connect(slot)
            self._dsd_status(self._waiting_text())
        elif self.mode in B.DSD_MODES:
            self._dsd_status(f"{self.mode}: dsd-fme not installed", "#ff6b6b")
        else:
            self._dsd_status("")

    def _waiting_text(self):
        b = self.br.bridge
        if getattr(b, "proto", None) == "DMR":
            # on DMR, dsd-fme only watches for mobile-station / direct-mode bursts: nothing to say yet
            return "DMR-MS (dsd-fme): waiting for sync…" if self.mode == "DMR-MS" else ""
        if getattr(b, "proto", "NXDN") == "EDACS":
            return f"EDACS ({self.edacs['variant']}): waiting for sync…"
        return f"{'NXDN96' if b is None or b.nxdn96 else 'NXDN48'}: waiting for sync…"

    def _dsd_decodes_dmr(self):
        """dsd-fme is the DMR decoder now: DMR-MS picked, or DMR with mobile-station / direct-mode bursts on
        the channel (op25 decodes base-station DMR, and keeps doing so)."""
        b = self.br.bridge
        return getattr(b, "proto", None) == "DMR" and (self.mode == "DMR-MS" or self._dmr_kind == "MS")

    def _apply_voice_pref(self):
        """When op25 and a DMR dsd-fme both decode a call, only one's voice plays (they'd overlap)."""
        if self.voice is None:
            return
        b = self.br.bridge
        if getattr(b, "proto", None) != "DMR":
            self.voice.prefer = None
        elif self._dsd_decodes_dmr():
            self.voice.prefer = ("only", b.relay_port)
        else:
            self.voice.prefer = ("not", b.relay_port)

    def _on_dmr_kind(self, kind):
        """dsd-fme's DMR bursts changed kind: on DMR, mobile-station / direct-mode bursts hand the call to
        dsd-fme (op25 can't decode them), base-station bursts give it back."""
        self._dmr_kind = kind
        self._apply_voice_pref()
        if self.mode == "DMR" and kind == "MS":
            self._dsd_status("DMR: mobile-station / direct-mode bursts, decoded with dsd-fme", "#39ff88")
        elif self.mode == "DMR":
            self._dsd_status("")

    def apply_edacs(self):
        """Settings > EDACS changed: new dsd-fme flags (a running EDACS decode restarts)."""
        self.br.set_edacs_flags(D.edacs_flags(self.edacs))
        self._sync_bridge()

    # -- locks, the speaker -------------------------------------------------------------------------------
    def _claim_label(self):
        """What the signal meter shows while a decoder holds the speaker: the protocol that decoded (op25's
        lock doesn't say which: SmartNet runs beside the picked decoder), else the picked one."""
        if self.nac is not None and self.proto in (None, "P25"):
            return f"P25 NAC {self.nac:03X}"
        return self.proto or {"NXDN": self._mode_text()}.get(self.mode, self.mode)

    def _saw(self, proto):
        """A decode of ``proto``: the claim's label follows it."""
        if proto != self.proto:
            self.proto = proto
            if self.locked:
                self.ui.audio.claim(self.name, label=self._claim_label())

    def _set_lock(self, src, on):
        """``src`` ("op25" / "dsd") got / lost sync on the tuned channel. While either holds a lock: claim the
        speaker (analog muted, voice passed on). When the last one is lost: keep the claim for the hang time,
        so short sync drops don't flap the audio. Each decoder counts on its own -- op25 reports "no sync"
        about once a second while dsd-fme decodes NXDN, which must not end dsd-fme's claim (and op25's
        repeated report must not restart the hang, or a claim never ends)."""
        was = any(self._locks.values())
        self._locks[src] = bool(on)
        now = any(self._locks.values())
        if src == "op25":
            if on:
                self._stale.start(STALE_MS)
            else:
                self._stale.stop()
        if now:
            self._hang.stop()
            self.locked = True
            self.ui.audio.claim(self.name, label=self._claim_label())
            if self.voice is not None:
                self.voice.allow = True
            self._lock_light()
        elif was:
            self.encrypted = False
            self.nac = None              # sync lost: forget the station's NAC
            # NOTE: deliberately NOT clearing the dedup state here: op25's sync-timeout timer fires once
            # a second whenever it isn't holding a voice-slot lock (CACH-only content), and clearing it
            # here re-logged the same line every second.
            self._lock_light(False)
            self._hang.start(HANG_MS)

    def _on_lock(self, locked):
        """op25's lock (DigitalMonitor.lock_changed)."""
        self._set_lock("op25", locked)

    def _alive(self):
        """op25 delivered something: its lock isn't stale."""
        if self._locks["op25"]:
            self._stale.start(STALE_MS)

    def _release(self):
        """The hang ran out with no new lock."""
        self.locked = False
        if self.voice is not None:
            self.voice.allow = False
        self.ui.audio.release(self.name)

    def _leave_channel(self):
        """The channel was left: drop any lock at once, or the analog path would stay muted on the new
        frequency until the decoder notices and the hang runs out."""
        self._hang.stop()
        self._stale.stop()
        self._locks = {k: False for k in self._locks}
        self._flush_p25_gps()                   # (a report already received is still logged)
        self._p25_src = None
        self._ess_unknown = None
        self._dsd_group = None
        self._release()
        self._lock_light(False)
        self.encrypted = False
        self.nac = None
        self.proto = None
        self._seen.clear()
        self._dsd_seen.clear()
        b = self.br.bridge
        if b is not None:
            # also resets the consecutive-sync counter, so a near-miss before the move can't count
            # toward a false lock on whatever the new channel carries
            b.force_unlock()
            self._dsd_status(self._waiting_text())

    def _on_tuned(self, freq_hz, primary, how=None, **_):
        # a scan landing on a channel is handled by "scan"; a sub-kHz nudge stays on the channel
        if how not in ("scan", "nudge"):
            self._leave_channel()

    def _on_scan(self, state):
        if state != "hold":
            self._leave_channel()

    def _on_replay_jump(self, **_):
        if self.br is not None:
            self.br.flush()
        self._leave_channel()

    # -- bank channels: the TX settings ride on the channel -----------------------------------
    TX_FIELDS = {"P25": ("p25_tx", ("nac", "tgid", "src")), "DMR": ("dmr_tx", ("cc", "tgid", "radio_id")),
                 "DMR-MS": ("dmr_ms_tx", ("cc", "tgid", "src"))}

    def channel_fields(self, channel):
        """The picked TX mode's settings (NAC / CC / talkgroup / radio id), stored on a channel saved now."""
        tx = self.ui.tx_mode() if self.ui is not None else None
        if tx not in self.TX_FIELDS:
            return None
        attr, keys = self.TX_FIELDS[tx]
        d = getattr(self, attr)
        return {"tx": tx, **{k: int(d[k]) for k in keys}}

    def channel_recalled(self, channel, fields):
        """A recalled channel's stored TX settings go back into that TX mode (older channels: the tone
        text, through apply_tone)."""
        tx = fields.get("tx")
        if tx not in self.TX_FIELDS:
            return
        attr, keys = self.TX_FIELDS[tx]
        d = getattr(self, attr)
        for k in keys:
            if k in fields:
                d[k] = int(fields[k])
        if "nac" in d:
            d["nac"] &= 0xfff
        if "cc" in d:
            d["cc"] &= 0xf
        self._sync_tx_widgets()

    def channel_summary(self, fields):
        tx = fields.get("tx", "")
        parts = []
        if "nac" in fields:
            parts.append(f"NAC {int(fields['nac']):X}")
        if "cc" in fields:
            parts.append(f"CC {fields['cc']}")
        if "tgid" in fields:
            parts.append(f"TG {fields['tgid']}")
        for k in ("src", "radio_id"):
            if k in fields:
                parts.append(f"ID {fields[k]}")
        return f"{tx} TX: " + " ".join(parts)

    # -- op25 decodes -> the decode log -------------------------------------------------------------------
    def _on_decoded(self, d):
        """An op25 decode: counted for recording labels, and one log line per distinct content (deduplicated
        on content, not frame type, with REPEAT_GAP_S) -- protocol-aware, so no bogus NAC on a DMR signal."""
        proto = d.get("proto", "P25")
        self._alive()
        if proto == "P25" and d.get("encrypted") is not None:
            d = self._p25_ess_checked(d)
        if proto == "P25" and d.get("lcw_kind") and not d.get("lcw_gps"):
            # a voice link control word names the call's talkgroup / unit; op25's JSON often doesn't
            # (conventional and simplex calls), so the log line and the recording labels take them from here
            d = dict(d)
            for k in ("tgid", "src", "dst"):
                if d.get(k) is None and d.get("lcw_" + k) is not None:
                    d[k] = d["lcw_" + k]
        ids = {k: d[k] for k in ("nac", "tgid", "src", "cc") if d.get(k) is not None}
        if proto == "P25" and "nac" in ids:
            ids["NAC"] = ids.pop("nac")
        elif proto == "DMR" and "cc" in ids:
            ids["CC"] = ids.pop("cc")
        if self.mode in B.DSD_MODES and proto in ("P25", "DMR") and not (self.mode == "DMR-MS" and proto == "DMR"):
            # op25's rx_sync auto-detects P25 / DMR whatever its demod filter is, so it decodes real
            # P25 / DMR traffic even while NXDN / EDACS is picked: then that pick is wrong (dsd-fme decodes
            # nothing useful, op25's filter isn't the right one). Switch to what is decoding.
            self._set_mode(proto)
        elif (self.mode in ("P25", "DMR") and proto in ("P25", "DMR") and proto != self.mode
              and any(d.get(f) is not None for f in _DECODE_INFO_FIELDS)):
            # the same between P25 and DMR: op25 decodes either, but DMR picked is what runs dsd-fme beside it
            # (which takes mobile-station / direct-mode calls op25 can't decode), and the demod filter follows
            self._set_mode(proto)
        self._saw(proto)
        if d.get("nac") is not None and d["nac"] != self.nac:
            self.nac = d["nac"]
            if self.locked:
                self.ui.audio.claim(self.name, label=self._claim_label())
        if d.get("encrypted"):
            self.encrypted = True
            self._lock_light()
        informative = any(d.get(f) is not None for f in _DECODE_INFO_FIELDS)
        text = self._op25_text(proto, d) if informative else ""
        key = None
        if informative:
            freq = self.ui.tuned_hz()
            key = (freq, proto, d.get("nac"), d.get("tgid"), d.get("src"), d.get("encrypted"), d.get("csbko"),
                   d.get("freq_mhz"), d.get("sysid"), d.get("dst"), d.get("lcn"), d.get("cc"))
            now = time.monotonic()
            last = self._seen.get(key)
            self._seen[key] = now
            if len(self._seen) > 200:
                cutoff = now - REPEAT_GAP_S
                self._seen = {k: t for k, t in self._seen.items() if t >= cutoff}
            if last is not None and now - last < REPEAT_GAP_S:
                text = ""
        rec_ids = {k.lower(): v for k, v in ids.items()}
        self.ui.publish(Decode(source="op25", protocol=proto, text=text, ids=rec_ids, fields=dict(d),
                               log=bool(text), dedup_s=0.0))
        if proto == "P25":                      # the unit on the air now: for crediting a GPS report
            if d.get("lcw_src") or d.get("src"):
                self._p25_src = d.get("lcw_src") or d.get("src")
                self._flush_p25_gps()           # a report that came before the unit id: now it has one
            elif d.get("duid") in ("TDU", "TDULC"):
                self._flush_p25_gps()           # end of the call: report what's waiting without a unit,
                self._p25_src = None            # and the next report is someone else's
                self._ess_unknown = None
        if proto == "P25" and (d.get("lcw_gps") or d.get("lcw_protected")):
            self._on_p25_gps(d)
        # SmartNet has no separate DATA burst: the OSW body is the whole message
        if proto == "SmartNet" and d.get("raw") and self.capture_data:
            self._on_data("SmartNet", d.get("label", ""), d["raw"])

    def _on_p25_gps(self, d):
        """A P25 link control word carrying a GPS report (Motorola embedded GPS, sent with voice): a log line,
        the unit on the map, and the 9 raw bytes in the payload pane (Data bursts on), tied by one ref. A
        radio repeats the same word for a whole call, so each distinct word is handled once per REPEAT_GAP_S."""
        raw = d.get("lcw") or b""
        now = time.monotonic()
        last = self._lcw_seen.get(raw)
        self._lcw_seen[raw] = now
        if len(self._lcw_seen) > 200:
            self._lcw_seen = {k: t for k, t in self._lcw_seen.items() if now - t < REPEAT_GAP_S}
        if last is not None and now - last < REPEAT_GAP_S:
            return
        if self._p25_src is None:
            # op25 can deliver a call's GPS word before the voice-user word that names the unit: wait for it
            # (or for the end of the call, at most 1.5 s)
            self._p25_gps_pending = d
            QtCore.QTimer.singleShot(1500, self._flush_p25_gps)
            return
        self._publish_p25_gps(d, self._p25_src)

    def _flush_p25_gps(self):
        d, self._p25_gps_pending = self._p25_gps_pending, None
        if d is not None:
            self._publish_p25_gps(d, self._p25_src)

    def _publish_p25_gps(self, d, src):
        raw = d.get("lcw") or b""
        ref = ("op25", next(_REFS))
        nac = d.get("nac")
        who = f"SRC {src}" if src else (f"NAC 0x{nac:03X}" if nac is not None else "")
        g = d.get("lcw_gps")
        if g:
            text = f"★ P25 GPS  {g['lat']:.5f}, {g['lon']:.5f}  {g['fix']} fix  {who}".rstrip()
            fields = {"lat": g["lat"], "lon": g["lon"], "fix": g["fix"], "src": src, "nac": nac}
            unit = f"p25:{src}" if src else f"p25:nac{nac}"
            self.ui.publish_position(Position(id=unit, kind="radio", lat=g["lat"], lon=g["lon"],
                                              label=f"P25 {src}" if src else "P25",
                                              attrs={"fix": g["fix"], "nac": nac}))
            label = f"LCW {d.get('lcw_kind', '')}  {g['lat']:.5f},{g['lon']:.5f} {g['fix']}"
        else:
            text = f"★ P25 GPS  (protected)  {who}".rstrip()
            fields, label = {"protected": True, "src": src, "nac": nac}, f"LCW {d.get('lcw_kind', '')}  protected"
        self.ui.publish(Decode(source="op25", protocol="P25", text=text, fields=fields, counts=False,
                               dedup_s=0.0, ref=ref))
        if self.capture_data and raw:
            self.ui.publish(Decode(source="op25", protocol="P25", text=label, payload=bytes(raw),
                                   linktype=LINKTYPE_P25_LCW, log=False, counts=False, ref=ref))

    def _p25_ess_checked(self, d):
        """An ESS (LDU2) naming an algorithm that isn't a registered ALGID is usually a damaged frame: op25
        caught the call mid-frame, or just after another mode, and decoded noise as "encrypted, alg 0x08".
        Report it only when the next ESS says the same (real encryption repeats in every LDU2); a known
        algorithm counts at once, a clear report or the call's end resets it."""
        if not d.get("encrypted"):
            self._ess_unknown = None
            return d
        algid = d.get("algid") or 0
        if p25_algid_name(algid) is not None:
            return d
        sig = (algid, d.get("keyid"))
        if self._ess_unknown == sig:
            return d                            # said twice: believe it
        self._ess_unknown = sig
        return dict(d, encrypted=None, algid=None, keyid=None)

    def _op25_text(self, proto, d):
        detail = [proto]
        if d.get("nac") is not None:
            detail.append(f"NAC 0x{d['nac']:03X}")
        if d.get("duid"):
            detail.append(d["duid"])
        if d.get("label"):                   # DMR frame type (SLOT_VLC, CSBK, ...)
            detail.append(d["label"])
        if d.get("cc") is not None:
            detail.append(f"CC {d['cc']}")
        if d.get("call"):
            detail.append(d["call"])
        if d.get("csbko") is not None:
            detail.append(f"CSBKO 0x{d['csbko']:02X}")
        if d.get("lcn") is not None:          # DMR Connect Plus channel grant
            ts = d.get("tslot")
            detail.append(f"LCN {d['lcn']}" + (f" TS{ts}" if ts is not None else ""))
        if d.get("tgid") is not None:
            detail.append(f"TG {d['tgid']}")
        if d.get("src") is not None:
            detail.append(self._dmr_src_label(d["src"]) if proto == "DMR" else f"SRC {d['src']}")
        if d.get("dst") is not None:
            detail.append(f"DST {d['dst']}")
        if d.get("sysid") is not None:
            detail.append(f"SYS 0x{d['sysid']:04X}")
        if d.get("freq_mhz") is not None:
            detail.append(f"{d['freq_mhz']:.4f} MHz")
        if d.get("encrypted"):
            algid = d.get("algid") or 0
            name = p25_algid_name(algid)
            alg = f"{name} (alg 0x{algid:02X})" if name else f"alg 0x{algid:02X}"
            keyid = d.get("keyid")
            have = any(k["keyid"] == keyid for k in self.crypt_keys)
            detail.append(f"🔒 ENCRYPTED {alg} key {keyid} ({'key loaded ✓' if have else 'no audio'})")
        elif d.get("encrypted") == 0:
            detail.append("clear")
        return "  ".join(detail) if len(detail) > 1 else ""

    def _dmr_src_label(self, dmr_id):
        """"SRC <id>", or "SRC <id> (CALLSIGN)" once radioid.net has resolved it (in the background; the
        callsign fills in within the same call)."""
        key = str(dmr_id)
        if key not in self._dmr_id_cache:
            self._dmr_resolve_src(dmr_id)
            return f"SRC {dmr_id}"
        info = self._dmr_id_cache[key]
        return f"SRC {dmr_id} ({info['callsign']})" if info else f"SRC {dmr_id}"

    def _dmr_resolve_src(self, dmr_id):
        if dmr_id in self._dmr_id_pending or radioid.DmrIdWorker is None:
            return
        self._dmr_id_pending.add(dmr_id)
        w = radioid.DmrIdWorker(dmr_id)
        w.done.connect(self._on_dmr_id)
        w.finished.connect(lambda w=w: self._dmr_id_workers.remove(w) if w in self._dmr_id_workers else None)
        w.finished.connect(w.deleteLater)
        self._dmr_id_workers.append(w)
        w.start()

    def _on_dmr_id(self, dmr_id, info):
        self._dmr_id_pending.discard(dmr_id)
        self._dmr_id_cache[str(dmr_id)] = info
        radioid.save_cache(self._dmr_id_cache)

    # -- dsd-fme lines -> the decode log --------------------------------------------------------------------
    def _on_dsd_line(self, line):
        """dsd-fme's own status text. It re-broadcasts the same control-channel content every ~1 s, so lines
        are deduplicated on their text (with dsd-fme's own HH:MM:SS stripped); every line still counts for
        the recording label."""
        proto = getattr(self.br.bridge, "proto", "NXDN")
        if proto == "DMR":
            # one sync line per 30 ms burst: never logged (the link control is, by _on_dsd_decoded); a clean
            # one counts for the recording label while dsd-fme is the DMR decoder (else op25's decode counts)
            if self._dsd_decodes_dmr() and _dsd._dmr_valid_line(line):
                cc = _dsd._DMR_CC_RE.search(line)
                self._saw("DMR")
                self.ui.publish(Decode(source="dsd-fme", protocol="DMR", text="", ids={"cc": int(cc.group(1))},
                                       log=False, counts=True, dedup_s=0.0, ref=self._dsd_group))
            return
        text = _TS_RE.sub("", line)
        evidence = self._dsd_evidence(proto, line)
        if proto == "EDACS":
            text = self._edacs_log_text(text)
        now = time.monotonic()
        last = self._dsd_seen.get(text)
        self._dsd_seen[text] = now
        if len(self._dsd_seen) > 200:
            cutoff = now - REPEAT_GAP_S
            self._dsd_seen = {k: t for k, t in self._dsd_seen.items() if t >= cutoff}
        fresh = last is None or now - last >= REPEAT_GAP_S
        if evidence is None and not fresh:
            return
        label, ids = evidence if evidence is not None else (proto, {})
        ref = self._dsd_group or ("dsd-fme", next(_REFS))     # the frame / data call this line belongs to
        if evidence is not None:
            self._saw(label)
            if proto == "EDACS" and self.capture_data:
                self._edacs_payload(line, text, ref)
        self.ui.publish(Decode(source="dsd-fme", protocol=label, text=f"{proto}  {text}" if fresh else "",
                               ids=ids, log=fresh, counts=evidence is not None, dedup_s=0.0, ref=ref))

    def _dsd_evidence(self, proto, line):
        """(label, ids) when a dsd-fme line is evidence of its protocol (an NXDN sync line or the RAN / site
        fields after one; a BCH-clean EDACS frame), else None."""
        if proto == "EDACS":
            d = _dsd._parse_edacs_line(line)
            if d is None:
                return None
            return "EDACS", {k: d[k] for k in ("site", "sysid", "cc_lcn") if d.get(k) is not None}
        m = _NXDN_SYNC_RE.search(line)
        if m:
            self._nxdn_variant = m.group(1).upper()
        elif getattr(self, "_nxdn_variant", None) is None:
            return None
        ran, sysc, site, loc = (_RAN_RE.search(line), _SYS_RE.search(line), _SITE_RE.search(line),
                                _LOC_RE.search(line))
        if not (m or ran or sysc or site or loc):
            return None
        ids = {"ran": int(ran.group(1)) if ran else None, "sys_code": int(sysc.group(1)) if sysc else None,
               "site_code": int(site.group(1)) if site else None,
               "location_id": loc.group(1).upper() if loc else None}
        return self._nxdn_variant, {k: v for k, v in ids.items() if v is not None}

    def _edacs_payload(self, line, text, ref=None):
        """A BCH-clean EDACS frame's two 28-bit message words to the payload pane (Data bursts on): 8 bytes,
        MSG_1 then MSG_2 big-endian, labeled with the message types and dsd-fme's reading. A control channel
        repeats its messages every frame, so each word pair is shown once per REPEAT_GAP_S."""
        m = _EDACS_WORDS_RE.search(line)
        if not m:
            return
        w1, w2 = int(m.group(1), 16), int(m.group(2), 16)
        now = time.monotonic()
        key = (w1, w2)
        last = self._edacs_raw_seen.get(key)
        self._edacs_raw_seen[key] = now
        if len(self._edacs_raw_seen) > 200:
            self._edacs_raw_seen = {k: t for k, t in self._edacs_raw_seen.items() if now - t < REPEAT_GAP_S}
        if last is not None and now - last < REPEAT_GAP_S:
            return
        raw = w1.to_bytes(4, "big") + w2.to_bytes(4, "big")
        self.ui.publish(Decode(source="dsd-fme", protocol="EDACS", text=f"({m.group(3)})  {text.strip()}",
                               payload=raw, linktype=LINKTYPE_EDACS, log=False, counts=False, ref=ref))

    def _edacs_log_text(self, text):
        """An EDACS line for the log: the raw message words dropped (the decoded text says the same), and a
        grant's LCN shown with its frequency when it is in Settings > EDACS."""
        text = _EDACS_MSG_RE.sub("", text) or text

        def _freq(m):
            f = D.edacs_lcn_freq(self.edacs, m.group(1))
            return m.group(0) + (f" = {f:.4f} MHz" if f else "")
        return _EDACS_GRANT_LCN_RE.sub(_freq, text)

    def _on_dsd_lock(self, locked):
        self._set_lock("dsd", locked)
        if not locked:
            self._dsd_status(self._waiting_text())

    def _on_dsd_decoded(self, d):
        proto = d.get("proto", "NXDN")
        if proto == "DMR":
            self._on_dsd_dmr(d)
            return
        if proto == "EDACS":
            if "site" in d:
                self._edacs_site = d["site"]
            bits = [f"Site {self._edacs_site:02X}" if self._edacs_site is not None else None,
                    f"Group {d['group']}" if "group" in d else None, f"LCN {d['lcn']}" if "lcn" in d else None]
        else:
            bits = [f"RAN {d['ran']}" if "ran" in d else None, f"TG {d['tgid']}" if "tgid" in d else None,
                    f"SRC {d['src']}" if "src" in d else None]
        summary = "  ".join(b for b in bits if b) or "sync"
        self._dsd_status(f"{proto}: {datetime.now():%H:%M:%S}  {summary}", "#39ff88")

    def _on_dsd_dmr(self, d):
        """A DMR link control dsd-fme decoded: logged like op25's DMR lines (callsign lookup included), once per
        distinct content per REPEAT_GAP_S -- only while dsd-fme is the DMR decoder (op25 logs base-station
        calls itself)."""
        if not self._dsd_decodes_dmr():
            return
        kind = d.get("kind") or "MS"
        fields = {k: d[k] for k in ("cc", "call", "tgid", "src") if d.get(k) is not None}
        text = self._op25_text("DMR", dict(fields, label=kind))
        if not text:
            return
        key = ("DMR", kind) + tuple(fields.get(k) for k in ("cc", "call", "tgid", "src"))   # not the text: a
        now = time.monotonic()                          # callsign resolved later mustn't make a 2nd line
        last = self._dsd_seen.get(key)
        self._dsd_seen[key] = now
        fresh = last is None or now - last >= REPEAT_GAP_S
        self._saw("DMR")
        self.ui.publish(Decode(source="dsd-fme", protocol="DMR", text=text if fresh else "", fields=dict(fields),
                               ids={k: fields[k] for k in ("cc", "tgid", "src") if k in fields},
                               log=fresh, counts=True, dedup_s=0.0, ref=self._dsd_group))
        bits = [f"CC {fields['cc']}" if "cc" in fields else None, f"TG {fields.get('tgid')}",
                f"SRC {fields.get('src')}"]
        self._dsd_status(f"DMR ({kind}, dsd-fme): {datetime.now():%H:%M:%S}  {'  '.join(b for b in bits if b)}",
                         "#39ff88")

    def _on_nxdn_position(self, fix):
        """A GPS fix from an NXDN data call: logged, and on the map, one target per sending unit."""
        src = fix.get("src")
        who = f"NXDN {src}" if src is not None else "NXDN (unknown unit)"
        extra = ""
        if "speed_mps" in fix:
            extra += f"  {fix['speed_mps']:.1f} m/s"
        if "heading_deg" in fix:
            extra += f"  hdg {fix['heading_deg']}°"
        self.ui.publish(Decode(source="dsd-fme", protocol="NXDN", counts=False, dedup_s=0.0, ref=self._dsd_group,
                               text=f"★ NXDN GPS  {who}  {fix['lat']:.6f}, {fix['lon']:.6f}{extra}"))
        tag = f"nxdn:{src}" if src is not None else f"nxdn@{self.ui.tuned_hz() / 1e6:.4f}"
        self.ui.publish_position(Position(id=tag, kind="radio", lat=fix["lat"], lon=fix["lon"], label=who,
                                          attrs={"speed_mps": fix.get("speed_mps"),
                                                 "heading_deg": fix.get("heading_deg")}))

    # -- data bursts -> the payload pane, LRRP -> the map ---------------------------------------------------
    def _on_dsd_group(self, ref):
        """dsd-fme started a new frame or data call: the lines, payloads and GPS fixes that follow belong to it."""
        self._dsd_group = ref

    def _on_dsd_data(self, proto, label, data):
        self._on_data(proto, label, data, ref=self._dsd_group)

    def _on_data(self, proto, label, data, ref=None):
        """A decoded DATA burst (op25's stderr, dsd-fme's payload lines, a SmartNet OSW): into the payload
        pane, and an LRRP location onto the map."""
        if not data or data == self._last_payload:
            return
        self._last_payload = data
        station = f"{self.ui.tuned_hz() / 1e6:.4f}"
        ref = ref or ("op25", next(_REFS))      # the burst's log lines and its payload belong together
        loc = parse_lrrp(data)
        if loc:
            extra = ""
            if "speed_mps" in loc:
                extra += f"  {loc['speed_mps']:.1f} m/s"
            if "heading_deg" in loc:
                extra += f"  hdg {loc['heading_deg']}°"
            rid = ip_radio_id(data)             # one map target per reporting radio, not per channel
            who = f"  {self._dmr_src_label(rid)}" if rid else ""
            self.ui.publish(Decode(source="op25", protocol=proto, counts=False, dedup_s=0.0, ref=ref,
                                   text=f"★ LRRP LOCATION  {loc['lat']:.6f}, {loc['lon']:.6f}{extra}{who}",
                                   fields={"lat": loc["lat"], "lon": loc["lon"], "src": rid}))
            label = f"LRRP {loc['lat']:.5f},{loc['lon']:.5f}  {label}"
            self.ui.publish_position(Position(id=f"dmr:{rid}" if rid else station, kind="radio",
                                              lat=loc["lat"], lon=loc["lon"],
                                              label=f"DMR {rid}" if rid else station,
                                              attrs={"speed_mps": loc.get("speed_mps"),
                                                     "heading_deg": loc.get("heading_deg")}))
        else:
            desc = describe_data_frame(data)     # ARS reg / ICMP / TMS / ...
            if desc:
                self.ui.publish(Decode(source="op25", protocol=proto, text=desc, counts=False, dedup_s=0.0,
                                       ref=ref))
                label = f"{desc}  {label}"
        self.ui.publish(Decode(source="op25", protocol=proto, text=label, payload=bytes(data),
                               linktype=LINKTYPE_RAW, log=False, counts=False, ref=ref))

    def _set_capture(self, on):
        """Capture op25's DATA bursts: its decoder prints them to stderr only at debug >= 10."""
        self.capture_data = bool(on)
        if on and B.OP25_AVAILABLE and self.br is not None and self.br.op25_asm is not None:
            if self.capture is None:
                self.capture = Op25DataCapture(tee=bool(self.ui and self.ui.option("op25_stderr")))
                self.capture.data.connect(self._on_data)
                self.capture.start()
            self.br.set_debug(10)
        else:
            if self.br is not None:
                try:
                    self.br.set_debug(0)
                except Exception:
                    pass
            if self.capture is not None:
                self.capture.stop()
                self.capture = None
        cb = self._w.get("data")
        if cb is not None and cb.isChecked() != self.capture_data:
            cb.blockSignals(True)
            cb.setChecked(self.capture_data)
            cb.blockSignals(False)

    # -- keys -----------------------------------------------------------------------------------------
    def _apply_crypt_keys(self):
        n = 0
        for k in self.crypt_keys:
            kb = D.parse_hex_key(k["key"])
            if kb and self.br.add_crypt_key(k["keyid"], k["algid"], kb):
                n += 1
        return n

    # -- TX ---------------------------------------------------------------------------------------------
    # Shared TX-field widgets. Every spin/hex field is registered in self._tx_fields so
    # _sync_tx_widgets() refreshes it from the settings dict (after load_state, which runs AFTER the
    # widgets are first built), keeping the Settings-dialog and main-screen quick fields in lockstep.
    def _tx_spin(self, row, label, settings, key, lo, hi, enabled):
        if label:
            row.addWidget(QtWidgets.QLabel(label))
        s = QtWidgets.QSpinBox()
        s.setRange(lo, hi)
        s.setValue(int(settings[key]))
        s.valueChanged.connect(lambda val, d=settings, k=key: d.__setitem__(k, int(val)))
        s.setEnabled(enabled)
        row.addWidget(s)
        self._tx_fields.append((settings, key, s, "spin"))
        return s

    def _tx_hex(self, row, label, settings, key, enabled, width=60, maxlen=3, tip=""):
        if label:
            row.addWidget(QtWidgets.QLabel(label))
        e = QtWidgets.QLineEdit(f"{settings[key]:X}")
        e.setMaxLength(maxlen)
        e.setFixedWidth(width)
        if tip:
            e.setToolTip(tip)

        def _edit(text, d=settings, k=key):
            try:
                d[k] = int(text, 16) & 0xfff
            except ValueError:
                pass                                 # keep the last valid value mid-edit
        e.textChanged.connect(_edit)
        e.setEnabled(enabled)
        row.addWidget(e)
        self._tx_fields.append((settings, key, e, "hex"))
        return e

    def _sync_tx_widgets(self):
        """Refresh every registered TX-field widget from its settings dict (signals blocked)."""
        for settings, key, w, kind in self._tx_fields:
            w.blockSignals(True)
            if kind == "spin":
                w.setValue(int(settings[key]))
            else:
                w.setText(f"{int(settings[key]):X}")
            w.blockSignals(False)

    def _apply_dmr_tone(self, tone):
        """A recalled channel's tone ("CC 6", "CC 5 TG 100"): the DMR TX color code / talkgroup."""
        from sdrexplorer.api import parse_tone        # (tone text is RadioReference's)
        info = parse_tone(tone)
        if info and info.get("kind") == "CC":
            self.dmr_tx["cc"] = int(info["value"]) & 0xf
            self.dmr_tx["tgid"] = int(info.get("tgid", self.dmr_tx["tgid"]))
            self._sync_tx_widgets()

    def _dmr_tx_widget(self, parent):
        w = QtWidgets.QWidget(parent)
        v = QtWidgets.QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        row = QtWidgets.QHBoxLayout()
        en = TX.DMR_TX_AVAILABLE
        self._tx_spin(row, "DMR TX  Radio ID:", self.dmr_tx, "radio_id", 1, 16_777_215, en)
        hint = QtWidgets.QLabel("TG and CC: beside the TX: picker")
        hint.setStyleSheet("color:#8b95a1;")
        row.addWidget(hint)
        row.addStretch(1)
        v.addLayout(row)
        if not TX.DMR_TX_AVAILABLE:
            n = QtWidgets.QLabel("DMR TX needs op25's TX support on the path "
                                 "(op25_repeater.ambe_encoder_sb + dmr_bs_tx_bb).")
            n.setWordWrap(True)
            n.setStyleSheet("color:#8b95a1;")
            v.addWidget(n)
        return w

    def _dmr_tx_quick(self, parent):
        """Main-screen quick fields for DMR: TG + CC (edits the same dict as the submenu)."""
        w = QtWidgets.QWidget(parent)
        row = QtWidgets.QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(QtWidgets.QLabel("TG:"))
        self._tx_spin(row, None, self.dmr_tx, "tgid", 1, 16_777_215, TX.DMR_TX_AVAILABLE)
        self._tx_spin(row, "CC:", self.dmr_tx, "cc", 0, 15, TX.DMR_TX_AVAILABLE)
        return w

    def _apply_dmr_ms_tone(self, tone):
        """A recalled channel's tone ("CC 6 TG 9"): the DMR-MS TX color code / talkgroup."""
        from sdrexplorer.api import parse_tone
        info = parse_tone(tone)
        if info and info.get("kind") == "CC":
            self.dmr_ms_tx["cc"] = int(info["value"]) & 0xf
            self.dmr_ms_tx["tgid"] = int(info.get("tgid", self.dmr_ms_tx["tgid"]))
            self._sync_tx_widgets()

    def _dmr_ms_tx_widget(self, parent):
        w = QtWidgets.QWidget(parent)
        v = QtWidgets.QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        note = QtWidgets.QLabel("DMR-MS keys a repeater INPUT (mobile-station bursts): set your Radio ID "
                                "here, and the repeater's TG and CC beside the TX: picker. Clear voice "
                                "only. Transmit is confined to the ham bands (Settings ▸ Transmit); set "
                                "the repeater's TX split there.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#8b95a1;")
        v.addWidget(note)
        row = QtWidgets.QHBoxLayout()
        en = MSTX.MS_TX_AVAILABLE
        self._tx_spin(row, "DMR-MS  Radio ID:", self.dmr_ms_tx, "src", 1, 16_777_215, en)
        row.addStretch(1)
        v.addLayout(row)
        if not MSTX.MS_TX_AVAILABLE:
            n = QtWidgets.QLabel("DMR-MS TX needs op25's TX support with the dmr_ms_tx_bb block "
                                 "(the sdrexplorer op25 patch).")
            n.setWordWrap(True)
            n.setStyleSheet("color:#8b95a1;")
            v.addWidget(n)
        return w

    def _dmr_ms_tx_quick(self, parent):
        """Main-screen quick fields for DMR-MS: TG + CC (Radio ID stays in the submenu)."""
        w = QtWidgets.QWidget(parent)
        row = QtWidgets.QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(QtWidgets.QLabel("TG:"))
        self._tx_spin(row, None, self.dmr_ms_tx, "tgid", 1, 16_777_215, MSTX.MS_TX_AVAILABLE)
        self._tx_spin(row, "CC:", self.dmr_ms_tx, "cc", 0, 15, MSTX.MS_TX_AVAILABLE)
        return w

    def _apply_p25_tone(self, tone):
        """A recalled channel's tone ("123 NAC", RadioReference's hex format): the P25 TX NAC."""
        from sdrexplorer.api import parse_tone        # (tone text is RadioReference's)
        info = parse_tone(tone)
        if info and info.get("kind") == "NAC":
            self.p25_tx["nac"] = int(info["value"]) & 0xfff
            self._sync_tx_widgets()

    def _p25_tx_widget(self, parent):
        w = QtWidgets.QWidget(parent)
        v = QtWidgets.QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        note = QtWidgets.QLabel("P25 TX: CLEAR VOICE ONLY — op25's encoder has no encryption support "
                                "(always ALGID 0x80).")
        note.setWordWrap(True)
        note.setStyleSheet("color:#8b95a1;")
        v.addWidget(note)
        row = QtWidgets.QHBoxLayout()
        en = TX.P25_TX_AVAILABLE
        self._tx_spin(row, "P25 TX  Radio ID:", self.p25_tx, "src", 1, 0xffffff, en)
        hint = QtWidgets.QLabel("TG and NAC: beside the TX: picker")
        hint.setStyleSheet("color:#8b95a1;")
        row.addWidget(hint)
        row.addStretch(1)
        v.addLayout(row)
        if not TX.P25_TX_AVAILABLE:
            n = QtWidgets.QLabel("P25 TX needs op25's TX support on the path "
                                 "(op25_repeater.vocoder + apps/tx/op25_c4fm_mod).")
            n.setWordWrap(True)
            n.setStyleSheet("color:#8b95a1;")
            v.addWidget(n)
        return w

    def _p25_tx_quick(self, parent):
        """Main-screen quick fields for P25: TG + NAC (hex), like DMR's TG + CC (Radio ID stays in the
        submenu). The talkgroup goes into the call's Link Control."""
        w = QtWidgets.QWidget(parent)
        row = QtWidgets.QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(QtWidgets.QLabel("TG:"))
        tg = self._tx_spin(row, None, self.p25_tx, "tgid", 1, 0xffff, TX.P25_TX_AVAILABLE)
        tg.setToolTip("P25 talkgroup of the call (sent in its Link Control).")
        self._tx_hex(row, "NAC:", self.p25_tx, "nac", TX.P25_TX_AVAILABLE,
                     tip="P25 network access code (hex) of the repeater you're keying.")
        return w

    # -- the Digital tab ------------------------------------------------------------------------------
    def _make_panel(self, parent):
        w = QtWidgets.QWidget(parent)
        v = QtWidgets.QVBoxLayout(w)
        v.setContentsMargins(4, 2, 4, 2)
        row = QtWidgets.QHBoxLayout()
        row.addWidget(QtWidgets.QLabel("Decode"))
        mode = QtWidgets.QComboBox()
        mode.addItems(["P25", "DMR", "DMR-MS", "NXDN96", "NXDN48", "EDACS"])
        mode.setToolTip("Which decoder runs on the tuned channel, beside the analog mode: P25 / DMR (op25), "
                        "NXDN96 / NXDN48 / EDACS (dsd-fme). DMR also watches for mobile-station / direct-mode "
                        "bursts (a repeater input, simplex) and decodes those with dsd-fme by itself; DMR-MS "
                        "always uses dsd-fme. SmartNet control channels decode all the time. A classifier "
                        "label or a bank channel's mode switches it.")
        for i, name in enumerate(["P25", "DMR", "DMR-MS", "NXDN96", "NXDN48", "EDACS"]):
            ok = B.OP25_AVAILABLE if name in ("P25", "DMR") else _dsd.dsd_fme_available()
            if not ok:
                mode.setItemData(i, f"Unavailable: needs {'op25' if name in ('P25', 'DMR') else 'dsd-fme'}",
                                 QtCore.Qt.ToolTipRole)
        mode.setCurrentText(self._mode_text())
        mode.currentTextChanged.connect(self._on_mode_picked)
        row.addWidget(mode)
        lock = QtWidgets.QLabel("● no lock")
        lock.setStyleSheet("color:#5a636e;")
        row.addWidget(lock)
        row.addStretch(1)
        keys = QtWidgets.QPushButton("Keys…")
        keys.setToolTip("Enter P25 decryption keys (KID + algorithm + hex key) to decrypt supported traffic.")
        keys.clicked.connect(lambda: D.open_keys_dialog(self, self.app))
        keys.setEnabled(B.OP25_AVAILABLE)
        row.addWidget(keys)
        only = QtWidgets.QCheckBox("Digital only")
        only.setChecked(self.digital_only)
        only.setToolTip("Keep analog fully muted (no FM passthrough) so you only ever hear decoded digital "
                        "voice — for monitoring a digital channel.")
        only.toggled.connect(self._on_digital_only)
        row.addWidget(only)
        data = QtWidgets.QCheckBox("Data bursts")
        data.setChecked(self.capture_data)
        data.setToolTip("Capture op25's decoded DATA bursts (short data / LRRP / PDU / PDP) into the payload "
                        "pane (pcap-exportable as raw IP). Raw op25 output is parsed then discarded unless "
                        "started with --module-option digital.op25_stderr=1.")
        data.toggled.connect(self._set_capture)
        data.setEnabled(B.OP25_AVAILABLE)
        row.addWidget(data)
        v.addLayout(row)
        status = QtWidgets.QLabel("")
        status.setStyleSheet("color:#8b95a1;")
        status.setToolTip("dsd-fme decodes NXDN / EDACS when picked above (op25 can't). This updates once it "
                          "gets a CRC-clean sync (EDACS: a BCH-clean frame). EDACS variant and LCN "
                          "frequencies: Settings ▸ EDACS…")
        v.addWidget(status)
        self._w.update(mode=mode, lock=lock, only=only, data=data, status=status)
        self._lock_light(self.locked)
        self._sync_bridge()
        if self._bridge_ref is None and self.mode not in B.DSD_MODES:
            self._dsd_status("" if B.OP25_AVAILABLE else "op25 not found: P25 / DMR / SmartNet off",
                             "#8b95a1" if B.OP25_AVAILABLE else "#ff6b6b")
        return w

    def _sync_panel(self):
        for key, val in (("only", self.digital_only), ("data", self.capture_data)):
            cb = self._w.get(key)
            if cb is not None and cb.isChecked() != val:
                cb.blockSignals(True)
                cb.setChecked(val)
                cb.blockSignals(False)

    def _on_digital_only(self, on):
        self.digital_only = bool(on)
        self.ui.audio.analog_off = self.digital_only

    def _lock_light(self, locked=None):
        lab = self._w.get("lock")
        if lab is None:
            return
        locked = self.locked if locked is None else locked
        if locked:
            lab.setText("● LOCK" + (" 🔒" if self.encrypted else ""))
            lab.setStyleSheet("color:#39ff88; font-weight:bold;")
        else:
            lab.setText("● no lock")
            lab.setStyleSheet("color:#5a636e;")

    def _dsd_status(self, text, color="#8b95a1"):
        lab = self._w.get("status")
        if lab is not None:
            lab.setText(text)
            lab.setStyleSheet(f"color:{color};")

