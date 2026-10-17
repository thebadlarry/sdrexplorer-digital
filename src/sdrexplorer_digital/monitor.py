# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""op25 digital-decode support.

Two things live here now:

* ``DigitalMonitor`` — polls the op25 ``frame_assembler`` status message queue
  (``rx_q``) that ``radio.ScannerRadio`` builds for its IN-PROCESS op25 decoder,
  and turns each message into Qt signals (sync lock / decoded metadata). This is
  what drives the analog audio gate and the decoded-output window. There is no
  subprocess and no device hand-off — the decoder is part of the live flowgraph.

* ``build_iq_config`` + friends — build an op25 ``multi_rx`` config that replays
  a recorded IQ file (device ``args:"iqsrc"``). Used by the standalone offline
  replay tool (``tools/op25_replay.py``) to decode captures deterministically,
  free of live-RF variance. This is the ONLY remaining subprocess path.
"""
from __future__ import annotations

import ctypes
import json
import os
import queue
import re
import struct
import time

from PyQt5 import QtCore

from sdrexplorer.api import paths as _paths

from . import smartnet
from .pathkeys import register_paths

register_paths()


def op25_apps():
    """op25's gr-op25_repeater/apps directory (paths key "op25_apps"), or None."""
    return _paths.ext("op25_apps")


def multi_rx():
    """op25's multi_rx.py (the offline replay tool runs it), or None."""
    apps = op25_apps()
    p = os.path.join(apps, "multi_rx.py") if apps else None
    return p if p and os.path.exists(p) else None

OFFSET = 300_000            # offset-tune the device below the channel (DC spike)
SAMP_RATE = 2_400_000       # HackRF minimum-friendly rate

# demod parameters per digital mode. P25 P1 here is fsk4/rc — the params proven
# to decode a real C4FM P25 system via capture replay. These feed
# the offline replay tool; the in-process branch keeps its own copy in radio.py.
_MODE_PARAMS = {
    "P25":  dict(demod_type="fsk4", filter_type="rc",  symbol_rate=4800),
    "DMR":  dict(demod_type="fsk4", filter_type="rrc", symbol_rate=4800),
    # op25 has no NXDN frame decoder (see this module's docstring + the
    # nxdn_bridge module), but its demodulator DOES have a dedicated NXDN
    # pulse-shaping path (p25_demodulator.py filter_type='nxdn' — a different
    # transmit filter + gain trim than P25/DMR's, not the generic 'rrc' used
    # here previously) needed to hand dsd-fme clean symbols. symbol_rate 4800
    # is NXDN96 (12.5 kHz channels, the common case); NXDN48 (6.25 kHz) is
    # 2400 — override per-system if you hit one.
    "NXDN": dict(demod_type="fsk4", filter_type="nxdn", symbol_rate=4800),
    "P25P2": dict(demod_type="cqpsk", filter_type="rc", symbol_rate=6000),
    # SmartNet's control channel is 3600 bps BINARY (2-level) FSK, not 4-level —
    # op25 gets there via demod_type='fsk4' (selects the FM-discriminator front
    # end, as opposed to cqpsk) + filter_type='fsk2mm' (the 2-level MM clock
    # recovery + binary slicer variant of that chain; see op25's own
    # apps/multi_rx.py channel() dispatch and apps/smartnet_example.json).
    "SMARTNET": dict(demod_type="fsk4", filter_type="fsk2mm", symbol_rate=3600),
}
SUPPORTED_MODES = ["P25", "DMR", "NXDN", "SmartNet"]

# op25 status message types (op25_msg_types.h), read from frame_assembler's rx_q
_M_SYNC_ESTAB = -4          # digital sync/lock established
_M_TIMEOUT = -1             # sync lost / call timeout (also SmartNet CC timeout)
_M_JSON = -3                # body is JSON call metadata (grpaddr/src/encrypted…)
_M_SMARTNET_BAD_OSW = -2    # SmartNet: sync/CRC failure on one OSW (op25_msg_types.h)
_M_SMARTNET_OSW = 0         # SmartNet: a good 5-byte OSW (addr:2, group:1, cmd:2)

# op25 message-queue protocol ids (op25_msg_types.h, high 16 bits of type())
_PROTO_P25 = 0
_PROTO_DMR = 1
_PROTO_SMARTNET = 2
_PROTO_NAMES = {_PROTO_P25: "P25", _PROTO_DMR: "DMR", _PROTO_SMARTNET: "SmartNet"}


def parse_p25_lcw(lcw):
    """A P25 Phase 1 Link Control Word (9 bytes, RS-corrected by op25): {"format", "opcode", "mfid", "kind"},
    plus "gps" {"lat", "lon", "fix"} for Motorola's embedded GPS (MFID 0x90, opcode 6), or "protected" when
    its contents are encrypted. Ported from dsd-fme (p25_lcw.c / dsd_gps.c apx_embedded_gps): 72 bits, P-bit
    first; lat = sign bit 24 + 23 bits x 90/0x7FFFFF (sign set: -90), lon = sign bit 48 + 23 bits x
    180/0x7FFFFF (sign set: -180); bit 23 set = the last known fix, not a current one."""
    if len(lcw) < 9:
        return None
    fmt, mfid = lcw[0], lcw[1]
    out = {"format": fmt, "opcode": fmt & 0x3f, "mfid": mfid, "kind": f"LCO 0x{fmt & 0x3f:02X} MFID 0x{mfid:02X}"}
    if mfid in (0x00, 0x01) and fmt in (0x00, 0x03):          # standard voice channel users (the call's unit)
        src = int.from_bytes(bytes(lcw[6:9]), "big")
        if fmt == 0x00:
            out.update(kind="Group Voice Channel User", tgid=int.from_bytes(bytes(lcw[4:6]), "big"), src=src)
        else:
            out.update(kind="Unit to Unit Voice Channel User", dst=int.from_bytes(bytes(lcw[3:6]), "big"), src=src)
        return out
    if mfid == 0x90 and (fmt & 0x3f) == 0x06:
        out["kind"] = "MFID90 (Motorola) GPS"
        v = int.from_bytes(bytes(lcw[:9]), "big")
        bit = lambda i: (v >> (71 - i)) & 1                         # noqa: E731
        field = lambda i, n: (v >> (72 - i - n)) & ((1 << n) - 1)   # noqa: E731
        if bit(0):
            out["protected"] = True
            return out
        lat = field(25, 23) * 90.0 / 0x7FFFFF - (90.0 if bit(24) else 0.0)
        lon = field(49, 23) * 180.0 / 0x7FFFFF - (180.0 if bit(48) else 0.0)
        if abs(lat) < 90 and abs(lon) < 180:
            out["gps"] = {"lat": round(lat, 6), "lon": round(lon, 6), "fix": "last" if bit(23) else "current"}
    return out


def _msg_bytes(msg):
    """Raw frame body of an op25 status message as bytes (empty on none)."""
    body = msg.to_string()
    if isinstance(body, str):
        body = body.encode("latin-1", "replace")
    return bytes(body) if body else b""
# P25 DUID frame types that carry the 12-bit NAC in the first 2 body bytes
_P25_DUID = {0: "HDU", 3: "TDU", 5: "LDU1", 7: "TSBK", 10: "LDU2", 12: "PDU",
             15: "TDULC", 16: "MAC_PTT", 17: "MAC_END", 18: "MAC_PDU", 19: "LCW"}
_DMR_TYPES = {0: "CACH_SLC", 1: "CACH_CSBK", 2: "SLOT_PI", 3: "SLOT_VLC",
              4: "SLOT_TLC", 5: "SLOT_CSBK", 6: "SLOT_MBC", 7: "SLOT_ELC",
              8: "SLOT_ERC", 9: "SLOT_ESB"}
_M_DMR_CACH_SLC = 0
_M_DMR_PI, _M_DMR_VLC, _M_DMR_TLC, _M_DMR_CSBK = 2, 3, 4, 5
# Embedded LC: the same dst/src Link Control repeated every voice superframe
# (~360ms) via the EMB signaling field, decoded by op25's dmr_slot.cc
# decode_embedded_lc() and sent as a 9-byte d_lc buffer (+ 1 trailing color-
# code byte, see below) -- identical byte layout to VLC/TLC's d_lc[0:9], just
# without the 3 trailing RS parity bytes. Catches the talkgroup on calls
# where the Voice LC Header was missed (late tune-in) or failed its RS(12,9)
# correction, since ELC repeats all call long.
_M_DMR_ELC = 7
# DMR Full-Link-Control FLCO opcodes we can name (op25 dmr_slot: d_lc[0] & 0x3f)
_DMR_FLCO = {0x00: "Group Call", 0x03: "Private Call"}


def op25_available():
    return multi_rx() is not None and _paths.ext("op25") is not None


# ---------------------------------------------------------------------------
#  In-process decode-status monitor (polls radio.rx_q)
# ---------------------------------------------------------------------------
class DigitalMonitor(QtCore.QThread):
    """Poll the op25 frame_assembler status queue on its own thread and surface
    lock state + decoded metadata as Qt signals (queued -> safe to touch the
    GUI from the slots). Runs for the life of the app; ``stop()`` ends it."""

    lock_changed = QtCore.pyqtSignal(bool)   # digital sync established / lost
    decoded = QtCore.pyqtSignal(dict)        # {nac, duid, tgid, src, encrypted…}
    raw_line = QtCore.pyqtSignal(str)        # freeform status line

    def __init__(self, rx_q, parent=None):
        super().__init__(parent)
        self.rx_q = rx_q
        self._keep = True
        self._sn = smartnet.OswTracker()    # SmartNet control-channel OSW correlator
        # DMR LCN -> receive frequency (Hz), for MotoTRBO Connect/Capacity Plus
        # channel grants. Unlike SmartNet there's no formula for this (LCNs are
        # an arbitrary per-system assignment the air interface never broadcasts
        # a frequency for) so it's a user-supplied table; see set_dmr_bandplan.
        self._dmr_lcn_freqs = {}

    def set_smartnet_bandplan(self, bandplan):
        self._sn.set_bandplan(bandplan)

    def set_dmr_bandplan(self, lcn_freqs):
        """``lcn_freqs``: {lcn(int) -> freq_hz(float)}, replacing the current
        table wholesale (so callers can just pass their whole edited dict)."""
        try:
            self._dmr_lcn_freqs = {int(lcn): float(hz) for lcn, hz in lcn_freqs.items()}
        except (TypeError, ValueError, AttributeError):
            pass

    def run(self):
        if self.rx_q is None:
            return
        while self._keep:
            if self.rx_q.empty_p():
                time.sleep(0.01)
                continue
            msg = self.rx_q.delete_head()
            if msg is None:
                break
            try:
                self._handle(msg)
            except Exception:
                pass                          # never let a bad frame kill the loop

    def _handle(self, msg):
        t = msg.type()
        proto = ctypes.c_int16((t >> 16) & 0xffff).value
        m_type = ctypes.c_int16(t & 0xffff).value
        if proto == _PROTO_P25:
            self._handle_p25(m_type, msg)
        elif proto == _PROTO_DMR:
            self._handle_dmr(m_type, msg)
        elif proto == _PROTO_SMARTNET:
            self._handle_smartnet(m_type, msg)
        else:
            self._handle_other(proto, m_type, msg)

    def _handle_smartnet(self, m_type, msg):
        """SmartNet control channel: op25's rx_smartnet.cc has already framed,
        deinterleaved, error-corrected and CRC-checked the OSW; feed the 5-byte
        result into smartnet.OswTracker (which correlates 1-3 OSW sequences into
        named trunking events — voice grants, control-channel ID, busy/deny…)
        and emit one ``decoded`` per event. Unlike DMR/P25 there's no distinct
        sync-established message — receiving a good OSW at all IS the lock."""
        if m_type == _M_TIMEOUT:
            self.lock_changed.emit(False)
            self._sn.reset()               # control channel lost: drop partial state
            return
        if m_type == _M_SMARTNET_BAD_OSW:
            self._sn.reset()               # bad CRC would misalign a multi-OSW msg
            return
        if m_type != _M_SMARTNET_OSW:
            return
        body = _msg_bytes(msg)
        if len(body) < 5:
            return
        addr = (body[0] << 8) | body[1]
        group = body[2]
        cmd = (body[3] << 8) | body[4]
        self.lock_changed.emit(True)
        for ev in self._sn.feed(addr, group, cmd, time.time()):
            self.decoded.emit(dict(ev, proto="SmartNet", raw=body))

    def _handle_other(self, proto, m_type, msg):
        """Any protocol we don't parse in detail (NXDN, …): still capture the
        raw frame payload so it shows in the hexdump / save file."""
        if m_type in (_M_SYNC_ESTAB, _M_TIMEOUT):
            self.lock_changed.emit(m_type == _M_SYNC_ESTAB)
            return
        raw = _msg_bytes(msg)
        if raw:
            self.decoded.emit({"proto": _PROTO_NAMES.get(proto, f"proto{proto}"),
                               "label": f"type{m_type}", "raw": raw})

    def _handle_p25(self, m_type, msg):
        if m_type == _M_SYNC_ESTAB:
            self.lock_changed.emit(True)
            return
        if m_type == _M_TIMEOUT:
            self.lock_changed.emit(False)
            return
        body = _msg_bytes(msg)
        if m_type == _M_JSON:
            try:
                d = json.loads(body)
            except (ValueError, TypeError):
                return
            self.decoded.emit({
                "proto": "P25",
                "tgid": d.get("grpaddr") or d.get("tgid"),
                "src": d.get("srcaddr") or d.get("src"),
                "encrypted": d.get("encrypted"),
                "algid": d.get("algid"),
                "keyid": d.get("keyid"),
                "raw": body,                        # JSON metadata bytes
            })
        elif m_type in _P25_DUID and len(body) >= 2:
            nac = (body[0] << 8) | body[1]          # 12-bit NAC, big-endian
            if nac <= 0xFFF:                        # sanity: real P25 NAC
                out = {"proto": "P25", "nac": nac, "duid": _P25_DUID[m_type], "raw": body}
                if _P25_DUID[m_type] == "LCW" and len(body) >= 11:
                    lc = parse_p25_lcw(body[2:11])  # NAC (2 bytes) then the 9-byte link control word
                    out["lcw"] = bytes(body[2:11])
                    for k in ("gps", "protected", "src", "tgid", "dst"):
                        if lc and k in lc:
                            out["lcw_" + k] = lc[k]
                    if lc:
                        out["lcw_kind"] = lc["kind"]
                self.decoded.emit(out)

    def _handle_dmr(self, m_type, msg):
        # DMR emits no sync-established message, only a timeout; treat any slot
        # activity as "locked" (the hang timer releases it) so the gate works
        # when DMR mode is selected, and surface the frame type + parsed content.
        #
        # op25's DMR decoder has NO JSON metadata sink (unlike P25) — the rich
        # detail is only fprintf'd to op25's stderr log. But the raw frame bytes
        # DO reach this queue, so we parse the useful fields out of the Voice/
        # Terminator/Embedded LC (talkgroup + radio ID -- Embedded LC repeats
        # every superframe, so it fills in TG/src on calls where the Voice LC
        # Header was missed or failed correction), the Privacy header
        # (encryption), and CSBK (opcode + Connect Plus grant, resolved to a
        # frequency via self._dmr_lcn_freqs when the LCN is in the user's
        # bandplan table). Color code isn't part of the LC/CSBK/CACH payload
        # itself -- it's learned separately from the burst sync/EMB -- so our
        # local op25 build (dmr_slot.cc/dmr_cai.cc) appends it as one trailing
        # byte on CACH_SLC, VLC, TLC, ELC and CSBK messages specifically so it
        # reaches this queue; stock upstream op25 only fprintf's it to stderr.
        # Short-data / LRRP / SMS bursts are stderr-only in op25 and never
        # reach this queue.
        if m_type == _M_TIMEOUT:
            self.lock_changed.emit(False)
            return
        self.lock_changed.emit(True)
        b = _msg_bytes(msg)
        out = {"proto": "DMR", "label": _DMR_TYPES.get(m_type, f"type{m_type}"),
               "raw": b}
        if m_type == _M_DMR_CACH_SLC and len(b) >= 5:
            out["cc"] = b[4] & 0xf
        elif m_type in (_M_DMR_VLC, _M_DMR_TLC, _M_DMR_ELC) and len(b) >= 9:
            flco = b[0] & 0x3f
            out["flco"] = flco
            out["call"] = _DMR_FLCO.get(flco)
            out["tgid"] = (b[3] << 16) | (b[4] << 8) | b[5]   # dst (talkgroup)
            out["src"] = (b[6] << 16) | (b[7] << 8) | b[8]    # source radio ID
            out["fid"] = b[1]
            cc_idx = 9 if m_type == _M_DMR_ELC else 12
            if len(b) > cc_idx:
                out["cc"] = b[cc_idx] & 0xf
        elif m_type == _M_DMR_PI and len(b) >= 10:
            out["algid"] = b[0]
            out["keyid"] = b[2]
            out["encrypted"] = 1 if b[0] else 0               # algid 0 = clear
        elif m_type == _M_DMR_CSBK and len(b) >= 2:
            out["csbko"] = b[0] & 0x3f
            out["fid"] = b[1]
            if len(b) >= 11:
                out["cc"] = b[10] & 0xf
            if (b[0] & 0x3f) == 0x03 and b[1] == 0x06 and len(b) >= 9:
                out["src"] = (b[2] << 16) | (b[3] << 8) | b[4]   # ConnectPlus grant
                out["tgid"] = (b[5] << 16) | (b[6] << 8) | b[7]
                # b[8]: bits 64-67 of the CSBK = LCN, bit 68 = timeslot (dmr_slot.cc
                # decode_csbk: extract(csbk,64,68) / csbk[68]) -> top nibble / next bit.
                out["lcn"] = (b[8] >> 4) & 0x0f
                out["tslot"] = (b[8] >> 3) & 0x1
                freq = self._dmr_lcn_freqs.get(out["lcn"])
                if freq is not None:
                    out["freq_mhz"] = freq / 1e6
        self.decoded.emit(out)

    def stop(self):
        self._keep = False


# ---------------------------------------------------------------------------
#  op25 stderr DATA-payload capture (the actual short-data / LRRP / PDU bursts)
# ---------------------------------------------------------------------------
# op25's C++ decoder writes decoded DATA payloads only to stderr (never the msgq),
# guarded by debug>=10. A payload line ends in its hex bytes ("… DEST(x) : aa bb
# cc"), whereas voice/AMBE and LC dumps have trailing text after their hex — so
# an end-anchored hex match plus a data-keyword filter isolates real data bursts.
_DATA_MARK = re.compile(r'PDP|PDU|MBT|LRRP|SDS|SMS|\bDATA\b', re.I)
_HEXTAIL = re.compile(r':\s*((?:[0-9A-Fa-f]{2}\s+)*[0-9A-Fa-f]{2})\s*$')
# op25 log prefix is "%m/%d/%y %H:%M:%S.uuuuuu [msgq_id] " (log_ts.h) — drop the
# date and [id] but KEEP the time (useful for correlating data bursts).
_TS_DATE = re.compile(r'^\s*\d{2}/\d{2}/\d{2}\s+')
_MSGQID = re.compile(r'\s*\[\d+\]\s*')
# op25 writes payloads two ways: a trailing space-separated hex run after ": "
# (PDP short-data, LC), OR contiguous hex inside DATA(...) (CSBK, MBC, etc.).
_DATA_PAREN = re.compile(r'\bDATA\(([0-9A-Fa-f]+)\)')


def parse_op25_data_line(line):
    """Return (proto, label, payload_bytes) for an op25 stderr line that carries
    a decoded DATA payload, else None."""
    if not _DATA_MARK.search(line):
        return None
    data, end = None, None
    m = _HEXTAIL.search(line)                     # ": aa bb cc" at end of line
    if m:
        try:
            data = bytes(int(h, 16) for h in m.group(1).split())
            end = m.start()
        except ValueError:
            data = None
    if data is None:                              # "DATA(aabbcc)" contiguous hex
        mp = _DATA_PAREN.search(line)
        if mp:
            hx = mp.group(1)
            # op25 logs CSBK DATA via %lx (a 64-bit field) so leading zero nibbles
            # are dropped — left-pad to the full 8-byte width so byte offsets line
            # up with op25's parser (src=[0:3], grp=[3:6], lcn/slot=[6], …).
            hx = hx.zfill(16) if len(hx) <= 16 else ("0" + hx if len(hx) % 2 else hx)
            try:
                data = bytes.fromhex(hx)
                end = mp.start()
            except ValueError:
                data = None
    if not data:
        return None
    proto = ("DMR" if ("Slot(" in line or "PDP" in line or "CSBK" in line
                       or "SLCO" in line)
             else "P25" if ("PDU" in line or "NAC" in line or "MBT" in line)
             else "DATA")
    label = _TS_DATE.sub("", line[:end])          # drop the date
    label = _MSGQID.sub(" ", label)               # drop the [msgq_id] token
    label = re.sub(r"\s{2,}", " ", label).strip().rstrip(" ,:")
    return (proto, label, data)


# --- LRRP (Motorola Location Request/Response Protocol) location decode -------
# LRRP location reports ride inside DMR PDP short-data bursts (the payloads we
# capture). Coordinate encoding per the SDRTrunk MotoTRBO LRRP decoder:
#   Point2d token 0x66 + 8 bytes: latitude  = 31-bit magnitude (bit8 = S/neg)
#   × 180/(2^32-1); longitude = two's-complement 32-bit × 360/(2^32-1).
# Point3d 0x69 / Circle2d 0x51 / Circle3d 0x55 share the same 8-byte coordinate
# prefix (with extra altitude/radius bytes we don't decode). Speed 0x6C (2 B),
# Heading 0x56 (1 B) follow the point when present.
_LRRP_LAT_MULT = 180.0 / 4294967295.0
_LRRP_LON_MULT = 360.0 / 4294967295.0
_LRRP_POINT_TOKENS = (0x66, 0x69, 0x51, 0x55)   # tokens whose payload starts w/ a point


def _lrrp_point(data, off):
    """Decode the 8-byte LRRP coordinate at ``off``; return (lat, lon) if it's a
    valid on-Earth position, else None."""
    if off + 8 > len(data):
        return None
    b = data[off:off + 8]
    lat_raw = ((b[0] & 0x7f) << 24) | (b[1] << 16) | (b[2] << 8) | b[3]
    lat = lat_raw * _LRRP_LAT_MULT * (-1.0 if (b[0] & 0x80) else 1.0)
    lon_raw = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]
    if lon_raw >= 0x80000000:                    # two's complement
        lon_raw -= 0x100000000
    lon = lon_raw * _LRRP_LON_MULT
    if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0 and (lat or lon):
        return (lat, lon)
    return None


# MotoTRBO application services by UDP port (the traffic that rides the DMR data
# channel): LRRP = GPS location, ARS = presence/registration, TMS = text/SMS.
_MOTOTRBO_UDP = {4001: "LRRP", 4004: "LRRP", 4005: "ARS",
                 4007: "TMS", 4008: "TELEMETRY"}
_NON_LRRP_SERVICES = ("ARS", "TMS", "TELEMETRY")
_ICMP_UNREACH = {0: "net-unreachable", 1: "host-unreachable",
                 3: "port-unreachable", 13: "admin-prohibited"}


def classify_ip(data):
    """Parse a captured DMR data payload as an IPv4 datagram. Returns a dict —
    ``proto``, ``src``/``dst`` (dotted), ``sport``/``dport`` + ``service`` (UDP),
    ``icmp_type``/``icmp_code`` (ICMP), and ``body`` (the L4 application payload)
    — or None when it isn't a well-formed IPv4 datagram.

    The strict length/version checks are deliberate: bit-errored or truncated
    RATE-3/4 bursts (a corrupt protocol byte, or a frame that starts mid-header)
    fail here and return None, so nothing downstream tries to read a coordinate
    out of garbage."""
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0f) * 4
    total_len = (data[2] << 8) | data[3]
    if ihl < 20 or not (ihl <= total_len <= len(data)):
        return None
    proto = data[9]
    info = {"proto": proto,
            "src": ".".join(str(b) for b in data[12:16]),
            "dst": ".".join(str(b) for b in data[16:20]),
            "sport": None, "dport": None, "service": None,
            "icmp_type": None, "icmp_code": None,
            "body": bytes(data[ihl:total_len])}
    if proto == 17 and total_len - ihl >= 8:          # UDP
        u = data[ihl:total_len]
        info["sport"] = (u[0] << 8) | u[1]
        info["dport"] = (u[2] << 8) | u[3]
        info["service"] = (_MOTOTRBO_UDP.get(info["dport"])
                           or _MOTOTRBO_UDP.get(info["sport"]))
        info["body"] = bytes(u[8:])
    elif proto == 1 and total_len - ihl >= 2:         # ICMP
        info["icmp_type"] = data[ihl]
        info["icmp_code"] = data[ihl + 1]
        info["service"] = "ICMP"
    return info


# P25 encryption Algorithm IDs (TIA-102 registered). NOTE: op25's crypto in this
# build only DECRYPTS ADP (0xaa) and DES-OFB (0x81) — the rest are labeled for
# information only (AES etc. would need op25's C++ crypto extended).
_P25_ALGIDS = {
    0x80: "clear", 0x81: "DES-OFB", 0x83: "3DES", 0x84: "AES-256",
    0x85: "AES-128", 0x9f: "DES-XL", 0xaa: "ADP (RC4-40)",
}
_P25_DECRYPTABLE = (0x81, 0xaa)          # what op25 can actually decrypt here


def p25_algid_name(algid):
    """Human name for a P25 ALGID (e.g. 0x84 -> 'AES-256'), or None if unknown."""
    return _P25_ALGIDS.get(algid)


def p25_algid_decryptable(algid):
    """True if op25 (this build) can decrypt this algorithm given the key."""
    return algid in _P25_DECRYPTABLE


def parse_lrrp(data):
    """Decode an LRRP position from a captured DMR data payload, or None.

    LRRP location reports ride in UDP datagrams, so we require a clean IPv4+UDP
    datagram and scan ONLY the UDP application payload. This deliberately rejects:
      * ICMP errors (port-unreachable replies) — proto != UDP,
      * bit-errored / truncated bursts — not well-formed IPv4,
      * ARS / TMS / telemetry — their fixed message headers (notably the ARS
        ``00 0d f0 20 …`` prefix) are exactly what produced the bogus 0.03828°
        'latitude' false hits.
    Only the L4 payload is scanned, never the IP/UDP headers (whose checksum byte
    was the coincidental point token in the original misparse)."""
    if not data:
        return None
    info = classify_ip(data)
    if info is None or info["proto"] != 17:           # not a clean UDP datagram
        return None
    if info["service"] in _NON_LRRP_SERVICES:         # ARS/TMS/telemetry, not GPS
        return None
    body = info["body"]
    for i, tok in enumerate(body):
        if tok not in _LRRP_POINT_TOKENS:
            continue
        pt = _lrrp_point(body, i + 1)
        if not pt:
            continue
        out = {"lat": round(pt[0], 6), "lon": round(pt[1], 6),
               "token": tok, "offset": i}
        rest = body[i + 9:]                            # tokens after the 9-byte point
        # Speed (0x6C, 2 bytes, 0.1 m/s) / Heading (0x56, 1 byte, 2°/unit) if present
        for j, t in enumerate(rest):
            if t == 0x6C and j + 3 <= len(rest):
                out["speed_mps"] = ((rest[j + 1] << 8) | rest[j + 2]) / 10.0
            elif t == 0x56 and j + 2 <= len(rest):
                out["heading_deg"] = rest[j + 1] * 2
        return out
    return None


def ip_radio_id(data):
    """The DMR radio id behind a captured IPv4 datagram's source address, or None. MOTOTRBO gives each radio
    the address <network>.<id as 3 bytes> (12.0.0.137 is radio 137, 12.188.97.78 is radio 12345678; dsd-fme's
    "SRC(24)"), and an LRRP report comes from the radio, so its source is the reporting unit."""
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    rid = (data[13] << 16) | (data[14] << 8) | data[15]
    return rid or None


def _ars_rid(body):
    """Pull the radio ID (ASCII digits) out of an ARS device-registration body
    (…``f0 <subtype> <len> <len ASCII bytes>``…), or None."""
    for i in range(len(body) - 2):
        if body[i] == 0xf0:
            slen = body[i + 2]
            s = body[i + 3:i + 3 + slen]
            if 0 < slen == len(s) and all(0x30 <= c <= 0x39 for c in s):
                return s.decode("ascii", "ignore")
    return None


def describe_data_frame(data):
    """A short human classification of a captured DMR data payload for the decode
    log — e.g. 'ARS registration RID 12345678' or 'ICMP port-unreachable
    13.0.0.2 -> 12.0.0.1' — or None when it isn't a recognizable clean
    IP frame (LRRP frames return None; parse_lrrp labels those with the fix)."""
    info = classify_ip(data)
    if info is None:
        return None
    if info["proto"] == 1:                            # ICMP
        if info["icmp_type"] == 3:
            reason = _ICMP_UNREACH.get(info["icmp_code"], "unreachable")
            return f"ICMP {reason}  {info['src']} -> {info['dst']}"
        return f"ICMP type {info['icmp_type']} code {info['icmp_code']}"
    svc = info["service"]
    if svc == "ARS":
        rid = _ars_rid(info["body"])
        return "ARS registration" + (f" RID {rid}" if rid else "")
    if svc == "TMS":
        return "TMS text message"
    if svc == "TELEMETRY":
        return "telemetry"
    return None                                       # LRRP / unknown: no extra tag


class Op25DataCapture(QtCore.QThread):
    """Redirect the process's stderr (fd 2 — where op25's decoder fprintf's its
    decoded DATA payloads) into a pipe, tee every line back to the real stderr so
    nothing is lost, and emit the data bursts as (proto, label, payload). Enable
    op25 debug>=10 (radio.set_digital_debug) for these lines to appear.

    fd-level (not sys.stderr) redirection is required because op25 is C++ writing
    straight to fd 2. stop() restores fd 2 and unblocks the reader."""

    data = QtCore.pyqtSignal(str, str, bytes)

    def __init__(self, tee=False, parent=None):
        super().__init__(parent)
        self._keep = True
        self._tee = bool(tee)                 # echo op25's raw stderr to terminal?
        self._saved = os.dup(2)               # the real stderr
        self._r, self._w = os.pipe()
        os.dup2(self._w, 2)                   # fd 2 -> pipe (op25 writes here now)

    def run(self):
        buf = b""
        while self._keep:
            try:
                chunk = os.read(self._r, 8192)   # blocks; EOF (b"") on stop()
            except OSError:
                break
            if not chunk:
                break
            if self._tee:                        # --op25-stderr: echo to terminal
                try:
                    os.write(self._saved, chunk)
                except OSError:
                    pass
            # else: raw op25 output is dropped (parsed for payloads, then /dev/null)
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                hit = parse_op25_data_line(raw.decode("utf-8", "replace"))
                if hit:
                    self.data.emit(*hit)

    def stop(self):
        self._keep = False
        try:
            os.dup2(self._saved, 2)           # restore first: op25 -> real stderr
        except OSError:
            pass
        try:
            os.close(self._w)                 # closes pipe write end -> reader EOF
        except OSError:
            pass
        self.wait(1000)
        for fd in (self._r, self._saved):
            try:
                os.close(fd)
            except OSError:
                pass


# ---------------------------------------------------------------------------
#  Offline IQ-file replay config (subprocess op25 via tools/op25_replay.py)
# ---------------------------------------------------------------------------
def _channel(freq_hz, mode, device_name, audio_port):
    """One conventional digital channel bound to a device."""
    p = _MODE_PARAMS.get(str(mode).upper(), _MODE_PARAMS["P25"])
    return {
        "name": str(mode).upper(), "frequency": int(freq_hz), "device": device_name,
        "demod_type": p["demod_type"], "filter_type": p["filter_type"],
        "symbol_rate": p["symbol_rate"], "if_rate": 24000, "excess_bw": 0.2,
        "cqpsk_tracking": p["demod_type"] == "cqpsk",
        "destination": f"udp://127.0.0.1:{audio_port}",
        "enable_analog": "off", "trunking_sysname": "",
        "plot": "", "blacklist": "", "whitelist": "",
    }


def _wrap(channel, device, audio_port):
    audio = {"module": "sockaudio.py", "instances": [
        {"instance_name": "audio0", "device_name": "default",
         "udp_port": audio_port, "audio_gain": 1.0, "number_channels": 1}]}
    return {
        "channels": [channel],
        "devices": [device],
        "trunking": {"module": "", "chans": []},
        # NOTE: unlike configure_trunking (which defaults "" via from_dict),
        # op25's configure_metadata does a raw importlib.import_module(config
        # ['module']) — "" isn't a caught ImportError, it's an uncaught
        # ValueError ("Empty module name") that kills multi_rx.py outright.
        # "none.py" fails to import too, but ModuleNotFoundError IS caught,
        # leaving self.metadata = None (streams=[] means it's never used anyway).
        "metadata": {"module": "none.py", "streams": []},
        "audio": audio,
        # NOTE: no "terminal" key -> op25 runs headless, logs to stderr
    }


def build_iq_config(iq_file, chan_hz, mode, center_hz=None, samp_rate=SAMP_RATE,
                    iq_size=1, iq_signed=True, ppm=0.0, audio_port=23456):
    """Return an op25 multi_rx config that replays a recorded IQ file instead of
    opening the HackRF (device ``args:"iqsrc"``). Deterministic + repeatable, so
    it's the right way to prove/tune the decode chain free of live-RF variance.

    ``iq_size``/``iq_signed`` describe the sample format: 1=int8, 2=int16,
    4=float32. HackRF's native ``hackrf_transfer`` output is signed int8
    (iq_size=1, iq_signed=True); the GUI recorder writes int16 (iq_size=2).
    ``center_hz`` is the frequency the file was recorded at (defaults to
    chan-OFFSET, matching our offset-tune recorder)."""
    if center_hz is None:
        center_hz = int(chan_hz) - OFFSET
    device = {
        "args": "iqsrc", "name": "iq0",
        "iq_file": str(iq_file), "iq_size": int(iq_size),
        "iq_signed": bool(iq_signed), "iq_seek": 0,
        "frequency": int(center_hz), "rate": int(samp_rate),
        "offset": 0, "ppm": float(ppm), "usable_bw_pct": 0.85, "tunable": False,
    }
    return _wrap(_channel(chan_hz, mode, "iq0", audio_port), device, audio_port)
