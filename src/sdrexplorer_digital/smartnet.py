# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""Motorola SmartNet / SmartZone (Type I/II) trunking control-channel decode.

op25's C++ decoder (``rx_smartnet.cc``, selected via ``frame_assembler``
options="smartnet") already frames, deinterleaves, error-corrects and
CRC-checks each 3600 bps OSW (Outbound Signaling Word) and delivers the
5-byte result (address:2, group-flag:1, command:2) on the same ``rx_q`` the
P25/DMR decoders use — ``digital.py``'s ``DigitalMonitor`` dispatches
protocol id 2 (SmartNet) to ``OswTracker`` here.

This module turns that raw (address, group, command) triple into named
trunking events — voice grants, control-channel identification, busy/deny
codes — porting the OSW meaning table and band-plan channel->frequency math
out of op25's own ``tk_smartnet.py`` (which normally drives a whole separate
``multi_rx.py`` subprocess trunking config that this in-process app never
runs).

Deliberately a SUBSET of ``tk_smartnet.py``: covers the "standard" (non-OBT)
800/900 MHz band plans and their common 1-3 OSW message shapes, and skips
the bad-OSW/interleaved-idle re-ordering recovery tk_smartnet does (we just
drop the in-flight multi-OSW correlation on a bad OSW/timeout — see
``reset()``). Good enough for a meaningful decode log; NOT a full
trunk-tracker (nothing here retunes to follow a grant).
"""
from __future__ import annotations

from collections import deque, namedtuple

# --- band-plan channel-number -> receive-frequency math (op25 tk_smartnet.py) --
# OBT (custom base/spacing band plans) and uplink/transmit frequencies are
# intentionally not ported — this app only ever needs the downlink/listen
# frequency to show in the decode log.
BANDPLANS = ["800_domestic", "800_domestic_splinter", "800_rebanded",
             "800_international", "800_international_splinter", "900"]
DEFAULT_BANDPLAN = "800_domestic"


def is_chan(cmd, bandplan=DEFAULT_BANDPLAN):
    """True if ``cmd`` (an OSW command field) is a valid channel number
    (as opposed to a status/control opcode) under ``bandplan``."""
    if cmd < 0:
        return False
    if bandplan == "900":
        return cmd <= 0x1de
    international = bandplan.startswith("800_international")
    if not international:
        if (0x2d0 <= cmd <= 0x2f7) or (0x32f <= cmd <= 0x33f) \
                or (0x3c1 <= cmd <= 0x3fe) or cmd == 0x3be:
            return True
        if bandplan == "800_rebanded":
            return cmd <= 0x22f
        return cmd <= 0x2cf
    return cmd <= 0x2f7


def get_freq(cmd, bandplan=DEFAULT_BANDPLAN):
    """Receive frequency (MHz) for channel number ``cmd`` under ``bandplan``,
    or None if ``cmd`` isn't a valid channel number for that plan."""
    if not is_chan(cmd, bandplan):
        return None
    if bandplan == "900":
        return round(935.0125 + 0.0125 * cmd, 5)
    international = bandplan.startswith("800_international")
    splinter = bandplan.endswith("splinter")
    freq = 0.0
    if not international:
        if bandplan == "800_rebanded":
            if cmd <= 0x1b7:
                freq = 851.0125 + 0.025 * cmd
            elif cmd <= 0x22f:
                freq = 851.0250 + 0.025 * (cmd - 0x1b8)
        elif splinter:
            if cmd <= 0x257:
                freq = 851.0000 + 0.025 * cmd
            elif cmd <= 0x2cf:
                freq = 866.0125 + 0.025 * (cmd - 0x258)
        else:
            if cmd <= 0x2cf:
                freq = 851.0125 + 0.025 * cmd
        if 0x2d0 <= cmd <= 0x2f7:
            freq = 866.0000 + 0.025 * (cmd - 0x2d0)
        elif 0x32f <= cmd <= 0x33f:
            freq = 867.0000 + 0.025 * (cmd - 0x32f)
        elif 0x3c1 <= cmd <= 0x3fe:
            freq = 867.4250 + 0.025 * (cmd - 0x3c1)
        elif cmd == 0x3be:
            freq = 868.9750
    else:
        freq = (851.0000 if splinter else 851.0125) + 0.025 * cmd
    return round(freq, 5) if freq else None


# --- OSW meaning tables (op25 tk_smartnet.py process_osws, standard path) -----
# Call-denial reason codes: low 10 bits of an extended-function OSW whose
# address is 0x2cXX (i.e. addr & 0xfc00 == 0x2c00).
DENIAL_REASONS = {
    0x004: "invalid talkgroup", 0x011: "announcement listen only",
    0x012: "clear tx only", 0x013: "listen only", 0x014: "no private call",
    0x015: "private call invalid ID", 0x016: "no interconnect",
    0x020: "unsupported mode", 0x041: "private call target offline",
    0x047: "group busy (in progress)", 0x048: "private call ring target offline",
    0x04a: "forbidden on site", 0x04e: "call alert invalid ID",
    0x04f: "call alert target offline", 0x056: "radio wrong modulation",
    0x060: "OmniLink trespass", 0x065: "radio ID denied",
    0x066: "talkgroup ID denied", 0x090: "group busy (starting)",
    0x096: "private call target busy",
}
# Extended functions on an individual radio: exact-match OSW address values.
_RADIO_CHECK, _DEAFFILIATION, _EMERGENCY_ACK = 0x261b, 0x261c, 0x26e8


def _denial(osw1_addr):
    return DENIAL_REASONS.get(osw1_addr & 0x3ff, f"code 0x{osw1_addr & 0x3ff:03x}")


_Osw = namedtuple("_Osw", "addr group cmd ts")
_WAIT = object()          # sentinel: not enough OSWs buffered yet, wait for more


class OswTracker:
    """Feed decoded (address, group, command) OSW triples in and get back a
    list of named trunking-event dicts. Stateful (buffers up to 3 OSWs to
    correlate multi-word messages) — one instance per control-channel
    receiver; call ``reset()`` on a bad OSW / control-channel timeout so a
    dropped frame can't misalign the next multi-OSW message."""

    def __init__(self, bandplan=DEFAULT_BANDPLAN):
        self.bandplan = bandplan
        self._q = deque()
        self.sysid = None
        self.cc_freq_mhz = None

    def set_bandplan(self, bandplan):
        if bandplan in BANDPLANS:
            self.bandplan = bandplan

    def reset(self):
        self._q.clear()

    def _freq(self, cmd):
        return get_freq(cmd, self.bandplan)

    def feed(self, addr, group, cmd, ts=0.0):
        self._q.append(_Osw(int(addr), bool(group), int(cmd), ts))
        events = []
        while self._q:
            ev = self._try_consume()
            if ev is _WAIT:
                break
            if ev is not None:
                events.append(ev)
        return events

    # -- single-OSW dispatch (op25 tk_smartnet.py process_osws, 1-OSW cases) --
    def _one_osw(self, osw):
        rx_chan = is_chan(osw.cmd, self.bandplan)
        if rx_chan and osw.group:                       # group voice update
            freq = self._freq(osw.cmd)
            return dict(kind="voice_update", label="GROUP VOICE UPDATE",
                        tgid=osw.addr, freq_mhz=freq)
        if rx_chan and not osw.group and (osw.addr & 0xff00) == 0x1f00:
            freq = self._freq(osw.cmd)                   # control channel ID
            self.cc_freq_mhz = freq
            return dict(kind="control_channel", label="CONTROL CHANNEL",
                        freq_mhz=freq)
        if osw.cmd == 0x2f8 and not osw.group:
            return dict(kind="idle", label="SYSTEM IDLE")
        if osw.cmd == 0x300 and osw.group:
            return dict(kind="busy", label="GROUP BUSY QUEUED", tgid=osw.addr)
        if osw.cmd == 0x303 and osw.group:
            return dict(kind="busy", label="EMERGENCY BUSY QUEUED", tgid=osw.addr)
        return None                                      # not decoded standalone

    # -- two-OSW dispatch (osw2 = first/older, osw1 = second/newer) -----------
    def _two_osw(self, osw2, osw1):
        rx1 = is_chan(osw1.cmd, self.bandplan)
        if rx1 and not osw1.group and (osw1.addr & 0xff00) == 0x1f00:
            self.sysid = osw2.addr
            self.cc_freq_mhz = self._freq(osw1.cmd)
            return dict(kind="control_channel", label="CONTROL CHANNEL",
                        sysid=self.sysid, freq_mhz=self.cc_freq_mhz)
        if rx1 and osw1.group and osw1.addr and osw2.addr:
            return dict(kind="voice_grant", label="GROUP VOICE GRANT",
                        src=osw2.addr, tgid=osw1.addr, freq_mhz=self._freq(osw1.cmd))
        if rx1 and not osw1.group and osw1.addr and osw2.addr:
            return dict(kind="private_call", label="PRIVATE CALL",
                        src=osw1.addr, dst=osw2.addr, freq_mhz=self._freq(osw1.cmd))
        if rx1 and not osw1.group and osw1.addr and not osw2.addr:
            return dict(kind="interconnect", label="INTERCONNECT CALL",
                        src=osw1.addr, freq_mhz=self._freq(osw1.cmd))
        if osw1.cmd == 0x2f8:
            return dict(kind="idle", label="SYSTEM IDLE", src=osw2.addr)
        if osw1.cmd == 0x300 and osw1.group:
            return dict(kind="busy", label="GROUP BUSY QUEUED",
                        src=osw2.addr, tgid=osw1.addr)
        if osw1.cmd == 0x302 and not osw1.group:
            return dict(kind="busy", label="PRIVATE CALL BUSY QUEUED",
                        src=osw2.addr, dst=osw1.addr)
        if osw1.cmd == 0x303 and osw1.group:
            return dict(kind="busy", label="EMERGENCY BUSY QUEUED",
                        src=osw2.addr, tgid=osw1.addr)
        if osw1.cmd == 0x30a and not osw2.group and not osw1.group:
            return dict(kind="regroup", label="DYNAMIC REGROUP",
                        src=osw2.addr, tgid=osw1.addr)
        return dict(kind="unknown",
                    label=f"UNKNOWN OSW (0x{osw1.addr:04x},{'g' if osw1.group else 'i'},0x{osw1.cmd:03x})")

    # -- three-OSW dispatch: osw1.cmd == 0x30b, osw0 is the extra lookahead ---
    def _three_osw(self, osw2, osw1, osw0):
        if (osw1.group and not osw0.group and is_chan(osw0.cmd, self.bandplan)
                and (osw0.addr & 0xff00) == 0x1f00
                and (osw1.addr & 0xfc00) == 0x2800 and (osw1.addr & 0x3ff) == osw0.cmd):
            self.sysid = osw2.addr
            self.cc_freq_mhz = self._freq(osw0.cmd)
            return dict(kind="control_channel", label="CONTROL CHANNEL",
                        sysid=self.sysid, freq_mhz=self.cc_freq_mhz)
        # osw0 wasn't part of this message after all -- it belongs to the next
        # one, so put it back where _two_osw-style dispatch on (osw2, osw1) can
        # be tried, then it'll be re-examined as the head of the next message.
        self._q.appendleft(osw0)
        if (osw1.addr & 0xfc00) == 0x2800 and osw1.group:
            self.sysid = osw2.addr
            self.cc_freq_mhz = self._freq(osw1.addr & 0x3ff)
            return dict(kind="control_channel", label="CONTROL CHANNEL",
                        sysid=self.sysid, freq_mhz=self.cc_freq_mhz)
        if (osw1.addr & 0xfc00) == 0x2c00:
            return dict(kind="denied", label=f"DENIED ({_denial(osw1.addr)})",
                        src=osw2.addr, reason=_denial(osw1.addr))
        if osw1.group:
            return dict(kind="ext_func", label=f"GROUP EXTENDED FUNCTION 0x{osw1.addr:04x}",
                        tgid=osw2.addr)
        if osw1.addr == _RADIO_CHECK:
            return dict(kind="radio_check", label="RADIO CHECK", dst=osw2.addr)
        if osw1.addr == _DEAFFILIATION:
            return dict(kind="deaffiliation", label="DEAFFILIATION", src=osw2.addr)
        if 0x26e0 <= osw1.addr <= 0x26e7:
            return dict(kind="status_ack", label=f"STATUS ACK {(osw1.addr & 0x7) + 1}",
                        src=osw2.addr)
        if osw1.addr == _EMERGENCY_ACK:
            return dict(kind="emergency_ack", label="EMERGENCY ALARM ACK", src=osw2.addr)
        if 0x26f0 <= osw1.addr <= 0x26ff:
            return dict(kind="message_ack", label="MESSAGE ACK", src=osw2.addr)
        return dict(kind="ext_func", label=f"EXTENDED FUNCTION 0x{osw1.addr:04x}",
                    src=osw2.addr)

    def _try_consume(self):
        head = self._q[0]
        if head.cmd != 0x308:
            self._q.popleft()
            ev = self._one_osw(head)
            return ev if ev is not None else dict(
                kind="unknown",
                label=f"UNKNOWN OSW (0x{head.addr:04x},{'g' if head.group else 'i'},0x{head.cmd:03x})")
        if len(self._q) < 2:
            return _WAIT
        if self._q[1].cmd == 0x30b and len(self._q) < 3:
            return _WAIT
        osw2 = self._q.popleft()
        osw1 = self._q.popleft()
        if osw1.cmd == 0x30b:
            osw0 = self._q.popleft()
            return self._three_osw(osw2, osw1, osw0)
        return self._two_osw(osw2, osw1)
