#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""Tests for the digital module, in the real sdrexplorer window (offscreen) with the core checkout beside
this repo. No radio, no sound device; dsd-fme bridges are faked where a test needs a running one.

    QT_QPA_PLATFORM=offscreen python3 tests/test_digital.py
"""
import json
import os
import socket
import sys
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "src"))
sys.path.insert(0, os.path.join(os.path.dirname(REPO), "sdrexplorer"))

import numpy as np                                      # noqa: E402
from PyQt5 import QtCore, QtWidgets                     # noqa: E402

_QAPP = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
from sdrexplorer import paths as P                      # noqa: E402

_TMP = tempfile.mkdtemp(prefix="sdrexplorer-digital-test-")
P.override(_TMP, module_dirs=[REPO])
from sdrexplorer import app as A                        # noqa: E402
from sdrexplorer.api import proofs as api_proofs        # noqa: E402
from sdrexplorer.api.testing import use_fake_sources    # noqa: E402

from sdrexplorer_digital import branches as B           # noqa: E402
from sdrexplorer_digital import dsdfme as NB            # noqa: E402
from sdrexplorer_digital import dialogs as D            # noqa: E402
from sdrexplorer_digital import module as DM            # noqa: E402
from sdrexplorer_digital.monitor import (parse_lrrp, describe_data_frame,  # noqa: E402
                                         p25_algid_name, p25_algid_decryptable)

_REAL_START = A.ScannerRadio.start


def _stubs():
    use_fake_sources()
    A.ScannerRadio.start = lambda self: setattr(self, "running", True)
    _orig = A.ScannerRadio.__init__

    def _init(self, *a, **kw):
        kw["audio_out"] = False
        _orig(self, *a, **kw)
    A.ScannerRadio.__init__ = _init
    # never spawn dsd-fme from the window (tests that need a bridge fake it)
    B.DigitalBranches.bridge_available = lambda self: False
    DM.VOICE_PORT_OFFSET = 0


def _fresh_state(state=None):
    try:
        os.remove(A._state_path())
    except OSError:
        pass
    if state is not None:
        os.makedirs(os.path.dirname(A._state_path()), exist_ok=True)
        with open(A._state_path(), "w") as fh:
            json.dump(state, fh)


def _build():
    w = A.ScannerApp()
    w.resize(900, 700)
    return w


def _mod(win):
    return win.modules.get("digital")


class FakeBridge(QtCore.QObject):
    raw_line = QtCore.pyqtSignal(str)
    decoded = QtCore.pyqtSignal(dict)
    lock_changed = QtCore.pyqtSignal(bool)
    data = QtCore.pyqtSignal(str, str, bytes)
    position = QtCore.pyqtSignal(dict)

    def __init__(self, proto="NXDN", nxdn96=True, flags=None):
        super().__init__()
        self.proto, self.nxdn96, self.flags = proto, nxdn96, flags
        self.flushes, self._locked = 0, False
        self.relay_port, self.kind = 0, ""

    def flush(self):
        self.flushes += 1

    def force_unlock(self):
        self.flush()


def _fake_bridges(win):
    """Swap the module's dsd-fme start / stop for fakes; returns the list of bridges started."""
    br = _mod(win).br
    started = []

    def start(proto="NXDN"):
        if br.bridge is not None:
            return False
        br.bridge = FakeBridge(proto, br.nxdn96, list(br.edacs_flags) if proto == "EDACS" else None)
        started.append(br.bridge)
        return True

    def stop():
        br.bridge = None
    br.start_bridge, br.stop_bridge = start, stop
    return started


# ---------------------------------------------------------------------------------------------------------
def _udp_datagram(dport, payload, sport=50000, src=(12, 0, 0, 1), dst=(13, 0, 0, 2)):
    """Build a minimal IPv4/UDP datagram carrying ``payload`` (for tests)."""
    total = 20 + 8 + len(payload)
    ip = bytes([0x45, 0x00, total >> 8, total & 0xff, 0, 0, 0, 0, 0x40, 0x11,
                0, 0, *src, *dst])
    udp = bytes([sport >> 8, sport & 0xff, dport >> 8, dport & 0xff,
                 0x00, 8 + len(payload), 0x00, 0x00]) + payload
    return ip + udp


def test_lrrp_gate_rejects_junk_keeps_real():
    """The gate must reject ICMP, ARS, and bit-errored/truncated frames (no
    phantom coordinate) while still decoding a real UDP-wrapped LRRP position."""
    # 1. ICMP port-unreachable (proto 0x01) -> no location.
    icmp = bytes.fromhex(
        "45000047402f00008001b9610d0000020c00000103033e4b000000004501002b"
        "042d00004011356f0c0000010d0000020fa50fa50017d655000df02008313233"
        "34353637380000")
    assert parse_lrrp(icmp) is None
    assert "ICMP" in (describe_data_frame(icmp) or ""), describe_data_frame(icmp)

    # 2. bit-errored RATE-3/4 frame: parses as IPv4 but proto byte is 0x51.
    corrupt = bytes.fromhex(
        "45 01 00 2b 1e 5e a6 9d 28 51 35 65 0c 00 00 01"
        "07 d0 fa c0 0c 00 00 05 0d 00 00 02 00 0d f0 20"
        "7c 69 31 32 54 30 b3 36 38 00 00".replace(" ", ""))
    assert parse_lrrp(corrupt) is None, "corrupt non-UDP frame must not decode"

    # 3. truncated frame that starts mid-IP-header (first byte 0x0d, not 0x4x).
    truncated = bytes.fromhex("0d0000020c00000103033e4b00000000" + "45" * 40)
    assert parse_lrrp(truncated) is None, "non-IPv4 buffer must not decode"

    # 4. clean ARS registration (UDP 4005): not a location, labeled as ARS.
    ars_body = bytes.fromhex("000df020083132333435363738 0000".replace(" ", ""))
    ars = _udp_datagram(4005, ars_body)
    assert parse_lrrp(ars) is None, "ARS (4005) must not yield a location"
    assert describe_data_frame(ars) == "ARS registration RID 12345678", \
        describe_data_frame(ars)

    # 5. a real LRRP position on the LRRP port (4001) still decodes.
    pt = bytes([0x66, 0x3B, 0xBB, 0xBB, 0xBC, 0xCD, 0x82, 0xD3, 0x8E])  # ~(42,-71)
    lrrp = _udp_datagram(4001, pt)
    got = parse_lrrp(lrrp)
    assert got is not None and abs(got["lat"] - 42.0) < 0.01 \
        and abs(got["lon"] + 71.0) < 0.01, got
    print("ok  test_lrrp_gate_rejects_junk_keeps_real")


def test_p25_algid_names():
    """P25 ALGIDs map to human names, and decryptability matches op25's support
    (ADP + DES only; AES is labeled but not decryptable in this build)."""
    assert p25_algid_name(0x84) == "AES-256"
    assert p25_algid_name(0xaa) == "ADP (RC4-40)"
    assert p25_algid_name(0x81) == "DES-OFB"
    assert p25_algid_name(0x80) == "clear"
    assert p25_algid_name(0x77) is None          # unknown -> caller shows raw hex
    assert p25_algid_decryptable(0xaa) and p25_algid_decryptable(0x81)
    assert not p25_algid_decryptable(0x84)       # AES not supported here
    print("ok  test_p25_algid_names")


def test_smartnet_bandplan_freq():
    """Ported band-plan channel->frequency math (op25 tk_smartnet.py get_freq/
    is_chan) for the plans that matter: standard domestic, rebanded, and 900."""
    from sdrexplorer_digital import smartnet as SN
    assert SN.get_freq(0x100) == 857.4125            # 800_domestic (default)
    assert SN.get_freq(0x100, "800_rebanded") == 857.4125
    assert SN.get_freq(0x1b8, "800_rebanded") == 851.025          # rebanded upper break
    assert SN.get_freq(0x1de, "900") == 940.9875
    assert SN.get_freq(0x2d0) == 866.0000             # shared upper-channel range
    assert SN.get_freq(-1) is None and not SN.is_chan(-1)
    assert SN.get_freq(0x1de + 1, "900") is None      # past the 900 MHz band -> invalid
    print("ok  test_smartnet_bandplan_freq")


def test_smartnet_osw_tracker():
    """OswTracker correlates 1-3 OSW SmartNet control-channel messages into
    named events: control-channel ID, group voice grant, and a denial code —
    ported from op25's tk_smartnet.py process_osws (standard/non-OBT path)."""
    from sdrexplorer_digital import smartnet as SN
    t = SN.OswTracker()                               # default 800_domestic

    # 2-OSW system ID + control-channel broadcast
    assert t.feed(0x1234, 0, 0x308) == []              # buffered, waiting on osw1
    evs = t.feed(0x1f05, 0, 0x100)
    assert len(evs) == 1 and evs[0]["kind"] == "control_channel"
    assert evs[0]["sysid"] == 0x1234 and evs[0]["freq_mhz"] == SN.get_freq(0x100)
    assert t.sysid == 0x1234

    # 2-OSW group voice grant: osw2=src, osw1=(tgid, group=1, channel)
    assert t.feed(12345, 0, 0x308) == []
    evs = t.feed(4001, 1, 0x102)
    assert len(evs) == 1
    g = evs[0]
    assert g["kind"] == "voice_grant" and g["src"] == 12345 and g["tgid"] == 4001
    assert g["freq_mhz"] == SN.get_freq(0x102)

    # 3-OSW denial: osw2=src, osw1=(0x2c04 -> invalid talkgroup, cmd 0x30b), osw0=filler
    assert t.feed(999, 0, 0x308) == []
    assert t.feed(0x2c04, 0, 0x30b) == []              # needs one more OSW lookahead
    evs = t.feed(0, 0, 0x000)
    kinds = [e["kind"] for e in evs]
    assert "denied" in kinds, evs
    deny = next(e for e in evs if e["kind"] == "denied")
    assert deny["src"] == 999 and deny["reason"] == "invalid talkgroup"

    # a bad-OSW reset mid-sequence drops partial state instead of misparsing
    t.feed(1, 0, 0x308)                                 # start a 2-OSW sequence...
    t.reset()                                           # ...but it's abandoned
    assert list(t._q) == []
    print("ok  test_smartnet_osw_tracker")


class _FakeMsg:
    """Stand-in for a gr.message: op25's real msgq messages expose .type()/
    .to_string()/.arg1()/.arg2() — enough surface for DigitalMonitor._handle."""
    def __init__(self, proto, m_type, body=b""):
        self._type = ((proto & 0xffff) << 16) | (m_type & 0xffff)
        self._body = body

    def type(self):
        return self._type

    def to_string(self):
        return self._body

    def arg1(self):
        return 0

    def arg2(self):
        return 0.0


def test_smartnet_digital_monitor_emits():
    """DigitalMonitor dispatches SmartNet (protocol id 2) frames to the OSW
    tracker and emits a Qt 'decoded' signal per correlated event, with
    lock_changed(True) on a good OSW and (False) + a tracker reset on
    control-channel timeout — mirrors the P25/DMR handlers' signal wiring."""
    from sdrexplorer_digital.monitor import DigitalMonitor
    mon = DigitalMonitor(None)
    mon.set_smartnet_bandplan("900")
    assert mon._sn.bandplan == "900"
    mon.set_smartnet_bandplan("800_domestic")   # back to default for the rest of this test
    locks, decoded = [], []
    mon.lock_changed.connect(lambda v: locks.append(v))
    mon.decoded.connect(lambda d: decoded.append(d))

    def osw(addr, group, cmd):
        body = bytes([(addr >> 8) & 0xff, addr & 0xff, group & 0xff,
                      (cmd >> 8) & 0xff, cmd & 0xff])
        mon._handle(_FakeMsg(2, 0, body))

    osw(0x1234, 0, 0x308)
    osw(0x1f05, 0, 0x100)                    # completes a control-channel ID event
    assert locks == [True, True]
    assert len(decoded) == 1
    d = decoded[0]
    assert d["proto"] == "SmartNet" and d["kind"] == "control_channel"
    assert d["sysid"] == 0x1234 and "raw" in d

    mon._handle(_FakeMsg(2, -1, b""))         # M_SMARTNET_TIMEOUT
    assert locks[-1] is False
    assert list(mon._sn._q) == [], "timeout must drop partial OSW correlation"
    print("ok  test_smartnet_digital_monitor_emits")


def test_dmr_csbk_grant_lcn_freq():
    """A MotoTRBO Connect/Capacity Plus channel-grant CSBK (csbko=0x03,
    fid=0x06) decodes src/tgid/lcn/tslot from the raw CSBK body (dmr_slot.cc
    decode_csbk's own field layout: 10 bytes of packed CSBK bits + our local
    op25 build's 1 trailing color-code byte), and resolves to freq_mhz only
    once that LCN is in the user's bandplan table (set_dmr_bandplan). A short
    9-byte body (no CC, e.g. an unpatched op25) must still decode everything
    else and simply omit "cc"."""
    from sdrexplorer_digital.monitor import DigitalMonitor, _PROTO_DMR, _M_DMR_CSBK
    mon = DigitalMonitor(None)
    decoded = []
    mon.decoded.connect(lambda d: decoded.append(d))

    lcn, tslot = 7, 1
    body = bytes([
        0x03,                                   # LB=0,PF=0,CSBKO=0x03
        0x06,                                   # FID=0x06 (MotoTRBO)
        0x11, 0x12, 0x13,                       # src
        0x44, 0x55, 0x66,                       # tgid
        (lcn << 4) | (tslot << 3),              # bits64-67=LCN, bit68=tslot
        0x00,
        0x09,                                   # color code (trailing byte)
    ])
    mon._handle(_FakeMsg(_PROTO_DMR, _M_DMR_CSBK, body))
    assert len(decoded) == 1
    d = decoded[0]
    assert d["csbko"] == 0x03 and d["fid"] == 0x06
    assert d["src"] == 0x111213 and d["tgid"] == 0x445566
    assert d["lcn"] == lcn and d["tslot"] == tslot
    assert d["cc"] == 9
    assert "freq_mhz" not in d, "no bandplan entry yet -> no frequency"

    mon.set_dmr_bandplan({lcn: 451_637_500.0})   # 451.6375 MHz, in Hz
    mon._handle(_FakeMsg(_PROTO_DMR, _M_DMR_CSBK, body))
    assert abs(decoded[1]["freq_mhz"] - 451.6375) < 1e-9

    mon._handle(_FakeMsg(_PROTO_DMR, _M_DMR_CSBK, body[:9]))   # no CC byte
    assert "cc" not in decoded[2]
    print("ok  test_dmr_csbk_grant_lcn_freq")


def test_dmr_embedded_lc_yields_tgid():
    """Embedded LC (SLOT_ELC, m_type 7) repeats every voice superframe during
    a call -- unlike the Voice/Terminator LC Header, which only appears once
    at call start/end -- so it must decode tgid/src/call the same way VLC/TLC
    do (same d_lc[0:9] byte layout, just without the 3 trailing RS parity
    bytes the 12-byte VLC/TLC buffer carries, plus our local op25 build's 1
    trailing color-code byte at a different offset than VLC/TLC's since ELC
    has no parity bytes to push it out). This is what lets late tune-ins
    still show a talkgroup instead of just CACH_SLC."""
    from sdrexplorer_digital.monitor import DigitalMonitor, _PROTO_DMR, _M_DMR_ELC
    mon = DigitalMonitor(None)
    decoded = []
    mon.decoded.connect(lambda d: decoded.append(d))

    body = bytes([
        0x00,                     # PF=0, FLCO=0x00 (Group Call)
        0x00,                     # FID
        0x00,                     # SVCOPT
        0x44, 0x55, 0x66,         # dstaddr (tgid)
        0x11, 0x12, 0x13,         # srcaddr
        0x05,                     # color code (trailing byte)
    ])
    mon._handle(_FakeMsg(_PROTO_DMR, _M_DMR_ELC, body))
    assert len(decoded) == 1
    d = decoded[0]
    assert d["label"] == "SLOT_ELC"
    assert d["call"] == "Group Call"
    assert d["tgid"] == 0x445566 and d["src"] == 0x111213
    assert d["cc"] == 5

    mon._handle(_FakeMsg(_PROTO_DMR, _M_DMR_ELC, body[:9]))   # no CC byte
    assert "cc" not in decoded[1]
    print("ok  test_dmr_embedded_lc_yields_tgid")


def test_dmr_cach_slc_cc():
    """CACH_SLC (m_type 0) is the only DMR frame that decodes even when the
    voice slot itself never syncs (it rides the CACH between slots), so it's
    often the ONLY thing a marginal-signal DMR receive shows. Our local op25
    build appends the color code op25 already tracks per-slot (dmr_slot's
    d_cc, exposed via the new get_cc()) as CACH_SLC's 5th byte -- previously
    CC was invisible to sdrexplorer even on a clean decode."""
    from sdrexplorer_digital.monitor import DigitalMonitor, _PROTO_DMR, _M_DMR_CACH_SLC
    mon = DigitalMonitor(None)
    decoded = []
    mon.decoded.connect(lambda d: decoded.append(d))

    body = bytes([0x00, 0x00, 0x00, 0x00, 0x03])   # slco/d0/d1/d2 + CC=3
    mon._handle(_FakeMsg(_PROTO_DMR, _M_DMR_CACH_SLC, body))
    assert len(decoded) == 1
    d = decoded[0]
    assert d["label"] == "CACH_SLC"
    assert d["cc"] == 3

    mon._handle(_FakeMsg(_PROTO_DMR, _M_DMR_CACH_SLC, body[:4]))   # no CC byte
    assert "cc" not in decoded[1]
    print("ok  test_dmr_cach_slc_cc")


# dsd-fme -fn -Z output in the shape of two units' GPS data calls (made-up units, positions and payload bytes)
_NXDN_GPS_DSD = """\
12:25:36 Sync: NXDN96  RDCH Data   F2U-Ve: 2.5;  RAN 05  UDCH DCALL_HEADER
 Data Call Header (029400) Source: 1001; Target: 250; Group Call 9600bps Half Duplex
 Blocks: 2; Padding: 18; TX Frag: 0; Starting Fragment;
 UDCH Payload
  [0D][09][00][00][00][00][00][FA][00][02][94][00][00]
  [00][00][00][00][00][00][00][00][00][00][00][00][00]
12:25:36 Sync: NXDN96  RDCH Data   F2U-Ve: 2.5;  RAN 05  UDCH DCALL_DATA
 Data Call (2/2); Type: 1; Byte Len: 20; Pad: 18; Total: 042; Ptr: 0000;
 UDCH Payload
  [0D][0B][22][00][00][00][00][00][00][00][00][00][00]
  [00][00][00][00][00][00][00][00][00][00][00][00][00]
12:25:36 Sync: NXDN96  RDCH Data   F2U-Ve: 1.5;  RAN 05  UDCH DCALL_DATA
 Data Call (0/0); Type: 1; Byte Len: 20; Pad: 18; Total: 042; Ptr: 0320;
 DATA: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000
  REV: 000000000000000000000000000000000000000000000000000000000000000000000000
 \x1b[33mGPS: (42.360000°, -71.060000°) Speed: 10.500000 k/h; COG: 260.900000; Elevation: 15; Date: 2026/01/01 Time: 12:00 \x1b[0m
 UDCH Payload
  [0D][0B][00][00][00][00][00][00][00][00][00][00][00]
12:25:36 Sync: NXDN96  RDCH Data   F2U-Ve: 2.5;  RAN 05  UDCH DCALL_HEADER
 Data Call Header (029400) Source: 1002; Target: 250; Group Call 9600bps Half Duplex
12:25:36 Sync: NXDN96  RDCH Data   F2U-Ve: 1.5;  RAN 05  UDCH DCALL_DATA
 Data Call (0/0); Type: 1; Byte Len: 20; Pad: 18; Total: 042; Ptr: 0320;
 GPS: (42.350000°, -71.100000°) Speed: 16.500000 k/h; COG: 339.800000; Elevation: 30; Date: 2026/01/01 Time: 12:00
 GPS: (0.000000°, 0.000000°) Speed: 0.000000 k/h; COG: 0.000000; Elevation: 0; Date: 2026/01/01 Time: 12:00
"""



# dsd-fme -fn lines. The PF X/4 one is noise: dsd-fme reprints the last good RAN on a
# SACCH whose CRC failed and marks it only with "PF X/" (seen live on channels with no NXDN).
_NXDN_LINES_OK = ["00:17:56 Sync: NXDN96  RCCH Data   RAN 01  CAC SRV_INFO",
                  "00:17:57 Sync: NXDN96  RDCH Data   F2U-Ve: 6.9;  RAN 05  FACCH2 IDLE"]
_NXDN_LINES_NOISE = ["23:15:11 Sync: NXDN96  RTCH V1+F2  S-Ve: 6.0;  RAN 30 PF X/4",
                     "23:15:16 Sync: NXDN96  RTCH Data   S-Ve: 5.0;  RAN 30 PF X/1 IDLE",
                     "23:15:19 Sync: NXDN96  RCCH Data   C-Ve: 32.0;  RAN 30  CAC (CRC ERR)"]


# dsd-fme -fe lines from an EDACS control channel (made-up site, groups and units).
_EDACS_LINES_OK = [
    "17:52:43 Sync: +EDACS  MSG_1 [FD60342] MSG_2 [FD60342] (MT1: 1F; MT2: A)  Extended Addressing :: "
    "Site ID [03][003] Area [04][004]",
    "17:52:44 Sync: +EDACS  MSG_1 [FC00000] MSG_2 [600C0A5] (MT1: 1F; MT2: 8)  System Information :: "
    "System ID [0000] CC LCN [10]",
    "17:52:43 Sync: -EDACS  MSG_1 [1970064] MSG_2 [1A0002A] (MT1: 03)          Digital Group Call Update :: "
    "Group [00100] Source [00000042] LCN [11]"]
_EDACS_LINES_NOISE = ["17:52:43 Sync: +EDACS  BCH FAIL ", "Sync: no sync",
                      "00:17:56 Sync: NXDN96  RCCH Data   RAN 01  CAC SRV_INFO"]


# ---------------------------------------------------------------------------------------------------------
def test_loads_into_the_app():
    """The module loads beside the core: its Digital tab, Settings entries, TX modes, decodable labels, path
    keys and proofs; the core itself names none of it."""
    _fresh_state()
    win = _build()
    try:
        m = _mod(win)
        assert m is not None, [f.name for f in win.modules.found]
        tabs = [win.module_tabs.tabText(i) for i in range(win.module_tabs.count())]
        assert "Digital" in tabs, tabs
        texts = [a.text() for a in win._module_actions]
        assert {"Smart&Net bandplan…", "&DMR bandplan (LCN)…", "&EDACS…"} <= set(texts), texts
        for label in ("P25-P1", "P25", "DMR", "NXDN96", "NXDN48", "EDACS", "SmartNet"):
            assert label in win.decodable_labels(), label
        txs = [win.tx_mode_combo.itemText(i) for i in range(win.tx_mode_combo.count())]
        assert "P25" in txs and "DMR" in txs, txs
        assert {"op25", "op25_apps", "dsd_fme"} <= set(P.KEYS)
        for label in ("DMR", "P25-P1", "NXDN48", "NXDN96", "EDACS", "EDACS-V", "SmartNet"):
            assert api_proofs.get(label) is not None, label
        from sdrexplorer import recindex
        assert recindex.DISPLAY.get("P25-P1") == "P25"
    finally:
        win.close()
    print("ok  test_loads_into_the_app")


def test_request_decode_follows_variant_and_scan_modes():
    """A labeling module's request_decode picks the decoder: NXDN48 <-> NXDN96 restarts dsd-fme on the
    other variant (it used to keep the old one), DMR stops it, a bank channel / scan hit's mode goes the same
    way, and a retune drops the PCM queued for dsd-fme from the old channel. dsd-fme's lines reach the
    core's decode log through the bridge the module connected."""
    _fresh_state({"modules": {"digital": {"mode": "NXDN", "nxdn96": True}}})
    win = _build()
    m = _mod(win)
    started = _fake_bridges(win)
    try:
        br = m.br
        m._set_mode("NXDN", True)
        assert br.bridge is not None and m._bridge_ref is br.bridge
        win.radio.band_center_hz = 470_000_000
        win.spectrum.reset_view()
        labels = {470_300_000: "NXDN96", 470_500_000: "NXDN48"}
        for hz, want96 in ((470_500_000, False), (470_300_000, True), (470_500_000, False)):
            win._on_spectrum_click(hz)
            assert win.request_decode(labels[hz], hz)
            b = br.bridge
            assert b is not None and b.nxdn96 is want96, (hz, b and b.nxdn96)
            assert m._bridge_ref is b
            assert m._w["status"].text().startswith("NXDN96" if want96 else "NXDN48")
            assert m._w["mode"].currentText() == ("NXDN96" if want96 else "NXDN48")
        br.bridge.raw_line.emit("Sync: NXDN48 RAN 02 test-line")
        assert "test-line" in win.dig_log.toPlainText()
        br.bridge.lock_changed.emit(True)                                  # dsd-fme locked...
        assert m._locks["dsd"] and win.audio.claimed("digital")
        m._set_mode("DMR")                                                 # ...then its bridge stops
        assert not m._locks["dsd"]                                         # (it never says "lost")
        assert br.bridge.proto == "DMR"                     # DMR runs its own dsd-fme, the MS / DM detector
        m._set_mode("NXDN", False)
        win._on_spectrum_click(470_700_000)
        assert win.request_decode("DMR", 470_700_000)
        assert br.bridge.proto == "DMR" and m._bridge_ref is br.bridge and m._w["mode"].currentText() == "DMR"
        win._apply_channel_mode("NXDN96")                                # scan hit / bank row
        assert br.bridge is not None and m._bridge_ref is br.bridge
        br.bridge.raw_line.emit("Sync: NXDN96 RAN 05 scan-line")
        assert "scan-line" in win.dig_log.toPlainText()
        win._apply_channel_mode("DMR")
        assert br.bridge.proto == "DMR"
        win._apply_channel_mode("DMR-MS")                               # a channel saved as DMR-MS
        assert m.mode == "DMR-MS" and br.bridge.proto == "DMR" and m._w["mode"].currentText() == "DMR-MS"
        win._apply_channel_mode("NXDN96")
        b, f0 = br.bridge, br.bridge.flushes
        win._on_spectrum_click(470_300_000)                              # retune: old PCM dropped
        win.radio.set_frequency(455_000_000)
        assert b.flushes >= f0 + 2, b.flushes
        # a scan sweeping doesn't take a label from another module
        win._scanning = True
        try:
            assert not win.request_decode("DMR", 470_700_000, {"source": "classifier"})
        finally:
            win._scanning = False
    finally:
        win.close()

    # lock rule on real dsd-fme lines; buffered reads; ~2 s of PCM at most
    assert all(NB._valid_sync_line(l) for l in _NXDN_LINES_OK)
    assert not any(NB._valid_sync_line(l) for l in _NXDN_LINES_NOISE)
    assert NB._STDOUT_BUFSIZE >= 4096
    assert NB._QUEUE_MAX * NB._READ_CHUNK <= 2.5 * NB._PCM_BYTES_PER_S
    assert NB._PCM_BYTES_PER_S == 2 * B.AUDIO_RATE
    b = NB.NxdnBridge(os.path.join(_TMP, "unused.fifo"))
    for _ in range(5):
        b._enqueue(b"x" * NB._READ_CHUNK)
    b.flush()
    assert b._q.qsize() == 0
    b._q.put(None); b.flush()
    assert b._q.get_nowait() is None                                     # stop() sentinel kept
    print("ok  test_request_decode_follows_variant_and_scan_modes")


def test_lock_claims_the_speaker():
    """A decoder lock claims the core's speaker (analog muted, the meter shows the protocol / NAC) and lets
    voice through; a lost lock keeps the claim for the hang time; leaving the channel ends it at once;
    Digital only keeps analog off; a scan sweep silences the voice input."""
    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        m._on_lock(True)
        assert win.audio.claimed("digital") and m._w["lock"].text().startswith("● LOCK")
        assert m.voice is None or m.voice.allow
        m._on_decoded({"proto": "P25", "nac": 0x293, "duid": "LDU1"})
        assert win.audio.label() == "P25 NAC 293", win.audio.label()
        win._update_signal()
        assert win.radio._gate_open is False and "P25 NAC 293" in win.sig_label.text()
        m._on_decoded({"proto": "SmartNet", "kind": "control_channel", "sysid": 0x0D14, "label": "CONTROL CHANNEL"})
        assert win.audio.label() == "SmartNet", win.audio.label()      # the protocol that decoded
        m._on_lock(False)
        assert win.audio.claimed("digital") and m._hang.isActive()        # hang time
        m._on_lock(True)
        assert not m._hang.isActive()
        win._on_spectrum_click(win.radio.band_center_hz + 150_000)        # left the channel
        assert not win.audio.claimed("digital") and m._w["lock"].text() == "● no lock"
        # a lock that is never reported lost (one late frame after a retune) runs out on its own, and so
        # does one op25 keeps reporting lost every second (each report must not restart the hang)
        DM.STALE_MS, DM.HANG_MS = 200, 300
        try:
            m._on_lock(True)
            t0 = time.time()
            while win.audio.claimed("digital") and time.time() - t0 < 2:
                _QAPP.processEvents(); time.sleep(0.02)
            assert not win.audio.claimed("digital"), "a stale lock must end"
            m._on_lock(True)
            m._on_lock(False)
            t0 = time.time()
            while win.audio.claimed("digital") and time.time() - t0 < 2:
                m._on_lock(False)                                          # "lost" again and again
                for _ in range(5):
                    _QAPP.processEvents(); time.sleep(0.02)
            assert not win.audio.claimed("digital"), "repeated losses must not hold the claim"
            # op25's repeated "no sync" doesn't end a lock dsd-fme holds (NXDN on a channel op25 can't read)
            m._set_lock("dsd", True)
            for _ in range(5):
                m._on_lock(False)
                for _ in range(5):
                    _QAPP.processEvents(); time.sleep(0.02)
            assert win.audio.claimed("digital"), "dsd-fme's lock must hold through op25's losses"
            m._set_lock("dsd", False)
            t0 = time.time()
            while win.audio.claimed("digital") and time.time() - t0 < 2:   # then the hang runs out
                _QAPP.processEvents(); time.sleep(0.02)
            assert not win.audio.claimed("digital")
        finally:
            DM.STALE_MS, DM.HANG_MS = 3000, 2000
        m._w["only"].setChecked(True)
        assert win.audio.analog_off and not win.audio.analog_allowed()
        m._w["only"].setChecked(False)
        assert win.audio.analog_allowed()
        win._scan_state("sweep")
        assert win.radio._inputs_muted
        win._scan_state("idle")
    finally:
        win.close()
    print("ok  test_lock_claims_the_speaker")


def test_voice_reaches_the_speaker():
    """Decoded voice (op25 / dsd-fme UDP frames, 8 kHz s16) is written into the core's audio input, x4 and
    clipped, only while allowed (a lock); op25's drop flag empties what's queued."""
    from sdrexplorer.api import AudioArbiter
    from sdrexplorer_digital.voice import VoiceReceiver, GAIN
    arb = AudioArbiter()
    ain = arb.open_input("digital", 8000)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    v = VoiceReceiver(ain, port)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        frame = np.full(160, 1000, np.int16).tobytes()                    # 320 bytes, one op25 frame
        tx.sendto(frame, ("127.0.0.1", port))
        time.sleep(0.3)
        assert v.frames == 0 and ain.buffered_s() == 0                    # no lock: dropped
        v.allow = True
        for _ in range(3):
            tx.sendto(frame, ("127.0.0.1", port))
        t0 = time.time()
        while v.frames < 3 and time.time() - t0 < 2:
            time.sleep(0.02)
        assert v.frames == 3 and abs(ain.buffered_s() - 3 * 160 / 8000) < 1e-6
        out = ain.read(160)
        assert abs(out.mean() - GAIN * 1000 / 32768) < 1e-4, out.mean()
        tx.sendto(np.array([1], np.int16).tobytes(), ("127.0.0.1", port))   # op25: drop
        time.sleep(0.3)
        assert ain.buffered_s() == 0
    finally:
        tx.close()
        v.stop()
    print("ok  test_voice_reaches_the_speaker")


def test_voice_prefers_one_decoder():
    """Two decoders on one DMR call (op25 and dsd-fme): VoiceReceiver.prefer plays one sender's voice only,
    and the other's drain / drop flag doesn't touch it."""
    from sdrexplorer.api import AudioArbiter
    from sdrexplorer_digital.voice import VoiceReceiver
    arb = AudioArbiter()
    ain = arb.open_input("digital", 8000)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    v = VoiceReceiver(ain, port)
    a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a.bind(("127.0.0.1", 0))
    b.bind(("127.0.0.1", 0))
    frame = np.full(160, 1000, np.int16).tobytes()

    def send(sock, data, n=1):
        for _ in range(n):
            sock.sendto(data, ("127.0.0.1", port))
        time.sleep(0.3)
    try:
        v.allow = True
        v.prefer = ("only", a.getsockname()[1])
        send(a, frame, 2)
        send(b, frame, 3)
        assert v.frames == 2, v.frames
        send(b, np.array([1], np.int16).tobytes())          # the other decoder's drop: ignored
        assert ain.buffered_s() > 0
        v.prefer = ("not", a.getsockname()[1])
        send(a, frame, 2)
        send(b, frame, 1)
        assert v.frames == 3, v.frames
        v.prefer = None
        send(a, frame)
        assert v.frames == 4
    finally:
        a.close()
        b.close()
        v.stop()
    print("ok  test_voice_prefers_one_decoder")


# dsd-fme -fs output for a made-up DMR call (ids are not real), mobile-station then base-station bursts
_DMR_MS_DSD = (
    "12:00:00 Sync: +DMR MS/DM MODE/MONO | Color Code=XX | VLC\n"
    "12:00:00 Sync: +DMR MS/DM MODE/MONO | Color Code=06 | VLC\n"
    "12:00:00 Sync: +DMR MS/DM MODE/MONO | Color Code=06 | VC1\n"
    " SLOT 1 TGT=3125 SRC=1234567 FLCO=0x00 FID=0x00 SVC=0x00 Group Call\n")
_DMR_BS_DSD = (
    "12:00:05 Sync: +DMR  [SLOT1]  slot2  | Color Code=06 | VC2\n"
    "12:00:05 Sync: +DMR   slot1  [slot2] | CACH/Burst FEC ERR\n"
    "12:00:05 Sync: +DMR  [SLOT1]  slot2  | Color Code=06 | VC3\n"
    " SLOT 1 TGT=8 SRC=1234567 FLCO=0x00 FID=0x00 SVC=0x00 Group Call\n")


def test_dmr_mobile_station_handed_to_dsd_fme():
    """DMR through dsd-fme: a clean sync line (a color code, no error) counts for the lock and says the burst
    kind (base station / mobile-station or direct mode), link control lines parse, stereo voice mixes to mono.
    On DMR, mobile-station bursts hand the call to dsd-fme (its voice, its log line, with the callsign
    lookup); base-station bursts leave it to op25 (no second log line, op25's voice). DMR-MS always uses
    dsd-fme."""
    import io
    import types as _types
    assert NB._dmr_valid_line("Sync: +DMR MS/DM MODE/MONO | Color Code=06 | VC1")
    assert not NB._dmr_valid_line("Sync: +DMR MS/DM MODE/MONO | Color Code=XX | VLC")
    assert not NB._dmr_valid_line("Sync: +DMR   slot1  [slot2] | CACH/Burst FEC ERR")
    d = NB._parse_dmr_line(" SLOT 1 TGT=3125 SRC=1234567 FLCO=0x00 FID=0x00 SVC=0x00 Group Call")
    assert d == {"proto": "DMR", "slot": 1, "tgid": 3125, "src": 1234567, "call": "Group Call",
                 "raw_text": " SLOT 1 TGT=3125 SRC=1234567 FLCO=0x00 FID=0x00 SVC=0x00 Group Call"}, d
    b = NB.DmrBridge(os.path.join(_TMP, "unused_dmr.fifo"))
    assert b._decoder_flags() == ["-fs"]
    st = np.array([100, 300, -200, -400], np.int16).tobytes()             # two stereo frames
    assert np.frombuffer(b._voice_pcm(st), np.int16).tolist() == [200, -300]
    kinds, locks, dec = [], [], []
    b.kind_changed.connect(kinds.append, QtCore.Qt.DirectConnection)
    b.lock_changed.connect(locks.append, QtCore.Qt.DirectConnection)
    b.decoded.connect(dec.append, QtCore.Qt.DirectConnection)
    b._proc = _types.SimpleNamespace(stdout=io.BytesIO(_DMR_MS_DSD.encode()))
    b._pump_stdout()
    assert locks == [True] and kinds == ["MS"] and b.cc == 6, (locks, kinds)
    assert dec and dec[-1]["tgid"] == 3125 and dec[-1]["kind"] == "MS" and dec[-1]["cc"] == 6, dec
    b._proc = _types.SimpleNamespace(stdout=io.BytesIO(_DMR_BS_DSD.encode()))
    b._pump_stdout()
    assert kinds == ["MS", "BS"], kinds
    b._proc = None

    _fresh_state()
    win = _build()
    m = _mod(win)
    _fake_bridges(win)
    try:
        if m.voice is None:
            print("ok  test_dmr_mobile_station_handed_to_dsd_fme (no voice port here: module part skipped)")
            return
        m._dmr_id_cache.update({"1234567": {"callsign": "TEST1"}})
        # the picker follows what op25 decodes between P25 and DMR (DMR is what runs the MS / DM detector)
        m._set_mode("P25")
        m._on_decoded({"proto": "DMR", "label": "SLOT_PI", "raw": b""})        # no content: stays
        assert m.mode == "P25"
        m._on_decoded({"proto": "DMR", "label": "SLOT_VLC", "cc": 6, "tgid": 9, "src": 1234567, "raw": b""})
        assert m.mode == "DMR" and m.br.bridge.proto == "DMR" and m._w["mode"].currentText() == "DMR"
        m._on_decoded({"proto": "P25", "nac": 0x123, "duid": "HDU", "raw": b"\x01\x23"})
        assert m.mode == "P25" and m.br.bridge is None
        m._set_mode("DMR-MS")                                   # the override isn't pulled back
        m._on_decoded({"proto": "DMR", "label": "SLOT_VLC", "cc": 6, "tgid": 9, "src": 1234567, "raw": b""})
        assert m.mode == "DMR-MS"
        m._set_mode("DMR")
        fake = m.br.bridge
        b2 = NB.DmrBridge(os.path.join(_TMP, "unused_dmr2.fifo"))
        m.br.bridge = b2                                          # the real bridge class, not started
        m._sync_bridge()
        port = b2.relay_port
        assert m.voice.prefer == ("not", port)                    # base station / nothing yet: op25's voice
        b2.kind_changed.emit("MS")
        assert m.voice.prefer == ("only", port) and "dsd-fme" in m._w["status"].text()
        b2.decoded.emit({"proto": "DMR", "slot": 1, "tgid": 3125, "src": 1234567, "call": "Group Call",
                         "cc": 6, "kind": "MS"})
        line = [l for l in win._dig_lines if "TG 3125" in l]
        assert line and "DMR  MS  CC 6  Group Call  TG 3125  SRC 1234567 (TEST1)" in line[-1], win._dig_lines
        m._dmr_id_cache["1234567"] = {"callsign": "TEST2"}       # a lookup that changes the text: no 2nd line
        b2.decoded.emit({"proto": "DMR", "slot": 1, "tgid": 3125, "src": 1234567, "call": "Group Call",
                         "cc": 6, "kind": "MS"})
        assert len([l for l in win._dig_lines if "TG 3125" in l]) == 1, win._dig_lines
        b2.kind_changed.emit("BS")
        assert m.voice.prefer == ("not", port)
        n = len(win._dig_lines)
        b2.decoded.emit({"proto": "DMR", "slot": 1, "tgid": 8, "src": 1234567, "call": "Group Call",
                         "cc": 6, "kind": "BS"})
        assert len(win._dig_lines) == n                           # op25 logs base-station calls
        m.mode = "DMR-MS"                                         # (the picker's DMR-MS, bridge kept)
        m._apply_voice_pref()
        assert m.voice.prefer == ("only", port)
        b2.decoded.emit({"proto": "DMR", "slot": 1, "tgid": 8, "src": 1234567, "call": "Group Call",
                         "cc": 6, "kind": "BS"})
        assert [l for l in win._dig_lines if "DMR  BS  CC 6  Group Call  TG 8" in l], win._dig_lines
        m.br.bridge = fake
    finally:
        win.close()
    print("ok  test_dmr_mobile_station_handed_to_dsd_fme")


def test_edacs_decode_wired():
    """EDACS: picked by request_decode("EDACS"), one dsd-fme at a time (NXDN <-> EDACS swaps the bridge),
    its lines reach the decode log with an LCN's frequency from Settings > EDACS and count for the
    recording label with the site id, the settings become dsd-fme flags (variant, AFS, -C channel map)
    and a running bridge restarts on a change. Old top-level settings are taken over once."""
    _fresh_state({"digital_mode": "P25", "edacs": {"variant": "EA", "lcns": [{"lcn": 11, "freq_mhz": 851.0125}]}})
    win = _build()
    m = _mod(win)
    started = _fake_bridges(win)
    try:
        br = m.br
        assert br.bridge is None and m.edacs["lcns"][0]["lcn"] == 11      # taken over from the old keys
        assert br.edacs_flags[0] == "-fe" and "-C" in br.edacs_flags       # LCN table -> dsd-fme -C
        csv = br.edacs_flags[br.edacs_flags.index("-C") + 1]
        assert open(csv).read().splitlines()[1] == "11,851012500"
        win.radio.band_center_hz = 854_000_000
        win.spectrum.reset_view()
        win._on_spectrum_click(853_725_000)
        win._rec_labels = A.RecordingLabels(853_725_000)
        assert win.request_decode("EDACS", 851_500_000)
        b = br.bridge
        assert m._w["mode"].currentText() == "EDACS" and b is not None and b.proto == "EDACS"
        assert m._bridge_ref is b and m._w["status"].text().startswith("EDACS")
        for _ in range(3):
            for l in _EDACS_LINES_OK + _EDACS_LINES_NOISE:
                b.raw_line.emit(l)
        log = win.dig_log.toPlainText()
        assert "EDACS  Digital Group Call Update" in log and "LCN [11] = 851.0125 MHz" in log, log
        assert "MSG_1" not in log                                          # raw words dropped
        s = win._rec_labels.summary()
        win._rec_labels = None
        assert s["label"] == "EDACS" and s["protocols"]["EDACS"]["frames"] == 9, s
        assert s["protocols"]["EDACS"]["site"] == [3] and s["protocols"]["EDACS"]["sysid"] == [0]
        assert not [e for e in win._payloads if e["proto"] == "EDACS"]      # Data bursts off: no payloads
        m._set_capture(True)
        for _ in range(3):                                                 # words repeat: shown once each
            for l in _EDACS_LINES_OK + _EDACS_LINES_NOISE:
                b.raw_line.emit(l)
        ed = [e for e in win._payloads if e["proto"] == "EDACS"]
        assert [e["raw"].hex().upper() for e in ed] == ["0FD603420FD60342", "0FC000000600C0A5",
                                                        "0197006401A0002A"], ed
        assert ed[1]["linktype"] == 147 and ed[1]["label"].startswith("(MT1: 1F; MT2: 8)  System Information")
        m._set_capture(False)
        b.decoded.emit(NB._parse_edacs_line(_EDACS_LINES_OK[0]))
        assert "Site 03" in m._w["status"].text()
        win._on_spectrum_click(854_300_000)
        assert win.request_decode("NXDN96", 854_300_000)
        assert br.bridge is not None and br.bridge.proto == "NXDN" and br.bridge is not b
        win._apply_channel_mode("EDACS")
        assert br.bridge.proto == "EDACS" and m._bridge_ref is br.bridge
        b = br.bridge
        m.edacs["variant"] = "Standard/Networked"                          # Settings > EDACS
        m.edacs["afs"] = "344"
        m.apply_edacs()
        assert br.bridge is not b and br.bridge.flags[0] == "-fh344"      # restarted
        assert m._bridge_ref is br.bridge
        win._apply_channel_mode("DMR")
        assert br.bridge.proto == "DMR"                      # EDACS's dsd-fme gone, DMR's detector instead
        D.open_edacs_settings(m, win)                                      # the dialog builds
        assert m._edacs_dialog is not None
    finally:
        win.close()
    st = json.load(open(A._state_path()))["modules"]["digital"]
    assert st["edacs"]["variant"] == "Standard/Networked" and st["edacs"]["lcns"][0]["lcn"] == 11

    assert all(NB._edacs_valid_line(l) for l in _EDACS_LINES_OK)
    assert not any(NB._edacs_valid_line(l) for l in _EDACS_LINES_NOISE)
    d = NB._parse_edacs_line(_EDACS_LINES_OK[2])
    assert (d["group"], d["src"], d["lcn"]) == (100, 42, 11) and "cc_lcn" not in d
    d = NB._parse_edacs_line(_EDACS_LINES_OK[1])
    assert d["sysid"] == 0 and d["cc_lcn"] == 10 and "lcn" not in d
    assert NB.edacs_flags("EA + ESK") == ["-fE"] and NB.edacs_flags("EA", "344") == ["-fe"]
    eb = NB.EdacsBridge(os.path.join(_TMP, "unused_edacs.fifo"))
    assert eb.proto == "EDACS" and eb._decoder_flags() == ["-fe"]
    assert eb._valid_line(_EDACS_LINES_OK[0]) and not eb._valid_line(_NXDN_LINES_OK[0])
    print("ok  test_edacs_decode_wired")


def _moto_gps_lcw(lat, lon, last=False, protected=False):
    """A Motorola embedded-GPS link control word (MFID 0x90, opcode 6) for made-up coordinates, encoded as
    a radio sends it (the inverse of monitor.parse_p25_lcw)."""
    v = (0x86 if protected else 0x06) << 64 | 0x90 << 56 | (1 if last else 0) << 48
    v |= (1 if lat < 0 else 0) << 47 | round((lat + 90 if lat < 0 else lat) * 0x7FFFFF / 90) << 24
    v |= (1 if lon < 0 else 0) << 23 | round((lon + 180 if lon < 0 else lon) * 0x7FFFFF / 180)
    return v.to_bytes(9, "big")


def test_p25_gps_link_control():
    """P25 link control words: Motorola embedded GPS (as dsd-fme reads it) and the voice-user words that
    name the call's unit. A GPS report reaches the decode log, the map and (Data bursts on) the payload pane,
    tied by one ref, credited to the call's unit even when op25 delivers it before the unit id; a call that
    ends without one still reports it. Made-up coordinates and ids."""
    from sdrexplorer_digital.monitor import parse_p25_lcw
    gps = _moto_gps_lcw(42.36, -71.06)
    d = parse_p25_lcw(gps)
    assert d["kind"] == "MFID90 (Motorola) GPS" and d["gps"]["fix"] == "current"
    assert abs(d["gps"]["lat"] - 42.36) < 2e-5 and abs(d["gps"]["lon"] + 71.06) < 3e-5, d
    assert parse_p25_lcw(_moto_gps_lcw(-33.9, 151.2, last=True))["gps"]["fix"] == "last"
    assert parse_p25_lcw(_moto_gps_lcw(42.36, -71.06, protected=True)).get("protected") is True
    user = bytes([0x00, 0x00, 0x44, 0x00]) + (100).to_bytes(2, "big") + (1001).to_bytes(3, "big")
    assert parse_p25_lcw(user) == {"format": 0, "opcode": 0, "mfid": 0, "kind": "Group Voice Channel User",
                                   "tgid": 100, "src": 1001}
    u2u = bytes([0x03, 0x00, 0x00]) + (2002).to_bytes(3, "big") + (1003).to_bytes(3, "big")
    assert parse_p25_lcw(u2u)["dst"] == 2002 and parse_p25_lcw(u2u)["src"] == 1003

    def lcw(word, nac=0x123):
        lc = parse_p25_lcw(word)
        out = {"proto": "P25", "nac": nac, "duid": "LCW", "lcw": word, "lcw_kind": lc["kind"]}
        out.update({"lcw_" + k: lc[k] for k in ("gps", "protected", "src", "tgid") if k in lc})
        return out

    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        m._set_capture(True)
        win.dig_hex_cb.setChecked(True)
        m._on_decoded(lcw(gps))                         # the GPS word first, as op25 sends it
        assert not [l for l in win._dig_lines if "P25 GPS" in l]          # waits for the unit id
        m._on_decoded(lcw(user))
        lines = [l for l in win._dig_lines if "P25 GPS" in l]
        assert len(lines) == 1 and "42.3600" in lines[0] and "-71.060" in lines[0] and "SRC 1001" in lines[0], lines
        # the voice-user word's talkgroup and unit reach the log line (op25's JSON often has neither)
        calls = [l for l in win._dig_lines if "NAC 0x123" in l and "TG 100" in l and "SRC 1001" in l]
        assert calls and "GPS" not in calls[0], win._dig_lines
        m._on_decoded(lcw(gps))                         # the same word again within the call: once only
        assert len([l for l in win._dig_lines if "P25 GPS" in l]) == 1
        pays = [e for e in win._payloads if e["linktype"] == 148]
        assert len(pays) == 1 and pays[0]["raw"] == gps and "LCW MFID90" in pays[0]["label"]
        radios = {x["id"]: x for x in win.targets.snapshot() if x["kind"] == "radio"}
        assert abs(radios["p25:1001"]["lat"] - 42.36) < 1e-4, radios
        win.dig_search.setText("SRC 1001")              # the decode strip links the line to its payload
        win.hex_follow_cb.setChecked(True)
        assert gps.hex()[:8] not in win.dig_hex.toPlainText() and "LCW MFID90" in win.dig_hex.toPlainText()
        win.dig_search.setText("")
        m._on_decoded({"proto": "P25", "nac": 0x123, "duid": "TDU"})      # end of call: unit forgotten
        other = _moto_gps_lcw(42.35, -71.10)
        m._on_decoded(lcw(other))
        m._on_decoded({"proto": "P25", "nac": 0x123, "duid": "TDU"})      # ends without a unit id
        last = [l for l in win._dig_lines if "P25 GPS" in l][-1]
        assert "42.3500" in last and "-71.100" in last and "NAC 0x123" in last and "SRC" not in last, last
    finally:
        win.close()
    print("ok  test_p25_gps_link_control")


def test_p25_damaged_ess_not_reported_encrypted():
    """An ESS naming an unregistered algorithm (a damaged LDU2, e.g. just after another mode: "alg 0x08")
    isn't reported as encryption unless the next ESS says the same; a known algorithm counts at once; a
    clear report resets it."""
    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        def ess(alg, key):
            m._on_decoded({"proto": "P25", "tgid": None, "src": None, "encrypted": 1, "algid": alg,
                           "keyid": key, "raw": b"{}"})
        ess(0x08, 50478)
        assert not m.encrypted and not [l for l in win._dig_lines if "ENCRYPTED" in l], win._dig_lines
        m._on_decoded({"proto": "P25", "tgid": 9, "src": 1001, "encrypted": 0, "raw": b"{}"})   # clear
        ess(0x08, 50478)                        # once again after a clear report: still not believed
        assert not m.encrypted
        ess(0x08, 50478)                        # the same twice in a row: believed
        assert m.encrypted and [l for l in win._dig_lines if "ENCRYPTED alg 0x08" in l], win._dig_lines
        m.encrypted = False
        ess(0x84, 7)                            # AES-256: at once
        assert m.encrypted                      # (its log line is the same content as the last: deduplicated)
    finally:
        win.close()
    print("ok  test_p25_damaged_ess_not_reported_encrypted")


def test_dsd_groups_tie_lines_to_payloads():
    """dsd-fme's output is grouped per frame (a Sync: line, its decoded lines, its -Z payload), and an NXDN
    data call (DCALL_HEADER + its DCALL_DATA frames) is one group: the bridge announces each group before
    its lines, so a GPS fix, the call's lines and its UDCH payloads share a Decode.ref and "Follow log
    filter" on "GPS" shows that call's payloads. Made-up data (the _NXDN_GPS_DSD fixture)."""
    import io
    import types as _types
    b = NB.NxdnBridge(os.path.join(_TMP, "unused_groups.fifo"))
    b._locked = True
    events = []
    D = QtCore.Qt.DirectConnection
    b.group.connect(lambda g: events.append(("group", g)), D)
    b.data.connect(lambda p, l, raw: events.append(("data", raw)), D)
    b.position.connect(lambda fix: events.append(("fix", fix["src"])), D)
    tail = "12:25:40 Sync: NXDN96  RCCH Data   C-Ve: 6.0;          CAC SRV_INFO\n CAC Payload\n  [01][02][03]\n"
    b._proc = _types.SimpleNamespace(stdout=io.BytesIO((_NXDN_GPS_DSD + tail).encode()))
    b._pump_stdout()
    b._finish_payload(crc_err=False)
    group, seen = None, []                      # (group, kind) per event
    for kind, v in events:
        if kind == "group":
            group = v
        else:
            seen.append((group, kind, v))
    first_call = [g for g, k, v in seen if k == "fix" and v == 1001][0]
    call1 = [v for g, k, v in seen if g == first_call and k == "data"]
    assert len(call1) == 3, seen                # the call's header block + two data blocks, one group
    cac = [g for g, k, v in seen if k == "data" and v == bytes([1, 2, 3])]
    assert cac and cac[0] != first_call         # the next frame: a group of its own
    groups = [v for k, v in events if k == "group"]
    assert len(groups) == len(set(groups)) >= 3

    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        m._set_capture(True)
        win.dig_hex_cb.setChecked(True)
        win.hex_follow_cb.setChecked(True)
        m._on_dsd_group(("NXDN", "call-a"))
        m._on_dsd_line(" GPS: (42.360000, -71.060000) Speed: 10.5 k/h;")
        m._on_dsd_data("NXDN", "UDCH", bytes.fromhex("0d0b2200aabbcc"))
        m._on_dsd_group(("NXDN", "frame-b"))
        m._on_dsd_line(" Location Information - Cat: Local - Sys Code: 1 - Site Code 2")
        m._on_dsd_data("NXDN", "CAC", bytes.fromhex("01020304"))
        win.dig_search.setText("gps")
        pane = win.dig_hex.toPlainText()
        assert "aa bb cc" in pane and "01 02 03 04" not in pane, pane
        win.dig_search.setText("location")
        pane = win.dig_hex.toPlainText()
        assert "01 02 03 04" in pane and "aa bb cc" not in pane, pane
    finally:
        win.close()
    print("ok  test_dsd_groups_tie_lines_to_payloads")


def test_positions_reach_the_map():
    """LRRP locations in DMR data bursts (one target per radio, from the IP source address) and NXDN GPS
    reports (one target per unit) reach the core's map
    as 'radio' positions; a data burst lands in the payload pane as raw IP (pcap-exportable); a (0, 0)
    no-fix report is dropped."""
    import io
    import types as _types
    b = NB.NxdnBridge(os.path.join(_TMP, "unused.fifo"))
    b._locked = True
    fixes = []
    b.position.connect(fixes.append, QtCore.Qt.DirectConnection)
    b._proc = _types.SimpleNamespace(stdout=io.BytesIO(_NXDN_GPS_DSD.encode()))
    b._pump_stdout()
    assert [f["src"] for f in fixes] == [1001, 1002], fixes
    assert abs(fixes[0]["lat"] - 42.36) < 1e-6 and abs(fixes[0]["lon"] + 71.06) < 1e-6
    assert NB._parse_gps_line(" GPS: (95.0°, 10.0°) Speed: 0 k/h;") is None
    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        for f in fixes:
            m._on_nxdn_position(f)
        m._on_nxdn_position(dict(fixes[0], lat=42.3610))
        radios = {x["id"]: x for x in win.targets.snapshot() if x["kind"] == "radio"}
        assert {"nxdn:1001", "nxdn:1002"} <= set(radios), radios
        assert radios["nxdn:1001"]["label"] == "NXDN 1001"
        assert len(win.targets._targets["nxdn:1001"].track) == 2
        assert "★ NXDN GPS  NXDN 1001" in win.dig_log.toPlainText()
        pt = bytes([0x66, 0x3B, 0xBB, 0xBB, 0xBC, 0xCD, 0x82, 0xD3, 0x8E])
        m._dmr_id_cache.update({"137": None, "12345678": None})      # made-up ids: no radioid.net lookup
        m._on_data("DMR", "test", _udp_datagram(4001, pt, src=(12, 0, 0, 137)))
        # a second radio on the same channel (12.188.97.78 = id 12345678) gets its own target
        pt2 = bytes([0x66, 0x3B, 0xBB, 0xBB, 0xBC, 0xCD, 0x82, 0xD3, 0x9E])
        m._on_data("DMR", "test", _udp_datagram(4001, pt2, src=(12, 188, 97, 78)))
        lrrp = {x["id"]: x for x in win.targets.snapshot() if x["kind"] == "radio" and x["id"].startswith("dmr:")}
        assert set(lrrp) == {"dmr:137", "dmr:12345678"}, lrrp
        assert lrrp["dmr:137"]["label"] == "DMR 137"
        assert abs(lrrp["dmr:137"]["lat"] - 42.0) < 0.01 and abs(lrrp["dmr:137"]["lon"] + 71.0) < 0.01
        assert len(win.targets._targets["dmr:137"].track) == 1     # not one target hopping between two radios
        log = win.dig_log.toPlainText()
        assert "★ LRRP LOCATION" in log and "SRC 137" in log and "SRC 12345678" in log, log
        assert win._payloads and win._payloads[-1]["linktype"] == 101
        from sdrexplorer import pcap
        files = pcap.write_by_linktype(os.path.join(_TMP, "p.pcap"), win._payloads)
        assert files and files[0][2] == 2, files      # the two LRRP bursts
    finally:
        win.close()
    print("ok  test_positions_reach_the_map")


def test_decode_log_dedup_and_ids():
    """op25 decodes: one log line per distinct content (SLOT_ELC repeats and content-free SLOT_ESB pings
    collapse), a lost lock doesn't re-arm the dedup, a real gap does, alternating broadcast types dedup
    each against its own last occurrence -- and every frame still counts for a recording's label with its
    ids (DMR color code, P25 NAC). The station tag names the bank channel the NAC matches."""
    from sdrexplorer.banks import Channel
    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        m._dmr_id_cache = {}
        m._dmr_resolve_src = lambda i: None          # no network
        elc = {"proto": "DMR", "label": "SLOT_ELC", "cc": 9, "call": "Group Call",
               "tgid": 3133, "src": 2345678, "flco": 0, "fid": 0}
        esb = {"proto": "DMR", "label": "SLOT_ESB"}
        win._rec_labels = A.RecordingLabels(int(win.radio.freq_hz))
        for d in (elc, esb, elc, esb, elc):
            m._on_decoded(d)
        lines = [l for l in win._dig_lines if "SLOT_ELC" in l or "SLOT_ESB" in l]
        assert len(lines) == 1 and "TG 3133" in lines[0] and "SRC 2345678" in lines[0], lines
        s = win._rec_labels.summary()
        assert s["protocols"]["DMR"]["frames"] == 5 and s["protocols"]["DMR"]["cc"] == [9], s
        m._on_lock(False)
        m._on_decoded(elc)
        assert len([l for l in win._dig_lines if "SLOT_ELC" in l]) == 1
        m._seen = {k: t - (DM.REPEAT_GAP_S + 1) for k, t in m._seen.items()}
        m._on_decoded(elc)
        assert len([l for l in win._dig_lines if "SLOT_ELC" in l]) == 2
        csbk = {"proto": "DMR", "label": "SLOT_CSBK", "cc": 1, "csbko": 0x3D}
        cach = {"proto": "DMR", "label": "CACH_SLC", "cc": 1}
        for d in (csbk, cach) * 3:
            m._on_decoded(d)
        assert len([l for l in win._dig_lines if "SLOT_CSBK" in l]) == 1
        assert len([l for l in win._dig_lines if "CACH_SLC" in l]) == 1
        # the station tag: two channels on the same frequency, told apart by the decoded NAC
        hz = int(win.radio.freq_hz)
        win._set_bank = None
        bank = win.store.bank()
        bank.channels[:] = [Channel(freq=hz, mode="P25", label="Fire", tone="1A2 NAC"),
                            Channel(freq=hz, mode="P25", label="Police", tone="293 NAC")]
        m._on_decoded({"proto": "P25", "nac": 0x293, "duid": "HDU", "tgid": 7})
        last = win._dig_lines[-1]
        assert "Police" in last and "NAC 0x293" in last, last
        assert win._rec_labels.summary()["protocols"]["P25"]["nac"] == [0x293]
        win._rec_labels = None
    finally:
        win.close()
    print("ok  test_decode_log_dedup_and_ids")


def test_dmr_src_resolves_callsign():
    """DMR SRC ids resolve to callsigns (radioid.net) off the UI thread, one lookup per id at a time, cached."""
    _fresh_state()
    win = _build()
    m = _mod(win)
    real = (DM.radioid.DmrIdWorker, DM.radioid.save_cache)
    try:
        class _Fake(QtCore.QObject):
            done = QtCore.pyqtSignal(int, object)
            finished = QtCore.pyqtSignal()

            def __init__(self, dmr_id, parent=None):
                super().__init__(parent)
                self.dmr_id = dmr_id

            def start(self):
                pass

            def wait(self, ms=0):
                return True

            def deleteLater(self):
                pass
        saved = []
        DM.radioid.DmrIdWorker = _Fake
        DM.radioid.save_cache = lambda c: saved.append(dict(c))
        m._dmr_id_cache, m._dmr_id_pending, m._dmr_id_workers = {}, set(), []
        i = 9_999_001
        assert m._dmr_src_label(i) == f"SRC {i}" and i in m._dmr_id_pending and len(m._dmr_id_workers) == 1
        w = m._dmr_id_workers[0]
        m._dmr_src_label(i)
        assert len(m._dmr_id_workers) == 1
        w.done.emit(i, {"callsign": "N0CALL"})
        w.finished.emit()
        assert i not in m._dmr_id_pending and m._dmr_id_workers == []
        assert saved[-1][str(i)]["callsign"] == "N0CALL" and m._dmr_src_label(i) == f"SRC {i} (N0CALL)"
    finally:
        DM.radioid.DmrIdWorker, DM.radioid.save_cache = real
        win.close()
    print("ok  test_dmr_src_resolves_callsign")


def test_crypt_keystore():
    """P25 keystore: hex parsing, load / save round trip, keys pushed into op25 with the right lengths,
    and a legacy memory/keys.json migrated once into the core keystore (api.secrets)."""
    from sdrexplorer.api import secrets as SEC
    aes = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    # a pre-keystore install: keys in memory/keys.json, nothing in the keystore yet
    SEC.delete(D._SECRET_OWNER, D._SECRET_NAME)
    legacy = D._legacy_keys_path()
    os.makedirs(os.path.dirname(legacy), exist_ok=True)
    for stale in (legacy, legacy + ".moved"):
        try:
            os.remove(stale)
        except OSError:
            pass
    with open(legacy, "w") as fh:
        json.dump([{"keyid": 161, "algid": 0x84, "key": aes}], fh)
    # record what reaches op25 instead of loading a key (a real key and its teardown: test_crypt_key_teardown)
    calls = []
    real = B.DigitalBranches.add_crypt_key
    B.DigitalBranches.add_crypt_key = lambda self, kid, alg, kb: calls.append((kid, alg, len(list(kb)))) or True
    _fresh_state()
    try:
        win = _build()                      # loading the module migrates keys.json -> the keystore
    finally:
        B.DigitalBranches.add_crypt_key = real
    m = _mod(win)
    try:
        assert len(m.crypt_keys) == 1 and m.crypt_keys[0]["keyid"] == 161
        assert calls == [(161, 0x84, 32)], calls                 # pushed at start, AES-256 = 32 bytes
        # the legacy file was consumed (renamed .moved) and the key now lives in the keystore
        assert not os.path.exists(legacy) and os.path.exists(legacy + ".moved")
        in_store = json.loads(SEC.get(D._SECRET_OWNER, D._SECRET_NAME))
        assert in_store and in_store[0]["keyid"] == 161
        assert D.parse_hex_key("12 34 ab") == [0x12, 0x34, 0xab]
        assert D.parse_hex_key("0x12,0x34") == [0x12, 0x34] and D.parse_hex_key("123") is None
        m.br.add_crypt_key = lambda kid, alg, kb: calls.append((kid, alg, len(list(kb)))) or True
        assert m._apply_crypt_keys() == 1 and calls[-1] == (161, 0x84, 32)
        m.crypt_keys.append({"keyid": 1, "algid": 0xAA, "key": "1234567890"})
        D.save_crypt_keys(m.crypt_keys)
        assert json.loads(SEC.get(D._SECRET_OWNER, D._SECRET_NAME))[1]["algid"] == 0xAA
    finally:
        win.close()
        # later windows would load these keys into a real op25 (see above)
        SEC.delete(D._SECRET_OWNER, D._SECRET_NAME)
        try:
            os.remove(legacy + ".moved")
        except OSError:
            pass
    print("ok  test_crypt_keystore")


def test_crypt_key_teardown():
    """A frame_assembler holding AES and DES keys is destroyed cleanly. Unpatched op25 segfaults here
    (~op25_crypt_algs erased through an invalidated iterator), so it runs in a child process."""
    if not B.OP25_AVAILABLE:
        print("ok  test_crypt_key_teardown (skipped: no op25)")
        return
    import subprocess
    code = (f"import gc, json, sys; sys.path[:0] = {[os.path.join(REPO, 'src'), os.path.join(os.path.dirname(REPO), 'sdrexplorer')]!r}\n"
            "from gnuradio import gr\n"
            "from sdrexplorer_digital import branches as B\n"
            "asm = B._op25_repeater.frame_assembler('p25_decoder', 0, 0, gr.msg_queue(10))\n"
            "for kid, alg, n in ((161, 0x84, 32), (2, 0x81, 8)):\n"
            "    asm.control(json.dumps({'tuner': 0, 'cmd': 'crypt_key', 'keyid': kid, 'algid': alg,\n"
            "                            'key': list(range(n))}))\n"
            "del asm\n"
            "gc.collect()\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"exit {r.returncode} (op25 without the ~op25_crypt_algs fix?): {r.stderr[-400:]}"
    print("ok  test_crypt_key_teardown")


def test_smartnet_always_on():
    """SmartNet decodes without being picked: its own demod + frame_assembler stay attached whatever the
    picked decoder; a SmartNet label is taken without switching anything; the bandplan dialog applies."""
    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        from sdrexplorer_digital import smartnet as SN
        assert m.smartnet_bandplan == SN.DEFAULT_BANDPLAN and m.smartnet_bandplan in SN.BANDPLANS
        assert "SmartNet" not in [m._w["mode"].itemText(i) for i in range(m._w["mode"].count())]
        if B.OP25_AVAILABLE:
            sn = m.br.sn_demod
            assert any(b is sn for b in win.radio.taps.attached("channel"))
            m._set_mode("DMR")
            m._set_mode("P25")
            assert m.br.sn_demod is sn and any(b is sn for b in win.radio.taps.attached("channel"))
            op = m.br.op25_demod
            assert any(b is op for b in win.radio.taps.attached("channel"))
            before = m.mode
            assert win.request_decode("SmartNet", int(win.radio.freq_hz)) and m.mode == before
        D.open_smartnet_settings(m, win)
        m._smartnet_dialog.findChild(QtWidgets.QComboBox).setCurrentText("900")
        assert m.smartnet_bandplan == "900"
        win._save_state()
        assert json.load(open(A._state_path()))["modules"]["digital"]["smartnet_bandplan"] == "900"
    finally:
        win.close()
    print("ok  test_smartnet_always_on")


def test_branches_on_a_running_flowgraph():
    """The real flowgraph (IQ replay, the radio alone as paging's test does): the branches (op25, SmartNet,
    the discriminator tap) attach to a running radio, the op25 demod is swapped on a decoder change, ADS-B's
    suspend takes the branches off and back, and they follow a capture-rate change."""
    if not B.OP25_AVAILABLE:
        print("ok  test_branches_on_a_running_flowgraph (skipped: op25 not found)")
        return
    from sdrexplorer.radio import SAMP_RATE, ScannerRadio
    p = os.path.join(_TMP, "rep.cs16")
    n = SAMP_RATE * 2
    t = np.arange(n) / SAMP_RATE
    z = 0.3 * np.exp(2j * np.pi * 300_000 * t) + 0.01 * (np.random.randn(n) + 1j * np.random.randn(n))
    iq = np.empty(2 * n, np.int16)
    iq[0::2], iq[1::2] = (z.real * 2000).astype(np.int16), (z.imag * 2000).astype(np.int16)
    iq.tofile(p)
    A.ScannerRadio.start = _REAL_START
    try:
        r = ScannerRadio(audio_out=False)
        r.set_replay(p, {"samp_rate": SAMP_RATE, "center_hz": 462_000_000, "chan_hz": 462_300_000}, loop=True)
        r.start()
        try:
            br = B.DigitalBranches(r, r.taps)
            br.start()
            att = r.taps.attached("channel")
            assert any(b is br.op25_demod for b in att) and any(b is br.sn_demod for b in att)
            assert any(b is br.disc_filt for b in att)                  # the discriminator tap: always on
            time.sleep(0.3)
            old = br.op25_demod
            br.set_mode("DMR")
            assert br.op25_demod is not old and any(b is br.op25_demod for b in r.taps.attached("channel"))
            time.sleep(0.3)
            r.taps.suspend("channel")
            time.sleep(0.2)
            r.taps.resume("channel")
            br.set_mode("P25")
            time.sleep(0.3)
            assert r.running
            br.stop()
            assert not r.taps.attached("channel")
            br.start()
        finally:
            r.stop()
        old = r.chan
        r.set_samp_rate(4_800_000 if r.samp_rate != 4_800_000 else 9_600_000)
        assert r.chan is not old and len(r.taps.attached("channel")) == 3
    finally:
        A.ScannerRadio.start = lambda self: setattr(self, "running", True)
    print("ok  test_branches_on_a_running_flowgraph")


def test_tx_modes():
    """P25 / DMR TX: the core's TxChain builds each modulator (no device: stops at the sink); DMR's settings
    reach dmr_bs_tx_bb's config, which is removed afterwards; the P25 NAC/LC settings reach the vocoder;
    a channel saved while DMR / P25 is the TX mode gets the CC/TG / NAC tone back and forth."""
    from sdrexplorer_digital import tx as TX
    if not (TX.P25_TX_AVAILABLE and TX.DMR_TX_AVAILABLE):
        print("ok  test_tx_modes (skipped: no op25 TX support)")
        return
    from gnuradio import blocks, gr
    from sdrexplorer.api import TX_RATE

    class TB(gr.top_block):
        pass
    for build in (TX.build_p25, TX.build_dmr):
        tb = TB()
        src = blocks.null_source(gr.sizeof_float)
        mod = build(tb, src, {"cc": 3, "tgid": 77, "radio_id": 5, "nac": 0x123, "src": 0x3E9})
        sink = blocks.head(gr.sizeof_gr_complex, int(TX_RATE * 0.1))
        tb.connect(mod, sink, blocks.null_sink(gr.sizeof_gr_complex))
        if build is TX.build_dmr:
            conf = tb._dmr_conf_path_digital
            assert "cc1=3" in open(conf).read() and "ga1=77" in open(conf).read()
            TX.cleanup_dmr(tb)
            assert not os.path.exists(conf)

    # the P25 TX NAC/LC setters exist (the op25 patch) and build_p25 drives them
    # with the settings. pybind methods can't be monkeypatched on an instance, so
    # record through a factory that returns the real block (needed for connect())
    # and tees the setter calls into a list.
    recorded = {}
    real = TX._br._op25_repeater.vocoder
    v0 = real(True, False, 0, "", 0, False)
    assert hasattr(v0, "set_nac") and hasattr(v0, "set_lc"), "op25 TX NAC/LC patch not built"

    class _Tee:
        """Forwards everything to the real vocoder block (so GNU Radio sees a
        real gr.block) but records set_nac / set_lc."""
        def __init__(self, blk):
            object.__setattr__(self, "_blk", blk)
        def set_nac(self, n):
            recorded["nac"] = n
            return self._blk.set_nac(n)
        def set_lc(self, *x):
            recorded["lc"] = x
            return self._blk.set_lc(*x)
        def __getattr__(self, name):
            return getattr(object.__getattribute__(self, "_blk"), name)
    try:
        TX._br._op25_repeater.vocoder = lambda *a, **k: _Tee(real(*a, **k))
        tb = TB()
        TX.build_p25(tb, blocks.null_source(gr.sizeof_float), {"nac": 0x123, "tgid": 9, "src": 0x3E9})
    finally:
        TX._br._op25_repeater.vocoder = real
    assert recorded.get("nac") == 0x123, recorded
    assert recorded.get("lc") == (0, 0, 0, 0, 9, 0, 0x3E9), recorded

    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        win.tx_mode_combo.setCurrentText("DMR")
        m.dmr_tx.update(cc=6, tgid=100)
        win._add_current()
        assert win.store.bank().channels[-1].tone == "CC 6 TG 100"
        win._apply_tx_tone("CC 2 TG 31")
        assert (m.dmr_tx["cc"], m.dmr_tx["tgid"]) == (2, 31)
        # P25: a channel saved while P25 is the TX mode gets the NAC as "<hex> NAC"
        win.tx_mode_combo.setCurrentText("P25")
        m.p25_tx["nac"] = 0x123
        win._add_current()
        assert win.store.bank().channels[-1].tone == "123 NAC"
        win._apply_tx_tone("293 NAC")
        assert m.p25_tx["nac"] == 0x293
        # DMR-MS: a channel saved while DMR-MS is the TX mode gets the CC/TG tone back and forth
        if "DMR-MS" in win._tx_specs:
            win.tx_mode_combo.setCurrentText("DMR-MS")
            m.dmr_ms_tx.update(cc=5, tgid=9)
            win._add_current()
            assert win.store.bank().channels[-1].tone == "CC 5 TG 9"
            win._apply_tx_tone("CC 1 TG 3100")
            assert (m.dmr_ms_tx["cc"], m.dmr_ms_tx["tgid"]) == (1, 3100)
        # the TX settings are also stored as the module's own channel fields, and come back on recall
        win.tx_mode_combo.setCurrentText("P25")
        m.p25_tx.update(nac=0x123, tgid=9, src=0x3E9)
        win._add_current()
        ch = win.store.bank().channels[-1]
        assert ch.fields_for("digital") == {"tx": "P25", "nac": 0x123, "tgid": 9, "src": 0x3E9}
        assert m.channel_summary(ch.fields_for("digital")) == "P25 TX: NAC 123 TG 9 ID 1001"
        m.p25_tx.update(nac=0x293, tgid=1)
        m.channel_recalled(ch, ch.fields_for("digital"))
        assert (m.p25_tx["nac"], m.p25_tx["tgid"]) == (0x123, 9)
        win.tx_mode_combo.setCurrentText("Analog")
        win._add_current()
        assert win.store.bank().channels[-1].fields_for("digital") == {}
    finally:
        win.close()
    print("ok  test_tx_modes")


def test_tx_settings_persist():
    """TX settings survive a restart AND the widgets (Settings dialog + main-screen quick fields) show
    the loaded values — regression for the bug where widgets were built from defaults before load_state
    and never refreshed, so the dialog showed defaults after restart."""
    _fresh_state()
    win = _build()
    m = _mod(win)
    try:
        m.dmr_ms_tx.update(cc=6, tgid=3125, src=7654321)
        m.p25_tx.update(nac=0x123, tgid=345)
        m.dmr_tx.update(cc=4, tgid=77)
        win._save_state()
    finally:
        win.close()
    saved = json.load(open(A._state_path()))["modules"]["digital"]
    assert saved["dmr_ms_tx"] == {"cc": 6, "tgid": 3125, "src": 7654321}
    assert saved["p25_tx"]["nac"] == 0x123
    # a fresh window loads the saved state; the dicts AND every registered TX widget must show it
    win = _build()
    m = _mod(win)
    try:
        assert m.dmr_ms_tx == {"cc": 6, "tgid": 3125, "src": 7654321}, m.dmr_ms_tx
        assert m.p25_tx["nac"] == 0x123 and m.p25_tx["tgid"] == 345
        assert m.dmr_tx["cc"] == 4 and m.dmr_tx["tgid"] == 77
        # P25's main-screen quick fields: TG and NAC, like DMR's TG and CC
        from PyQt5 import QtWidgets as _QW
        q = m._p25_tx_quick(None)
        assert [s.value() for s in q.findChildren(_QW.QSpinBox)] == [345]
        from PyQt5.QtCore import Qt as _Qt
        assert [e.text() for e in q.findChildren(_QW.QLineEdit, options=_Qt.FindDirectChildrenOnly)] == ["123"]
        q.deleteLater()
        for settings, key, w, kind in m._tx_fields:
            if kind == "spin":
                assert w.value() == int(settings[key]), (key, w.value(), settings[key])
            else:
                assert int(w.text(), 16) == int(settings[key]), (key, w.text(), settings[key])
    finally:
        win.close()
    print("ok  test_tx_settings_persist")


def test_dmr_ms_tx_decodes():
    """The DMR-MS TX chain (audio -> ambe -> dmr_ms_tx_bb -> dibits) produces a mobile-station call that
    dsd-fme decodes: voice LC header + embedded LC + terminator with the configured CC / TG / source."""
    from sdrexplorer_digital import dmr_ms_tx as MSTX
    if not MSTX.MS_TX_AVAILABLE or not NB.dsd_fme_available():
        print("ok  test_dmr_ms_tx_decodes (skipped: no op25 MS TX / dsd-fme)")
        return
    import tempfile, os, subprocess, re
    from sdrexplorer_digital import proofs
    from gnuradio import gr, blocks, analog
    tb = gr.top_block()
    tone = analog.sig_source_f(8000, analog.GR_SIN_WAVE, 600, 16000)
    thr = blocks.throttle(gr.sizeof_float, 8000)
    f2s = blocks.float_to_short(1, 1.0)
    enc = B._op25_repeater.ambe_encoder_sb(0)
    conf = MSTX.write_ms_config(6, 100, 1234)
    fr = B._op25_repeater.dmr_ms_tx_bb(0, conf)
    snk = blocks.vector_sink_b()
    tb.connect(tone, thr, f2s, enc, fr, snk)
    try:
        tb.start(); time.sleep(2.0); fr.send_terminator(); time.sleep(1.0); tb.stop(); tb.wait()
        data = bytes([x & 3 for x in snk.data()])
        td = tempfile.mkdtemp()
        binf = os.path.join(td, "ms.bin")
        with open(binf, "wb") as fh:
            fh.write(data)
        dsd, env = proofs.dsd_fme()
        p = subprocess.run([dsd, "-fs", "-i", binf, "-o", "null", "-Z"], capture_output=True,
                           text=True, env=env, timeout=40, stdin=subprocess.DEVNULL)
        ANSI = re.compile(r"\x1b\[[0-9;]*m")
        L = [ANSI.sub("", x) for x in (p.stdout + p.stderr).splitlines()]
    finally:
        os.unlink(conf)
    assert sum("VLC" in x for x in L) >= 1, "no voice LC header decoded"
    assert sum("TGT=100 SRC=1234" in x for x in L) >= 1, "talkgroup/source not decoded"
    assert sum("TLC" in x for x in L) >= 1, "no terminator decoded"
    print("ok  test_dmr_ms_tx_decodes")


def test_proofs():
    """The proofs reject noise for every label, and EDACS-V / SmartNet find their signals in synthetic ones."""
    from sdrexplorer_digital.proofs import PROOFS, smartnet_crc, edacs_dotting
    rng = np.random.default_rng(1)
    fs = 24_000
    noise = (rng.standard_normal(2 * fs) + 1j * rng.standard_normal(2 * fs)).astype(np.complex64)
    for label in ("SmartNet", "EDACS-V") + (("DMR", "P25-P1", "NXDN48", "NXDN96", "EDACS")
                                            if NB.dsd_fme_available() else ()):
        r = PROOFS[label](noise, fs)
        assert r["ok"] is False, (label, r)
    t = np.arange(int(0.2 * fs)) / fs                    # 9600 Bd dotting: FM at +-4800 Hz square
    f = 2400 * np.sign(np.sin(2 * np.pi * 4800 * t))
    z = np.exp(1j * 2 * np.pi * np.cumsum(f) / fs).astype(np.complex64)
    assert edacs_dotting(z, fs) >= 0.08 and PROOFS["EDACS-V"](z, fs)["ok"]
    assert smartnet_crc([0] * 27) == smartnet_crc([0] * 27)
    print("ok  test_proofs")


def main():
    _stubs()
    tests = [test_lrrp_gate_rejects_junk_keeps_real, test_p25_algid_names, test_smartnet_bandplan_freq,
             test_smartnet_osw_tracker, test_smartnet_digital_monitor_emits, test_dmr_csbk_grant_lcn_freq,
             test_dmr_embedded_lc_yields_tgid, test_dmr_cach_slc_cc, test_loads_into_the_app,
             test_request_decode_follows_variant_and_scan_modes, test_lock_claims_the_speaker,
             test_voice_reaches_the_speaker, test_voice_prefers_one_decoder,
             test_dmr_mobile_station_handed_to_dsd_fme, test_edacs_decode_wired, test_positions_reach_the_map, test_p25_gps_link_control,
             test_p25_damaged_ess_not_reported_encrypted,
             test_dsd_groups_tie_lines_to_payloads, test_decode_log_dedup_and_ids,
             test_dmr_src_resolves_callsign, test_crypt_keystore, test_crypt_key_teardown,
             test_smartnet_always_on,
             test_branches_on_a_running_flowgraph, test_tx_modes, test_tx_settings_persist,
             test_dmr_ms_tx_decodes, test_proofs]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as e:
            failed += 1
            import traceback
            print(f"FAIL {t.__name__}: {e}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} digital tests passed", flush=True)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(1 if failed else 0)


if __name__ == "__main__":
    main()
