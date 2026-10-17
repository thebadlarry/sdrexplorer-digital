# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""The decoders' GNU Radio branches off the core's channel tap (api.TAP_CHANNEL, 240 kHz, the tuned frequency
at 0 Hz). Moved from sdrexplorer's radio.py (ScannerRadio's op25 / SmartNet demods and the NXDN tap); the
DSP is unchanged.

    op25      p25_demod_cb -> frame_assembler (P25 / DMR, rx_sync auto-detects either); one at a time, its
              demod filter follows the picked mode. Voice: UDP to OP25_AUDIO_PORT (voice.py plays it).
    smartnet  a second, always-on p25_demod_cb (fsk2mm, 3600 Bd) -> frame_assembler("smartnet"), sharing
              the same message queue.
    disc      FM discriminator audio (the NFM mode's filter and gain) -> DC block -> int16 -> a file_sink,
              opened on a FIFO that a dsd-fme subprocess reads (dsdfme.py: NXDN, EDACS, DMR) while NXDN /
              EDACS / DMR / DMR-MS is picked, closed otherwise (on DMR it runs beside op25, see BRIDGE_PROTO). Always attached (as op25's branches are): attaching it at each
              dsd-fme start would cost a flowgraph reconfiguration -- a stall -- every time.
"""
from __future__ import annotations

import json
import math
import os
import tempfile

from gnuradio import analog, blocks, gr
from gnuradio import filter as gr_filter
from gnuradio.filter import firdes

from sdrexplorer.api import TAP_CHANNEL, paths as _paths

from . import dsdfme as _dsd
from .pathkeys import register_paths

QUAD_RATE = 240_000                  # the tap point's rate (sdrexplorer.api: TAP_CHANNEL)
AUDIO_RATE = 48_000
STAGE2_DECIM = QUAD_RATE // AUDIO_RATE
NFM_BW, NFM_MAX_DEV = 12_500, 5_000  # the core's NFM mode: the discriminator tap uses its filter and gain
NXDN_DC_BLOCK_LEN = 4800             # NXDN tap DC removal: 0.1 s moving average at AUDIO_RATE

# --- op25 in-process -----------------------------------------------------------------------------------
# op25's decoder blocks import in-process (its install prefix, paths key "op25", merges with system GR 3.10
# via the gnuradio namespace package; its apps/ dir, key "op25_apps", holds p25_demodulator / tx/
# op25_c4fm_mod). If unavailable the decoders that need it are grayed out.
register_paths()
try:
    _paths.activate("op25")
    _paths.activate("op25_apps")
    from gnuradio import op25_repeater as _op25_repeater
    import p25_demodulator as _p25_demodulator
    OP25_AVAILABLE = True
except Exception:                    # op25 not on the path
    _op25_repeater = _p25_demodulator = None
    OP25_AVAILABLE = False

OP25_IF_RATE = 24_000
OP25_AUDIO_PORT = 23466              # != 23456 (the offline replay tool's port)
OP25_USABLE_BW = 0.85

# demod parameters per digital mode. P25 P1 uses fsk4/rc here — the exact params
# proven to decode a real C4FM P25 system via capture replay. DMR
# and NXDN are 4-level FSK too. (cqpsk is for CQPSK/LSM simulcast systems; add a
# variant if one is encountered.)
# NXDN uses filter_type='nxdn' (op25's dedicated NXDN pulse-shaping + gain trim
# — see monitor.py's _MODE_PARAMS comment), NOT the generic 'rrc' used
# previously. op25 still can't parse an NXDN frame once demodulated (no NXDN
# entry in its frame_assembler sync table) — see dsdfme.py, which decodes the
# discriminator tap instead. symbol_rate 4800 is NXDN96 (12.5 kHz channels).
DIGITAL_PARAMS = {
    "P25":  dict(demod_type="fsk4", filter_type="rc",  symbol_rate=4800),
    "DMR":  dict(demod_type="fsk4", filter_type="rrc", symbol_rate=4800),
    "NXDN": dict(demod_type="fsk4", filter_type="nxdn", symbol_rate=4800),
    # EDACS (GE/Harris trunking control channel, 9600 Bd 2FSK) is decoded by dsd-fme through the
    # same discriminator tap and bridge as NXDN (dsdfme.EdacsBridge); op25 has no EDACS decoder.
    # The op25 demod just keeps P25's settings while EDACS is picked (rx_sync still catches P25/DMR).
    "EDACS": dict(demod_type="fsk4", filter_type="rc", symbol_rate=4800),
}
# DMR-MS: DMR decoded by dsd-fme, which reads mobile-station / direct-mode bursts (a radio's own
# transmission: a repeater input, simplex) that op25 can't. op25 keeps its DMR demod settings beside it.
DIGITAL_PARAMS["DMR-MS"] = DIGITAL_PARAMS["DMR"]
DIGITAL_MODES = ["P25", "DMR", "DMR-MS", "NXDN", "EDACS"]
DSD_MODES = ("NXDN", "EDACS", "DMR-MS")   # digital modes decoded by dsd-fme through the discriminator tap
# the dsd-fme bridge each mode runs. DMR runs one too, beside op25: its sync lines tell base-station bursts
# (op25 decodes those) from mobile-station / direct-mode ones (then dsd-fme's decode is used)
BRIDGE_PROTO = {"NXDN": "NXDN", "EDACS": "EDACS", "DMR": "DMR", "DMR-MS": "DMR"}

# SmartNet's control channel is 3600 bps BINARY FSK (fsk2mm = the 2-level
# MM-clock-recovery/binary-slicer variant of op25's fsk4 front end — see op25
# apps/multi_rx.py channel() and apps/smartnet_example.json) at a lower
# if_rate/wider excess_bw than the voice modes above — physically incompatible
# with sharing the P25/DMR/NXDN demod slot (wrong symbol rate, wrong slicer),
# so SmartNet gets its own permanently-connected demod + frame_assembler that
# auto-decodes the same way DMR/NXDN already do, with no mode picker involved.
SMARTNET_PARAMS = dict(demod_type="fsk4", filter_type="fsk2mm", symbol_rate=3600,
                       if_rate=18_000, excess_bw=0.35)


def op25_available():
    return OP25_AVAILABLE


class DigitalBranches:
    """Every decoder branch on one radio. Built in attach_radio; nothing runs until start()."""

    def __init__(self, radio, taps):
        self.radio, self.taps = radio, taps
        self.rx_q = None
        self.op25_demod = self.op25_asm = None
        self.sn_demod = self.sn_asm = None
        self.digital_mode = "P25"
        self.nxdn96 = True              # NXDN variant for dsd-fme (False = NXDN48, 6.25 kHz)
        self.edacs_flags = _dsd.edacs_flags()
        self.bridge = None              # the running dsd-fme bridge (NXDN or EDACS)
        self.audio_port = None          # where decoded voice goes (voice.py), or None
        self._fifo_path = None
        self._disc_attached = False
        self.started = False
        if OP25_AVAILABLE:
            self.rx_q = gr.msg_queue(100)
            self.op25_asm = _op25_repeater.frame_assembler(
                f"udp://127.0.0.1:{OP25_AUDIO_PORT}", 0, 0, self.rx_q)
            self.op25_demod = self._make_op25_demod()
            self.sn_asm = _op25_repeater.frame_assembler("smartnet", 0, 1, self.rx_q)
            self.sn_demod = self._make_smartnet_demod()
        self._build_disc()

    # -- wiring ---------------------------------------------------------------------------------------
    def _locked(self, fn):
        r = self.radio
        if r.running:
            r.lock()
        try:
            fn()
        finally:
            if r.running:
                r.unlock()

    def start(self):
        """Connect the always-on branches (op25, SmartNet) in one reconfiguration."""
        if self.started:
            return
        self.started = True

        def go():
            if self.op25_demod is not None:
                self.taps.attach(TAP_CHANNEL, self.op25_demod, edges=[(self.op25_demod, self.op25_asm)])
            if self.sn_demod is not None:
                self.taps.attach(TAP_CHANNEL, self.sn_demod, edges=[(self.sn_demod, self.sn_asm)])
            self._attach_disc()
        self._locked(go)

    def stop(self):
        self.stop_bridge()

        def go():
            for demod in (self.op25_demod, self.sn_demod):
                if demod is not None:
                    self.taps.detach(TAP_CHANNEL, demod)
            self._detach_disc()
        if self.started:
            self._locked(go)
        self.started = False

    # -- op25 ---------------------------------------------------------------------------------------
    def _make_op25_demod(self):
        # Fed from the channel tap (already frequency-translated to baseband + decimated to the fixed
        # QUAD_RATE), NOT the raw wideband source — op25's own front-end filter cost scales with
        # input_rate (measured ~8x from 2.4 to 19.2 Msps). relative_freq is always 0: the channel
        # already centers the tuned channel at baseband, so op25 does no tuning of its own.
        p = DIGITAL_PARAMS.get(self.digital_mode, DIGITAL_PARAMS["P25"])
        return _p25_demodulator.p25_demod_cb(
            msgq_id=0, debug=0, input_rate=QUAD_RATE,
            demod_type=p["demod_type"], filter_type=p["filter_type"],
            usable_bw=OP25_USABLE_BW, excess_bw=p.get("excess_bw", 0.2),
            relative_freq=0, offset=0,
            if_rate=p.get("if_rate", OP25_IF_RATE), symbol_rate=p["symbol_rate"])

    def _make_smartnet_demod(self):
        p = SMARTNET_PARAMS
        return _p25_demodulator.p25_demod_cb(
            msgq_id=1, debug=0, input_rate=QUAD_RATE,
            demod_type=p["demod_type"], filter_type=p["filter_type"],
            usable_bw=OP25_USABLE_BW, excess_bw=p["excess_bw"],
            relative_freq=0, offset=0,
            if_rate=p["if_rate"], symbol_rate=p["symbol_rate"])

    def set_debug(self, level):
        """op25 frame_assembler debug level. At >=10 op25's decoder prints decoded DATA payloads
        (short-data / LRRP / PDU / PDP bursts) to stderr — the only place that data is exposed.
        Set BOTH ways (set_debug() and the 'set_debug' control command): op25 builds propagate it to
        the per-protocol decoders through one path or the other."""
        if self.op25_asm is None:
            return
        level = int(level)
        try:
            self.op25_asm.set_debug(level)
        except Exception:
            pass
        try:
            self.op25_asm.control(json.dumps({"tuner": 0, "cmd": "set_debug", "debug": level}))
        except Exception:
            pass

    def add_crypt_key(self, keyid, algid, key_bytes):
        """Load a P25 decryption key into op25's frame_assembler (5 bytes ADP, 8 DES-OFB, 32 AES-256).
        True if the command was issued. The frame_assembler persists across mode changes."""
        if self.op25_asm is None:
            return False
        try:
            self.op25_asm.control(json.dumps({
                "tuner": 0, "cmd": "crypt_key",
                "keyid": int(keyid), "algid": int(algid),
                "key": [int(b) & 0xff for b in key_bytes]}))
            return True
        except Exception:
            return False

    def set_mode(self, name, nxdn96=None):
        """Switch the op25 demod filter (P25 / DMR / NXDN / EDACS) and start / stop / restart dsd-fme.
        A change of NXDN variant while on NXDN restarts dsd-fme (compared against the running bridge)."""
        if nxdn96 is not None:
            self.nxdn96 = bool(nxdn96)
        if name == "NXDN" and self.digital_mode == "NXDN":
            b = self.bridge
            if b is not None and b.nxdn96 != self.nxdn96:
                self.stop_bridge()
                self.start_bridge("NXDN")
            elif b is None and self.started:
                self.start_bridge("NXDN")
            return
        if name not in DIGITAL_PARAMS:
            return
        want = BRIDGE_PROTO.get(name)
        if name == self.digital_mode:
            if want and self.bridge is None and self.started:
                self.start_bridge(want)
            return
        same_filter = DIGITAL_PARAMS[name] == DIGITAL_PARAMS.get(self.digital_mode)
        self.digital_mode = name
        if self.bridge is not None and self.bridge.proto != want:
            self.stop_bridge()          # one dsd-fme at a time: the old protocol's goes first
        if self.op25_demod is not None and not same_filter:
            old = self.op25_demod
            new = self._make_op25_demod()

            def swap():
                if self.started:
                    self.taps.detach(TAP_CHANNEL, old)
                self.op25_demod = new
                if self.started:
                    self.taps.attach(TAP_CHANNEL, new, edges=[(new, self.op25_asm)])
            self._locked(swap)
        if want and self.bridge is None and self.started:
            self.start_bridge(want)

    def set_edacs_flags(self, flags):
        """dsd-fme flags for EDACS (variant / AFS / -C channel map). Restarts a running EDACS bridge."""
        self.edacs_flags = list(flags)
        b = self.bridge
        if getattr(b, "proto", None) == "EDACS" and b.flags != self.edacs_flags:
            self.stop_bridge()
            self.start_bridge("EDACS")

    # -- the discriminator tap -> dsd-fme ---------------------------------------------------------------
    def _build_disc(self):
        # A plain FM discriminator off the channel (the core NFM mode's channel filter and gain --
        # a calibration proven in this RF chain; dsd-fme's own symbol leveling needs only a clean,
        # unclipped signal). dsd-fme's pipe-friendly input expects 16-bit PCM discriminator audio and
        # does its own symbol timing recovery from it.
        cutoff = max(2_500, NFM_BW / 2)
        self.disc_filt = gr_filter.fir_filter_ccf(STAGE2_DECIM, firdes.low_pass(1.0, QUAD_RATE, cutoff, cutoff / 2))
        self.disc = analog.quadrature_demod_cf(AUDIO_RATE / (2.0 * math.pi * NFM_MAX_DEV))
        # Remove the discriminator's DC: a transmitter off the tuned grid (e.g. 1.4 kHz off when the
        # click snapped to the 12.5 kHz grid) puts a constant offset on every 4FSK level, and
        # dsd-fme's fixed-center slicer then reads almost nothing (a real NXDN48 file: 0 clean
        # frames as tapped, 174 with the DC removed -- the same as decoding it re-centered).
        self.disc_dc = gr_filter.dc_blocker_ff(NXDN_DC_BLOCK_LEN, True)
        self.disc_clip = analog.rail_ff(-1.0, 1.0)
        self.disc_f2s = blocks.float_to_short(1, 32767.0)
        self.disc_sink = blocks.file_sink(gr.sizeof_short, os.devnull, False)
        self.disc_sink.set_unbuffered(True)   # real-time: no stdio buffering lag
        self.disc_sink.close()
        self._disc_edges = [(self.disc_filt, self.disc), (self.disc, self.disc_dc), (self.disc_dc, self.disc_clip),
                            (self.disc_clip, self.disc_f2s), (self.disc_f2s, self.disc_sink)]

    def _attach_disc(self):
        if self._disc_attached:
            return

        self.taps.attach(TAP_CHANNEL, self.disc_filt, edges=self._disc_edges)
        self._disc_attached = True

    def _detach_disc(self):
        """(caller holds the lock or the radio is stopped)"""
        if not self._disc_attached:
            return
        self.taps.detach(TAP_CHANNEL, self.disc_filt)
        self._disc_attached = False

    def bridge_available(self):
        return _dsd.dsd_fme_available()

    def start_bridge(self, proto="NXDN"):
        """Arm dsd-fme on the discriminator tap: attach the tap, make a fresh FIFO, hand the other end to a
        new dsd-fme subprocess, then point the tap's file_sink at it. Its lock_changed (a CRC-clean sync)
        is what gates audio and the log. False if dsd-fme isn't there or a bridge already runs."""
        if not self.bridge_available() or self.bridge is not None:
            return False
        path = os.path.join(tempfile.gettempdir(), f"sdrexplorer_nxdn_{os.getpid()}.fifo")
        if proto == "EDACS":
            bridge = _dsd.EdacsBridge(path, flags=self.edacs_flags, audio_port=self.audio_port)
        elif proto == "DMR":
            bridge = _dsd.DmrBridge(path, audio_port=self.audio_port)
        else:
            bridge = _dsd.NxdnBridge(path, nxdn96=self.nxdn96, audio_port=self.audio_port)
        bridge.start()
        if not bridge.reader_ready(timeout=3.0):
            bridge.stop()
            bridge.wait(2000)
            return False
        self.disc_sink.open(path)   # reader already attached -> returns immediately
        self._fifo_path = path
        self.bridge = bridge
        return True

    def stop_bridge(self):
        if self.bridge is None:
            return
        self.disc_sink.close()
        self.bridge.stop()
        self.bridge.wait(2000)
        self.bridge = None
        self._fifo_path = None

    def flush(self):
        """The channel moved: PCM still queued for dsd-fme is the old channel's."""
        b = self.bridge
        if b is not None:
            b.flush()
