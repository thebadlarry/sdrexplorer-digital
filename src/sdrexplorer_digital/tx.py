# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""P25 and DMR digital-voice transmit, as api.TxModeSpec modulators (moved from sdrexplorer's TxChain).

The core's transmit flowgraph gives float audio at 48 kHz; each modulator here returns complex baseband at
api.TX_RATE (240 kHz). P25 IMBE-encodes the audio (op25's vocoder, CLEAR VOICE ONLY — op25 has no TX-side
encryption) into C4FM symbols and FM-modulates them; DMR AMBE-encodes it (two timeslots: the call on slot
1, idle on slot 2) into op25's dmr_bs_tx_bb, into the same C4FM-family symbol stream (RRC-shaped instead
of P25's RC) via the same op25_c4fm_mod.p25_mod_bf.
"""
from __future__ import annotations

import math
import os
import tempfile

from gnuradio import analog, blocks
from gnuradio import filter as gr_filter

from sdrexplorer.api import TX_RATE

from . import branches as _br

AUDIO_RATE = 48_000
# op25_c4fm_mod.py lives in gr-op25_repeater/apps/tx (activated with op25_apps); op25_repeater.vocoder /
# ambe_encoder_sb / dmr_bs_tx_bb are in the same compiled extension the receive side imports.
try:
    import op25_c4fm_mod as _op25_c4fm_mod
    P25_TX_AVAILABLE = _br.OP25_AVAILABLE and hasattr(_br._op25_repeater, "vocoder")
    DMR_TX_AVAILABLE = _br.OP25_AVAILABLE and hasattr(_br._op25_repeater, "dmr_bs_tx_bb") \
        and hasattr(_br._op25_repeater, "ambe_encoder_sb")
except Exception:
    _op25_c4fm_mod = None
    P25_TX_AVAILABLE = False
    DMR_TX_AVAILABLE = False

DV_VOICE_RATE = 8_000                # IMBE/AMBE vocoders' native PCM rate
DV_AUDIO_LPF_HZ = 3_400.0            # voice bandwidth, matches op25's own dv_tx.py
DV_MAX_DEV = 12_500.0                # shared base deviation (op25's dv_tx.py setup_sdr_output)
# The gain/deviation constants below are op25's OWN reference TX (dv_tx.py: output_gains /
# gain_adjust_fullrate / mod_adjust, keyed by protocol) reused verbatim — verified end to end by feeding
# these TX chains into the receive chain (same demod params), which locked and decoded both P25 and DMR.
P25_ENCODER_GAIN_ADJUST = 2.0        # op25_repeater.vocoder.set_gain_adjust()
P25_MOD_OUTPUT_GAIN = 4.5            # post-p25_mod_bf amplitude gain
P25_MOD_ADJUST = 0.33                # k = 2*pi*DV_MAX_DEV*P25_MOD_ADJUST/rate
DMR_MOD_OUTPUT_GAIN = 5.5
DMR_MOD_ADJUST = 0.35
# DMR TX defaults (color code / talkgroup / radio ID); op25's dmr_bs_tx_bb needs a config file naming
# these per timeslot. Slot 2 is always idle (en2=0): one voice path per PTT press.
DMR_DEFAULT_CC = 1
DMR_DEFAULT_TGID = 9
DMR_DEFAULT_RADIO_ID = 1
# P25 TX defaults. NAC is the repeater's network access code (hex); op25's
# historic fixed value was 0x293. The Link Control defaults to a group call on
# P25_DEFAULT_TGID from P25_DEFAULT_SRC — a repeater that validates the LC (not
# just the NAC) needs a real one. Settable via Settings > Transmit; needs the
# op25 TX NAC/LC patch (vocoder.set_nac / set_lc), else they're ignored.
P25_DEFAULT_NAC = 0x293
P25_DEFAULT_TGID = 1
P25_DEFAULT_SRC = 1


def p25_available():
    return (True, "") if P25_TX_AVAILABLE else (False, "needs op25's TX support (op25_repeater.vocoder + "
                                                       "apps/tx/op25_c4fm_mod)")


def dmr_available():
    return (True, "") if DMR_TX_AVAILABLE else (False, "needs op25's TX support (ambe_encoder_sb + dmr_bs_tx_bb)")


def _voice_pcm(tb, audio):
    """48 kHz float -> 8 kHz s16 for the vocoders."""
    lpf = gr_filter.firdes.low_pass(1.0, AUDIO_RATE, DV_AUDIO_LPF_HZ, DV_AUDIO_LPF_HZ * 0.1)
    decim = gr_filter.fir_filter_fff(AUDIO_RATE // DV_VOICE_RATE, lpf)
    ascale = blocks.multiply_const_ff(32767.0)
    f2s = blocks.float_to_short()
    tb.connect(audio, decim, ascale, f2s)
    return f2s


def build_p25(tb, audio, settings):
    if not P25_TX_AVAILABLE:
        raise RuntimeError(p25_available()[1])
    pcm = _voice_pcm(tb, audio)
    enc = _br._op25_repeater.vocoder(True, False, 0, "", 0, False)
    enc.set_gain_adjust(P25_ENCODER_GAIN_ADJUST)
    # NAC + Link Control (clear voice only). set_nac / set_lc need the op25 TX
    # patch; guard so an unpatched op25 still transmits with its baked NAC 0x293.
    nac = int(settings.get("nac", P25_DEFAULT_NAC)) & 0xfff
    tgid = int(settings.get("tgid", P25_DEFAULT_TGID)) & 0xffff
    src = int(settings.get("src", P25_DEFAULT_SRC)) & 0xffffff
    if hasattr(enc, "set_nac"):
        enc.set_nac(nac)
        # LCF 0 (group voice), MFID 0, no service options, s=0 (no explicit-source
        # flag — the normal group LC), talkgroup, source radio ID.
        enc.set_lc(0, 0, 0, 0, tgid, 0, src)
    c4fm = _op25_c4fm_mod.p25_mod_bf(output_sample_rate=TX_RATE, rc="rc")
    mgain = blocks.multiply_const_ff(P25_MOD_OUTPUT_GAIN)
    mod = analog.frequency_modulator_fc(2 * math.pi * DV_MAX_DEV * P25_MOD_ADJUST / TX_RATE)
    tb.connect(pcm, enc, c4fm, mgain, mod)
    return mod


def write_dmr_config(cc, tgid, radio_id):
    """A dmr_bs_tx_bb config file (its own key=value format) for a single-slot TX: slot 1 carries the call,
    slot 2 is idle. Returns the temp file path."""
    cc, tgid, radio_id = int(cc) & 0xf, int(tgid) & 0xffffff, int(radio_id) & 0xffffff
    lines = ["ts1=0", "ts2=0", f"cc1={cc}", f"cc2={cc}", "so1=0", "so2=0",
             f"ga1={tgid}", f"ga2={tgid}", f"sa1={radio_id}", f"sa2={radio_id}", "en1=1", "en2=0"]
    fd, path = tempfile.mkstemp(prefix="sdrexplorer_dmr_tx_", suffix=".conf")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def build_dmr(tb, audio, settings):
    if not DMR_TX_AVAILABLE:
        raise RuntimeError(dmr_available()[1])
    conf = write_dmr_config(settings.get("cc", DMR_DEFAULT_CC), settings.get("tgid", DMR_DEFAULT_TGID),
                            settings.get("radio_id", DMR_DEFAULT_RADIO_ID))
    tb._dmr_conf_path_digital = conf
    pcm = _voice_pcm(tb, audio)
    enc1 = _br._op25_repeater.ambe_encoder_sb(0)
    tb.connect(pcm, enc1)
    silence = blocks.vector_source_s([0], True)   # repeating zero -> idle slot 2
    enc2 = _br._op25_repeater.ambe_encoder_sb(0)
    tb.connect(silence, enc2)
    dmr = _br._op25_repeater.dmr_bs_tx_bb(0, conf)
    tb.connect(enc1, (dmr, 0))
    tb.connect(enc2, (dmr, 1))
    c4fm = _op25_c4fm_mod.p25_mod_bf(output_sample_rate=TX_RATE, rc="rrc")
    mgain = blocks.multiply_const_ff(DMR_MOD_OUTPUT_GAIN)
    mod = analog.frequency_modulator_fc(2 * math.pi * DV_MAX_DEV * DMR_MOD_ADJUST / TX_RATE)
    tb.connect(dmr, c4fm, mgain, mod)
    return mod


def cleanup_dmr(tb):
    path = getattr(tb, "_dmr_conf_path_digital", None)
    if path:
        try:
            os.unlink(path)
        except OSError:
            pass
        tb._dmr_conf_path_digital = None
