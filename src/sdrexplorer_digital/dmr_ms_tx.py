# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""DMR mobile-station voice transmit, wired as an api.TxModeSpec.

op25's dmr_bs_tx_bb makes base-station bursts (repeater output); this makes MOBILE-station bursts, which
a repeater's RECEIVER accepts. The streaming/rate-locked part is a C++ block, `op25_repeater.dmr_ms_tx_bb`
(added by the op25 patch, modeled on dmr_bs_tx_bb): it reads AMBE codewords and emits DMR dibit bursts.
All the FEC'd CONSTANT bursts for a call (voice LC header, terminator, CACH, the 6 voice-superframe
middle fields = MS sync + embedded-LC fragments) are precomputed here in Python by `dmr_ms_frame` (the
generator verified against dsd-fme, in file loopback and over the air) and handed to the C++ block as a
flat dibit config file; the C++ block reimplements no FEC.

build_dmr_ms(tb, audio, settings): mic/file audio -> ambe_encoder_sb -> dmr_ms_tx_bb -> C4FM -> complex
baseband at TX_RATE. The deviation chain matches op25's own DMR TX (verified on-air):
p25_mod_bf(rrc) -> *5.5 -> FM(2*pi*12500*0.35/rate). cleanup_dmr_ms() appends the terminator and removes
the temp config file.
"""
from __future__ import annotations

import math
import os
import tempfile

from gnuradio import analog, blocks
from gnuradio import filter as gr_filter

from sdrexplorer.api import TX_RATE

from . import branches as _br
from . import dmr_ms_frame as _frame

try:
    import op25_c4fm_mod as _op25_c4fm_mod
    MS_TX_AVAILABLE = _br.OP25_AVAILABLE and hasattr(_br._op25_repeater, "ambe_encoder_sb") \
        and hasattr(_br._op25_repeater, "dmr_ms_tx_bb")
except Exception:
    _op25_c4fm_mod = None
    MS_TX_AVAILABLE = False

AUDIO_RATE = 48_000
DV_VOICE_RATE = 8_000
DV_AUDIO_LPF_HZ = 3_400.0
# op25's own DMR TX deviation chain (dv_tx.py / tx.build_dmr), verified on-air in the prototype.
DV_MAX_DEV = 12_500.0
DMR_MOD_OUTPUT_GAIN = 5.5
DMR_MOD_ADJUST = 0.35

MS_DEFAULT_CC = 1
MS_DEFAULT_TGID = 9
MS_DEFAULT_SRC = 1


def ms_tx_available():
    if MS_TX_AVAILABLE:
        return (True, "")
    return (False, "needs op25's TX support with the dmr_ms_tx_bb block "
                   "(ambe_encoder_sb + apps/tx/op25_c4fm_mod + the sdrexplorer op25 patch)")


def write_ms_config(cc, tgid, src):
    """Precompute the call's constant bursts and write the C++ block's 444-byte dibit config:
    header[144] term[144] cach[12] mid0..5[24 each]. Returns the temp file path."""
    cc, tgid, src = int(cc) & 0xf, int(tgid) & 0xffffff, int(src) & 0xffffff
    header = _frame.voice_lc_header(tgid, src, cc)          # 144 dibits
    term = _frame.terminator_lc(tgid, src, cc)              # 144
    cach = _frame.cach_field(cc)                            # 12
    mids = _frame.voice_mid_fields(tgid, src, cc)           # 6 x 24
    buf = bytearray()
    buf += bytes(d & 3 for d in header)
    buf += bytes(d & 3 for d in term)
    buf += bytes(d & 3 for d in cach)
    for m in mids:
        buf += bytes(d & 3 for d in m)
    assert len(buf) == 444, len(buf)
    fd, path = tempfile.mkstemp(prefix="sdrexplorer_dmr_ms_tx_", suffix=".bin")
    with os.fdopen(fd, "wb") as fh:
        fh.write(buf)
    return path


def _voice_pcm(tb, audio):
    lpf = gr_filter.firdes.low_pass(1.0, AUDIO_RATE, DV_AUDIO_LPF_HZ, DV_AUDIO_LPF_HZ * 0.1)
    decim = gr_filter.fir_filter_fff(AUDIO_RATE // DV_VOICE_RATE, lpf)
    ascale = blocks.multiply_const_ff(32767.0)
    f2s = blocks.float_to_short()
    tb.connect(audio, decim, ascale, f2s)
    return f2s


def build_dmr_ms(tb, audio, settings):
    """api.TxModeSpec build: audio -> AMBE -> dmr_ms_tx_bb -> C4FM, returns the complex baseband block.
    Keeps the framer handle + config path on tb so cleanup_dmr_ms can flush the terminator and unlink."""
    if not MS_TX_AVAILABLE:
        raise RuntimeError(ms_tx_available()[1])
    conf = write_ms_config(settings.get("cc", MS_DEFAULT_CC), settings.get("tgid", MS_DEFAULT_TGID),
                           settings.get("src", MS_DEFAULT_SRC))
    tb._dmr_ms_conf_path = conf
    pcm = _voice_pcm(tb, audio)
    enc = _br._op25_repeater.ambe_encoder_sb(0)
    framer = _br._op25_repeater.dmr_ms_tx_bb(0, conf)
    tb._dmr_ms_framer = framer
    c4fm = _op25_c4fm_mod.p25_mod_bf(output_sample_rate=TX_RATE, rc="rrc")
    mgain = blocks.multiply_const_ff(DMR_MOD_OUTPUT_GAIN)
    mod = analog.frequency_modulator_fc(2 * math.pi * DV_MAX_DEV * DMR_MOD_ADJUST / TX_RATE)
    tb.connect(pcm, enc, framer, c4fm, mgain, mod)
    return mod


def cleanup_dmr_ms(tb):
    framer = getattr(tb, "_dmr_ms_framer", None)
    if framer is not None:
        try:
            framer.send_terminator()       # append the call terminator before the flowgraph stops
        except Exception:
            pass
        tb._dmr_ms_framer = None
    path = getattr(tb, "_dmr_ms_conf_path", None)
    if path:
        try:
            os.unlink(path)
        except OSError:
            pass
        tb._dmr_ms_conf_path = None
