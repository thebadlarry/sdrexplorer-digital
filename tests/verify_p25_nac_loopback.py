#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""Loopback verification of the op25 P25 TX NAC + Link Control patch.

Feeds a tone through op25's P25 voice encoder (vocoder, encode mode) with a
chosen NAC and Link Control, modulates it (op25_c4fm_mod.p25_mod_bf) to C4FM at
240 kHz, resamples to op25's 24 kHz IF rate, and decodes it with op25's OWN
receive chain (p25_demod_cb -> frame_assembler). It asserts the decoder reports
back the NAC and the LC (talkgroup + source) that were set.

This exercises the ported BCH(64,16,23) NID encoder and the RS(24,12,13) +
Hamming(10,6,3) Link Control encoder end to end against op25's bch.cc /
p25p1_fdma.cc — a bit error in either would fail the decode.

Run (op25 on the path, a writable HOME):

  SDREXPLORER_OP25=<op25 install prefix> \
  SDREXPLORER_OP25_APPS=<op25 checkout>/op25/gr-op25_repeater/apps \
  PYTHONPATH=<sdrexplorer checkout> \
  python3 tests/verify_p25_nac_loopback.py

Exits 0 and prints "ok" on success; nonzero with a diagnostic otherwise.
"""
import json
import math
import sys
import time

# op25 made importable the way the digital module does it: register the module's
# path keys, then activate (preloads its shared libs via ctypes, adds its python
# + apps dirs). Point at the build with SDREXPLORER_OP25 / _APPS or paths.json.
from sdrexplorer import paths as _paths
from sdrexplorer_digital.pathkeys import register_paths
register_paths()
_paths.activate("op25")
_paths.activate("op25_apps")

from gnuradio import analog, blocks, gr
from gnuradio import filter as gr_filter
from gnuradio import op25_repeater
import op25_c4fm_mod
import p25_demodulator

TX_RATE = 240_000        # api.TX_RATE: the modulator's output rate
IF_RATE = 24_000         # op25's receive IF rate (branches.OP25_IF_RATE)
AUDIO_RATE = 8_000       # IMBE vocoder PCM rate

# Message types (op25_msg_types.h / monitor.py)
M_P25_FDMA_LCW = 19
PROTO_SHIFT = 16         # msg.type() high 16 bits = protocol id (0 == P25)


def build_and_run(nac, lco, mfid, svcopt, s, tgid, dst, src, seconds=3.0):
    tb = gr.top_block()

    # --- TX: tone -> IMBE encode (with NAC/LC) -> C4FM -> FM baseband --------
    tone = analog.sig_source_f(AUDIO_RATE, analog.GR_SIN_WAVE, 600.0, 8000.0)
    f2s = blocks.float_to_short()
    enc = op25_repeater.vocoder(True, False, 0, "", 0, False)  # encode mode
    enc.set_gain_adjust(2.0)
    enc.set_nac(nac)
    enc.set_lc(lco, mfid, svcopt, s, tgid, dst, src)
    c4fm = op25_c4fm_mod.p25_mod_bf(output_sample_rate=TX_RATE, rc="rc")
    mgain = blocks.multiply_const_ff(4.5)
    fm = analog.frequency_modulator_fc(2 * math.pi * 12_500.0 * 0.33 / TX_RATE)
    tb.connect(tone, f2s, enc, c4fm, mgain, fm)

    # --- resample 240k -> 24k, feed op25's receive demod + frame_assembler ---
    resamp = gr_filter.rational_resampler_ccf(interpolation=IF_RATE // 2000,
                                              decimation=TX_RATE // 2000)
    rx_q = gr.msg_queue(1000)
    asm = op25_repeater.frame_assembler("", 0, 0, rx_q)      # P25/DMR auto-sync
    demod = p25_demodulator.p25_demod_cb(
        msgq_id=0, debug=0, input_rate=IF_RATE,
        demod_type="fsk4", filter_type="rc", usable_bw=0.85, excess_bw=0.2,
        relative_freq=0, offset=0, if_rate=IF_RATE, symbol_rate=4800)
    tb.connect(fm, resamp, demod, asm)

    tb.start()
    time.sleep(seconds)
    tb.stop()
    tb.wait()

    # --- drain the message queue, collect NAC + LCW ------------------------
    nacs, lcws = set(), []
    while not rx_q.empty_p():
        msg = rx_q.delete_head()
        t = msg.type()
        proto = t >> PROTO_SHIFT
        m_type = t & 0xffff
        if m_type >= 0x8000:
            m_type -= 0x10000
        body = msg.to_string()
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        body = bytes(body)
        if proto != 0 or len(body) < 2:
            continue
        got_nac = (body[0] << 8) | body[1]
        if got_nac <= 0xfff:
            nacs.add(got_nac)
        if m_type == M_P25_FDMA_LCW and len(body) >= 11:
            lcw = body[2:11]
            lcws.append({
                "lco": lcw[0] & 0x3f,
                "tgid": (lcw[3] << 16) | (lcw[4] << 8) | lcw[5],
                "src": (lcw[6] << 16) | (lcw[7] << 8) | lcw[8],
            })
    return nacs, lcws


def main():
    # A typical repeater access: NAC 0x123, group call TG 9, source 0x0003E9. s=0 (no
    # explicit-source flag) is the normal group-voice LC; s=1 sets bit 32, which
    # op25's LCW parse (and sdrexplorer's monitor) folds into the TGID field.
    want_nac, want_tg, want_src = 0x123, 9, 0x0003E9
    nacs, lcws = build_and_run(nac=want_nac, lco=0, mfid=0, svcopt=0, s=0,
                               tgid=want_tg, dst=0, src=want_src)
    print(f"decoded NACs: {sorted(hex(n) for n in nacs)}")
    print(f"decoded LCWs: {lcws[:3]}{'…' if len(lcws) > 3 else ''} ({len(lcws)} total)")
    ok = True
    if want_nac not in nacs:
        print(f"FAIL: NAC {want_nac:#x} not reported by the decoder")
        ok = False
    tg_ok = any(l["tgid"] == want_tg and l["src"] == want_src for l in lcws)
    if not tg_ok:
        print(f"FAIL: no LCW with TG {want_tg} src {want_src:#x}")
        ok = False
    if ok:
        print(f"ok  P25 NAC {want_nac:#x} + LC (TG {want_tg}, src {want_src:#x}) "
              "round-tripped through op25's own receiver")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
