# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""Decoder proofs for the "sdrexplorer.proofs" entry point: ``fn(iq, fs) -> {"ok", "decoder", "frames",
"clean", "crc_err", "ids", "detail"}``, ``iq`` complex at ``fs`` with the signal at 0 Hz. Used by the hunt,
"Label as..." checks and the training tools without loading this module's UI: numpy / scipy and a dsd-fme
subprocess only, no Qt or GNU Radio.

The rules:
- DMR / P25-P1 / NXDN48 / NXDN96: the crop is FM-discriminated to 48 kHz 16-bit PCM like the module's
  discriminator tap (~6.25 kHz low-pass, full scale = 5 kHz), decoded with that mode's dsd-fme decoder; it
  passes with >= 4 sync lines of the protocol plus a CRC/FEC-clean field (color code, NAC, RAN / AMBE
  err=0). NXDN lines marked "PF X/" don't count: dsd-fme reprints the last good RAN on a SACCH whose CRC
  failed.
- EDACS (control channel): >= 8 BCH-clean dsd-fme -fe frames per 2 s.
- EDACS-V (analog working channel): >= 0.08 s of 9600 Bd dotting. Dotting comes only at a call's end, so
  this proves a RECORDING, not a crop.
- SmartNet: >= 4 CRC-valid OSWs (op25 rx_smartnet's deinterleave, parity correction and CRC).
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import wave

import numpy as np
from scipy.signal import butter, resample_poly, sosfiltfilt

DECODER = {"DMR": "-fs", "P25-P1": "-f1", "NXDN48": "-fi", "NXDN96": "-fn"}
CRC_ERR_RE = re.compile(r"CRC ERR|\(CRC ERR\)|ERR\b|FEC ERR", re.I)
SYNC_RE = re.compile(r"Sync:", re.I)
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Proof of a real decode, per protocol: a field that only exists after FEC/CRC passed. Validated against
# real dsd-fme output (NXDN48 "RAN 02" + AMBE err=[0], DMR "Color Code=10" + SLC_C_SYS_PARMS).
PROOF = {
    "DMR": re.compile(r"Color Code=\d+|SLC_C_SYS_PARMS|Net ID:|TGT=|SRC=", re.I),
    "P25-P1": re.compile(r"NAC(/CC)?[:= ]+[0-9A-F]{3}|TGID|SRC:|LDU\d|HDU|TSBK", re.I),
    "NXDN48": re.compile(r"\bRAN \d+|Location ID|SRV_INFO|SITE_INFO|AMBE [0-9A-F]+ err = \[0\]", re.I),
    "NXDN96": re.compile(r"\bRAN \d+|Location ID|SRV_INFO|SITE_INFO|AMBE [0-9A-F]+ err = \[0\]", re.I),
}
MIN_SYNCS = 4          # sync lines of the right protocol in a 2 s crop (DMR ~33/s, NXDN 12.5/s, P25 ~5.6/s)
NOT_PROOF_RE = re.compile(r"\bPF X/")
# system id in a proof line: DMR color code, P25 NAC, NXDN RAN
IDS_RE = {"DMR": re.compile(r"Color Code=(\d+)"), "P25-P1": re.compile(r"NAC(?:/CC)?[:= ]+([0-9A-F]{3})"),
          "NXDN48": re.compile(r"\bRAN (\d+)"), "NXDN96": re.compile(r"\bRAN (\d+)")}

EDACS_MIN_FRAMES = 8   # BCH-clean EDACS frames in a 2 s crop (a control channel sends ~33/s; real crops
#                        give 42-64 with the standard 6.25 kHz filter -- a 9 kHz one gave only 1-21)
EDACS_SYNC_RE = re.compile(r"Sync: [+-]EDACS")
EDACS_IDS_RE = re.compile(r"Site ID \[([0-9A-F]{2})\]")
EDACS_DOT_S = 0.08     # longest 9600 Bd dotting run (s). A real call end: 0.16 s; other modes' crops <= 0.02 s
SN_MIN_OSW = 4         # CRC-valid SmartNet OSWs in a crop


def dsd_fme():
    """(program, environment) of dsd-fme: the paths key dsd_fme (registered by this module), else PATH."""
    from sdrexplorer.api import paths
    from .pathkeys import register_paths
    register_paths()
    return paths.program("dsd_fme", "dsd-fme") or "dsd-fme", paths.tool_env("dsd_fme")


def to_wav(iq, fs, path, max_dev=5000.0, out_fs=48000):
    z = np.asarray(iq, np.complex64)
    z = sosfiltfilt(butter(6, 6250, fs=fs, output="sos"), z)
    disc = np.angle(z[1:] * np.conj(z[:-1])) * fs / (2 * np.pi)      # Hz
    a = resample_poly(disc, out_fs // 8000 * 1, int(fs) // 8000) if int(fs) % 8000 == 0 else \
        resample_poly(disc, out_fs, int(fs))
    pcm = np.clip(a / max_dev, -1, 1)                                   # full scale = max_dev
    with wave.open(path, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(out_fs)
        w.writeframes((pcm * 32767).astype("<i2").tobytes())


def run_dsd(wav, flag, timeout=30):
    dsd, env = dsd_fme()
    try:
        p = subprocess.run([dsd, flag, "-i", wav, "-o", "null", "-Z"], capture_output=True, text=True,
                           timeout=timeout, env=env, stdin=subprocess.DEVNULL)
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired as e:
        return (e.stdout or "") + (e.stderr or "") if isinstance(e.stdout, str) else ""
    except OSError as e:
        return f"dsd-fme not runnable: {e}"


def judge(label, text):
    lines = [ANSI.sub("", ln) for ln in text.splitlines() if ln.strip()]
    want = {"DMR": "DMR", "P25-P1": "P25", "NXDN48": "NXDN48", "NXDN96": "NXDN96"}[label]
    sync_ok = [ln for ln in lines if SYNC_RE.search(ln) and want in ln.upper()]
    other = [ln for ln in lines if SYNC_RE.search(ln) and "no sync" not in ln.lower() and want not in ln.upper()]
    proof = [ln for ln in lines if PROOF[label].search(ln) and not CRC_ERR_RE.search(ln)
             and not NOT_PROOF_RE.search(ln)]
    errs = [ln for ln in lines if CRC_ERR_RE.search(ln)]
    ok = len(sync_ok) >= MIN_SYNCS and len(proof) >= 1
    ids = sorted({int(m.group(1), 16) if label == "P25-P1" else int(m.group(1))
                  for ln in proof for m in [IDS_RE[label].search(ln)] if m})
    return {"ok": ok, "syncs": len(sync_ok), "other_syncs": len(other), "frames": len(sync_ok),
            "clean": len(proof), "crc_err": len(errs), "ids": ids if ok else [],
            "detail": (sync_ok[:1] + proof[:2]) if ok else (sync_ok[:1] + errs[:1] or ["no sync"])}


def _dsd_proof(label):
    def proof(iq, fs):
        with tempfile.TemporaryDirectory() as td:
            wav = os.path.join(td, "x.wav")
            to_wav(iq, fs, wav)
            out = run_dsd(wav, DECODER[label])
        r = judge(label, out)
        r["decoder"] = f"dsd-fme {DECODER[label]}"
        return r
    proof.__name__ = f"verify_{label.replace('-', '_').lower()}"
    return proof


def verify_edacs(iq, fs):
    """EDACS control channel: dsd-fme -fe frames that passed its BCH check. The BCH check comes before the
    Standard / Extended Addressing interpretation, so -fe proves an EDACS frame either way."""
    with tempfile.TemporaryDirectory() as td:
        wav = os.path.join(td, "x.wav")
        to_wav(iq, fs, wav)
        out = run_dsd(wav, "-fe")
    lines = [ANSI.sub("", ln) for ln in out.splitlines()]
    sync = [ln for ln in lines if EDACS_SYNC_RE.search(ln)]
    clean = [ln for ln in sync if "BCH FAIL" not in ln]
    need = max(4, int(round(EDACS_MIN_FRAMES * len(iq) / fs / 2.0)))
    ok = len(clean) >= need
    ids = sorted({int(m.group(1), 16) for ln in clean for m in [EDACS_IDS_RE.search(ln)] if m})
    return {"ok": bool(ok), "decoder": "dsd-fme -fe", "syncs": len(sync), "frames": len(sync),
            "clean": len(clean), "crc_err": len(sync) - len(clean), "ids": ids if ok else [],
            "detail": clean[:2] if ok else (sync[:1] or ["no EDACS frame"])}


def edacs_dotting(iq, fs, blk_s=0.02):
    """Longest run (s) of 20 ms blocks whose FM-discriminator power sits at 4800 Hz, i.e. 1010... at
    9600 Bd: the dotting an EDACS working channel sends around the end of a call. Speech, CTCSS/DCS and
    other 4FSK/2FSK modes don't hold that line for 3+ blocks."""
    z = sosfiltfilt(butter(6, 8000, fs=fs, output="sos"), np.asarray(iq, np.complex64))
    d = np.angle(z[1:] * np.conj(z[:-1])) * fs / (2 * np.pi)
    b = int(blk_s * fs)
    n = len(d) // b
    if n == 0:
        return 0.0
    D = d[:n * b].reshape(n, b)
    D = D - D.mean(1, keepdims=True)
    S = np.abs(np.fft.rfft(D * np.hanning(b), axis=1)) ** 2
    f = np.fft.rfftfreq(b, 1 / fs)
    on = S[:, np.abs(f - 4800) <= 300].sum(1) / (S[:, (f > 200) & (f < 10000)].sum(1) + 1e-20) > 0.5
    best = cur = 0
    for v in on:
        cur = cur + 1 if v else 0
        best = max(best, cur)
    return best * blk_s


def verify_edacs_voice(iq, fs):
    """EDACS working channel (analog FM voice): proven per RECORDING, not per crop -- use on the whole file."""
    t = edacs_dotting(iq, fs)
    return {"ok": bool(t >= EDACS_DOT_S), "decoder": "edacs-dotting", "frames": int(round(t / 0.02)),
            "clean": int(round(t / 0.02)), "crc_err": 0, "ids": [],
            "detail": [f"9600 Bd dotting {t:.2f} s" if t else "no EDACS dotting"]}


def smartnet_crc(data):
    """op25 rx_smartnet::crc_check over 27 data bits -> 10-bit CRC (transmitted inverted)."""
    acc, op = 0x0393, 0x036E
    for b in data:
        op = (op >> 1) ^ 0x0225 if op & 1 else op >> 1
        if b:
            acc ^= op
    return acc


def smartnet_osws(iq, fs, baud=3600):
    """CRC-valid SmartNet OSWs in a crop: FM-discriminate, integrate-and-dump at 3600 Bd (best of 12
    phases), find the 0xAC sync, then op25 rx_smartnet's deinterleave + parity correction + CRC."""
    z = sosfiltfilt(butter(6, 5000, fs=fs, output="sos"), np.asarray(iq, np.complex64))
    d = np.angle(z[1:] * np.conj(z[:-1]))
    sps = fs / baud
    sync = np.array([1, 0, 1, 0, 1, 1, 0, 0])
    best = 0
    for ph in np.linspace(0, sps, 12, endpoint=False):
        st = (ph + np.arange(int((len(d) - ph - sps) / sps)) * sps).astype(int)
        c = np.concatenate([[0], np.cumsum(d)])
        bits = ((c[np.minimum(st + int(round(sps)), len(d))] - c[st]) > 0).astype(int)
        good = 0
        for i in np.flatnonzero((np.lib.stride_tricks.sliding_window_view(bits, 8) == sync).all(1)):
            buf = bits[i + 8:i + 84]
            if len(buf) < 76:
                break
            raw = np.empty(76, int)
            for k in range(19):
                raw[4 * k:4 * k + 4] = buf[k::19][:4]
            exp = raw.copy()
            exp[1] = raw[0]
            exp[3::2] = raw[2::2] ^ raw[0:-2:2]
            syn = exp ^ raw
            ecc = np.array([(1 - raw[2 * k]) if (syn[2 * k + 1] and syn[2 * k + 3]) else raw[2 * k]
                            for k in range(37)])
            given = 0
            for j in range(10):
                given = (given << 1) + (1 - ecc[27 + j])
            good += int(given == smartnet_crc(ecc[:27]))
        best = max(best, good)
    return int(best)


def verify_smartnet(iq, fs):
    n = smartnet_osws(iq, fs)
    return {"ok": bool(n >= SN_MIN_OSW), "decoder": "smartnet-osw-crc", "frames": int(n), "clean": int(n),
            "crc_err": 0, "ids": [], "detail": [f"{n} CRC-valid SmartNet OSWs"]}


PROOFS = {label: _dsd_proof(label) for label in DECODER}
PROOFS.update({"EDACS": verify_edacs, "EDACS-V": verify_edacs_voice, "SmartNet": verify_smartnet})
