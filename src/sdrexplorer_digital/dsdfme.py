# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""Live FM-discriminator-audio bridge from op25 to dsd-fme, for NXDN.

op25 has no NXDN frame decoder (see digital.py's module docstring — its
frame_assembler sync table only knows P25/DMR/D-STAR/YSF/SmartNet). dsd-fme
has a complete, maintained NXDN48/96 protocol decoder but no RF front end of
its own here. Two designs were tried; only the second one actually works:

ATTEMPT 1 (superseded): pipe op25's own NXDN-tuned SLICED SYMBOL output
(radio.py's old nxdn_sink, tapped off op25_demod) through a FIFO into
dsd-fme. Building dsd-fme and reading its source (src/dsd_audio.c
openAudioInDevice) showed this can't work: its raw-dibit-compatible inputs
(".bin"/".raw"/".sym") all gate on `S_ISREG(stat_buf.st_mode)` — a FIFO is
not a regular file, so pointing `-i` at one silently falls through to
`audio_in_type = 0` (PulseAudio input) instead of an error. Its actual
pipe-friendly inputs (`-i -` stdin, `-i tcp:...`, a no-extension named
pipe) all expect plain 16-bit PCM DISCRIMINATOR AUDIO instead (libsndfile,
SF_FORMAT_RAW|PCM_16) — i.e. they assume dsd-fme does its OWN symbol timing
recovery/slicing, same as its normal rtl_fm/SDR++ use. So a live FIFO of
dibits was a dead end regardless of how well op25 tuned/sliced them.

ATTEMPT 2 (current, implemented in radio.py): tap self.chan with a plain FM
discriminator (analog.quadrature_demod_cf), independent of op25/digital_mode
entirely — see radio.py's nxdn_filt/nxdn_disc/nxdn_f2s/nxdn_sink, using the
same filter width + deviation gain as the app's existing "NFM" analog mode
(a calibration already proven in this exact RF chain, not a new unverified
NXDN-specific deviation figure — dsd-fme's own AGC-like symbol leveling
doesn't need exact deviation calibration, only a clean, unclipped signal),
converted to 16-bit PCM (blocks.float_to_short) at AUDIO_RATE (48000 Hz,
matching dsd-fme's own default `wav_sample_rate` exactly — no `-s` flag
needed). THIS module's job is unchanged in shape from attempt 1 (FIFO ->
bounded drop-oldest queue -> feeder thread -> dsd-fme's stdin via `-i -`) —
`-i -` calls sf_open_fd() on the fd directly with no S_ISREG check at all,
so an anonymous pipe (subprocess.Popen(stdin=PIPE)) is completely fine here,
unlike the ".bin" branch attempt 1 hit. Only the BYTES flowing through it
changed (16-bit PCM discriminator samples now, not dibits).

    op25's self.chan --(FM discriminator, 16-bit PCM)-->  FIFO  -->  this module
                                                                        |
                                                                        +--> dsd-fme
                                                                              stdin (-i -)
                                                                              |
                                                         dsd-fme stdout/stderr
                                                         (call/sync status text)
                                                                              |
                                                                      decoded/raw_line
                                                                      Qt signals back
                                                                      to the app

Why not just point radio.py's file_sink straight at dsd-fme's stdin (skip
the queue)? Because that file_sink's fwrite() runs on the live GNU Radio
scheduler thread. If dsd-fme stalls or dies, that fwrite() blocks too —
freezing the WHOLE flowgraph (analog audio, P25/DMR decode, everything
sharing it), not just NXDN. Sitting a bounded, drop-oldest queue between the
FIFO reader and the dsd-fme feeder means a wedged dsd-fme only costs NXDN
decode, never the radio. (Validated: writing 4MB through the FIFO against a
dsd-fme stand-in that never reads its stdin at all completed in 0.02s — the
producer side never blocked.)

CONFIRMED WORKING end-to-end for the OFFLINE case (a real .bin symbol-
capture file, not this module — see tools/op25_replay.py plus a raw_output
arg, decoded via `dsd-fme -fn -i <path>.bin`, no `-N`): clean NXDN96 RCCH
decode of a real captured control channel (RAN 01, SRV_INFO/SITE_INFO),
zero header errors. Also confirmed: no `-N` (ncurses) — that flag calls
initscr() against the process's controlling terminal regardless of stdin/
stdout redirection, so it hard-fails ("Error opening terminal: unknown.")
under any subprocess with no tty, which is exactly how this bridge and any
GUI-spawned dsd-fme run. Default (no -N) mode is plain, parseable stdout
text (with ANSI color codes), which is what this module's parser expects.

NOT YET CONFIRMED: this attempt-2 PCM design itself hasn't been run against
the real binary yet (only attempt 1's dibit approach, and the offline .bin
path, have real dsd-fme runs behind them so far) — the discriminator tap is
new code. Should decode (dsd-fme's stdin path is exactly how the community
normally feeds it from rtl_fm), but verify before relying on it.

NOTE: _parse_dsd_fme_line's RAN pattern is confirmed against real dsd-fme
output ("RAN 01", space not colon); TG/SRC patterns are still unverified
guesses (the one real decode run so far was control-channel-only, no voice
grant to check them against).
"""
from __future__ import annotations

import itertools
import os
import queue
import re
import select
import shutil
import socket
import subprocess
import threading
import time

import numpy as np
from PyQt5 import QtCore

from sdrexplorer.api import paths as _paths

from .pathkeys import register_paths

register_paths()

# dsd-fme has no distro package: it's built to a local prefix (paths key "dsd_fme",
# default <install>/ext/dsd-fme), else whatever "dsd-fme" is on PATH. Its lib/ isn't
# on the system loader path (libmbe.so etc.), so any subprocess spawn of it needs
# LD_LIBRARY_PATH set explicitly -- ambient env is not enough, and IS what
# broke this the first time it was tried from the running app (dsd-fme was
# only ever put on PATH/LD_LIBRARY_PATH in the shell that built/tested it).
DSD_FME_BIN = _paths.program("dsd_fme", "dsd-fme") or "dsd-fme"
_READ_CHUNK = 4096
_PCM_BYTES_PER_S = 2 * 48_000   # s16 mono at radio.AUDIO_RATE: what the FIFO carries per second
# Drop-oldest queue of PCM between the FIFO and dsd-fme: ~2 s. dsd-fme decodes 25-50x real time,
# so a full queue only means it is stuck; holding more (it was 200 chunks = 8.5 s) just meant
# decoding audio that old -- of the channel you were on before a retune.
_QUEUE_MAX = 2 * _PCM_BYTES_PER_S // _READ_CHUNK
_SELECT_TIMEOUT = 0.2       # seconds; bounds how promptly stop() takes effect
# dsd-fme's text output is read through a normal buffered reader. With the raw pipe (bufsize=0),
# readline() was one read(1) syscall -- and one GIL hand-off -- per byte; while the rest of the app
# kept the GIL busy (19.2 Msps flowgraph blocks, modules, GUI) that reader fell behind dsd-fme's
# 1-10 kB/s of output, the 64 kB pipe filled, dsd-fme blocked on its own writes and stopped reading
# PCM, and the queue sat full: NXDN stopped decoding (or ran seconds late) until Stop/Start
# paused the flowgraph long enough for the reader to catch up. Reproduced with 6 GIL-busy threads.
_STDOUT_BUFSIZE = 64 * 1024

# "Locked" detection for the audio gate: confirmed empirically by feeding
# dsd-fme both /dev/zero and /dev/urandom directly. Zero produces zero
# "Sync:" lines at all. Random noise DOES spuriously trigger a handful of
# frame-sync hits -- most carry "(CRC ERR)", but at least one subtype
# (RTCH/UDCH "PF X/4" partial-frame lines) can show a bare "Sync:" with NO
# CRC ERR marker and NO RAN field, purely from noise -- CRC-clean alone is
# NOT enough. Every genuine content line seen from the one real system
# tested (SRV_INFO/SITE_INFO broadcasts) DOES carry a "RAN nn" field, so
# requiring "Sync:" + a RAN field + no CRC ERR is what's actually used --
# eliminates that false-positive class while still matching real traffic
# (real traffic's first line or two after acquiring a new frame can
# momentarily lack RAN too, per nxdn_deperm.c's nxdn_facch2_udch -- it's only
# printed once ITS OWN sub-message's CRC checks out -- but subsequent lines
# within the same broadcast cycle recover it well inside _LOCK_TIMEOUT_S).
# No valid line for _LOCK_TIMEOUT_S is "lost lock", mirroring op25's own ~1s
# recurring sync_timeout while idle (see rx_sync.cc) -- 3s here for a bit
# more margin since dsd-fme's broadcast cadence in the one real system
# tested was ~1/s.
#
# A SINGLE valid-looking line turned out not to be selective enough in
# practice: real-world non-NXDN content (another analog/digital signal, not
# literal white noise -- which has far more bit-level structure than
# /dev/urandom for a correlator to coincidentally match) produced ongoing
# false locks after tuning away from a genuine NXDN channel to something
# else. Requiring _CONSEC_REQUIRED valid lines each within _CONSEC_WINDOW_S
# of the previous one (not just of the first) before asserting lock squares
# an already-small per-line false-positive probability, cutting spurious
# lock-ons by roughly an order of magnitude while only delaying a genuine
# lock (which repeats every ~1s on real traffic) by about a second.
#
# "PF X/n" lines don't count either. dsd-fme prints the LAST good RAN on every SACCH line,
# CRC-checked or not (nxdn_deperm.c: state->nxdn_last_ran, sticky for the life of the process),
# and marks a SACCH that failed its CRC only as "PF X/4" / "PF X/1" -- no "CRC ERR". So once any
# noise burst had passed a CRC, every later noise sync line read "Sync: ... RAN 30 PF X/4" and
# the bridge locked on channels with no NXDN at all, showing RANs (30, 58) no system here uses.
_SYNC_OK_RE = re.compile(r"\bSync:")
_RAN_PRESENT_RE = re.compile(r"\bRAN\s+\d")
_CRC_ERR_RE = re.compile(r"CRC ERR", re.I)
_PF_BAD_RE = re.compile(r"\bPF X/")
_LOCK_TIMEOUT_S = 3.0
_CONSEC_REQUIRED = 2
_CONSEC_WINDOW_S = 2.0

# -Z raw payload capture: nxdn_deperm.c prints "<LABEL> Payload" (SCCH,
# FACCH1, CAC, UDCH, FACCH2, PICH, TCH, ...) followed by the raw bytes as
# "[XX]" tokens -- confirmed against a real run (-Z) that the shape is NOT
# uniform: SCCH/FACCH1 print label + hex + optional "(CRC ERR)" all on ONE
# line; CAC/UDCH/FACCH2 print a bare header line, then hex-only continuation
# line(s) (split at a fixed column, e.g. 13 bytes/line). Byte count also
# varies by type (SCCH=4, FACCH1=12, CAC=21 seen; no fixed constant). So
# rather than a per-type byte count table, this collects hex tokens starting
# at the header (which may itself carry the first chunk) through however
# many pure-hex continuation lines follow, and finalizes as soon as either a
# "(CRC ERR)" marker appears (always the LAST thing printed for a given
# message -- see nxdn_facch2_udch) or a non-hex line arrives (the payload
# dump implicitly ended without one, i.e. the message's CRC was clean).
_GROUPS = itertools.count(1)          # refs for the bridge's group signal

_PAYLOAD_HDR_RE = re.compile(r"\b(\w+)\s+Payload\b")
_HEX_BYTE_RE = re.compile(r"\[([0-9A-Fa-f]{2})\]")


def dsd_fme_available(bin_path=DSD_FME_BIN):
    return os.path.exists(bin_path) or shutil.which(bin_path) is not None


def _dsd_fme_env():
    """Subprocess env for dsd-fme: ambient env + its prefix's lib/ prepended to
    LD_LIBRARY_PATH, so libmbe.so etc. resolve regardless of what the parent
    process's own environment happens to have (a GUI launch generally won't)."""
    return _paths.tool_env("dsd_fme")


class NxdnBridge(QtCore.QThread):
    """One dsd-fme subprocess fed from a FIFO of 16-bit PCM discriminator audio.

    Usage: create with a not-yet-existing fifo_path, call start() (QThread),
    then reader_ready() to block until the FIFO's read end is open — only
    then is it safe to point radio.py's nxdn_sink file_sink at the same path
    (see radio.py start_nxdn_bridge), since a FIFO's write-side open()
    otherwise blocks until a reader exists. stop() tears the whole thing
    down; this object is single-use (mirrors a single dsd-fme process
    lifetime — toggling NXDN decode off then on again means a fresh
    NxdnBridge + fresh FIFO, not reopening this one)."""

    decoded = QtCore.pyqtSignal(dict)     # best-effort parse of a dsd-fme status line
    raw_line = QtCore.pyqtSignal(str)     # dsd-fme stdout/stderr lines WHILE LOCKED only
                                          # (see _pump_stdout) -- not literally everything;
                                          # noise/static produces real output that's just
                                          # not worth showing
    lock_changed = QtCore.pyqtSignal(bool)  # CRC-clean NXDN sync gained/lost -- see _SYNC_OK_RE
    data = QtCore.pyqtSignal(str, str, bytes)  # (proto, label, raw) -- same shape as
                                                # Op25DataCapture.data, see -Z parsing below
    group = QtCore.pyqtSignal(object)     # a new group of lines + payloads: one frame (from its Sync: line
                                          # to the next), or a whole NXDN data call (DCALL_HEADER + its
                                          # DCALL_DATA frames). Emitted before the group's lines / payloads
                                          # (same thread, so delivered in order): the app ties them together
                                          # (api.Decode.ref) for the decode strip's "Follow log filter"
    position = QtCore.pyqtSignal(dict)    # a GPS fix dsd-fme decoded from an NXDN data call
                                          # ({src, lat, lon, speed_mps?, heading_deg?}) -- see
                                          # _parse_gps_line; the app plots it on the live map

    def __init__(self, fifo_path, nxdn96=True, bin_path=DSD_FME_BIN, parent=None, audio_port=None):
        super().__init__(parent)
        self.fifo_path = str(fifo_path)
        self.nxdn96 = bool(nxdn96)
        self.bin_path = bin_path
        # decoded voice: dsd-fme sends it (8 kHz mono s16, 320-byte frames) to a local UDP relay
        # here, which forwards it to the app's digital-voice player (op25's sockaudio on
        # ``audio_port``) only while locked -- see _relay_audio. None: no voice output.
        self.audio_port = audio_port
        self._audio_rx = None
        self._audio_thread = None
        # the socket the relay sends from: its port tells the player this bridge's voice from op25's
        # (voice.VoiceReceiver.prefer), so the two can't play over each other on one call
        self._relay_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._relay_tx.bind(("127.0.0.1", 0))
        self.relay_port = self._relay_tx.getsockname()[1]
        self.voice_frames = 0          # frames forwarded to the player (diagnostics / tests)
        self._keep = True
        self._proc = None
        self._fifo_fd = None
        self._q = queue.Queue(maxsize=_QUEUE_MAX)
        self._reader_ready = threading.Event()
        self._feeder_thread = None
        self._stdout_thread = None
        self._locked = False           # written by _pump_stdout's thread and
        self._last_valid = 0.0         # (force_unlock) the main thread; read by
                                        # run()'s timeout check -- plain scalars,
                                        # GIL makes cross-thread access here safe
        self._consec_valid = 0         # consecutive valid lines seen so far --
        self._prev_valid_ts = 0.0      # see _CONSEC_REQUIRED/_CONSEC_WINDOW_S
        self._payload_label = None     # "UDCH"/"FACCH2" while collecting a -Z
        self._payload_hex = []         # hex payload block; both _pump_stdout-thread-only
        self._call_src = None          # Source of the current data call header (_pump_stdout-only)
        self._group = None             # the current group ref (see the group signal; _pump_stdout-only)
        self._in_call = False          # inside an NXDN data call (DCALL_HEADER .. its DCALL_DATA frames)

    # -- per-protocol hooks (EdacsBridge overrides these; the plumbing is shared) --
    proto = "NXDN"

    def _decoder_flags(self):
        return ["-fn" if self.nxdn96 else "-fi"]

    def _valid_line(self, line):
        return _valid_sync_line(line)

    def _parse_line(self, line):
        return _parse_dsd_fme_line(line)

    def _voice_pcm(self, data):
        """dsd-fme's voice packet as the player wants it (8 kHz mono s16)."""
        return data

    def reader_ready(self, timeout=5.0):
        """Block until the FIFO's read end is open (or the attempt failed).
        Returns False on timeout/failure — caller should not arm op25's
        file_sink in that case."""
        return self._reader_ready.wait(timeout)

    # -- QThread body: owns the FIFO read + dsd-fme subprocess lifetime ------
    def run(self):
        if not os.path.exists(self.fifo_path):
            os.mkfifo(self.fifo_path)
        try:
            # O_NONBLOCK on the read side: opening a FIFO for read normally
            # blocks until a writer exists, which here would deadlock against
            # the caller (radio.py) waiting on reader_ready() before it opens
            # the write side. With O_NONBLOCK the open returns immediately;
            # reads simply see no data until op25 attaches as writer.
            self._fifo_fd = os.open(self.fifo_path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            self._reader_ready.set()      # unblock the caller; nothing will decode
            return
        self._reader_ready.set()

        # NOT "-N": ncurses' initscr() opens the process's controlling
        # terminal directly regardless of stdin/stdout redirection, so it
        # hard-fails ("Error opening terminal: unknown.") under a subprocess
        # with no tty -- confirmed against the real binary. Default (no -N)
        # mode is plain stdout text, which is also what's actually parseable.
        # "-i -" (stdin) is correct here: the FIFO carries 16-bit PCM
        # discriminator audio (radio.py's nxdn_disc/nxdn_f2s), which is
        # exactly what dsd-fme's stdin path expects -- see module docstring.
        # "-o null": dsd-fme's own audio output defaults to "pulse" -- since
        # this bridge runs continuously regardless of what's tuned, an
        # unfiltered default meant dsd-fme was decoding AMBE audio out of
        # whatever noise/false frame-syncs it found on non-NXDN signals (see
        # the empirical /dev/urandom false-positive note above the lock
        # regexes) and playing that STRAIGHT TO THE SYSTEM'S AUDIO DEVICE,
        # bypassing sdrexplorer's own volume/mute entirely -- that's the
        # "random audio on some other frequency" bug this fixes. Decoded voice
        # is now sent instead to a UDP relay in this bridge (audio_port), which
        # passes it to the app's player only while locked -- see _relay_audio.
        # "-Z": extra payload/PDU logging -- prints NXDN UDCH/FACCH2 raw data
        # payloads as hex (see nxdn_deperm.c's nxdn_facch2_udch()), parsed
        # below into the same (proto, label, raw) shape as op25's own
        # Op25DataCapture.data, so it plugs into the existing hexdump/pcap
        # pipeline (_on_data_payload/_capture_payload in app.py).
        out = "null"
        if self.audio_port:
            try:
                self._audio_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._audio_rx.bind(("127.0.0.1", 0))           # any free port; dsd-fme sends here
                self._audio_rx.settimeout(_SELECT_TIMEOUT)
                out = f"udp:127.0.0.1:{self._audio_rx.getsockname()[1]}"
            except OSError:
                self._audio_rx = None
        args = [self.bin_path] + self._decoder_flags() + ["-i", "-", "-o", out, "-Z"]
        try:
            self._proc = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, bufsize=_STDOUT_BUFSIZE, env=_dsd_fme_env())
        except OSError as exc:
            self.raw_line.emit(f"{self.proto.lower()}_bridge: failed to start {self.bin_path}: {exc}")
            return

        self._stdout_thread = threading.Thread(target=self._pump_stdout, daemon=True)
        self._stdout_thread.start()
        self._feeder_thread = threading.Thread(target=self._feed_stdin, daemon=True)
        self._feeder_thread.start()
        if self._audio_rx is not None:
            self._audio_thread = threading.Thread(target=self._relay_audio, daemon=True)
            self._audio_thread.start()

        while self._keep:
            try:
                r, _, _ = select.select([self._fifo_fd], [], [], _SELECT_TIMEOUT)
            except OSError:
                break
            # Runs every ~_SELECT_TIMEOUT regardless of whether PCM data was
            # ready (this loop is the only thing guaranteed to tick while
            # dsd-fme goes quiet -- e.g. tuned off any NXDN signal at all, so
            # no stdout lines ever arrive to check from _pump_stdout's side).
            if self._locked and (time.monotonic() - self._last_valid) > _LOCK_TIMEOUT_S:
                self._locked = False
                self._consec_valid = 0    # re-accumulate from scratch on the next signal
                self.lock_changed.emit(False)
            if not r:
                continue
            try:
                chunk = os.read(self._fifo_fd, _READ_CHUNK)
            except OSError:
                break
            if not chunk:
                break          # writer (op25) closed for good — this bridge is done
            self._enqueue(chunk)
        self._q.put(None)      # sentinel: let the feeder thread exit

    def _enqueue(self, chunk):
        try:
            self._q.put_nowait(chunk)
            return
        except queue.Full:
            pass
        try:                   # drop the oldest buffered chunk, keep the bridge live
            self._q.get_nowait()
        except queue.Empty:
            pass
        try:
            self._q.put_nowait(chunk)
        except queue.Full:
            pass                # lost this chunk too; a handful of symbols, not fatal

    def flush(self):
        """Drop the PCM still queued for dsd-fme: it is audio of the channel before a retune.
        Safe from any thread (the feeder just finds the queue shorter)."""
        while True:
            try:
                chunk = self._q.get_nowait()
            except queue.Empty:
                return
            if chunk is None:              # stop()'s sentinel: keep it
                self._q.put_nowait(None)
                return

    def _feed_stdin(self):
        proc = self._proc
        while True:
            chunk = self._q.get()
            if chunk is None:
                break
            try:
                proc.stdin.write(chunk)
                proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                break
        try:
            proc.stdin.close()
        except OSError:
            pass

    def _relay_audio(self):
        """dsd-fme's decoded NXDN voice -> the app's digital-voice player, only while locked: an
        unlocked dsd-fme is decoding false syncs on whatever is tuned, and that audio is noise.
        The player (op25 sockaudio) scales by the app's volume and mutes during scan sweeps, the
        same as P25 / DMR voice."""
        tx = self._relay_tx
        dst = ("127.0.0.1", int(self.audio_port))
        try:
            while self._keep:
                try:
                    data = self._audio_rx.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if self._locked and len(data) > 2:
                    try:
                        tx.sendto(self._voice_pcm(data), dst)
                        self.voice_frames += 1
                    except OSError:
                        pass
        finally:
            tx.close()

    def _pump_stdout(self):
        proc = self._proc
        for raw in iter(proc.stdout.readline, b""):
            line = _ANSI_RE.sub("", raw.decode("utf-8", "replace")).rstrip("\r\n")
            if not line:
                continue
            crc_err = bool(_CRC_ERR_RE.search(line))
            if self._valid_line(line):
                now = time.monotonic()
                self._last_valid = now
                if now - self._prev_valid_ts <= _CONSEC_WINDOW_S:
                    self._consec_valid += 1
                else:
                    self._consec_valid = 1     # gap too long -- start over
                self._prev_valid_ts = now
                if not self._locked and self._consec_valid >= _CONSEC_REQUIRED:
                    self._locked = True
                    self.lock_changed.emit(True)

            if not self._locked:
                # Not on a real NXDN signal (or tuned to static) -- dsd-fme's
                # own false-positive frame syncs and CRC-ERR chatter are real
                # (see the /dev/urandom false-positive note above), so
                # suppress ALL of its output rather than spam the decode log
                # / payload pane with garbage from a frequency nobody's
                # actually decoding. Once a genuine detection flips _locked
                # True (above), THIS line and everything after it (including
                # its own transient CRC errors -- still real activity on a
                # real channel) shows normally, until the run() loop's
                # timeout flips it back to False and suppression resumes.
                continue

            if "Sync:" in line:              # a new frame: its lines and payload are one group,
                data_call = "DCALL_HEADER" in line or ("DCALL_DATA" in line and self._in_call)
                if not (data_call and "DCALL_DATA" in line):   # (a data call's frames share the call's)
                    self._finish_payload(crc_err=False)       # the last frame's payload is its own
                    self._group = (self.proto, next(_GROUPS))
                    self.group.emit(self._group)
                self._in_call = data_call
            self.raw_line.emit(line)

            # -Z raw payload capture (see _PAYLOAD_HDR_RE above).
            hdr = _PAYLOAD_HDR_RE.search(line)
            if hdr:
                self._finish_payload(crc_err=False)  # a new header implies any
                self._payload_label = hdr.group(1)   # still-open one already ended
                self._payload_hex = _HEX_BYTE_RE.findall(line)  # header line may
                if crc_err:                                     # itself carry bytes
                    self._finish_payload(crc_err=True)  # single-line case: done now
            elif self._payload_label is not None:
                hits = _HEX_BYTE_RE.findall(line)
                if hits:
                    self._payload_hex.extend(hits)
                    if crc_err:
                        self._finish_payload(crc_err=True)
                    # else: no terminator yet -- keep collecting on the next line
                else:
                    self._finish_payload(crc_err=False)  # non-hex line: dump
                                                          # implicitly ended clean

            hit = self._parse_line(line)
            if hit:
                self.decoded.emit(hit)

            # GPS in an NXDN data call: the "Data Call Header ... Source: N" line
            # comes first, then the DCALL_DATA blocks, then dsd-fme's own decode
            # of the position (nxdn_gps_report), which doesn't repeat the source.
            src = _CALL_SRC_RE.search(line)
            if src:
                self._call_src = int(src.group(1))
            fix = _parse_gps_line(line)
            if fix:
                fix["src"] = self._call_src
                self.position.emit(fix)

    def _finish_payload(self, crc_err):
        """Emit whatever hex has been collected for the current -Z payload
        label (if any) and reset collection state. No-op if nothing (or an
        empty byte list) was actually collected -- a header immediately
        followed by another header/non-hex line, or a header with no bytes
        at all, shouldn't emit a bogus empty payload."""
        if self._payload_label is not None and self._payload_hex:
            payload = bytes(int(h, 16) for h in self._payload_hex)
            label = self._payload_label + (" (CRC ERR)" if crc_err else "")
            self.data.emit(self.proto, label, payload)
        self._payload_label = None
        self._payload_hex = []

    def force_unlock(self):
        """Immediately drop lock (don't wait for _LOCK_TIMEOUT_S), for when
        the CALLER already knows the previous detection is stale -- e.g. a
        manual retune. Without this, a real lock's tail can keep showing/
        gating audio for up to _LOCK_TIMEOUT_S after you've already moved to
        a different, non-NXDN channel. Also resets the consecutive-match
        counter so a near-miss from just before the retune doesn't count
        toward a fresh false lock on whatever's on the new channel. Safe to
        call from the main thread (this object's Qt affinity IS the main
        thread -- only run() executes on a separate one). Queued PCM of the old
        channel is dropped too (flush)."""
        self.flush()
        self._consec_valid = 0
        if self._locked:
            self._locked = False
            self.lock_changed.emit(False)

    def stop(self):
        self._keep = False
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        if self._feeder_thread is not None:
            self._feeder_thread.join(timeout=2)
        if self._stdout_thread is not None:
            self._stdout_thread.join(timeout=2)
        if self._audio_thread is not None:
            self._audio_thread.join(timeout=2)
        if self._audio_rx is not None:
            try:
                self._audio_rx.close()
            except OSError:
                pass
        if self._fifo_fd is not None:
            try:
                os.close(self._fifo_fd)
            except OSError:
                pass
        try:
            os.unlink(self.fifo_path)
        except OSError:
            pass


# --- best-effort dsd-fme status-line parser ---------------------------------
# ANSI SGR color codes: dsd-fme colorizes its plain-text (non-ncurses) output
# (confirmed: "\x1b[36mData  \x1b[0m" etc. in real output) -- stripped before
# both regex matching and raw_line display so the log doesn't fill with
# escape junk.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# _RAN_RE confirmed against real dsd-fme output ("RAN 01" on an NXDN96 RCCH
# line). _TG_RE/_SRC_RE are still unverified guesses -- this module's first
# real decode was control-channel-only (RCCH SRV_INFO/SITE_INFO), with no
# voice grant line to check a talkgroup/source field against. Anything not
# matched still reaches the UI via raw_line, so nothing is silently lost
# while these two get corrected.
_RAN_RE = re.compile(r"\bRAN[:=]?\s*(\d+)", re.I)
_TG_RE = re.compile(r"\bTG(?:ID)?[:=]?\s*(\d+)", re.I)
_SRC_RE = re.compile(r"\bSRC[:=]?\s*(\d+)", re.I)
_SYNC_RE = re.compile(r"\bsync\b", re.I)


# NXDN data-call position, as printed by dsd-fme's nxdn_gps_report (dsd_gps.c), e.g.
#   " GPS: (42.360000°, -71.060000°) Speed: 10.500000 k/h; COG: 260.900000; Elevation: 15; ..."
# and the data call header that names the sender, e.g.
#   " Data Call Header (029400) Source: 1001; Target: 250; Group Call 9600bps Half Duplex"
# (both confirmed against dsd-fme -fn on a real NXDN96 capture).
_GPS_RE = re.compile(r"\bGPS:\s*\(\s*(-?\d+(?:\.\d+)?)\D{0,3},\s*(-?\d+(?:\.\d+)?)\D{0,3}\)")
_GPS_SPEED_RE = re.compile(r"Speed:\s*(-?\d+(?:\.\d+)?)\s*k/h", re.I)
_GPS_COG_RE = re.compile(r"COG:\s*(-?\d+(?:\.\d+)?)", re.I)
_CALL_SRC_RE = re.compile(r"Data Call Header\b.*?\bSource:\s*(\d+)", re.I)


def _valid_sync_line(line):
    """A dsd-fme line that counts toward lock: a frame sync with a RAN whose own CRC passed
    (no "CRC ERR", no "PF X/" -- see _PF_BAD_RE for why the RAN alone proves nothing)."""
    return bool(_SYNC_OK_RE.search(line) and _RAN_PRESENT_RE.search(line)
                and not _CRC_ERR_RE.search(line) and not _PF_BAD_RE.search(line))


def _parse_gps_line(line):
    """{lat, lon[, speed_mps, heading_deg]} for a dsd-fme GPS line, else None.
    (0, 0) and out-of-range values are dropped: that's a receiver with no fix."""
    m = _GPS_RE.search(line)
    if not m:
        return None
    lat, lon = float(m.group(1)), float(m.group(2))
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == 0 and lon == 0):
        return None
    out = {"lat": lat, "lon": lon}
    sp = _GPS_SPEED_RE.search(line)
    if sp:
        out["speed_mps"] = float(sp.group(1)) / 3.6
    cog = _GPS_COG_RE.search(line)
    if cog:
        out["heading_deg"] = round(float(cog.group(1)), 1)
    return out


def _parse_dsd_fme_line(line):
    """Return a decode dict for a dsd-fme line that looks like call/sync
    status, else None. Deliberately conservative: only fires on lines that
    match at least one known-ish field, so the exact regexes can be tightened
    later without callers having to change (unmatched lines still show up via
    raw_line)."""
    ran = _RAN_RE.search(line)
    tg = _TG_RE.search(line)
    src = _SRC_RE.search(line)
    if not (ran or tg or src):
        return None
    out = {"proto": "NXDN"}
    if ran:
        out["ran"] = int(ran.group(1))
    if tg:
        out["tgid"] = int(tg.group(1))
    if src:
        out["src"] = int(src.group(1))
    out["raw_text"] = line
    return out


# --- EDACS (GE/Harris) control channel through the same bridge ----------------------------------
# dsd-fme -fe / -fh decode the 9600 Bd 2FSK control channel from the same 48 kHz discriminator audio
# the NXDN tap makes (radio.py nxdn_*). Its 6.25 kHz channel filter is also what decodes EDACS best:
# 2 s crops of a real control channel gave 42-64 BCH-clean frames through a 6.25 kHz
# low-pass, 1-21 through 9 kHz and 0-6 through 10.5 kHz.
# -fe output lines look like this (made-up site, groups and units):
#   Sync: +EDACS  MSG_1 [FD60342] MSG_2 [FD60342] (MT1: 1F; MT2: A)  Extended Addressing :: Site ID [03][003] Area [04][004]
#   Sync: +EDACS  MSG_1 [FC00000] MSG_2 [600C0A5] (MT1: 1F; MT2: 8)  System Information :: System ID [0000] CC LCN [10]
#   Sync: +EDACS  MSG_1 [1970064] MSG_2 [1A0002A] (MT1: 03)          Digital Group Call Update :: Group [00100] Source [00000042] LCN [11]
# A frame whose BCH check failed prints "Sync: +EDACS  BCH FAIL" instead of its messages.
# Variants (Settings > EDACS): dsd-fme no longer tells Standard/Networked from Extended Addressing on
# its own (edacs-fme.c), so the user picks it; the frame sync and BCH are the same in all of them.
EDACS_VARIANTS = {"EA": "-fe", "Standard/Networked": "-fh", "EA + ESK": "-fE", "Standard + ESK": "-fH"}
EDACS_DEFAULT_VARIANT = "EA"
_EDACS_SYNC_RE = re.compile(r"\bSync:\s*[+-]EDACS\b")
_EDACS_KIND_RE = re.compile(r"\)\s+(.+?)\s+::")
_EDACS_SITE_RE = re.compile(r"Site ID \[([0-9A-F]{2})\]")
_EDACS_SYSID_RE = re.compile(r"System ID \[([0-9A-F]{4})\]")
_EDACS_CC_LCN_RE = re.compile(r"CC LCN \[(\d+)\]")
_EDACS_LCN_RE = re.compile(r"(?<!CC )\bLCN \[(\d+)\]")
_EDACS_GROUP_RE = re.compile(r"\bGroup \[(\d+)\]")
_EDACS_SRC_RE = re.compile(r"\b(?:Source|LID) \[(\d+)\]")


def edacs_flags(variant=EDACS_DEFAULT_VARIANT, afs=None, lcn_csv=None):
    """dsd-fme flags for an EDACS variant. ``afs`` (e.g. "344"): a custom 11-bit agency/fleet/subfleet
    split for Standard/Networked systems (-fh344 / -fH344). ``lcn_csv``: dsd-fme's -C channel map."""
    flag = EDACS_VARIANTS.get(variant, EDACS_VARIANTS[EDACS_DEFAULT_VARIANT])
    if afs and flag in ("-fh", "-fH") and str(afs).isdigit():
        flag += str(afs)
    out = [flag]
    if lcn_csv:
        out += ["-C", str(lcn_csv)]
    return out


def _edacs_valid_line(line):
    """An EDACS frame that passed dsd-fme's BCH check."""
    return bool(_EDACS_SYNC_RE.search(line) and "BCH FAIL" not in line)


def _parse_edacs_line(line):
    """{proto: "EDACS", kind, site?, sysid?, cc_lcn?, lcn?, group?, src?, raw_text} for a BCH-clean
    EDACS message line, else None."""
    if not _edacs_valid_line(line):
        return None
    k = _EDACS_KIND_RE.search(line)
    if not k:
        return None
    out = {"proto": "EDACS", "kind": k.group(1).strip()}
    for key, rx, base in (("site", _EDACS_SITE_RE, 16), ("sysid", _EDACS_SYSID_RE, 16),
                          ("cc_lcn", _EDACS_CC_LCN_RE, 10), ("lcn", _EDACS_LCN_RE, 10),
                          ("group", _EDACS_GROUP_RE, 10), ("src", _EDACS_SRC_RE, 10)):
        m = rx.search(line)
        if m:
            out[key] = int(m.group(1), base)
    out["raw_text"] = line
    return out


class EdacsBridge(NxdnBridge):
    """dsd-fme decoding an EDACS control channel: NxdnBridge's FIFO / queue / lock plumbing with
    EDACS flags, an EDACS lock rule (BCH-clean frames) and an EDACS line parser."""
    proto = "EDACS"

    def __init__(self, fifo_path, flags=None, bin_path=DSD_FME_BIN, parent=None, audio_port=None):
        super().__init__(fifo_path, True, bin_path, parent, audio_port)
        self.flags = list(flags or edacs_flags())

    def _decoder_flags(self):
        return list(self.flags)

    def _valid_line(self, line):
        return _edacs_valid_line(line)

    def _parse_line(self, line):
        return _parse_edacs_line(line)


# --- DMR through the same bridge: base-station and mobile-station / direct-mode bursts -------------------
# op25 decodes base-station DMR (a repeater's output: CACH, both timeslots) but not mobile-station or
# direct-mode bursts (a radio's own transmission: a repeater input, simplex). dsd-fme -fs decodes both
# from the same discriminator audio, and its sync line says which, e.g. (made-up ids):
#   Sync: +DMR  [SLOT1]  slot2  | Color Code=06 | VC2            base station (two timeslots)
#   Sync: +DMR MS/DM MODE/MONO | Color Code=06 | VLC              mobile station / direct mode
#   SLOT 1 TGT=3125 SRC=1234567 FLCO=0x00 FID=0x00 SVC=0x00 Group Call
# A burst whose CACH / slot type / EMB failed shows "Color Code=XX", "... FEC ERR" or "CACH/EMB ERR".
# Voice goes to UDP as 8 kHz s16 STEREO (left / right the same while one slot carries voice), 640-byte
# packets of 160 frames; the player wants mono.
_DMR_SYNC_RE = re.compile(r"\bSync:\s*[+-]?DMR\b")
_DMR_CC_RE = re.compile(r"Color Code=(\d\d)")
_DMR_MS_RE = re.compile(r"MS/DM")
_DMR_LC_RE = re.compile(r"\bSLOT\s*(\d)\s+TGT=(\d+)\s+SRC=(\d+)(?:.*?SVC=0x[0-9A-Fa-f]+\s+(.+?))?\s*$")


def _dmr_valid_line(line):
    """A DMR burst dsd-fme read cleanly: a sync line with a color code (not XX) and no error mark."""
    return bool(_DMR_SYNC_RE.search(line) and _DMR_CC_RE.search(line) and "ERR" not in line)


def _parse_dmr_line(line):
    """{proto: "DMR", slot, tgid, src, call?} for a dsd-fme DMR link control line, else None."""
    m = _DMR_LC_RE.search(line)
    if not m:
        return None
    out = {"proto": "DMR", "slot": int(m.group(1)), "tgid": int(m.group(2)), "src": int(m.group(3)),
           "raw_text": line}
    if m.group(4):
        out["call"] = m.group(4).strip()
    return out


class DmrBridge(NxdnBridge):
    """dsd-fme decoding DMR (-fs): NxdnBridge's plumbing with a DMR lock rule (a clean DMR sync line) and
    line parser. It also tells base-station from mobile-station / direct-mode bursts (``kind``, the
    kind_changed signal), which is what lets the module hand a call to dsd-fme only when op25 can't decode
    it. The color code of the last clean burst rides on each decoded link control (``cc``)."""
    proto = "DMR"
    kind_changed = QtCore.pyqtSignal(str)   # "BS" / "MS" / "" (lock lost or retuned)

    def __init__(self, fifo_path, bin_path=DSD_FME_BIN, parent=None, audio_port=None):
        super().__init__(fifo_path, True, bin_path, parent, audio_port)
        self.kind = ""
        self.cc = None
        self.lock_changed.connect(self._on_own_lock, QtCore.Qt.DirectConnection)

    def _decoder_flags(self):
        return ["-fs"]

    def _valid_line(self, line):
        ok = _dmr_valid_line(line)
        if ok:
            self.cc = int(_DMR_CC_RE.search(line).group(1))
            self._set_kind("MS" if _DMR_MS_RE.search(line) else "BS")
        return ok

    def _set_kind(self, kind):
        if kind != self.kind:
            self.kind = kind
            self.kind_changed.emit(kind)

    def _on_own_lock(self, locked):
        if not locked:                      # the signal went: whatever comes next is judged afresh
            self._set_kind("")

    def _parse_line(self, line):
        d = _parse_dmr_line(line)
        if d is not None:
            d["kind"] = self.kind
            if self.cc is not None:
                d["cc"] = self.cc
        return d

    def _voice_pcm(self, data):
        """Stereo (one channel per timeslot) -> mono: the two channels averaged."""
        a = np.frombuffer(data[: len(data) // 4 * 4], np.int16)
        if not len(a):
            return data
        return a.reshape(-1, 2).astype(np.int32).mean(axis=1).astype(np.int16).tobytes()

    def force_unlock(self):
        super().force_unlock()
        self._set_kind("")
