# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""Decoded voice into the core speaker (api.AudioInput).

op25's frame_assembler sends decoded voice as UDP datagrams to 127.0.0.1:OP25_AUDIO_PORT: 8 kHz s16 mono
frames (320 bytes), or a 2-byte flag (0: drain, 1: drop). dsd-fme's NXDN / EDACS voice is relayed to the
same port by dsdfme.py while it holds a lock (``prefer`` picks one when both decode a DMR call). This thread
receives both and writes them into the core's
audio chain, where the volume control and the shutdown / scan-sweep mutes apply. (It replaces op25's own
sockaudio player, which opened a second sound device the core's controls didn't reach.)

Voice is passed on only while the module says a decoder holds a lock (``allow``), so op25's output on a
channel it isn't really decoding never plays as static.
"""
from __future__ import annotations

import socket
import threading

import numpy as np

VOICE_RATE = 8000
GAIN = 4.0                       # op25's IMBE / AMBE audio is quiet: x4 at full volume (old audio_gain max)


class VoiceReceiver:
    def __init__(self, audio_input, port, gain=GAIN):
        self.input = audio_input
        self.port = int(port)
        self.gain = float(gain)
        self.allow = False
        # which decoder's voice plays, when two decode the same call (op25 and a dsd-fme bridge on DMR):
        # None = any; ("only", port) = only packets sent from that port (the bridge's relay);
        # ("not", port) = everything but that port (op25)
        self.prefer = None
        self.frames = 0
        self._keep = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", self.port))
        self._sock.settimeout(0.2)
        self._t = threading.Thread(target=self._run, name="digital-voice", daemon=True)
        self._t.start()

    def _run(self):
        while self._keep:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            pref = self.prefer
            if pref is not None and (addr[1] == pref[1]) != (pref[0] == "only"):
                continue                          # the other decoder's voice (or its drain / drop flag)
            if len(data) == 2:                    # op25 flags: 0 drain, 1 drop
                if np.frombuffer(data, np.int16)[0] == 1:
                    self.input.flush()
                continue
            if not self.allow or len(data) < 4:
                continue
            pcm = np.frombuffer(data[: len(data) // 2 * 2], np.int16).astype(np.float32) / 32768.0
            self.input.write(np.clip(pcm * self.gain, -1.0, 1.0))
            self.frames += 1

    def stop(self):
        self._keep = False
        try:
            self._sock.close()
        except OSError:
            pass
        self._t.join(1.0)
