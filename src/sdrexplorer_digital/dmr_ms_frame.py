# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""DMR mobile-station burst framing + FEC, vendored from the verified prototype.

BPTC(196,96), RS(12,9), Golay(20,8), Hamming(7,4), QR(16,7,6), BPTC(128,77). All FEC matrices and
interleave tables come from dsd-fme, so output decodes with dsd-fme. The full MS voice call (header +
embedded-LC superframes + terminator) was proven in dsd-fme and over the air (HackRF -> RTL-SDR). Pure
Python (0/1 bit lists, 0..3 dibits); no numpy / op25 dependency.
"""


# Hamming(13,9) generator rows (9 data bits -> 4 parity), from dsd-fme fec.c Hamming_13_9_m_G.
# Each row i: identity then the 4 parity bits for data bit i.
_H13_9_PAR = [
    (1, 1, 1, 1), (1, 1, 1, 0), (0, 1, 1, 1), (1, 0, 1, 0), (0, 1, 0, 1),
    (1, 0, 1, 1), (1, 1, 0, 0), (0, 1, 1, 0), (0, 0, 1, 1),
]
# Hamming(15,11) generator rows (11 data bits -> 4 parity), from Hamming_15_11_m_G.
_H15_11_PAR = [
    (1, 0, 0, 1), (1, 1, 0, 1), (1, 1, 1, 1), (1, 1, 1, 0), (0, 1, 1, 1),
    (1, 0, 1, 0), (0, 1, 0, 1), (1, 0, 1, 1), (1, 1, 0, 0), (0, 1, 1, 0),
    (0, 0, 1, 1),
]

# BPTCDeInterleavingIndex from dsd-fme bptc.c: decode does Output[DeInt[i]] = Input[i].
_DEINT = [
    0, 13, 26, 39, 52, 65, 78, 91, 104, 117, 130, 143, 156, 169, 182, 195,
    12, 25, 38, 51, 64, 77, 90, 103, 116, 129, 142, 155, 168, 181, 194, 11,
    24, 37, 50, 63, 76, 89, 102, 115, 128, 141, 154, 167, 180, 193, 10, 23,
    36, 49, 62, 75, 88, 101, 114, 127, 140, 153, 166, 179, 192, 9, 22, 35,
    48, 61, 74, 87, 100, 113, 126, 139, 152, 165, 178, 191, 8, 21, 34, 47,
    60, 73, 86, 99, 112, 125, 138, 151, 164, 177, 190, 7, 20, 33, 46, 59,
    72, 85, 98, 111, 124, 137, 150, 163, 176, 189, 6, 19, 32, 45, 58, 71,
    84, 97, 110, 123, 136, 149, 162, 175, 188, 5, 18, 31, 44, 57, 70, 83,
    96, 109, 122, 135, 148, 161, 174, 187, 4, 17, 30, 43, 56, 69, 82, 95,
    108, 121, 134, 147, 160, 173, 186, 3, 16, 29, 42, 55, 68, 81, 94, 107,
    120, 133, 146, 159, 172, 185, 2, 15, 28, 41, 54, 67, 80, 93, 106, 119,
    132, 145, 158, 171, 184, 1, 14, 27, 40, 53, 66, 79, 92, 105, 118, 131,
    144, 157, 170, 183,
]


def _h13_9(data9):
    """9 data bits -> 13-bit codeword (9 data + 4 parity), matching dsd-fme's column code."""
    par = [0, 0, 0, 0]
    for i, b in enumerate(data9):
        if b:
            p = _H13_9_PAR[i]
            for j in range(4):
                par[j] ^= p[j]
    return list(data9) + par


def _h15_11(data11):
    """11 data bits -> 15-bit codeword (11 data + 4 parity), matching dsd-fme's row code."""
    par = [0, 0, 0, 0]
    for i, b in enumerate(data11):
        if b:
            p = _H15_11_PAR[i]
            for j in range(4):
                par[j] ^= p[j]
    return list(data11) + par


def encode_196x96(data96):
    """96 info bits -> 196 interleaved bits (a DMR data-burst info field), as a list of 0/1.

    data96[0:8]  go to matrix row 0, cols 3..10 (cols 0..2 are R(2),R(1),R(0) = 0).
    data96[8:96] go to rows 1..8, cols 0..10.
    Then column Hamming(13,9) fills rows 9..12, row Hamming(15,11) fills cols 11..14, and the matrix
    is interleaved by the inverse of dsd-fme's deinterleave table.
    """
    assert len(data96) == 96, len(data96)
    M = [[0] * 15 for _ in range(13)]
    # place data
    k = 0
    for c in range(3, 11):
        M[0][c] = data96[k]; k += 1
    for r in range(1, 9):
        for c in range(11):
            M[r][c] = data96[k]; k += 1
    # column Hamming(13,9): columns 0..14, data in rows 0..8 -> parity rows 9..12
    for c in range(15):
        col = [M[r][c] for r in range(9)]
        cw = _h13_9(col)
        for r in range(9, 13):
            M[r][c] = cw[r]      # cw indices 9..12 are the 4 parity bits
    # row Hamming(15,11): rows 0..12, data in cols 0..10 -> parity cols 11..14
    for r in range(13):
        row = [M[r][c] for c in range(11)]
        cw = _h15_11(row)
        for c in range(11, 15):
            M[r][c] = cw[c]
    # linearize row-major into 196 "deinterleaved" bits, index 0 = R(3) = 0, then 13x15 at index 1..195
    deint = [0] * 196
    idx = 1
    for r in range(13):
        for c in range(15):
            deint[idx] = M[r][c]; idx += 1
    # interleave: decode does out[DEINT[i]] = in[i]; so encode in[i] = deint[DEINT[i]]
    inter = [deint[_DEINT[i]] for i in range(196)]
    return inter


# ---- MS sync patterns (48 bits), from op25 lib/frame_sync_magics.h, as hex ----
DMR_MS_VOICE_SYNC = 0x7F7D5DD57DFD
DMR_MS_DATA_SYNC = 0xD5D7F77FD757
DMR_MS_RC_SYNC = 0x77D55F7DFD77

# ---- RS(12,9) over GF(2^8) (dsd-fme rs-12-9.c) ----
_EXP = [
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1D,0x3A,0x74,0xE8,0xCD,0x87,0x13,0x26,
    0x4C,0x98,0x2D,0x5A,0xB4,0x75,0xEA,0xC9,0x8F,0x03,0x06,0x0C,0x18,0x30,0x60,0xC0,
    0x9D,0x27,0x4E,0x9C,0x25,0x4A,0x94,0x35,0x6A,0xD4,0xB5,0x77,0xEE,0xC1,0x9F,0x23,
    0x46,0x8C,0x05,0x0A,0x14,0x28,0x50,0xA0,0x5D,0xBA,0x69,0xD2,0xB9,0x6F,0xDE,0xA1,
    0x5F,0xBE,0x61,0xC2,0x99,0x2F,0x5E,0xBC,0x65,0xCA,0x89,0x0F,0x1E,0x3C,0x78,0xF0,
    0xFD,0xE7,0xD3,0xBB,0x6B,0xD6,0xB1,0x7F,0xFE,0xE1,0xDF,0xA3,0x5B,0xB6,0x71,0xE2,
    0xD9,0xAF,0x43,0x86,0x11,0x22,0x44,0x88,0x0D,0x1A,0x34,0x68,0xD0,0xBD,0x67,0xCE,
    0x81,0x1F,0x3E,0x7C,0xF8,0xED,0xC7,0x93,0x3B,0x76,0xEC,0xC5,0x97,0x33,0x66,0xCC,
    0x85,0x17,0x2E,0x5C,0xB8,0x6D,0xDA,0xA9,0x4F,0x9E,0x21,0x42,0x84,0x15,0x2A,0x54,
    0xA8,0x4D,0x9A,0x29,0x52,0xA4,0x55,0xAA,0x49,0x92,0x39,0x72,0xE4,0xD5,0xB7,0x73,
    0xE6,0xD1,0xBF,0x63,0xC6,0x91,0x3F,0x7E,0xFC,0xE5,0xD7,0xB3,0x7B,0xF6,0xF1,0xFF,
    0xE3,0xDB,0xAB,0x4B,0x96,0x31,0x62,0xC4,0x95,0x37,0x6E,0xDC,0xA5,0x57,0xAE,0x41,
    0x82,0x19,0x32,0x64,0xC8,0x8D,0x07,0x0E,0x1C,0x38,0x70,0xE0,0xDD,0xA7,0x53,0xA6,
    0x51,0xA2,0x59,0xB2,0x79,0xF2,0xF9,0xEF,0xC3,0x9B,0x2B,0x56,0xAC,0x45,0x8A,0x09,
    0x12,0x24,0x48,0x90,0x3D,0x7A,0xF4,0xF5,0xF7,0xF3,0xFB,0xEB,0xCB,0x8B,0x0B,0x16,
    0x2C,0x58,0xB0,0x7D,0xFA,0xE9,0xCF,0x83,0x1B,0x36,0x6C,0xD8,0xAD,0x47,0x8E,0x01,
]
_LOG = [
    0,0,1,25,2,50,26,198,3,223,51,238,27,104,199,75,4,100,224,14,52,141,239,129,28,193,105,248,200,8,76,113,
    5,138,101,47,225,36,15,33,53,147,142,218,240,18,130,69,29,181,194,125,106,39,249,185,201,154,9,120,77,228,114,166,
    6,191,139,98,102,221,48,253,226,152,37,179,16,145,34,136,54,208,148,206,143,150,219,189,241,210,19,92,131,56,70,64,
    30,66,182,163,195,72,126,110,107,58,40,84,250,133,186,61,202,94,155,159,10,21,121,43,78,212,229,172,115,243,167,87,
    7,112,192,247,140,128,99,13,103,74,222,237,49,197,254,24,227,165,153,119,38,184,180,124,17,68,146,217,35,32,137,46,
    55,63,209,91,149,188,207,205,144,135,151,178,220,252,190,97,242,86,211,171,20,42,93,158,132,60,57,83,71,109,65,162,
    31,45,67,216,183,123,164,118,196,23,73,236,127,12,111,246,108,161,59,82,41,157,85,170,251,96,134,177,187,204,62,90,
    203,89,95,176,156,169,160,81,11,245,22,235,122,117,44,215,79,174,213,233,230,231,173,232,116,214,244,234,168,80,88,175,
]
_GENPOLY = (0x40, 0x38, 0x0e, 0x01)   # dsd-fme rs_12_9_calc_checksum


def _gfmul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]


def rs_12_9_checksum(data9):
    """3 RS(12,9) parity bytes for 9 data bytes (dsd-fme rs_12_9_calc_checksum LFSR)."""
    cs = [0, 0, 0]
    for d in data9:
        fb = d ^ cs[0]
        cs0 = cs[1] ^ _gfmul(_GENPOLY[2], fb)
        cs1 = cs[2] ^ _gfmul(_GENPOLY[1], fb)
        cs2 = _gfmul(_GENPOLY[0], fb)
        cs = [cs0, cs1, cs2]
    return cs


# ---- Full Link Control ----
# 9 bytes = FLCO/PF/R (byte0), FID (byte1), service options (byte2), target/TGID (bytes 3-5),
# source (bytes 6-8). Group voice: FLCO 0x00, FID 0x00.
VLC_CRC_MASK = (0x96, 0x96, 0x96)
TLC_CRC_MASK = (0x99, 0x99, 0x99)


def full_lc_bytes(tgid, src, flco=0x00, fid=0x00, svc=0x00):
    return [flco & 0x3f, fid & 0xff, svc & 0xff,
            (tgid >> 16) & 0xff, (tgid >> 8) & 0xff, tgid & 0xff,
            (src >> 16) & 0xff, (src >> 8) & 0xff, src & 0xff]


def lc_payload96(tgid, src, crc_mask, **lc):
    """9-byte LC + 3 RS(12,9) parity (masked) -> 96 bits (MSB-first per byte)."""
    data9 = full_lc_bytes(tgid, src, **lc)
    par = rs_12_9_checksum(data9)
    par = [par[i] ^ crc_mask[i] for i in range(3)]
    out = []
    for byte in data9 + par:
        for b in range(7, -1, -1):
            out.append((byte >> b) & 1)
    return out                                   # 96 bits


# ---- DMR burst layout (144 dibits), from dsd-fme (dmr_ms.c / dmr_data.c), confirmed by read:
#   dibits  0..11   CACH (12)   - MS: TACT (cachdata[0:7]) must pass Hamming(7,4) for DATA bursts
#   dibits 12..60   info half 1 (49 dibits -> info[0:98])        [DATA]
#   dibits 61..65   SlotType first 5 dibits -> SlotType[0:10]    [DATA]
#   dibits 66..89   SYNC or EMB (24 dibits = 48 bits)
#   dibits 90..94   SlotType last 5 dibits  -> SlotType[10:20]   [DATA]
#   dibits 95..143  info half 2 (49 dibits -> info[98:196])      [DATA]
# For VOICE bursts there is no SlotType: info/AMBE run 12..65 and 90..143 (54+54 dibits).

# dsd-fme cachInterleave (dmr_data.c): cachdata[cachInterleave[k]] = dibit-bit k, k=0..23.
_CACH_INTERLEAVE = [0, 7, 8, 9, 1, 10, 11, 12, 2, 13, 14, 15, 3, 16, 4, 17, 18, 19, 5, 20, 21, 22, 6, 23]

# DMR data types (SlotType[4:8]): 0x1 = Voice LC Header (VLC), 0x2 = Terminator with LC (TLC).
DT_VLC = 0x1
DT_TLC = 0x2

# Golay(20,8) generator (dsd-fme fec.c Golay_20_8_m_G): 8 data bits -> 12 parity.
_G20_8_PAR = [
    (0,0,1,1,1,1,0,1,1,0,1,0), (1,1,0,1,1,0,0,1,1,0,0,1), (0,1,1,0,1,1,0,0,1,1,0,1),
    (0,0,1,1,0,1,1,0,0,1,1,1), (1,1,0,1,1,1,0,0,0,1,1,0), (1,0,1,0,1,0,0,1,0,1,1,1),
    (1,0,0,1,0,0,1,1,1,1,1,0), (1,0,0,0,1,1,1,0,1,0,1,1),
]
# Hamming(7,4) generator (dsd-fme Hamming_7_4_m_G): 4 data -> 3 parity.
_H7_4_PAR = [(1,0,1), (1,1,1), (1,1,0), (0,1,1)]


def _bits(value, n):
    return [(value >> (n - 1 - i)) & 1 for i in range(n)]


def _to_dibits(bits):
    return [(bits[2 * i] << 1) | bits[2 * i + 1] for i in range(len(bits) // 2)]


def _sync_dibits(magic48):
    """48-bit sync -> 24 dibits (the burst's middle field)."""
    return _to_dibits(_bits(magic48, 48))


def golay_20_8(data8):
    """8 data bits -> 20-bit SlotType codeword (8 data + 12 parity)."""
    par = [0] * 12
    for i, b in enumerate(data8):
        if b:
            for j in range(12):
                par[j] ^= _G20_8_PAR[i][j]
    return list(data8) + par


def _slottype_bits(cc, data_type):
    """SlotType[0:20]: CC (4) + data type (4) + Golay(20,8) parity (12)."""
    data8 = _bits(cc, 4) + _bits(data_type, 4)
    return golay_20_8(data8)


def _cach_dibits(cc):
    """12 CACH dibits whose TACT (cachdata[0:7]) is a valid Hamming(7,4) codeword, so dsd-fme's MS
    DATA path doesn't abort. tact_bits[1] = currentslot (0). The 4 TACT data bits carry no payload the
    MS path uses (CC comes from SlotType), so we send a valid all-zero TACT; the 17 payload CACH bits
    are 0."""
    cachdata = [0] * 24
    tact4 = [0, 0, 0, 0]                     # tact_bits[1] -> currentslot 0; all-zero is a valid H(7,4) cw
    par = [0, 0, 0]
    for i, b in enumerate(tact4):
        if b:
            for j in range(3):
                par[j] ^= _H7_4_PAR[i][j]
    tact7 = tact4 + par                      # cachdata[0:7] = TACT
    for i in range(7):
        cachdata[i] = tact7[i]
    # invert cachInterleave: dibit-bit stream[k] = cachdata[cachInterleave[k]]
    stream = [cachdata[_CACH_INTERLEAVE[k]] for k in range(24)]
    return _to_dibits(stream)


def data_burst(info196_bits, sync48, cc, data_type):
    """A full 144-dibit DMR DATA burst (voice LC header / terminator) in dsd-fme's layout."""
    assert len(info196_bits) == 196
    info1 = _to_dibits(info196_bits[:98])        # 49 dibits -> 12..60
    info2 = _to_dibits(info196_bits[98:])        # 49 dibits -> 95..143
    st = _slottype_bits(cc, data_type)           # 20 bits
    st1 = _to_dibits(st[:10])                    # 5 dibits -> 61..65
    st2 = _to_dibits(st[10:])                    # 5 dibits -> 90..94
    sync = _sync_dibits(sync48)                  # 24 dibits -> 66..89
    cach = _cach_dibits(cc)                      # 12 dibits -> 0..11
    burst = cach + info1 + st1 + sync + st2 + info2
    assert len(burst) == 144, len(burst)
    return burst


def voice_lc_header(tgid, src, cc=1):
    info = encode_196x96(lc_payload96(tgid, src, VLC_CRC_MASK))
    return data_burst(info, DMR_MS_DATA_SYNC, cc, DT_VLC)


def terminator_lc(tgid, src, cc=1):
    info = encode_196x96(lc_payload96(tgid, src, TLC_CRC_MASK))
    return data_burst(info, DMR_MS_DATA_SYNC, cc, DT_TLC)


# ---- EMB (embedded signaling) + embedded Link Control ----
# QR(16,7,6) generator (dsd-fme fec.c QR_16_7_6_m_G): 7 data bits -> 9 parity.
_QR16_7_PAR = [
    (0,0,1,0,0,1,1,1,1), (1,0,0,0,1,1,1,1,0), (1,1,0,1,1,0,1,1,1), (1,1,1,1,0,0,0,1,0),
    (1,1,1,0,0,1,0,0,1), (0,1,1,1,0,0,1,0,1), (0,0,1,1,1,0,0,1,1),
]
# Hamming(16,11,4) generator (dsd-fme Hamming_16_11_4_m_G): 11 data -> 5 parity.
_H16_11_PAR = [
    (1,0,0,1,1), (1,1,0,1,0), (1,1,1,1,1), (1,1,1,0,0), (0,1,1,1,0), (1,0,1,0,1),
    (0,1,0,1,1), (1,0,1,1,0), (1,1,0,0,1), (0,1,1,0,1), (0,0,1,1,1),
]
# LCSS (EMB fragment role): 1=first, 3=continuation, 2=last, 0=single. (dsd-fme/ETSI)
LCSS_SINGLE, LCSS_FIRST, LCSS_CONT, LCSS_LAST = 0, 1, 3, 2


def _qr_16_7_6(data7):
    par = [0] * 9
    for i, b in enumerate(data7):
        if b:
            for j in range(9):
                par[j] ^= _QR16_7_PAR[i][j]
    return list(data7) + par


def emb_pdu(cc, lcss, pi=0):
    """16-bit EMB: CC(4) + PI/power(1) + LCSS(2) -> QR(16,7,6)."""
    data7 = _bits(cc, 4) + [pi & 1] + _bits(lcss, 2)
    return _qr_16_7_6(data7)


def _h16_11_4(data11):
    par = [0] * 5
    for i, b in enumerate(data11):
        if b:
            for j in range(5):
                par[j] ^= _H16_11_PAR[i][j]
    return list(data11) + par


def embedded_lc_fragments(tgid, src, flco=0x00, fid=0x00, svc=0x00):
    """The 4 x 32-bit embedded-signaling fragments (bursts B..E) carrying the embedded LC.
    72 LC bits + 5-bit CRC -> BPTC(128,77) 8x16 matrix -> read out column-major in 32-bit chunks.
    Inverts dsd-fme's BPTC_128x77_Extract_Data + the dmr_dburst.c embedded assembly."""
    data9 = full_lc_bytes(tgid, src, flco=flco, fid=fid, svc=svc)
    lc72 = []
    for byte in data9:
        lc72 += _bits(byte, 8)
    crc = ComputeCrc5Bit(lc72)                       # 5-bit CRC over the 72 LC bits
    data77 = lc72 + _bits(crc, 5)
    # place 77 data bits into the 8x16 matrix data region (rows 0-1: 11 cols; rows 2-6: 10 cols;
    # rows 2-6 col 10 = the 5 CRC bits), matching the extract's read order.
    M = [[0] * 16 for _ in range(8)]
    k = 0
    for i in range(2):
        for j in range(11):
            M[i][j] = data77[k]; k += 1
    for i in range(2, 7):
        for j in range(10):
            M[i][j] = data77[k]; k += 1
    for i in range(2, 7):
        M[i][10] = data77[k]; k += 1                 # CRC bits in col 10
    # row Hamming(16,11,4) parity on rows 0..6 (cols 11..15)
    for i in range(7):
        cw = _h16_11_4([M[i][j] for j in range(11)])
        for j in range(11, 16):
            M[i][j] = cw[j]
    # row 7 = column even parity over rows 0..6
    for j in range(16):
        M[7][j] = sum(M[i][j] for i in range(7)) & 1
    # read out column-major (j inner, i outer) in 32-bit fragments -> 4 bursts
    k = 0
    frag = [[0] * 32 for _ in range(4)]
    burst = 0
    for i in range(16):
        for j in range(8):
            frag[burst][k] = M[j][i]
            k += 1
            if k >= 32:
                k = 0; burst += 1
    return frag                                       # 4 x 32 bits


def ComputeCrc5Bit(data_bits):
    """dsd-fme ComputeCrc5Bit: pack 72 bits -> 9 bytes, sum, mod 31."""
    s = 0
    for i in range(9):
        v = 0
        for b in range(8):
            v = (v << 1) | data_bits[i * 8 + b]
        s += v
    return s % 31


def _emb_middle(cc, lcss, frag32):
    """The 48-bit voice middle field: EMB[0:8] | embedded-signaling[0:32] | EMB[8:16]."""
    e = emb_pdu(cc, lcss)
    return e[:8] + list(frag32) + e[8:]


def voice_burst(ambe_dibits, is_first, cc=1, lcss=None, frag32=None):
    """A 144-dibit voice burst: CACH(12) + AMBE(54) + SYNC-or-EMB(24) + AMBE(54). ambe_dibits is 108
    dibits (3 AMBE codewords). First frame carries the MS voice sync; interior frames carry an EMB with
    an embedded-LC fragment (frag32) if given, else a CC-only EMB (null fragment)."""
    assert len(ambe_dibits) == 108, len(ambe_dibits)
    cach = _cach_dibits(cc)
    if is_first:
        mid = _sync_dibits(DMR_MS_VOICE_SYNC)
    else:
        frag = frag32 if frag32 is not None else [0] * 32
        mid = _to_dibits(_emb_middle(cc, lcss if lcss is not None else LCSS_SINGLE, frag))
    burst = cach + ambe_dibits[:54] + mid + ambe_dibits[54:]
    assert len(burst) == 144, len(burst)
    return burst


def voice_superframe(ambe_frames, tgid, src, cc=1):
    """6 voice bursts (A..F). A carries the voice sync; B..E carry the 4 embedded-LC fragments
    (LCSS first/cont/cont/last); F carries a CC-only EMB. ambe_frames: list of 6 x 108-dibit AMBE."""
    frags = embedded_lc_fragments(tgid, src)
    lcss_seq = [LCSS_FIRST, LCSS_CONT, LCSS_CONT, LCSS_LAST]
    out = []
    for j in range(6):
        if j == 0:
            out.append(voice_burst(ambe_frames[j], True, cc))
        elif 1 <= j <= 4:
            out.append(voice_burst(ambe_frames[j], False, cc, lcss_seq[j - 1], frags[j - 1]))
        else:
            out.append(voice_burst(ambe_frames[j], False, cc, LCSS_SINGLE, None))
    return out


# ---- middle fields for the C++ streaming block (sdrexplorer_digital.dmr_ms_tx) ----
def voice_mid_fields(tgid, src, cc=1):
    """The 6 middle fields (24 dibits each) a voice superframe uses, A..F: A = MS voice sync, B..E = the
    4 embedded-LC fragments (LCSS first/cont/cont/last), F = CC-only EMB. The C++ dmr_ms_tx_bb drops
    these into dibits 66..89 of each voice burst while interleaving the AMBE."""
    frags = embedded_lc_fragments(tgid, src)
    lcss_seq = [LCSS_FIRST, LCSS_CONT, LCSS_CONT, LCSS_LAST]
    mids = [_sync_dibits(DMR_MS_VOICE_SYNC)]
    for i in range(4):
        mids.append(_to_dibits(_emb_middle(cc, lcss_seq[i], frags[i])))
    mids.append(_to_dibits(_emb_middle(cc, LCSS_SINGLE, [0] * 32)))
    return mids                                       # 6 x 24 dibits


def cach_field(cc=1):
    """The 12 CACH dibits every MS voice burst carries (single logical channel)."""
    return _cach_dibits(cc)
