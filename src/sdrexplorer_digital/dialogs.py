# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bad Larry
"""The digital module's settings dialogs (moved from sdrexplorer's app.py): SmartNet bandplan, DMR LCN
bandplan, EDACS variant / AFS / LCN table, and the P25 decryption keystore. Each takes the module, whose
state it edits, and applies live."""
from __future__ import annotations

import json
import os

from PyQt5 import QtWidgets

from sdrexplorer.api import paths, secrets

from . import dsdfme as _dsd
from . import smartnet

# algorithms selectable in the Keys dialog -> (label, key length in bytes)
CRYPT_ALGS = [(0x84, "AES-256", 32), (0x85, "AES-128", 16),
              (0x81, "DES-OFB", 8), (0xAA, "ADP / RC4-40", 5)]

# the P25 decryption keys live in the core keystore (api.secrets, config/secrets.json, mode 0600) under
# this owner/name -- real key material, never in state.json or a repo. Older builds kept them in
# memory/keys.json; load_crypt_keys migrates that file once (see _migrate_legacy_keys).
_SECRET_OWNER = "digital"
_SECRET_NAME = "p25_keys"


# -- keystore (api.secrets: real key material, never in a repo) -----------------------------------------
def _legacy_keys_path():
    return paths.memory_file("keys.json")


def _coerce_keys(data):
    out = []
    for e in data if isinstance(data, list) else []:
        try:
            out.append({"keyid": int(e["keyid"]), "algid": int(e["algid"]), "key": str(e["key"])})
        except (KeyError, ValueError, TypeError):
            continue
    return out


def _migrate_legacy_keys():
    """One-time import of a pre-keystore memory/keys.json into api.secrets; the old file is renamed
    keys.json.moved so it's never read again. Returns the imported keys, or None if there was nothing
    to migrate."""
    old = _legacy_keys_path()
    try:
        with open(old) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    keys = _coerce_keys(data)
    save_crypt_keys(keys)                       # into api.secrets
    try:
        os.replace(old, old + ".moved")
    except OSError:
        pass
    return keys


def load_crypt_keys():
    raw = secrets.get(_SECRET_OWNER, _SECRET_NAME)
    if raw is None:
        migrated = _migrate_legacy_keys()       # first run after the move: pull keys.json in once
        return migrated if migrated is not None else []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    return _coerce_keys(data)


def save_crypt_keys(keys):
    try:
        secrets.set(_SECRET_OWNER, _SECRET_NAME, json.dumps(keys))
    except OSError:
        pass


def parse_hex_key(text):
    """Parse '12 34  AB' / '1234ab' / '0x12,0x34' -> list[int], or None."""
    s = text.strip().lower().replace("0x", "").replace(",", " ")
    s = "".join(s.split())
    if not s or len(s) % 2:
        return None
    try:
        return [int(s[i:i + 2], 16) for i in range(0, len(s), 2)]
    except ValueError:
        return None


def _algname(algid):
    return next((n for a, n, _ln in CRYPT_ALGS if a == algid), f"alg 0x{algid:02X}")


def open_keys_dialog(mod, parent):
    """Manage P25 decryption keys (KID + algorithm + hex key). Keys are pushed to op25 live and saved to the
    keystore."""
    dlg = QtWidgets.QDialog(parent)
    dlg.setWindowTitle("P25 decryption keys")
    v = QtWidgets.QVBoxLayout(dlg)
    v.addWidget(QtWidgets.QLabel(
        "Keys are stored locally in the keystore (config/secrets.json, mode 0600) "
        "and loaded into op25. Decryption needs op25 built with the algorithm (AES-256 "
        "requires a current boatbod build)."))
    lst = QtWidgets.QListWidget()

    def _refill():
        lst.clear()
        for k in mod.crypt_keys:
            kb = parse_hex_key(k["key"]) or []
            lst.addItem(f"KID {k['keyid']}  ·  {_algname(k['algid'])}  ·  {len(kb)} bytes")
    _refill()
    v.addWidget(lst)
    form = QtWidgets.QFormLayout()
    kid_edit = QtWidgets.QLineEdit()
    kid_edit.setPlaceholderText("e.g. 161 or 0xA1")
    form.addRow("Key ID:", kid_edit)
    alg_combo = QtWidgets.QComboBox()
    for algid, label, ln in CRYPT_ALGS:
        alg_combo.addItem(f"{label}  ({ln} bytes)", algid)
    form.addRow("Algorithm:", alg_combo)
    key_edit = QtWidgets.QLineEdit()
    key_edit.setPlaceholderText("hex key, e.g. 0123ABCD…")
    form.addRow("Key (hex):", key_edit)
    v.addLayout(form)
    status = QtWidgets.QLabel("")
    status.setStyleSheet("color:#ff6b6b;")
    v.addWidget(status)

    def _add():
        try:
            kid = int(kid_edit.text().strip(), 0)
        except ValueError:
            status.setText("Key ID must be a number (161 or 0xA1)")
            return
        algid = alg_combo.currentData()
        want = next((ln for a, _n, ln in CRYPT_ALGS if a == algid), 0)
        kb = parse_hex_key(key_edit.text())
        if kb is None:
            status.setText("Key must be hex (even number of digits)")
            return
        if want and len(kb) != want:
            status.setText(f"{_algname(algid)} needs {want} bytes, got {len(kb)}")
            return
        mod.crypt_keys = [k for k in mod.crypt_keys if k["keyid"] != kid]
        mod.crypt_keys.append({"keyid": kid, "algid": algid, "key": "".join(f"{b:02x}" for b in kb)})
        save_crypt_keys(mod.crypt_keys)
        if mod.br is not None:
            mod.br.add_crypt_key(kid, algid, kb)     # apply live
        status.setStyleSheet("color:#39ff88;")
        status.setText(f"loaded key {kid} ({_algname(algid)})")
        kid_edit.clear()
        key_edit.clear()
        _refill()

    def _remove():
        row = lst.currentRow()
        if 0 <= row < len(mod.crypt_keys):
            del mod.crypt_keys[row]
            save_crypt_keys(mod.crypt_keys)
            # op25 has no per-key unload; keys clear on decoder rebuild / restart
            _refill()
            status.setStyleSheet("color:#8b95a1;")
            status.setText("removed (takes effect on restart / mode change)")

    btns = QtWidgets.QHBoxLayout()
    for text, fn in (("Add / update", _add), ("Remove selected", _remove)):
        b = QtWidgets.QPushButton(text)
        b.clicked.connect(fn)
        btns.addWidget(b)
    btns.addStretch(1)
    close_btn = QtWidgets.QPushButton("Close")
    close_btn.clicked.connect(dlg.accept)
    btns.addWidget(close_btn)
    v.addLayout(btns)
    dlg.exec_()


# -- SmartNet ------------------------------------------------------------------------------------------
def open_smartnet_settings(mod, parent):
    """The channel->frequency band plan SmartNet uses to turn a decoded OSW channel number into the MHz shown
    in the decode log -- op25's tk_smartnet.py needs the same choice per system; most US 800 MHz systems are
    "800_domestic" or, if rebanded post-2008, "800_rebanded". Applies live."""
    if mod._smartnet_dialog is None:
        dlg = QtWidgets.QDialog(parent)
        dlg.setWindowTitle("SmartNet bandplan")
        form = QtWidgets.QFormLayout(dlg)
        combo = QtWidgets.QComboBox()
        combo.addItems(smartnet.BANDPLANS)
        combo.setCurrentText(mod.smartnet_bandplan)

        def on_change(name):
            mod.smartnet_bandplan = name
            if mod.monitor is not None:
                mod.monitor.set_smartnet_bandplan(name)
        combo.currentTextChanged.connect(on_change)
        form.addRow("Band plan:", combo)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        btns.rejected.connect(dlg.close)
        btns.accepted.connect(dlg.close)
        form.addRow(btns)
        mod._smartnet_dialog = dlg
    mod._smartnet_dialog.show()
    mod._smartnet_dialog.raise_()


# -- DMR LCN bandplan ----------------------------------------------------------------------------------
def dmr_lcn_freq_hz(bandplan):
    """[{lcn, freq_mhz}] -> {lcn: freq_hz} for DigitalMonitor.set_dmr_bandplan. Later entries win."""
    out = {}
    for e in bandplan:
        try:
            out[int(e["lcn"])] = float(e["freq_mhz"]) * 1e6
        except (KeyError, TypeError, ValueError):
            continue
    return out


def open_dmr_bandplan(mod, parent):
    """Map DMR Connect/Capacity Plus LCNs (seen in CSBK channel grants) to real receive frequencies, so a
    grant shows where to tune. Unlike SmartNet's bandplans this has no formula: the LCN->frequency assignment
    is up to the system operator and isn't broadcast, so it's entered by hand. Applies live."""
    if mod._dmr_bandplan_dialog is None:
        dlg = QtWidgets.QDialog(parent)
        dlg.setWindowTitle("DMR bandplan (LCN -> frequency)")
        v = QtWidgets.QVBoxLayout(dlg)
        v.addWidget(QtWidgets.QLabel(
            "Motorola Connect/Capacity Plus channel grants carry a Logical "
            "Channel Number (LCN), not a frequency — enter the mapping for "
            "this system so grants resolve to a frequency in the decode log."))
        lst = QtWidgets.QListWidget()

        def _refill():
            lst.clear()
            for e in mod.dmr_bandplan:
                lst.addItem(f"LCN {e['lcn']}  ->  {e['freq_mhz']:.4f} MHz")
        _refill()
        v.addWidget(lst)
        form = QtWidgets.QFormLayout()
        lcn_spin = QtWidgets.QSpinBox()
        lcn_spin.setRange(0, 15)                # b[8] top nibble, monitor.py
        form.addRow("LCN:", lcn_spin)
        freq_edit = QtWidgets.QLineEdit()
        freq_edit.setPlaceholderText("e.g. 451.0250")
        form.addRow("Frequency (MHz):", freq_edit)
        v.addLayout(form)
        status = QtWidgets.QLabel("")
        status.setStyleSheet("color:#ff6b6b;")
        v.addWidget(status)

        def _push_live():
            if mod.monitor is not None:
                mod.monitor.set_dmr_bandplan(dmr_lcn_freq_hz(mod.dmr_bandplan))

        def _add():
            lcn = lcn_spin.value()
            try:
                freq_mhz = float(freq_edit.text().strip())
            except ValueError:
                status.setText("Frequency must be a number (MHz)")
                return
            mod.dmr_bandplan = [e for e in mod.dmr_bandplan if e["lcn"] != lcn]
            mod.dmr_bandplan.append({"lcn": lcn, "freq_mhz": freq_mhz})
            _push_live()
            status.setStyleSheet("color:#39ff88;")
            status.setText(f"LCN {lcn} -> {freq_mhz:.4f} MHz")
            freq_edit.clear()
            _refill()

        def _remove():
            row = lst.currentRow()
            if 0 <= row < len(mod.dmr_bandplan):
                del mod.dmr_bandplan[row]
                _push_live()
                status.setStyleSheet("color:#8b95a1;")
                status.setText("removed")
                _refill()

        btns = QtWidgets.QHBoxLayout()
        for text, fn in (("Add / update", _add), ("Remove selected", _remove)):
            b = QtWidgets.QPushButton(text)
            b.clicked.connect(fn)
            btns.addWidget(b)
        btns.addStretch(1)
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btns.addWidget(close_btn)
        v.addLayout(btns)
        mod._dmr_bandplan_dialog = dlg
    mod._dmr_bandplan_dialog.show()
    mod._dmr_bandplan_dialog.raise_()


# -- EDACS ---------------------------------------------------------------------------------------------
def edacs_flags(edacs, csv_path=None):
    """dsd-fme flags for the EDACS settings; writes the LCN table as dsd-fme's -C channel map when it has
    entries (``csv_path``, default memory/edacs_lcn.csv)."""
    csv = None
    lcns = sorted(edacs["lcns"], key=lambda e: int(e["lcn"]))
    if lcns:
        path = csv_path or paths.memory_file("edacs_lcn.csv")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write("LSN(dec),frequency(Hz) (do not delete this line or won't import properly)\n")
                for e in lcns:
                    fh.write(f"{int(e['lcn'])},{int(round(float(e['freq_mhz']) * 1e6))}\n")
            csv = path
        except OSError:
            csv = None
    return _dsd.edacs_flags(edacs["variant"], edacs["afs"] or None, csv)


def edacs_lcn_freq(edacs, lcn):
    for e in edacs["lcns"]:
        if int(e["lcn"]) == int(lcn):
            return float(e["freq_mhz"])
    return None


def open_edacs_settings(mod, parent):
    """EDACS: which variant dsd-fme decodes (it can't tell Standard/Networked from Extended Addressing by
    itself), a custom AFS split, and the system's LCN -> frequency table (grants carry only a logical
    channel number; the assignment is per system). Applies live: a running EDACS decode restarts."""
    if mod._edacs_dialog is None:
        dlg = QtWidgets.QDialog(parent)
        dlg.setWindowTitle("EDACS")
        v = QtWidgets.QVBoxLayout(dlg)
        form = QtWidgets.QFormLayout()
        var = QtWidgets.QComboBox()
        var.addItems(list(_dsd.EDACS_VARIANTS))
        var.setCurrentText(mod.edacs["variant"])
        var.setToolTip("Extended Addressing (EA) or Standard/Networked. Wrong choice: frames still "
                       "decode (same sync / BCH), but the messages make no sense -- e.g. every "
                       "grant on one LCN. ESK: systems that XOR their messages with 0xA0.")
        form.addRow("Variant:", var)
        afs = QtWidgets.QLineEdit(mod.edacs["afs"])
        afs.setPlaceholderText("e.g. 344 (Standard only; blank = dsd-fme default)")
        form.addRow("AFS split:", afs)
        v.addLayout(form)
        v.addWidget(QtWidgets.QLabel("LCN -> frequency (grants show where to tune):"))
        lst = QtWidgets.QListWidget()
        v.addWidget(lst)
        row = QtWidgets.QHBoxLayout()
        lcn_spin = QtWidgets.QSpinBox()
        lcn_spin.setRange(1, 31)
        freq_edit = QtWidgets.QLineEdit()
        freq_edit.setPlaceholderText("MHz, e.g. 851.0125")
        row.addWidget(QtWidgets.QLabel("LCN"))
        row.addWidget(lcn_spin)
        row.addWidget(freq_edit, 1)
        v.addLayout(row)
        status = QtWidgets.QLabel("")
        v.addWidget(status)

        def _refill():
            lst.clear()
            for e in sorted(mod.edacs["lcns"], key=lambda e: int(e["lcn"])):
                lst.addItem(f"LCN {int(e['lcn']):2d}  ->  {float(e['freq_mhz']):.4f} MHz")

        def _apply():
            mod.edacs["variant"] = var.currentText()
            a = afs.text().strip()
            mod.edacs["afs"] = a if a.isdigit() else ""
            mod.apply_edacs()

        def _add():
            try:
                f = float(freq_edit.text().strip())
            except ValueError:
                status.setStyleSheet("color:#ff6b6b;")
                status.setText("Frequency must be a number (MHz)")
                return
            n = lcn_spin.value()
            mod.edacs["lcns"] = [e for e in mod.edacs["lcns"] if int(e["lcn"]) != n]
            mod.edacs["lcns"].append({"lcn": n, "freq_mhz": f})
            status.setStyleSheet("color:#39ff88;")
            status.setText(f"LCN {n} -> {f:.4f} MHz")
            freq_edit.clear()
            _refill()
            _apply()

        def _remove():
            items = sorted(mod.edacs["lcns"], key=lambda e: int(e["lcn"]))
            r = lst.currentRow()
            if 0 <= r < len(items):
                mod.edacs["lcns"].remove(items[r])
                _refill()
                _apply()

        var.currentTextChanged.connect(lambda _t: _apply())
        afs.editingFinished.connect(_apply)
        btns = QtWidgets.QHBoxLayout()
        for text, fn in (("Add / update", _add), ("Remove selected", _remove)):
            b = QtWidgets.QPushButton(text)
            b.clicked.connect(fn)
            btns.addWidget(b)
        btns.addStretch(1)
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btns.addWidget(close_btn)
        v.addLayout(btns)
        _refill()
        mod._edacs_dialog = dlg
    mod._edacs_dialog.show()
    mod._edacs_dialog.raise_()
