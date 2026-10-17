# sdrexplorer-digital

Digital voice and trunking decode for [sdrexplorer](../sdrexplorer): **op25** (P25 Phase 1, DMR, SmartNet,
P25 / DMR transmit) and **dsd-fme** (NXDN48 / NXDN96, EDACS, mobile-station / direct-mode DMR), as one module. For sdrexplorer module API 1.x.

## What it adds

- **A "Digital" tab** in the decode strip under the waterfall. Decoding runs on the tuned channel beside
  whatever analog mode is picked:
  - **Decode:** P25 or DMR (op25), NXDN96 or NXDN48 or EDACS (dsd-fme), or DMR-MS (dsd-fme). A classifier
    label you tune onto, or a bank channel's mode, switches it (`request_decode`).
  - The lock light. 🔒 means the call is encrypted.
  - **Keys…:** P25 decryption keys (key ID, algorithm, hex key), kept in the core keystore (`api.secrets`).
  - **Digital only:** keeps analog muted between transmissions.
  - **Data bursts:** captures op25's decoded DATA bursts (short data, LRRP, PDU, PDP) into the core's
    payload pane. They export as raw-IP pcap. EDACS control-channel frames go there too, as their two 28-bit
    message words (8 bytes, MSG_1 then MSG_2), with the message types and dsd-fme's reading; each pair is
    shown once per 5 s (a control channel repeats them every frame). They export as LINKTYPE_USER0 (147),
    in their own .pcap.
  - Every payload is tied to the log lines it was decoded with (`api.Decode.ref`): an op25 data burst and its
    LRRP / ARS / ICMP line, a dsd-fme frame and its lines, a whole NXDN data call (header, data blocks, GPS
    report). With the decode strip's "Follow log filter", searching the log for a unit, "GPS" or
    "Location" shows those payloads.
  - The dsd-fme status: what NXDN / EDACS decodes (RAN, talkgroup, source; site, group, LCN).
- **Voice through the core speaker.** A decoder with a lock takes the speaker: analog is muted and the
  signal meter shows the protocol (e.g. "P25 NAC 293"). The volume control and the scan's sweep mute apply
  to the decoded voice too. A 2 s hang keeps it through short sync drops.
- **Decode log lines** go to the core's log as `api.Decode` records. Each line names the station from your
  banks: a P25 NAC, DMR color code or NXDN RAN matches a channel's tone code. Every frame counts for the
  label of a recording made meanwhile.
- **SmartNet / SmartZone** control channels (OSW stream: voice grants, control-channel id, busy / deny
  codes) decode all the time, on their own demod. There is no mode to pick: tune to a control channel.
  - Settings ▸ SmartNet bandplan… picks the channel → frequency plan. Most US 800 MHz systems are
    `800_domestic`, or `800_rebanded` if rebanded after 2008.
  - Decode-only: voice grants aren't followed.
- **DMR**
  - **Base-station and mobile-station / direct-mode bursts.** A repeater's output (base station: CACH,
    both timeslots) is decoded by op25, with its trunking and data bursts. A radio's own transmission
    (mobile station or direct mode: a repeater input, simplex) is something op25 can't decode. On DMR,
    dsd-fme runs beside op25 on the discriminator audio and tells the two apart from their sync words:
    while the bursts are mobile-station / direct-mode, the call is decoded with dsd-fme (its voice, its
    log line `DMR  MS  CC … TG … SRC …`, the status says so); base-station bursts stay with op25. Only
    one decoder's voice plays at a time. **DMR-MS** in the Decode picker uses dsd-fme for every DMR call
    (an override; a bank channel saved with mode DMR-MS picks it). Needs dsd-fme; without it DMR is
    op25 only, as before. The picker follows what op25 decodes between P25 and DMR, so a DMR call heard
    while P25 is picked switches it to DMR (and its detector on) by itself; DMR-MS stays as picked.
  - Settings ▸ DMR bandplan (LCN)… maps Connect / Capacity Plus LCNs to frequencies, so a grant shows
    where to tune.
  - Source ids are resolved to callsigns through radioid.net, in the background, and cached.
- **EDACS** (needs dsd-fme): pick EDACS, or tune onto a signal the classifier has sync-confirmed as EDACS.
  - dsd-fme decodes the 9600 Bd control channel: site and system id, adjacent sites, group and individual
    call grants. Lock means a BCH-clean frame.
  - Settings ▸ EDACS… sets the variant: Extended Addressing (the default) or Standard/Networked, either
    with ESK, or a custom AFS split. dsd-fme can't tell these apart by itself. With the wrong one, frames
    still decode but the messages make no sense.
  - The same dialog takes the system's LCN → frequency table. It's passed to dsd-fme as its `-C` channel
    map, and the log shows each grant's frequency.
  - Decode-only: voice grants aren't followed.
- **Positions on the map:** LRRP locations in DMR data bursts, NXDN data-call GPS reports, and P25 GPS sent
  in the voice link control (Motorola embedded GPS, MFID 0x90), one target per unit.
  - DMR LRRP reports go to the decode log as "★ LRRP LOCATION lat, lon … SRC <radio>". The radio id is the
    low 24 bits of the report's IPv4 source address (MOTOTRBO addresses radios as 12.x.y.z), so each radio on
    a channel gets its own map target ("DMR <radio>").
  - P25 GPS reports go to the decode log as "★ P25 GPS lat, lon current/last fix SRC <unit>".
  - The unit comes from the same call's voice link control (group / unit-to-unit voice channel user).
  - With Data bursts on, the 9-byte link control word goes to the payload pane, exported as
    LINKTYPE_USER1 (148). The decode strip's "Follow log filter" shows a log line's payload.
  - A report marked protected (encrypted) is logged as such, without coordinates.
- **P25 and DMR transmit** in the main window's TX: picker. P25 is clear voice only: op25's encoder has
  no encryption. The fields that change from channel to channel are beside the TX: picker: TG and NAC for
  P25 (both sent in the call), TG and CC for DMR. Your radio id, which stays the same, is in Settings ▸
  Transmit. A channel saved while DMR is the TX mode keeps its CC and TG in its tone field ("CC 6 TG 100").
- **Decode log for P25 calls:** the talkgroup and unit come from the call's voice Link Control when op25's
  call metadata doesn't carry them (conventional and simplex calls), e.g. "P25 NAC 0x293 LCW TG 100 SRC 1001".
- **Decoder proofs** (`sdrexplorer.proofs` entry point, headless): DMR, P25-P1, NXDN48, NXDN96 (dsd-fme
  with a CRC-clean field), EDACS (BCH-clean frames), EDACS-V (9600 Bd dotting, per recording) and
  SmartNet (CRC-valid OSWs). The classifier's hunt and sdrexplorer-train use them.

## Install

1. Clone this repo next to the sdrexplorer checkout (`…/src/sdrexplorer-digital`), where it is found by
   itself. Or put it anywhere and use Settings ▸ Modules ▸ Add module…, or `pip install -e .` into
   sdrexplorer's Python.
2. Build **op25** (boatbod, commit `da5374d`, with `patches/op25-sdrexplorer.patch`, see [The op25 patch](#the-op25-patch)) and/or **dsd-fme**
   (lwvmobile, commit `69d3115`, with mbelib). Neither is on conda / PyPI. Each part works without the
   other: op25 alone gives P25 / DMR / SmartNet, dsd-fme alone gives NXDN / EDACS and the proofs.
3. Tell sdrexplorer where they are, in `paths.json`:

   ```json
   {"op25": "/path/to/op25-install", "op25_apps": "/path/to/op25/op25/gr-op25_repeater/apps",
    "dsd_fme": "/path/to/dsd-fme-install"}
   ```

   or `SDREXPLORER_OP25=…`, `SDREXPLORER_OP25_APPS=…`, `SDREXPLORER_DSD_FME=…` for one run. The old
   `OP25_PREFIX` / `OP25_APPS` still work. `op25_apps` defaults to `<op25>/apps`. Check with
   `python3 -m sdrexplorer.paths` (the keys appear once the module has loaded).

`--module-option digital.op25_stderr=1` echoes op25's raw decoder output to the terminal while data bursts
are captured (otherwise it's parsed and discarded).

## The op25 patch

`patches/op25-sdrexplorer.patch` holds seven changes to op25 at `da5374d`, each offered to boatbod/op25
as its own pull request. The patch shrinks as they are merged. The status below is as of 1.0.0; the patch
header's `Upstream-Status:` line has the current one.

| # | Change | Why sdrexplorer needs it | Upstream (1.0.0) |
|---|---|---|---|
| 1 | `op25_crypt_algs` destructor | A decoder holding P25 keys crashed when it was destroyed. | merged ([#306](https://github.com/boatbod/op25/pull/306)); no longer in the patch |
| 2 | NXDN TX filter taps (`transfer_function_nxdn` takes `rate_multiplier`) | NXDN transmit failed with a `TypeError`. | [#307](https://github.com/boatbod/op25/pull/307), open |
| 3 | DMR color code in the CACH SLC, CSBK, voice LC, terminator LC and embedded LC messages | The decode log shows each burst's color code. | [#308](https://github.com/boatbod/op25/pull/308), open |
| 4 | P25 Phase 1 TX: settable NAC and Link Control (`vocoder.set_nac` / `set_lc`) | op25 always sent NAC 0x293 and a fixed talkgroup / source, so it could only key a repeater that checks nothing else. | [#310](https://github.com/boatbod/op25/pull/310), open |
| 5 | `dmr_ms_tx_bb`: a DMR mobile-station voice transmitter | The "DMR-MS" TX mode: bursts a repeater's receiver accepts. | not yet offered (waiting for a test with a real repeater) |
| 6 | `dmr_bs_tx_bb`: embedded LC in voice bursts B–E, null embedded field in F | Receivers could never assemble the LC, so they showed no talkgroup or source. | [#309](https://github.com/boatbod/op25/pull/309), open |
| 7 | `dmr_bs_tx_bb`: idle data bursts in a disabled timeslot | The unused slot was decoded as garbage headers and voice. | not yet offered (builds on 6) |
| 8 | DMR receive: the color code learned on one timeslot applies to the other | A call with no data burst on its own slot had its embedded signaling rejected. | not yet offered (builds on 3) |

Details:
- **4:** the FEC (BCH(64,16,23) NID, RS(24,12,13) + Hamming(10,6,3) LC) is ported from op25's own
  `apps/tx/p25craft.py`, and the defaults reproduce the old NAC 0x293 / preset LC bit for bit.
  `tests/verify_p25_nac_loopback.py` round-trips a chosen NAC + LC through op25's own receiver (it needs op25
  on the path).
- **5:** unlike `dmr_bs_tx_bb`, which makes base-station (repeater output) bursts, `dmr_ms_tx_bb` emits
  mobile-station bursts: voice LC header, embedded-LC voice superframes, terminator. It reads AMBE codewords
  and emits DMR dibits. The FEC'd constant bursts are precomputed in Python (`dmr_ms_frame`) and loaded from a
  config file, so no FEC is reimplemented in C++. dsd-fme decodes the whole call it makes
  (`test_dmr_ms_tx_decodes`), but it has **not yet been tested with a real repeater**.

## Offline replay

`src/sdrexplorer_digital/tools/run_replay.sh cap.cs16 482662500 P25` replays a recording through op25's
`multi_rx.py` (deterministic, no radio).

## Layout

| Path | What |
|---|---|
| `src/sdrexplorer_digital/module.py` | `DigitalModule`: the Digital tab, locks and the speaker, decode log, request_decode, TX modes, state |
| `branches.py` | the GNU Radio branches on the core's channel tap: op25 P25 / DMR, SmartNet, the discriminator tap for dsd-fme |
| `monitor.py` | op25's message queue → decodes (P25 / DMR / SmartNet), LRRP, data-burst capture, replay config |
| `dsdfme.py` | dsd-fme bridges (NXDN, EDACS, DMR): FIFO, lock rule, line parsers, voice relay; DMR's tells base-station from mobile-station / direct-mode bursts |
| `voice.py` | decoded voice (UDP from op25 / dsd-fme) → the core's audio input; plays one decoder's voice when two decode a DMR call |
| `tx.py` | P25 / DMR (base-station) modulators (`api.TxModeSpec`) |
| `dmr_ms_tx.py`, `dmr_ms_frame.py` | DMR mobile-station TX ("DMR-MS"): the `dmr_ms_tx_bb` wiring + the burst/FEC generator |
| `dialogs.py` | Settings dialogs and the keystore |
| `smartnet.py`, `radioid.py`, `proofs.py`, `pathkeys.py` | OSW tracker / band plans, DMR id lookup, decoder proofs, path keys |
| `tests/test_digital.py` | 23 tests in the real window (offscreen) |
| `patches/` | the op25 changes |

## Tests

```bash
QT_QPA_PLATFORM=offscreen python3 tests/test_digital.py     # the sdrexplorer checkout beside this repo
```

## License

GPL-3.0-or-later (op25 and dsd-fme are GPL).
