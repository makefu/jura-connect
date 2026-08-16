# Changelog

All notable changes to `jura-connect` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.13.0] — 2026-08-16

Closes the gap against the official J.O.E. Android app
(`ch.toptronic.joe` 4.6.10). The app's WiFi adapter implements every
method of its own transport interface; this library implemented the
read paths and single-shot writes. Everything stateful — anything where
the machine talks back mid-operation — was missing, and four commands
carried the wrong meaning. `docs/JOE_GAPS.md` records the full
comparison.

Unless a bullet says otherwise, the new work is derived from the
decompiled app and verified against the simulator only: no coffee
machine was available while it was written. The wire formats that *are*
hardware-verified (the `@TP:` recipe blob, the `@TV:` value window) say
so in `docs/PROTOCOL.md`.

### Added
- **Product progress (`@TV:`) is decoded** —
  `jura_connect/progress.py`. 87 `ProgressState` codes, seven frame
  types, the `8F` extended value window and the `41` hot-water/bypass
  split. `ProductProgress` carries state, product or process, actual,
  maximum and percent, with `format()` and `to_dict()`;
  `JuraClient.iter_progress()`, `follow_progress()`,
  `brew(follow=True)` and the `progress` command consume it, and the
  simulator plays a whole brew. These frames used to be discarded, so a
  consumer could see the machine's alerts but never what it was doing —
  the reason the Home Assistant integration could not report "brewing,
  60 %". The value window and the completion frame match the live S8 EB
  brew recorded in `PROTOCOL.md` §5.9.
- **Maintenance processes are drivable** — `jura_connect/process.py`.
  `<PROCESS>` and `<STATE>` are parsed (83 states on the S8 EB), a run
  reports every step and whether it needs confirmation, and the client
  can accept (`@TG:04` / `@TG:10`, whichever the machine's XML
  declares), advance (`@TG:01`) or cancel (`@TG:FF`). `clean` and
  friends were fire-and-forget and stalled at the first state that
  wanted a confirmation.
- **`MachineStatus` answers "can I brew right now?"** The `<ALERT>`
  element's `Blocked` and `Process` attributes are parsed, so
  `blocked_kinds`, `blocking_alerts`, `alert_processes`,
  `can_brew_kind()` and `can_brew()` are available. Purely additive:
  every existing field and `to_dict()` key is unchanged.
- **Every counter bank a machine declares is read** — `@TR:52`/`@TR:53`
  special, `@TR:34`/`@TR:35` barista, and the four `@TR:42`–`@TR:45`
  **daily** banks with the gated `@TF:05` reset. Jura's own XML comments
  mark the daily banks "Not available in JOE": a real machine capability
  the official app never reads.
- **PMode writes** — `@TM:41` product read/write and `@TM:42` slot
  write, built from the machine profile and validated before anything
  reaches the wire. Gated.
- **Machine settings in one round trip** — the XML's
  `<BANK Name="Setting" Command="@TM:00,FC">`, with automatic fallback
  to one `@TM:<arg>` per setting. The app *declares* this bank and never
  sends it (`Bank.java` discards the argument list), so the reply layout
  is a documented guess and the fallback is the safety net.
- **Live parameter limits** — `@TM:60` returns the ranges the machine
  allows right now, as opposed to the XML's static ones.
- **Brew preselections** — extra shot, double, powder, cold brew, light
  brew, sweet foam. Two mechanisms: pre-`IntakeF18` machines (the S8 EB
  among them) swap in the double's own product code and overwrite
  specific blob bytes, while `IntakeF18` machines carry a preselection
  mask in a 20-byte blob. `products` lists what each product supports
  and flags what the connected machine cannot send.
- **Coffee timer** — `@TM:3C` schedules a brew (the trailing field is
  seconds until the pour) and `@TV:84` carries the target time of day.
  Gated: the machine pours with nobody present.
- **Language download** — the whole `@TS:F1` / `@TT:00`–`@TT:08` /
  `@TV:81`/`@TV:82` sequence with Motorola S-record payloads,
  capability-gated (6 of the 89 profiles declare it) and with the keypad
  unlock in a `finally` so a failed transfer cannot leave the display
  locked.
- **Firmware and milk cooler** — `@HB`, `@HO:`, `@HD:`, `@HE`, `@HT:3`,
  `@HU`, `@HU?`. The OTA sequencer is **library-only and deliberately
  not a named command**: it is only safe atomically, there is no image
  this library can obtain or verify, and a partial transfer is recovered
  by a service visit. Its entry points require
  `acknowledge_bricking_risk=True` and raise before any socket write.
  The exposed commands are `milk-cooler-status`, `milk-cooler-update`
  and `restart-dongle`.
- **Brew counts past 65535 survive on machines with an overflow bank.**
  34 of the 89 bundled profiles declare an `@TR:33` "Overflow Product
  Counter" alongside `@TR:32`; it carries the high byte of each slot,
  and without it a per-product count wraps at 65535.
  `MachineProfile.counter_banks` now records what a machine declares,
  and `read_product_counters()` reads `@TR:33` for those machines and
  folds it in as `value + (high << 16)`, matching J.O.E. Machines that
  declare no overflow bank — every S8/Z10 profile among them — issue the
  same single bank read as before. **Untested against hardware:** no
  machine available to the project declares the bank, so this path is
  covered by the simulator and by the decompiled app only.

### Breaking changes for library consumers

Checked mechanically against the `v0.12.0` tag: **no public class or
function was removed and no signature lost a parameter.** Every break
below is structural or behavioural, so it will surface at runtime rather
than at import. `ProductCounters`, `MachineInfo`, `SettingValue`,
`ProgramModeSlots` and `PModeSlot` are untouched, and `MachineStatus`
only gained fields.

- **`MaintenanceCounters` / `MaintenancePercent` changed shape.** The
  six (resp. three) dataclass *fields* became a single ordered
  `counters` / `percent` tuple of `(name, value)` pairs, because the
  field order is per machine (see Fixed). The old names still work for
  **reading** — they are now properties returning `int | None`:

  ```python
  counters.cleaning          # still fine, but may be None now
  counters.get("cappu_rinse")  # explicit, returns None when unreported
  ```

  What breaks: constructing one directly
  (`MaintenanceCounters(cleaning=26, …)` — use `parse()`),
  `dataclasses.replace()` / `asdict()` / `astuple()` on them, and any
  code assuming the attributes are always `int`. On a machine that
  reports four counters, `cappu_rinse` and `cappu_clean` are `None`.
- **`to_dict()` key sets are no longer fixed** for those two types: a
  counter the machine does not report is absent, not zero. Consumers
  that index (`d["cappu_rinse"]`) must use `.get()`. This is the one
  most likely to bite the Home Assistant integration.
- **The `reset-counters` command no longer exists**; it is
  `skip-quality-step` with an optional `one` / `all` argument.
  `run_named(client, "reset-counters")` now raises `CommandError`, and
  any CLI script using the old name fails. The rename is not cosmetic:
  `@TG:7E` is the quality-assistant skip, and calling it
  "reset counters" invited exactly the accident that named it.
- **`read_status()` no longer puts `@HU?` on the wire.** It waits for
  the `@TF:` frame the dongle pushes on its own. Callers that relied on
  the send (some firmwares want traffic on the socket first) pass
  `read_status(nudge=True)`. Timing changes: the call now returns on the
  machine's own broadcast interval, roughly every two seconds on an
  S8 EB, instead of immediately after a round trip.
- **`close()` sends an empty frame instead of `@HE`.** Anything
  asserting on the closing frame — a proxy, a capture-based test — sees
  a different byte sequence. `@HE` is the OTA-end verb and is now gated.
- **`DESTRUCTIVE_PREFIXES` is no longer the whole gate.** `@TG:FF` left
  the tuple (it is the ungated `cancel`) and ten families joined it, and
  `@HU` cannot be a prefix at all because it would swallow the `@HU?`
  read — it lives in the new `DESTRUCTIVE_EXACT`. Code that matched the
  tuple by hand must call `match_destructive(payload)` instead, which is
  what the runtime gate, the `raw` inspector and the simulator all use.
- **`ProductDef.build_recipe_hex()` can return a 17-byte blob.**
  Products declaring `Argument="F17"` (grinder freeness) previously
  raised; they now build the 17-byte form the app builds. Callers that
  hard-code a 32-hex-character length need to relax that check.
  Products without F17 still produce the byte-identical 16-byte blob.
- **`MachineProfile.has_pmode` changed meaning.** It used to probe for a
  `<PROGRAMMODE>` element that exists in no bundled XML, so it was
  always `False`; it now reflects `<MACHINESETTINGS Productprogramming>`
  and is `True` for 20 profiles. Code branching on it will take the
  other path for the first time.

### Changed
- The three API-level breaks are described in full under **Breaking
  changes for library consumers** above.
- Destructive gating grew an exact-match tier. `@HU` cannot be a prefix
  because it would swallow the `@HU?` read, so `match_destructive()` is
  now the single matcher shared by the runtime gate, the `raw` payload
  inspector and the simulator.
- The simulator models brewing and its progress stream, maintenance
  processes, PMode slots, the coffee timer, language download and the
  firmware family — each behind an explicit opt-in flag, and it still
  refuses destructive frames with `@an:error` by default.

### Fixed
- **Maintenance counters were labelled wrong on 21 of the 89 known
  machines.** The `@TG:43` / `@TG:C0` field order is declared per
  machine by the XML's `<BANK>` `<TEXTITEM Type=…>` children, not fixed:
  13 profiles report only four counters, 7 order the tail
  `CoffeeRinse, CappuRinse, CappuClean`, and EF567_C has no
  `FilterChange` at all. On any of them the hard-coded order silently
  mislabelled every value. `MachineProfile.maintenance_counter_fields` /
  `.maintenance_percent_fields` now drive the decode, with the old order
  kept as the no-profile fallback. The S8 EB and the EF536 baseline
  match that fallback, which is why this went unnoticed.
- **`@TG:FF` is not a reset.** It is the app's
  `WifiCommandCancelProductStep` — "abort the running step". It was
  gated as a destructive broad reset and is now the ungated `cancel`
  command.
- **`@HE` is not a polite close.** It is `WifiCommandOTAEnd`. The app
  closes a session with an *empty* frame, and `JuraClient.close()` now
  does the same.
- **`@HU?` is not a status request.** It is
  `WifiCommandMilkCoolerUpdateStatus`, which is why probing it returned
  `@hu:800` rather than a status frame: the first hex digit is the state
  (`0` idle, `1` updating with the low byte as percent, `8` no milk
  cooler connected), so `800` is exactly what an S8 EB should answer.
  This closes the open question in `PROTOCOL.md` §9.
- **Products with a grinder-freeness parameter could not be brewed at
  all.** `Argument="F17"` lands at blob offset 16 and raised on the
  16-byte path; the app builds a 17-byte blob for those products. Six
  profiles declare it, and on those machines neither `brew`, nor the
  library, nor the coffee timer could start anything.
- **`MachineProfile.has_pmode` was permanently `False`.** It probed for
  a `<PROGRAMMODE>` element that exists in no bundled XML and in neither
  documented template profile. The real declarations are
  `<MACHINESETTINGS Productprogramming=…>` (57 profiles, 20 of them
  true) and `NumberOfSlotsForProductProgramming` (5 profiles).
- **`flake.nix` was left at 0.11.0 by the v0.12.0 release.** The three
  version locations `AGENTS.md` requires to move in lockstep are back in
  step.
- **A Z10's double products are counted under their catalogue names
  again.** The Z10 (EF545) counts "2 Espressi" and "2 Coffee" at slots
  `0x12`/`0x13` rather than at their catalogue codes `0x31`/`0x36`, so
  those brews fell out of `ProductCounters.by_name` and survived only as
  raw entries in `by_code`. `client.COUNTER_SLOT_OVERRIDES` now carries
  the same per-machine remap J.O.E. uses, so the counts land under the
  machine's own product names. Machines outside the table — every other
  bundled profile — decode exactly as before. Reported with a full slot
  dump and a J.O.E. CSV cross-check by @bobcat0070 (#9).

## [0.12.0] — 2026-07-06

### Added
- **PIN-protected machines are now supported from the CLI.** `pair` and
  `command` gained a `--pin` flag that is sent in the `@HP:<pin>,…`
  handshake, so machines with a front-panel setup PIN (e.g. Jura E6 /
  EF1030) can be paired and controlled. The PIN is persisted in the
  credential store (`MachineCredentials.pin`) and replayed automatically
  on every reconnect, so `--pin` is only needed once at pair time (or to
  override a stored PIN). Live-verified that the empty-PIN flow is
  unchanged against a non-PIN S8 (EF1091). `pair` now also accepts a
  `host:port` address like `command` already did.

### Security
- **`creds --json` never prints the stored PIN.** The credential store
  keeps the PIN on disk (some machines demand it on every reconnect),
  but the user-facing `to_dict()` view redacts it to `pin_stored: true`;
  the full value only lives in the new `to_store_dict()` used for
  writing the JSON file.

## [0.11.0] — 2026-07-03

### Added
- **`milk_amount` (F5 → blob byte 4) is now a public, settable recipe
  parameter** — `KIND_MILK_AMOUNT`, listed in `RECIPE_PARAM_KINDS`, a
  `milk=` kwarg on `JuraClient.brew`, and a `milk_amount=<s>` key for
  the CLI `brew` command. Z10-class machines split milk into a liquid
  phase (`MILK_AMOUNT`, F5) and a foam phase (`MILK_FOAM_AMOUNT`, F6);
  previously the liquid phase always brewed at its XML default. Both
  bytes are now **live-verified on a Z10 (EA)/EF545**: blob
  `05000812030202000100000000000000` (Milkcoffee, strength 8, 90 ml,
  milk 3 s, foam 2 s, temp high) brewed with the physical pour matching
  both phases, so `milk_foam_amount` also drops its not-live-verified
  caveat.

### Fixed
- **`build_recipe_hex` no longer raises on machines with sub-indexed
  recipe arguments.** `MILK_FOAM_TEMP` / `MILK_TEMP` carry
  `Argument="F14_1"` / `"F14_2"`, which `int()` happily parses as
  `141` / `142` (PEP 515 underscore separators) — putting their
  "offset" far outside the 16-byte blob and making every Z10 milk
  product unbrewable. Sub-indexed arguments (unknown wire semantics)
  are now skipped during profile parsing.

## [0.10.0] — 2026-07-02

### Changed (breaking)
- **`decalc` renamed to `descale` across the whole API.** The CLI
  command is now `descale` (was `decalc`), the maintenance-counter
  attribute/dict-key is `MaintenanceCounters.descale` /
  `MaintenancePercent.descale` (was `.decalc`), and the derived alert
  name is `descale_alert` (was `decalc_alert`). Consumers (the Home
  Assistant component) must update `run_named("descale")`, `.descale`,
  and the `descale_alert` name. The wire command (`@TG:25`) and the
  bundled machine XMLs are unchanged.

### Fixed
- **Brewing actually brews now.** ``brew`` used to send the bare
  product code (``@TP:0D``) as the Bluetooth-era docs suggest. The
  WiFi firmware ACKs that with ``@tp:00`` and then silently does
  nothing — the same ACK-but-ignore trap as the unwrapped ``@TM:``
  writes fixed in v0.9.2. The firmware executes a **16-byte recipe
  blob** with the product code at byte 0 and every recipe parameter
  at the byte offset given by its machine-XML ``Argument`` F-number
  minus one (the F-numbers count the Bluetooth command's leading key
  byte, which the WiFi blob doesn't carry). See §5.9 of
  ``docs/PROTOCOL.md``.
- **Corrected the recipe-blob layout — now hardware-verified.** The
  blob is **0x00-padded** (not 0xFF) and **byte 8 is a constant
  0x01**; an FF-padded blob is ACKed ``@tp:00`` and silently ignored.
  Confirmed by physically brewing on a JURA S8 EB (EF1091) —
  ``cafe_barista`` strength 7 / 45 ml / normal / bypass 45 ml →
  ``@TP:28000709000001000109000000000000`` brewed on the first send —
  and matching the E6 author's two live-verified vectors
  (``02000809000002000100000000000000``,
  ``0300021A000001000100000000000000``). Water and bypass travel as
  5 ml ticks; with 0x00 padding an unset water byte is ``0x00`` = no
  water, so ``build_recipe_hex`` still refuses to leave a water
  parameter unset. ``JuraClient.brew`` now treats a bare ``@tp`` as
  the accept and ``@tp:00`` as a rejection.
- **Flood-guard on the recipe blob.** `build_recipe_hex` now *raises*
  when a water/ml parameter the product has would be left unset (no
  override and no XML default) instead of shipping its ``FF`` byte
  (255 ticks ≈ 1.3 l). Range/step validation also defaults a missing
  XML ``Min`` to ``0`` rather than silently skipping the check.
- **Active-default-true products restored.** Products with no
  ``Active`` XML attribute (Milk Foam, Cafe Barista, Barista Lungo on
  the E6, and menu items on ~42 other models) are brewable — J.O.E.
  defaults the flag true and only hides ``Active="false"`` entries.
  Such inactive entries stay in the catalogue (the machine still
  reports their counters) but are marked ``ProductDef.active = False``
  so a UI can hide them.

### Added
- **Recipe parameters parsed from the machine XMLs.**
  `ProductDef` now carries the product's recipe parameters
  (water amount, coffee strength, temperature, milk foam, bypass,
  milk break) as `ProductParam` entries — XML units, ranges,
  steps, and ITEM catalogues included —
  and `ProductDef.build_recipe_hex` builds the validated
  16-byte ``@TP:`` blob from them. The public recipe-parameter kind
  identifiers are exported as `KIND_WATER_AMOUNT`,
  `KIND_COFFEE_STRENGTH`, `KIND_TEMPERATURE`, `KIND_MILK_FOAM_AMOUNT`,
  `KIND_MILK_BREAK`, `KIND_BYPASS` and the `RECIPE_PARAM_KINDS` tuple,
  so consumers build override dicts without hard-coding strings.
- **`JuraClient.brew`** — brew by product name or code with
  keyword overrides: ``client.brew("hotwater", ml=220)``,
  ``client.brew("espresso", strength=7, temperature="high")``.
  Product names resolve by exact 2-hex code first, then exact
  snake_case name, then an unambiguous name *prefix* (pass
  ``substring=True`` to widen). An opt-in ``retry=True`` resends the
  blob once if the first reply isn't an ``@tp`` accept (energy-safe
  wake-up, PROTOCOL.md §5.9). Values are validated against the machine
  XML before anything goes on the wire.
- **CLI: ``brew <product> [param=value …]``** — e.g.
  ``brew hotwater water=220 temp=high``. The override argument is a
  real variadic (uncapped, shown in ``--help``); it accepts a profile
  product name, a 2-hex product code, or a full 32-hex recipe blob
  verbatim as an escape hatch. Out-of-catalogue values are refused
  client-side.
- **Bypass and milk overrides** (`bypass`, `milk_foam`, `milk_break`)
  are accepted by `build_recipe_hex`, `JuraClient.brew` and the CLI.
  **Not live-verified — may misbrew, verify on your hardware.** They
  are encoded from the XML (ml kinds ÷5 ticks, seconds as-is); only
  water and temperature are confirmed against a physical machine.
- **CLI: `products`** — a non-destructive command that lists every
  brewable product on the connected machine with its resolvable name
  and each `brew` `param=value` key's allowed values (min–max/step
  with units for water & milk, ordered item choices for strength &
  temperature), read from the loaded machine profile with no extra
  machine I/O. Params that are not live-verified (bypass/milk) carry
  the caveat. Params the machine reports but that are not overridable
  via `brew` (no CLI key, e.g. `milk_amount` on the S8) render under
  their kind name with a read-only annotation and `settable: false` in
  the structured output — never a blank column. Returns a
  `ProductCatalogue` result with `.format()` (human tree) and
  `.to_dict()` (structured). Use it to discover exactly what `brew`
  accepts.

## [0.9.5] — 2026-06-25

### Fixed
- **Odd-length ``@TF:`` status frames crashed the first data fetch.**
  The J8 (SAS / EF1069) WiFi Connect dongle emits status frames of 15
  hex nibbles — the 8-byte baseline frame with the final low nibble of
  byte 7 truncated. ``_hex_body`` fed that straight to
  ``bytes.fromhex``, which raised ``fromhex() arg must contain an even
  number of hexadecimal digits`` and left the integration stuck
  retrying setup (jura-connect-hass#3, thanks @DaftHonk and @petxya).
  Odd-length hex bodies are now padded with a trailing ``0`` before
  decoding, so byte 7 — which carries the J8-only bits 54
  (``ml_oz_status``) and 56 (``coffee_eye_cup_detected``) — is parsed
  instead of dropped. Captured-live regression fixtures cover the idle,
  water-tank-removed, and cup-detected frames.

### Added
- **S10 (EF1125) machine profile.** Bundled the S10 machine XML and
  refreshed the vendored profile data (``JOE_MACHINES.TXT`` and
  several existing EF XMLs), bringing the profile registry to 89
  machines (thanks @DaftHonk).

## [0.9.4] — 2026-05-12

### Fixed
- **``JuraClient.write_setting`` accepted arbitrary hex.** Library
  callers could pass any string and have it forwarded to the dongle,
  so e.g. ``write_setting("13", "30")`` (intending the ``"30min"``
  ItemSlider entry, but written as raw hex) would push byte
  ``0x30 = 48 dec`` onto the machine — a value the AutoOFF catalogue
  has no name for. The CLI was safe because ``_r_setting`` runs the
  value through ``SettingDef.normalise_value`` first; only library
  callers were exposed. ``write_setting`` now validates against the
  loaded `MachineProfile`'s `SettingDef` (when a
  profile is set) and raises `ValueError` before the request
  hits the wire. ITEM names like ``"30min"`` are also accepted as a
  convenience, so ``client.write_setting("13", "30min")`` now works
  the same way the CLI does.

### Added
- **Name-based settings API on `JuraClient`.** Three new
  methods that use snake_case setting names (``"auto_off"``,
  ``"hardness"``, ``"language"``) and named ITEM values
  (``"30min"``, ``"english"``) end-to-end:

  * `JuraClient.get_setting(name)` — returns a
    `SettingValue` with both the raw wire hex (``"1E"``) and
    the resolved ITEM name (``"30min"``), plus the underlying
    `SettingDef` for further inspection.
  * `JuraClient.set_setting(name, value)` — value accepts an
    ITEM name (``"30min"``), a wire-format hex string (``"211E"``),
    or for step-sliders a hex integer in range. Raises
    `ValueError` for anything else before the request hits
    the wire.
  * `JuraClient.list_settings()` — returns the full
    `SettingDef` catalogue from the loaded profile so
    callers can enumerate writable settings and their allowed
    ITEM values from a script or REPL.

  All three require a `MachineProfile` to be loaded on the
  client (pass ``profile=load_profile("EFxxxx")`` or use the CLI's
  ``--machine-type`` / stored credential).
- `SettingDef.validate_wire_hex` — hex-form variant of
  ``normalise_value`` for the library write path (step-slider input
  parsed as hex with range / step check; ITEM-driven kinds must match
  a catalogue value exactly). The pre-existing ``normalise_value``
  is unchanged — it still parses step-slider input as decimal for
  the CLI.
- `SettingDef.item_from_hex` — resolve a read-back hex value
  to its catalogue ITEM (exact match, falling back to suffix-match
  for AutoOFF's stripped readback form).
- `MachineProfile.setting_by_arg` — look up a setting by its
  ``P_Argument`` hex code (e.g. ``"13"`` for AutoOFF).
- `jura_connect.SettingValue` dataclass returned by
  ``get_setting``; re-exported from the top-level package.

## [0.9.3] — 2026-05-12

### Fixed
- **Settings writes still silently rejected on TT237W after the
  v0.9.2 lock/unlock wrapper.** Every ``@TM:<arg>,<val><csum>``
  attempt came back as ``@tm:00`` (the dongle's rejection token)
  and the value never changed. A pcap of the J.O.E. Android app
  writing AutoOFF on the same machine (Kaffeebert, ``192.168.111.192``)
  showed the missing piece: the J.O.E. app appends a literal
  ``\r\n`` to the *cleartext body* before encoding, in addition
  to the outer frame terminator. So the actual decoded body the
  dongle sees is e.g. ``@TM:13,211E96\r\n``, not ``@TM:13,211E96``.
  TT237W rejects writes whose body has no inner CRLF; reads happen
  to work without it, which is why v0.9.0–v0.9.2 looked half-OK.
  ``protocol.wrap`` now always appends the inner CRLF (idempotent
  for callers who already include it) and ``protocol.unwrap`` /
  ``FrameReader.next_frame`` strip it from incoming bodies so
  callers see clean payloads. Real-machine verified: AutoOFF on
  Kaffeebert now toggles between 30min and 6h on demand.
- ``JuraClient.write_setting`` no longer treats a stripped readback
  as a write failure. AutoOFF (``P_Argument=13``) ItemSlider writes
  use a 1-byte type-tag prefix (``21`` = 1-byte value follows,
  ``22`` = 2-byte value follows); the dongle stores and reads back
  only the value bytes for the ``21`` form, so writing ``211E``
  (30min) gives a readback of ``1E``. Verify now accepts when the
  stored form is a trailing slice of the written value, and the
  CLI's ITEM-name lookup falls back to suffix matching so
  ``setting auto_off`` displays ``30min`` rather than
  ``unknown — not in catalogue``.
- ``@tm:00`` from a non-00 write is now surfaced as an explicit
  rejection (``ValueError``) instead of being lumped in with the
  generic readback-mismatch error.

## [0.9.2] — 2026-05-11

### Fixed
- **Settings writes silently dropped on TT237W.** v0.9.0 and v0.9.1
  sent bare ``@TM:<arg>,<value><checksum>``; the dongle ACKs with
  ``@tm:<arg>`` so the CLI showed success, but the machine ignored
  the new value until power cycle. The J.O.E. APK always wraps
  these writes in ``@TS:01`` (lock keypad) / ``@TS:00`` (release
  keypad) via its ``PriorityChannel.PMODE`` dispatch path (visible
  in ``apk_unpacked/smali_classes2/k8/c.smali:367``); the Python
  port now does the same. Defence in depth:
  ``JuraClient.write_setting(..., verify=True)`` reads the value
  back after the unlock and raises `ValueError` if the
  stored value doesn't match what was sent, so the silent-drop
  failure mode can never look like a successful write again.

## [0.9.1] — 2026-05-11

### Fixed
- **`setting` read returned a corrupt integer that included the
  trailing checksum byte.** The dongle's reply for ``@TM:<arg>`` is
  ``@tm:<arg>,<value_hex><checksum>`` (same ``ByteOperations.d``
  checksum as the write side); v0.9.0 swallowed the whole tail. The
  user observed ``setting hardness`` reporting 3581 (=0x0DFD) on a
  machine actually set to 13 °dH — the body was ``0DFD`` (value
  ``0D`` + checksum ``FD``). The client now strips the trailing two
  chars, verifies them against the recomputed checksum, and raises
  ``ValueError`` on a mismatch so a silently-corrupt value can't
  slip through. Simulator updated to emit the checksum on read
  replies; two new regression tests pin both branches.

## [0.9.0] — 2026-05-11

### Fixed
- **Status-bit decoding was off by 7 positions per byte.** v0.8.0
  and earlier extracted alert bits LSB-first within each byte; the
  J.O.E. Android app's ``Status.a()`` uses MSB-first
  (``(1 << (7 - i%8)) & bArr[i/8]``). On Kaffeebert's idle frame
  ``@TF:0004000008000000`` the prior code reported ``no_beans`` +
  ``cappu_rinse_alert``; the real meaning is ``coffee_ready`` +
  ``energy_safe``. Every named bit in `_STATUS_BITS` and every
  per-machine ``AlertDef.bit`` was already correct — only the
  ``MachineStatus.parse`` byte/bit extraction was wrong.

### Added
- **``setting`` command — read or write machine settings.** Each
  profile's ``<MACHINESETTINGS>`` block is parsed into
  ``MachineProfile.settings`` (``SettingDef`` + ``SettingItem``);
  reads send ``@TM:<arg>`` and decode the value against the
  catalogue, writes send ``@TM:<arg>,<val><checksum>`` with the J.O.E.
  APK's ``ByteOperations.d`` checksum. EF1091 (S8 EB) exposes seven
  settings: hardness, auto_off, units, language,
  display_brightness_setting, milk_rinsing, frother_instructions.
- **Profile-driven input validation.**
  ``SettingDef.normalise_value`` enforces step-slider range/step
  (``hardness 99`` → ``99 is outside [1, 30]``), switch/combobox
  membership (``language klingon`` → ``klingon is not a recognised
  value. Allowed: german=01, english=02, …``), and accepts either an
  ITEM name or its raw hex. Writes are dispatched through a
  *dynamic* destructive gate — ``setting hardness`` (read) is
  unrestricted, ``setting hardness 18`` (write) needs
  ``--allow-destructive-commands``.
- **Conditional-destructive command spec.** ``CommandSpec`` gained
  ``dynamic_danger: Callable[[args], str | None]`` so one named
  command can wrap a safe read and a gated write without duplicating
  the entry. ``Argument`` gained ``optional: bool`` so the
  ``setting <name> [<value>]`` signature renders correctly in
  ``--list`` output.
- **``_settings_checksum`` helper** exposed from
  ``jura_connect.client`` (Python port of ``ByteOperations.d``) for
  test-suite and downstream tool use.
- **New public types** ``SettingDef``, ``SettingItem``.

### Changed
- ``power-off`` (``@AN:02``) danger string rewritten: the J.O.E.
  Android app does NOT use this command over WiFi (zero references
  in the decompiled APK), and live testing on TT237W shows the
  dongle silently ignores it. The command stays in the registry for
  completeness and historical UART/Bluetooth compatibility, but the
  CLI now tells users up front that the firmware likely won't act on
  it.
- Simulator's ``DEFAULT_STATUS_PAYLOAD`` changed from the live
  Kaffeebert frame (``0004000008000000``) to a synthetic frame
  (``0020000020000000``) that activates one ``info`` (no_beans) and
  one ``process`` (cleaning_alert) bit, so the test-suite keeps
  exercising all three severity branches under MSB-first decoding.
  A new regression test pins ``KAFFEEBERT_IDLE_STATUS_PAYLOAD``
  (the real frame) decoding to coffee_ready + energy_safe so the
  v0.9.0 fix can't regress silently.
- Simulator handles ``@TM:<arg>`` (settings read) and
  ``@TM:<arg>,<val><checksum>`` (settings write with checksum
  verification) against a configurable per-profile defaults table.

### Documentation
- New `docs/PROTOCOL.md` §5.7 documents the settings wire format,
  checksum algorithm, and the EF1091 settings catalogue.
- `docs/PROTOCOL.md` §5.4 updated to spell out the MSB-first bit
  indexing trap.
- README clarifies that "Kaffeebert" is the WiFi dongle's display
  name (read via UDP discovery, set via the existing gated
  ``set-name`` command / ``@HW:82``). There is no separate per-
  machine display-name field exposed over WiFi.

## [0.8.0] — 2026-05-11

### Added
- **Per-machine profiles.** The 88 machine XMLs from the J.O.E. APK
  are bundled with the package; `jura_connect.profile.load_profile(code)`
  loads any of them (e.g. `EF1091` for the S8 EB) and surfaces its
  alert bitmap + product code map. Alert names and brew-counter names
  are now lifted from the machine's own XML rather than a hard-coded
  EF536 baseline — Kaffeebert's `0x2B` is "Cortado", not "(unnamed
  slot)".
- **`pmode` named command.** Reads programmable-recipe slots via
  `@TM:50` + `@TM:42,<slot>`. Gracefully surfaces the S8 EB's
  "every slot returns C2" state as "not supported by machine"
  instead of crashing.
- **`set-machine-type` CLI subcommand.** Retro-fit a machine_type
  onto an existing paired credential:
  ``jura-connect set-machine-type --name Kaffeebert EF1091``.
- **`machine-types` CLI subcommand.** Print every known
  (friendly_name, EF_code) pair, with ``--filter`` substring search
  and ``--json`` output for scripting.
- **`pair --machine-type EF1091`** stores the EF code in the
  credential. Without the flag the pair flow attempts UDP discovery
  to read the article number and look it up via `JOE_MACHINES.TXT`
  — works on older firmwares; TT237W doesn't reply to unicast UDP, so
  the explicit flag is the practical path there.
- **`command --machine-type EF1091`** lets you override the stored
  profile for one invocation.
- New public types: `MachineProfile`, `AlertDef`, `ProductDef`,
  `MachineCatalogueEntry`, `PModeSlot`, `ProgramModeSlots`.
- `CredentialStore.set_machine_type(name, code)` for programmatic
  retrofitting.

### Changed
- `MachineCredentials` gained a `machine_type` field. Existing
  credentials without one fall through to the EF536 baseline, so no
  migration is required.
- `JuraClient(profile=…)` is the new way to make status/brews aware
  of a specific machine variant. The CLI loads this automatically
  from the stored credential.

### Fixed
- Verified live against Kaffeebert (S8 EB, EF1091): brews output now
  names every slot (`cortado`, `sweet_latte`, `2_espressi`,
  `2_coffee`) instead of leaving them as `0x2B=2, 0x2C=1, 0x31=1,
  0x36=10`. Status output and `pmode` likewise behave correctly on
  the real machine.

## [0.7.0] — 2026-05-11

### Added
- `jura-connect command brews` — new named read command returning the
  per-product brew counter table (the same data the J.O.E. app shows
  on its Statistics screen). Wire protocol is the paginated
  `@TR:32,<page>` (16 pages × 4 u16 slots = 64-slot table indexed by
  product code); decoded into `jura_connect.ProductCounters` with
  `total`, `by_name`, and `by_code` views.
- `jura_connect.PRODUCT_NAMES` — code → human name map derived from
  the per-machine XMLs under `apk/assets/documents/xml/`. Covers the
  TT237W family (S8, ENA8, Z8); unknown codes still surface via
  `by_code`.
- `MachineStatus.errors` / `.info` / `.process` — the status bits are
  now categorised by severity, lifted from the machine XML's
  `ALERT.Type` attribute. `active_alerts` is preserved for backwards
  compatibility.

### Fixed
- The `status` and `info` CLI output no longer mis-reports
  informational bits as active errors. `no_beans` on the S8 EB is
  `Type="info"` (bean bin low, not blocked) and now appears under
  ``info flags``, not under ``errors``. Same correction for the
  periodic maintenance prompts (`filter_alert`, `descale_alert`,
  `cleaning_alert`, `cappu_rinse_alert`), which surface under
  ``process flags``.
- The `@TR:32` "known unknown" entry in `docs/PROTOCOL.md` is removed
  — the paginated form is now documented and implemented.

## [0.6.1] — 2026-05-11

### Added
- `AGENTS.md` — distilled conventions and gotchas for contributors
  and AI assistants. Covers the protocol's reverse-engineered
  status, the destructive-command incident and gate, the
  no-mocks-only-simulator test discipline, the library/CLI split,
  the QA gate via `nix build .#default`, the
  naming / versioning / release flow, and commit style.
- README: a short "Usage of LLMs" note recording that the codebase
  was written by Claude Code (Opus 4.7) from 2026-05-11 onwards.

### Changed
- README acknowledgement: tightened the closing line about the
  Jutta-Proto project.

## [0.6.0] — 2026-05-11

### Added
- GitHub Actions workflow ([.github/workflows/ci.yml](.github/workflows/ci.yml))
  running `nix build .#default` on every push and PR. README gains a
  CI badge that turns green only when ruff, ty, *and* pytest pass.
- The package's build derivation now runs ruff (lint + format check)
  and ty (type check) in `preBuild`, alongside the existing pytest
  in checkPhase. `nix build .#default` is the single QA gate.

### Changed
- **Breaking (small):** `CredentialStore.list()` was renamed to
  `CredentialStore.entries()` so the method no longer shadows the
  builtin (which prevented ty from analysing its return annotation).
  CLI internals and tests follow; downstream users with explicit
  ``store.list()`` calls need to rename.

### Fixed
- ty type errors in `discovery._broadcast_addresses` /
  `_local_ipv4_networks` — the stdlib stubs leave
  `getaddrinfo(...)[4][0]` as `str | int`; narrowed via an
  `isinstance(ip, str)` guard rather than a `# type: ignore`.
- Whole codebase reformatted to ruff 0.15 defaults.

## [0.5.0] — 2026-05-11

### Added
- `jura-connect command --json` emits the command result as JSON on
  stdout. The handshake banner, watch announcement, watched frames,
  and every error / refusal message move to stderr, so a pipeline
  like ``jura-connect command --name K --json counters | jq`` is
  parseable verbatim.
- Library-level `to_dict()` on `MaintenanceCounters`,
  `MaintenancePercent`, `MachineStatus`, `MachineInfo`, and
  `CommandResult`. Composite types recurse, plain-string command
  replies (`lock` / `raw` / etc.) pass through. Everything is plain
  ``json.dumps``-able.

## [0.4.0] — 2026-05-11

### Changed
- **Breaking:** the Python package was renamed from `jura_wifi` to
  `jura_connect` and the console script from `jura-wifi` to
  `jura-connect`. The repository directory was already named
  `jura-connect`; this release makes the module and the CLI follow
  suit so a single name (`jura-connect`) covers the project, the
  module, the CLI, the Nix flake attribute, and the credentials
  directory under `$XDG_DATA_HOME`.
- Migration: ``from jura_wifi import …`` → ``from jura_connect import …``;
  ``jura-wifi <subcommand>`` → ``jura-connect <subcommand>``. The
  on-disk credentials path is unchanged.

### Removed
- Stale `jura_wifi/README.md` (the in-package duplicate that still
  described the long-removed `connect --cmd` interface and an "8-char
  hex" auth hash). The top-level `README.md` is the single source of
  truth.

## [0.3.0] — 2026-05-11

### Added
- Destructive command names are now part of the registry and reachable
  by name: `clean`, `descale`, `filter-change`, `cappu-clean`,
  `cappu-rinse`, `reset-counters`, `restart`, `power-off`,
  `brew <recipe>`, `set-pin <pin>`, `set-ssid <ssid>`,
  `set-password <pwd>`, `set-name <name>`.
- Each destructive command carries a human-readable `danger`
  explanation that the new `jura_connect.DestructiveCommandError`
  surfaces verbatim, so users see *what* the command does on the
  machine and *how to recover* if it bites.
- New CLI flag `--allow-destructive-commands` and matching
  `run_named(..., allow_destructive=True)` library parameter. Without
  the flag the command is refused *before* it touches the wire and
  the user gets a message explaining the danger and how to override.
- `raw` now inspects its payload against `DESTRUCTIVE_PREFIXES` and
  is subject to the same gate, so the escape hatch can't be used as
  an accidental bypass.
- `command --list` separates the catalogue into read-only and
  destructive groups.

## [0.2.0] — 2026-05-11

### Added
- `jura_connect.commands` — named-command registry mapping user-friendly
  names (`info`, `counters`, `percent`, `status`, `lock`, `unlock`,
  `mem-read`, `register-read`, `raw`) to wire-level commands. The
  registry is the single source of truth for both the CLI and library
  callers (`jura_connect.run_named(client, "info")`).
- `format()` methods on `MaintenanceCounters`, `MaintenancePercent`,
  `MachineStatus`, and `MachineInfo` — presentation logic now lives
  next to the data, not in the CLI.
- `__version__` exposed from `jura_connect`; `--version` flag on the CLI.
- Host can now be passed as `host:port` to the `command` subcommand
  (useful for tests and non-standard deployments).
- New tests: `tests/test_commands.py` (registry round-trips via
  simulator) and `tests/test_cli.py` (CLI end-to-end).

### Changed
- **Breaking:** CLI subcommand `connect` was renamed to `command`. The
  hex-code interface (`--read '@TG:43'`) was removed; use named
  commands instead, e.g. `jura-connect command --name K counters`. For
  raw access use `jura-connect command --name K raw '@TG:43'`.
- CLI command output formatting moved into library `format()`
  methods so the CLI is now a thin shell over the library.

### Removed
- `cmd_connect` / `--read-info` / `--read` CLI surface (replaced by
  the registry).

## [0.1.0] — 2026-05-11

### Added
- Initial release.
- Reverse-engineered Jura WiFi protocol (`@HP:` handshake, framing,
  cipher, discovery) verified end-to-end against an S8 EB running
  `TT237W V06.11`.
- UDP/51515 broadcast discovery with TCP fallback sweep.
- Unset-PIN pairing flow with on-machine "Connect" confirmation.
- Read commands: maintenance counters, maintenance percent, machine
  status / alerts, screen lock/unlock.
- JSON credential store (atomic write, `0600`).
- In-tree simulator + 257-case pytest suite (no mocks).
- Nix flake with `nix flake check` passthrough.
