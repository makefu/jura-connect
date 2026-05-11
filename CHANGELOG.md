# Changelog

All notable changes to `jura-connect` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

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
  back after the unlock and raises :class:`ValueError` if the
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
  ``energy_safe``. Every named bit in :data:`_STATUS_BITS` and every
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
  periodic maintenance prompts (`filter_alert`, `decalc_alert`,
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
  by name: `clean`, `decalc`, `filter-change`, `cappu-clean`,
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
