# Changelog

All notable changes to `jura-connect` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

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
