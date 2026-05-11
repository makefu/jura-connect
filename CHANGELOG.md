# Changelog

All notable changes to `jura-connect` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-05-11

### Added
- `jura_wifi.commands` — named-command registry mapping user-friendly
  names (`info`, `counters`, `percent`, `status`, `lock`, `unlock`,
  `mem-read`, `register-read`, `raw`) to wire-level commands. The
  registry is the single source of truth for both the CLI and library
  callers (`jura_wifi.run_named(client, "info")`).
- `format()` methods on `MaintenanceCounters`, `MaintenancePercent`,
  `MachineStatus`, and `MachineInfo` — presentation logic now lives
  next to the data, not in the CLI.
- `__version__` exposed from `jura_wifi`; `--version` flag on the CLI.
- Host can now be passed as `host:port` to the `command` subcommand
  (useful for tests and non-standard deployments).
- New tests: `tests/test_commands.py` (registry round-trips via
  simulator) and `tests/test_cli.py` (CLI end-to-end).

### Changed
- **Breaking:** CLI subcommand `connect` was renamed to `command`. The
  hex-code interface (`--read '@TG:43'`) was removed; use named
  commands instead, e.g. `jura-wifi command --name K counters`. For
  raw access use `jura-wifi command --name K raw '@TG:43'`.
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
