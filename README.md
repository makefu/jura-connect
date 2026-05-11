# jura-connect

[![CI](https://github.com/makefu/jura-connect/actions/workflows/ci.yml/badge.svg)](https://github.com/makefu/jura-connect/actions/workflows/ci.yml)

A dependency-free Python WiFi interface for Jura coffee machines fitted
with a **Smart Connect** WiFi dongle. Reverse-engineered from the
official J.O.E. (Jura Operating Experience) Android app and verified
end-to-end against a **JURA S8 EB** running firmware **TT237W V06.11**
("Kaffeebert").

## Status

| Capability | Status |
| --- | --- |
| UDP/51515 broadcast discovery + parser | ✓ ; falls back to TCP-port-sweep on the TT237W firmware which doesn't reply to UDP |
| Wire framing (`* … \r\n`) and obfuscation cipher | ✓ ; 2 000-input random round-trip + every key value exhaustively tested |
| storage of authentication codes | ✓ |
| Read commands: maintenance counters, maintenance %, machine status / alerts, screen lock/unlock | ✓ |
| Brewing / writes / maintenance processes | available but require extra attention |

## Installation

The package is pure Python ≥ 3.11 with no runtime dependencies. The
recommended way is via the flake:

```sh
nix shell .#jura-connect            # binary + library available in the shell
nix run .#jura-connect -- discover  # run the CLI directly
```

Or build/install with the bundled `pyproject.toml`:

```sh
pip install .                    # adds the `jura-connect` console script
python -m jura_connect discover
```

## Quickstart

### Pair a new machine (one-time, requires physical access)

```sh
# 1. Find the machine on your LAN
$ jura-connect discover
tcp/51515 open -> 192.168.1.42  (try: jura_connect pair 192.168.1.42)

# 2. Run the pairing flow. The machine will show a "Connect" prompt
#    on its own display; press OK there to accept this device.
$ jura-connect pair 192.168.1.42 --name Kaffeebert
connecting to 192.168.1.42:51515 as conn-id 'jura-connect-7f31a8c2'
look at the coffee machine -- a 'Connect' prompt should appear.
  -> Coffee machine should be showing a 'Connect' prompt — press OK on the machine to accept this device (waiting up to 60s).
handshake -> CORRECT  (@hp4:13908FE4...C13156C052)
saved credentials for 'Kaffeebert' -> /home/you/.local/share/jura-connect/credentials.json
```

The auth-hash is written to `$XDG_DATA_HOME/jura-connect/credentials.json`
with `0600` permissions. Override the location with the global
`--store /path/to.json` flag.

### Run commands against a paired machine

The CLI exposes a `command` subcommand that takes a *named* read
command, not a raw hex code. Discover the catalog with:

```sh
$ jura-connect command --list
available commands:
  read-only:
    info                     full read-only snapshot (status + counters + percent)
    counters                 maintenance counters (@TG:43)
    percent                  maintenance percent indicators (@TG:C0)
    status                   parsed status / active alerts (@HU? -> @TF:)
    lock                     lock the front-panel display (@TS:01)
    unlock                   unlock the front-panel display (@TS:00)
    mem-read <addr>          read a memory/setting slot (@TM:<addr>); firmware-specific
    register-read <bank>     read a register bank (@TR:<bank>); firmware-specific
    raw <frame>              send a verbatim '@…' command; payload checked against the destructive set

  destructive (require --allow-destructive-commands; see 'jura-connect command --help'):
    clean                    [destructive] start coffee-system cleaning cycle (@TG:24)
    decalc                   [destructive] start descaling cycle (@TG:25)
    filter-change            [destructive] run water-filter change procedure (@TG:26)
    cappu-clean              [destructive] start cappuccino-system cleaning (@TG:21)
    cappu-rinse              [destructive] rinse the milk system (@TG:23)
    reset-counters           [destructive] zero every maintenance counter (@TG:7E)
    restart                  [destructive] reboot the WiFi dongle (@TF:02)
    power-off                [destructive] put the machine into standby (@AN:02)
    brew <recipe>            [destructive] start brewing a recipe (@TP:<recipe>)
    set-pin <pin>            [destructive] write a new front-panel PIN (@HW:01,<pin>)
    set-ssid <ssid>          [destructive] write a new WiFi SSID for the dongle (@HW:80,<ssid>)
    set-password <password>  [destructive] write a new WiFi password (@HW:81,<pwd>)
    set-name <name>          [destructive] rename the dongle (@HW:82,<name>)
```

The same catalogue is reachable from Python as
`jura_connect.list_commands()`. Run a command by name:

```sh
$ jura-connect command --name Kaffeebert info
handshake -> CORRECT  (@hp4)
== machine info ==
  conn-id        : jura-connect-7f31a8c2
  handshake state: CORRECT
  auth-hash      : 13908FE4D3EB986B...
  status bits    : 0004000008000000
  active alerts  : no_beans
  maintenance    : cleaning=21 filter=1 decalc=8 cappu_rinse=344 coffee_rinse=3617 cappu_clean=91
  maintenance %  : cleaning=80 filter=255 decalc=30

$ jura-connect command --name Kaffeebert counters
handshake -> CORRECT  (@hp4)
cleaning=21 filter=1 decalc=8 cappu_rinse=344 coffee_rinse=3617 cappu_clean=91

$ jura-connect command --name Kaffeebert status --watch 5
handshake -> CORRECT  (@hp4)
bits=0004000008000000  alerts=no_beans
watching status for 5.0s ...
<-- '@TF:0004000008000000'
<-- '@TF:0004000008000000'
```

For one-off advanced use, `raw` echoes any wire command verbatim:

```sh
$ jura-connect command --name Kaffeebert raw '@TG:43'
handshake -> CORRECT  (@hp4)
@tg:4300150001000801580E21005B
```

`--watch SECONDS` streams unsolicited `@TF:` (status) and `@TV:`
(progress) frames; the parsers and the maintenance helpers all just
call into the same `JuraClient.request()` / `iter_frames()`.

### JSON output for scripting

Pass `--json` and the command's result is emitted on stdout as a JSON
object; the handshake banner, watch announcement, watched frames, and
all error/refusal messages move to stderr so stdout is parseable
verbatim:

```sh
$ jura-connect command --name Kaffeebert --json counters | jq .
{
  "name": "counters",
  "value": {
    "cleaning": 21,
    "filter_change": 1,
    "decalc": 8,
    "cappu_rinse": 344,
    "coffee_rinse": 3617,
    "cappu_clean": 91,
    "raw_hex": "0015000100080158..."
  }
}
```

Composite values like `info` nest the same way:
``payload["value"]["maintenance_counters"]["cleaning"]``. String
replies (`lock`, `unlock`, `raw`, the destructive commands' wire
responses) come through as ``payload["value"]`` directly. Every
structured result type — `MaintenanceCounters`, `MaintenancePercent`,
`MachineStatus`, `MachineInfo`, `CommandResult` — exposes the same
`to_dict()` from Python.

### Destructive commands (gated)

Commands that change the machine's physical state — start cleaning
cycles, brew product, reset counters, write WiFi credentials or the
machine PIN — live in the same registry but are refused by default
*before* anything is sent. The error you get spells out the risk:

```sh
$ jura-connect command --name Kaffeebert clean
handshake -> CORRECT  (@hp4)
refused: 'clean' is a destructive command — starts a real cleaning
cycle (~5 min) that consumes a cleaning tablet and locks the machine
until the cycle finishes. There is no remote 'abort'.
Re-run with --allow-destructive-commands (CLI) or
allow_destructive=True (library) if you really mean it.
```

Pass `--allow-destructive-commands` once you've read what the command
does and have any required supplies / containers / cups in place:

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands clean
```

The list of gated wire prefixes (`@TG:21/23/24/25/26/7E/FF`, `@TF:02`,
`@AN:02`, `@TP:`, `@HW:`) is exported as
`jura_connect.DESTRUCTIVE_PREFIXES`. The `raw` escape hatch inspects its
argument against the same list, so `command raw '@TG:24'` is gated
too — the bypass cannot be used by accident.

Wrong values for `set-pin` / `set-ssid` / `set-password` can leave you
locked out of the machine or unable to reach the dongle over WiFi;
the only recovery is a **factory reset on the machine itself**.
`reset-counters` is **irreversible** — there is no way to learn back
when the machine was last serviced once it's been zeroed.

### List / remove stored credentials

```sh
$ jura-connect creds
# /home/you/.local/share/jura-connect/credentials.json
Kaffeebert            192.168.1.42     conn-id=jura-connect-7f31a8c2  hash=13908FE4D3EB986B...  paired_at=2026-05-11T08:42:00Z

$ jura-connect creds --delete Kaffeebert
removed 'Kaffeebert' from .../credentials.json
```

## Library API

```python
from jura_connect import (
    JuraClient, CredentialStore, MachineCredentials,
    discover, run_named, list_commands,
)

# Discovery
for m in discover(timeout=4.0):
    print(m.name, m.fw, m.address)

# First-time pair (requires user to press OK on the machine)
client = JuraClient("192.168.1.42", conn_id="laptop-1")
result = client.pair(timeout=60.0,
                     on_user_prompt=lambda msg: print(msg))
print(result.state)        # "CORRECT"
print(result.new_hash)     # 64-hex-char auth token

# Persist
store = CredentialStore()
store.put(MachineCredentials(
    name="Kaffeebert",
    address="192.168.1.42",
    conn_id="laptop-1",
    auth_hash=result.new_hash,
))
client.close()

# Reconnect later from disk and run named commands
creds = store.get("Kaffeebert")
with JuraClient(creds.address, conn_id=creds.conn_id,
                auth_hash=creds.auth_hash) as c:
    # Either the high-level helpers …
    info = c.read_machine_info()
    print(info.maintenance_counters)   # MaintenanceCounters(cleaning=21, ...)
    print(info.status.active_alerts)   # ('no_beans',)

    # … or the named-command registry — same API the CLI uses:
    for spec in list_commands():
        print(spec.usage(), "—", spec.description)
    result = run_named(c, "counters")
    print(result.format())             # cleaning=21 filter=1 decalc=8 …
```

## Tests, lint, and type-check

The package's build derivation runs **all three** as a single QA gate:

```sh
# Builds the package; preBuild runs ruff + ty, then pytest runs in
# the install-check phase. One command, no separate invocations.
nix build .#default --print-build-logs

# Same derivation, called as a "flake check" — identical behaviour.
nix flake check
```

Concretely the gate is:

1. `ruff check jura_connect/ tests/` — lint.
2. `ruff format --check jura_connect/ tests/` — formatting drift.
3. `ty check jura_connect/` — Astral's type checker on the library.
4. `pytest tests/ -q` — the 319-case test suite against the in-tree
   simulator.

If you want to run any one of them ad-hoc without the whole build,
enter the dev shell (`nix develop`) which has all four tools on
`$PATH`, then run them directly. The [GitHub Actions workflow](./.github/workflows/ci.yml)
runs `nix build .#default` on every push and PR, so the badge at the
top of this README turns green only when all four steps pass.

The test-suite covers:

* every byte value of the cipher key (`test_crypto.py`),
* discovery-reply parsing including the unusual MSB-counted bit checks
  (`test_discovery.py`),
* every handshake state via the simulator + a tiny one-shot socket
  server for the garbage-reply path (`test_handshake.py`),
* every read command and the simulator's destructive-command guardrail
  (`test_reads.py`),
* the JSON credential round-trip plus a full pair→persist→reconnect
  workflow (`test_credentials.py`),
* every entry of the named-command registry round-tripped through the
  simulator, plus error paths (`test_commands.py`),
* CLI smoke tests for `command --list`, `command info` against the
  simulator, and credential-store interactions (`test_cli.py`).

## Versioning

This project follows [Semantic Versioning](https://semver.org/). See
[`CHANGELOG.md`](CHANGELOG.md) for the release history; the current
version is also exposed as `jura_connect.__version__` and `jura-connect --version`.

## Releasing

Cutting a release is a CLI flow — no clicking around the GitHub UI:

```sh
# 1. Bump the version in the three places it lives, and add a
#    CHANGELOG entry. ./jura_connect/__init__.py, pyproject.toml,
#    flake.nix.
$EDITOR jura_connect/__init__.py pyproject.toml flake.nix CHANGELOG.md

# 2. Verify locally — this is the same gate CI runs.
nix build .#default --print-build-logs

# 3. Commit and push.
git add -A
git commit -m "jura-connect: release vX.Y.Z"
git push

# 4. Tag and push the tag.
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z

# 5. Create the GitHub release. Use --notes-file to feed the
#    matching CHANGELOG section straight in.
awk '/^## \[X\.Y\.Z\]/,/^## \[/{ if (/^## \[/ && !/X\.Y\.Z/) exit; print }' \
    CHANGELOG.md > /tmp/notes.md
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file /tmp/notes.md
```

Publishing the GitHub release triggers the
[`publish` workflow](./.github/workflows/publish.yml), which:

1. re-runs `nix build .#default` against the tag (so a stale or
   broken tag cannot ship);
2. builds the sdist + wheel with `python -m build`;
3. uploads to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/)
   (OIDC — no long-lived API token in repo secrets).

### One-time PyPI setup

Before the first PyPI upload succeeds, register this repo as a
trusted publisher at
<https://pypi.org/manage/account/publishing/> with:

| Field            | Value                              |
| ---------------- | ---------------------------------- |
| PyPI Project name | `jura_connect`                    |
| Owner            | `makefu`                           |
| Repository name  | `jura-connect`                     |
| Workflow name    | `publish.yml`                      |
| Environment name | `pypi`                             |

After registering, create a GitHub environment called `pypi` on the
repo (Settings → Environments → New environment) to match the
workflow's `environment.name`.

### Manual fallback (no CI)

If GitHub Actions is unavailable, the same artefacts can be built
and uploaded by hand. Use `python -m build` (the pypa standard) plus
twine — works on any Python 3.11+:

```sh
python -m pip install --upgrade build twine
python -m build --sdist --wheel --outdir dist/
twine check dist/*
twine upload dist/*    # prompts for credentials
```

Or as a one-shot `nix-shell` if you'd rather not touch the system
Python:

```sh
nix-shell -p 'python313.withPackages(ps: [ ps.build ])' \
          -p python313Packages.twine \
          --run '
    python -m build --sdist --wheel --outdir dist/
    twine check dist/*
    twine upload dist/*
  '
```

## Protocol reference

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the technical workflow
description (wire framing, handshake state-machine, command catalogue,
known unknowns). This document is the source of truth for the
implementation and was used to validate every code path against the
Android APK and against Kaffeebert.

## Acknowledgements

The Bluetooth and UART flavours of the Jura control protocol were
reverse-engineered first by the **[Jutta-Proto](https://github.com/Jutta-Proto)**
project — most notably:

* [`Jutta-Proto/protocol-bt-cpp`](https://github.com/Jutta-Proto/protocol-bt-cpp)
  — C++ Bluetooth implementation for the BlueFrog dongle. Their write-up
  of the obfuscation / encoding scheme, the `@HP:` handshake, and the
  destructive command set was the starting point for understanding the
  shared "Jura control language" that the WiFi dongle also speaks.
* [`Jutta-Proto/protocol-cpp`](https://github.com/Jutta-Proto/protocol-cpp)
  — C++ UART implementation, which in turn builds on the earlier
  [Protocol JURA wiki](http://protocoljura.wiki-site.com/index.php/Hauptseite)
  community work for older serial-only models.

This project is an independent port targeting the *WiFi* transport
(`Smart Connect` dongle, TT237W firmware family) and was developed by
reading the J.O.E. Android APK and validating against a physical S8 EB.
The framing, cipher, and handshake match what the Jutta-Proto repos
describe; the differences live in the transport (TCP/51515 instead of
GATT characteristics) and in the WiFi-specific discovery and pairing
handshake.

Without the Jutta-Proto work the project would not have started in first place.

## Usage of LLMs

This project has been 100% written by the Claude Code Model "Opus 4.7" starting 2026-05-11

## License

MIT
