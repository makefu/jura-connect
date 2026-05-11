# jura-connect

A dependency-free Python WiFi interface for Jura coffee machines fitted
with a **Smart Connect** WiFi dongle. Reverse-engineered from the
official J.O.E. (Jura Operating Experience) Android app and verified
end-to-end against a real **S8 EB** running firmware **TT237W V06.11**
(nicknamed "Kaffeebert" in the test setup).

The code ships as a small Python package plus a Nix flake that runs the
test-suite as a passthrough build. The test-suite drives the client
against an in-tree TCP **simulator** that reuses the *same* crypto and
framing modules — no mocks anywhere.

## Status

| Capability | Status |
| --- | --- |
| UDP/51515 broadcast discovery + parser | ✓ ; falls back to TCP-port-sweep on the TT237W firmware which doesn't reply to UDP |
| Wire framing (`* … \r\n`) and obfuscation cipher | ✓ ; 2 000-input random round-trip + every key value exhaustively tested |
| `@HP:` handshake (`CORRECT` / `WRONG_PIN` / `WRONG_HASH` / `ABORTED`) | ✓ |
| Unset-PIN pairing with on-machine confirmation | ✓ ; client surfaces a prompt and waits for the user to press OK |
| Auth-hash persistence (JSON, 0600) | ✓ |
| Read commands: maintenance counters, maintenance %, machine status / alerts, screen lock/unlock | ✓ |
| Brewing / writes / maintenance processes | **deliberately not exposed** — destructive |

## Installation

The package is pure Python ≥ 3.11 with no runtime dependencies. The
recommended way is via the flake:

```sh
nix shell .#jura-wifi            # binary + library available in the shell
nix run .#jura-wifi -- discover  # run the CLI directly
```

Or build/install with the bundled `pyproject.toml`:

```sh
pip install .                    # adds the `jura-wifi` console script
python -m jura_wifi discover
```

## Quickstart

### Pair a new machine (one-time, requires physical access)

```sh
# 1. Find the machine on your LAN
$ jura-wifi discover
tcp/51515 open -> 192.168.1.42  (try: jura_wifi pair 192.168.1.42)

# 2. Run the pairing flow. The machine will show a "Connect" prompt
#    on its own display; press OK there to accept this device.
$ jura-wifi pair 192.168.1.42 --name Kaffeebert
connecting to 192.168.1.42:51515 as conn-id 'jura-connect-7f31a8c2'
look at the coffee machine -- a 'Connect' prompt should appear.
  -> Coffee machine should be showing a 'Connect' prompt — press OK on the machine to accept this device (waiting up to 60s).
handshake -> CORRECT  (@hp4:13908FE4...C13156C052)
saved credentials for 'Kaffeebert' -> /home/you/.local/share/jura-connect/credentials.json
```

The auth-hash is written to `$XDG_DATA_HOME/jura-connect/credentials.json`
with `0600` permissions. Override the location with the global
`--store /path/to.json` flag.

### Use a paired machine

```sh
$ jura-wifi connect --name Kaffeebert --read-info
handshake -> CORRECT  (@hp4)
== machine info ==
  conn-id        : jura-connect-7f31a8c2
  handshake state: CORRECT
  auth-hash      : 13908FE4D3EB986B...
  status bits    : 0004000008000000
  active alerts  : no_beans
  maintenance    : cleaning=21 filter=1 decalc=8 cappu_rinse=344 coffee_rinse=3617 cappu_clean=91
  maintenance %  : cleaning=80 filter=255 decalc=30
```

### Issue ad-hoc read commands

```sh
$ jura-wifi connect --name Kaffeebert --read '@TG:43' --read '@TG:C0' --watch 5
--> @TG:43
<-- '@tg:4300150001000801580E21005B'
--> @TG:C0
<-- '@tg:C050FF1E'
watching status for 5.0s ...
<-- '@TF:0004000008000000'
<-- '@TF:0004000008000000'
```

`--watch SECONDS` streams unsolicited `@TF:` (status) and `@TV:`
(progress) frames; the read parsers and the maintenance helpers all
just call into the same `JuraClient.request()` / `iter_frames()`.

### List / remove stored credentials

```sh
$ jura-wifi creds
# /home/you/.local/share/jura-connect/credentials.json
Kaffeebert            192.168.1.42     conn-id=jura-connect-7f31a8c2  hash=13908FE4D3EB986B...  paired_at=2026-05-11T08:42:00Z

$ jura-wifi creds --delete Kaffeebert
removed 'Kaffeebert' from .../credentials.json
```

## Library API

```python
from jura_wifi import JuraClient, CredentialStore, MachineCredentials, discover

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

# Reconnect later from disk
creds = store.get("Kaffeebert")
with JuraClient(creds.address, conn_id=creds.conn_id,
                auth_hash=creds.auth_hash) as c:
    info = c.read_machine_info()
    print(info.maintenance_counters)   # MaintenanceCounters(cleaning=21, ...)
    print(info.status.active_alerts)   # ('no_beans',)
```

## Tests

```sh
# Direct pytest run
nix shell nixpkgs#python313Packages.pytest --command pytest tests/ -q

# Nix flake check (runs the suite in a sandboxed derivation)
nix flake check

# Build the package + run its pytest checkPhase in one shot
nix build .#default --print-build-logs
```

The test-suite covers:

* every byte value of the cipher key (`test_crypto.py`),
* discovery-reply parsing including the unusual MSB-counted bit checks
  (`test_discovery.py`),
* every handshake state via the simulator + a tiny one-shot socket
  server for the garbage-reply path (`test_handshake.py`),
* every read command and the simulator's destructive-command guardrail
  (`test_reads.py`),
* the JSON credential round-trip plus a full pair→persist→reconnect
  workflow (`test_credentials.py`).

## Protocol reference

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the technical workflow
description (wire framing, handshake state-machine, command catalogue,
known unknowns). This document is the source of truth for the
implementation and was used to validate every code path against the
Android APK and against Kaffeebert.

## License

MIT.
