# jura-connect

[![CI](https://github.com/makefu/jura-connect/actions/workflows/ci.yml/badge.svg)](https://github.com/makefu/jura-connect/actions/workflows/ci.yml)

A dependency-free Python interface — library plus `jura-connect` CLI —
for Jura coffee machines fitted with a **Smart Connect** WiFi dongle.
Reverse-engineered from the official J.O.E. Android app; verified
end-to-end against a JURA S8 EB (EF1091, TT237W V06.11) and with
community hardware (see [Supported machines](#supported-machines)).

Read status and counters, browse settings, brew by product name with
validated parameters, watch progress, run maintenance cycles, and
schedule brews — over plain TCP, no cloud, no Jura account.

53 named commands; 805 tests. How thoroughly each area is verified is
documented honestly in [docs/VERIFICATION.md](docs/VERIFICATION.md) —
read it before trusting a feature on your machine.

## Installation

Pure Python ≥ 3.11, no runtime dependencies.

```sh
pip install jura_connect         # adds the `jura-connect` console script
```

Or via the flake:

```sh
nix shell .#jura-connect         # binary + library in the shell
nix run .#jura-connect -- discover
```

## Quickstart

### Pair a machine (one-time, requires physical access)

```sh
# 1. Find the machine on your LAN
$ jura-connect discover
tcp/51515 open -> 192.168.1.42  (try: jura_connect pair 192.168.1.42)

# 2. Pair. The machine shows a "Connect" prompt on its display;
#    press OK there to accept this device.
$ jura-connect pair 192.168.1.42 --name Kaffeebert
look at the coffee machine -- a 'Connect' prompt should appear.
handshake -> CORRECT  (@hp4:13908FE4...C13156C052)
machine type   : EF1091  (discovery)
saved credentials for 'Kaffeebert' -> /home/you/.local/share/jura-connect/credentials.json
```

If the machine has a setup PIN: add `--pin 12345678`. It is stored
with the auth-hash and reused on reconnects; `creds --json` never
prints it. Credentials live in `$XDG_DATA_HOME/jura-connect/credentials.json`
(mode `0600`); override with the global `--store /path/to.json`.

Manage stored machines:

```sh
$ jura-connect creds                         # list
$ jura-connect creds --delete Kaffeebert     # forget
```

### Tell the library which machine you have

Jura models speak one wire protocol but disagree on which product
codes and alert bits mean what. 89 machine profiles (extracted from
the J.O.E. app) are bundled and looked up by EF code; pairing detects
the code automatically, except on firmwares that ignore unicast UDP
(notably TT237W) — pass it explicitly there:

```sh
$ jura-connect machine-types --filter "S8 (EB)"
   15480  S8 (EB)                         EF1091
   15482  S8 (EB)                         EF1151

$ jura-connect pair 192.168.1.42 --name Kaffeebert --machine-type EF1091
$ jura-connect set-machine-type --name Kaffeebert EF1091   # retro-fit
$ jura-connect command --name Kaffeebert --machine-type EF1091 brews
```

Without a profile you fall back to the EF536 baseline: counts still
work, but products surface as `0x2B=2` instead of `cortado`.

### Run commands

```sh
$ jura-connect command --list                  # the full catalogue

$ jura-connect command --name Kaffeebert brews
total brews : 3229
  espresso            : 78
  americano           : 1019
  flat_white          : 210
  ...

$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew espresso water=35 strength=7
```

Commands that change the machine's physical state (cleaning, brewing,
counter resets, WiFi/PIN writes) are **refused by default** — the
refusal message explains what the command does and how to recover if
it bites. Re-run with `--allow-destructive-commands` once you've read
it and have supplies in place. Details:
[docs/DESTRUCTIVE.md](docs/DESTRUCTIVE.md).

Per-feature walkthroughs — settings, brewing and parameters, progress,
maintenance cycles, counter banks, programmable recipes, coffee
timer, languages, milk cooler — are in
[docs/CLI.md](docs/CLI.md); the complete command list with its wire
codes is [docs/COMMANDS.md](docs/COMMANDS.md).

## Use it from other tools (JSON)

`--json` prints the command result as one JSON object on stdout; the
handshake banner, streamed frames and error/refusal messages go to
stderr, so stdout is parseable verbatim. Exit code `2` with an
`error:` / `refused:` / `timeout:` line on stderr for user errors.

```sh
$ jura-connect command --name Kaffeebert --json counters | jq .
{
  "name": "counters",
  "value": {
    "cleaning": 21,
    "filter_change": 1,
    "descale": 8,
    "cappu_rinse": 344,
    "coffee_rinse": 3617,
    "cappu_clean": 91
  }
}
```

Composite results nest the same way (`payload["value"]...`), and every
structured result type exposes the identical `to_dict()` from Python.
This is the interface the Home Assistant integration
([jura-connect-hass](https://github.com/makefu/jura-connect-hass))
builds on.

## Library API

```python
from jura_connect import (
    JuraClient, CredentialStore, MachineCredentials,
    discover, run_named, list_commands, load_profile,
)

# Discovery
for m in discover(timeout=4.0):
    print(m.name, m.fw, m.address)

# First-time pair (a user presses OK on the machine)
client = JuraClient("192.168.1.42", conn_id="laptop-1")
result = client.pair(timeout=60.0, on_user_prompt=print)   # pin="12345678" if set
store = CredentialStore()
store.put(MachineCredentials(
    name="Kaffeebert", address="192.168.1.42",
    conn_id="laptop-1", auth_hash=result.new_hash,
))
client.close()

# Reconnect later and use the machine
creds = store.get("Kaffeebert")
with JuraClient(creds.address, conn_id=creds.conn_id,
                auth_hash=creds.auth_hash,
                profile=load_profile("EF1091")) as c:
    info = c.read_machine_info()
    print(info.maintenance_counters.cleaning)   # 21 (None if not reported)
    print(info.status.active_alerts)            # ('coffee_ready', 'energy_safe')

    # or the named-command registry — the same API the CLI uses:
    result = run_named(c, "counters")
    print(result.format(), result.to_dict())
```

### Readiness and progress

The two things a long-running integration needs: *may I start this
product now*, and *how far along is it*. Both need a profile; without
one `can_brew()` answers `True` rather than guessing.

```python
with JuraClient(addr, conn_id=cid, auth_hash=h,
                profile=load_profile("EF1091")) as c:
    status = c.read_status()              # waits for the next pushed @TF:
    status.can_brew("espresso")           # False while a blocking alert is up
    status.blocked_kinds                  # ('C', 'CM')
    status.alert_processes                # (('cleaning_alert', 'cleaning'),)

    if status.can_brew("espresso"):
        c.brew("espresso", ml=45, follow=True,          # blocks until ENJOY
               on_progress=lambda p: print(p.format(), p.percent))

    # Watch without sending anything — includes brews started
    # at the front panel.
    for update in c.iter_progress(timeout=60.0):
        print(update.state_name, update.product, update.percent)
        if update.is_complete:
            break
```

Progress frames never raise on unknown state codes or truncated
frames; every result type exposes the same `format()` / `to_dict()`
pair. Maintenance processes mirror the CLI: `c.watch_process()`
(read-only), `c.process_runner("cleaning")` (step-by-step),
`c.run_process("cleaning", auto_accept=True)`. Language download and
the dongle OTA are library-only (`jura_connect.language`,
`jura_connect.firmware`); the OTA refuses to send anything without
`acknowledge_bricking_risk=True`.

## Supported machines

All machines with a **Smart Connect** WiFi dongle speak the same wire
protocol, so everything works on every profile unless noted. The 89
bundled profiles come from the J.O.E. app, not from machines; only the
rows below have been confirmed against physical hardware by someone:

| Machine (EF code) | Tested on hardware | By | Evidence |
| --- | --- | --- | --- |
| S8 EB (**EF1091**) | full sweep — the reference machine (TT237W V06.11) | maintainer | [docs/VERIFICATION.md](docs/VERIFICATION.md), [`docs/captures/`](docs/captures/) |
| Z10 (**EF545**) | double-product counters, milk brew params, all settings reads | @bobcat0070 | [#9](https://github.com/makefu/jura-connect/issues/9), [#11](https://github.com/makefu/jura-connect/pull/11) |
| Z10 (**EF545**) | milk `milk_amount`/foam phases brewed and physically checked | @Legendberg | [#7](https://github.com/makefu/jura-connect/pull/7) |
| GIGA 6 (**EF566**) | twin-grinder ratio; clock + weekday timers | @martins-netizen | [`docs/EF566_GRINDER_RATIO.md`](docs/EF566_GRINDER_RATIO.md), [#18](https://github.com/makefu/jura-connect/pull/18)/[#19](https://github.com/makefu/jura-connect/pull/19) |
| GIGA 10 (**EF1065**) | pairing, live status, product listing | @chamseddine04 | [#12](https://github.com/makefu/jura-connect/issues/12) |
| E6 (EF532 / **EF1030**) | brew blob; PIN-protected pairing | maintainer, @kykc | §5.9 of PROTOCOL.md, [#3](https://github.com/makefu/jura-connect/pull/3) |
| S10 (**EF1123**) | profile contributed; no wire-level report yet | @DaftHonk | [#5](https://github.com/makefu/jura-connect/pull/5) |
| A8 (**EF1171M**) | discovery, status, maintenance counters work; no bundled profile yet, falls back to the EF536 baseline | @jybisiaux | [#20](https://github.com/makefu/jura-connect/issues/20) |

### Model-specific features and quirks

What some machines can do *more* — and where specific models behave
differently:

- **Z10 (EF545)** — split-phase milk: the liquid phase
  (`milk_amount=<s>`) and the foam phase (`milk=`/`milk_foam=<s>`) are
  settable independently, live-verified by brewing
  ([#7](https://github.com/makefu/jura-connect/pull/7)). Two
  quirks: its double products are counted one nibble above their
  singles (`0x12`/`0x13`, not the catalogue's `0x31`/`0x36`) — the
  library remaps this per EF code, mirroring the J.O.E. app's only
  special case ([#9](https://github.com/makefu/jura-connect/issues/9));
  and the dongle dislikes session churn — reconnecting within a few
  seconds of closing gets a reset mid-handshake, leave ~20 s
  ([docs/PROTOCOL.md](docs/PROTOCOL.md) §4.5). The Z10's scheduled
  "automatic turning on" (weekday switch-on times) is a machine-menu
  feature; the library API to read and edit those timers is
  introduced in [#19](https://github.com/makefu/jura-connect/pull/19)
  (currently EF566-verified only) — Z10 owners are invited to test it
  there.
- **GIGA 6 (EF566)** — twin grinders: `brew espresso grinder=100_0`
  selects the left hopper only, `0_100` the right; physically verified
  ([docs/EF566_GRINDER_RATIO.md](docs/EF566_GRINDER_RATIO.md)). It is
  also the only machine so far with a clock/date/weekday-timer API —
  `machine-clock`, `set-machine-clock`, `weekday-timers` — gated to
  EF566 until other models are confirmed
  ([#18](https://github.com/makefu/jura-connect/pull/18)/[#19](https://github.com/makefu/jura-connect/pull/19)).
- **S8 EB / old T-protocol machines (e.g. EF1091)** — two firmware
  behaviours worth knowing: the TT237W dongle ignores unicast UDP
  discovery, so pair with an explicit `--machine-type`; and it does
  not support product programming — `pmode` answers "not supported by
  machine" (`@tm:C2`) instead of failing.
- **Across the catalogue** — features are declared per profile, so
  check yours with `machine-types` / `processes` / `products`:
  programmable recipes (`pmode-*`) exist on 20 of 89 profiles; special
  counters (cold brew, sweet foam; `@TR:52`) on 14; daily counter
  banks (`daily-brews`, useful for a "brews today" sensor) on 37; and
  newer `IntakeF18` machines (23 of 89) encode brew preselections
  (`double`, `extra_shot`) as a mask byte while older machines switch
  to a separate product code.

Everything else is **supported-by-catalogue, untested**: product
names, alerts and settings still resolve through that machine's XML,
but no human has pointed this library at it. Hardware reports —
especially a `machine-types` miss like #20, or a counter/alert that
names itself wrong on your model — are exactly what we need:
**PRs and issue reports with your EF code welcome.**

## Documentation

| Document | For |
| --- | --- |
| [docs/CLI.md](docs/CLI.md) | per-feature CLI usage (brew, settings, maintenance, …) |
| [docs/COMMANDS.md](docs/COMMANDS.md) | full named-command catalogue with wire codes |
| [docs/DESTRUCTIVE.md](docs/DESTRUCTIVE.md) | the gate, gated patterns, risk & recovery notes |
| [docs/VERIFICATION.md](docs/VERIFICATION.md) | what is hardware-verified vs simulator-only |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | wire protocol reference (source of truth) |
| [docs/JOE_GAPS.md](docs/JOE_GAPS.md) | feature scoreboard vs the J.O.E. app; open questions |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | contributing: QA gate, tests, releasing |

## Acknowledgements

The Bluetooth and UART flavours of the Jura control protocol were
reverse-engineered first by the **[Jutta-Proto](https://github.com/Jutta-Proto)**
project — most notably
[`protocol-bt-cpp`](https://github.com/Jutta-Proto/protocol-bt-cpp)
(their write-up of the obfuscation scheme, the `@HP:` handshake and
the destructive command set was the starting point) and
[`protocol-cpp`](https://github.com/Jutta-Proto/protocol-cpp), which
builds on the earlier
[Protocol JURA wiki](http://protocoljura.wiki-site.com/index.php/Hauptseite)
community work. This project is an independent port targeting the
*WiFi* transport (TCP/51515, `Smart Connect` dongle), developed by
reading the J.O.E. Android APK and validating against a physical
S8 EB. Without the Jutta-Proto work the project would not have
started in first place.

## Usage of LLMs

This project has been 100% written by the Claude Code Model "Opus 4.7" starting 2026-05-11

## License

MIT
