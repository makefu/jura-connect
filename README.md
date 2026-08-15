# jura-connect

[![CI](https://github.com/makefu/jura-connect/actions/workflows/ci.yml/badge.svg)](https://github.com/makefu/jura-connect/actions/workflows/ci.yml)

A dependency-free Python WiFi interface for Jura coffee machines fitted
with a **Smart Connect** WiFi dongle. Reverse-engineered from the
official J.O.E. (Jura Operating Experience) Android app and verified
end-to-end against a **JURA S8 EB** running firmware **TT237W V06.11**
("Kaffeebert").

## Status

53 named commands, 770 tests. The table splits by *how well verified*
each area is, because that is the thing worth knowing before you point
this at your machine.

**Verified against physical hardware** (a JURA S8 EB / EF1091 running
TT237W V06.11, plus an E6 for the brew blob):

| Capability | Status |
| --- | --- |
| UDP/51515 broadcast discovery + parser | ✓ ; falls back to TCP-port-sweep on the TT237W firmware which doesn't reply to UDP |
| Wire framing (`* … \r\n`) and obfuscation cipher | ✓ ; 2 000-input random round-trip + every key value exhaustively tested |
| `@HP:` handshake, pairing (with or without a setup PIN), credential storage | ✓ |
| Read commands: maintenance counters, maintenance %, machine status / alerts, per-product brew counters, screen lock/unlock | ✓ |
| Per-machine profiles — 89 bundled XMLs from the J.O.E. APK; alert names + product codes are looked up per `EF_code` so a Cortado on an S8 EB names itself, not `0x2B=2` | ✓ |
| Machine settings: single-setting read and checksummed write | ✓ |
| Brewing by product name — `brew hotwater water=220 temp=high` — with water / strength / temperature / bypass overrides validated against the machine XML | ✓ ; the `@TP:` recipe-blob format is verified by physically brewing, see §5.9 of [`docs/PROTOCOL.md`](docs/PROTOCOL.md) |

**Implemented, simulator-verified, never run against hardware** — see
the warning below. Section numbers refer to
[`docs/PROTOCOL.md`](docs/PROTOCOL.md):

| Capability | Wire | Doc |
| --- | --- | --- |
| Product progress: 87 decoded states, live percentage, `brew(follow=True)` | `@TV:` | §5.10 |
| Interactive maintenance processes (start, watch, confirm, advance) | `@TG:01` / `@TG:04` / `@TG:10` | §5.11 |
| Extra counter banks: special, barista, daily + daily reset | `@TR:52/53/34/35/42..45`, `@TF:05` | §5.5 |
| Batch settings read, live per-product limits | `@TM:00,FC`, `@TM:60` | §5.7 |
| Programmable-recipe (PMode) writes | `@TM:41` / `@TM:42` | §5.6 |
| Brew preselections (extra shot, double, powder, cold brew, sweet foam) | `@TP:` mask / overwrites | §5.13 |
| Coffee timer (scheduled brew) | `@TM:3C` + `@TV:84` | §5.12 |
| Language download | `@TS:F1` / `@TT:xx` / `@TV:8x` | §5.14 |
| Milk cooler update, dongle restart, dongle firmware OTA | `@HU` / `@HT:3` / `@HB`…`@HE` | §5.15 |

> ### ⚠ Read this before using anything in the second table
>
> Everything in it was reverse-engineered from the J.O.E. Android APK
> and is exercised only against `jura_connect.simulator` — a TCP server
> in this repo that speaks the same protocol. **The simulator's replies
> were written from the same APK reading as the client's expectations,
> so a shared misreading passes both halves of the test-suite.** No
> byte in that table has ever been confirmed by a real Jura machine.
>
> Practically: a wrong preselection or recipe byte **misbrews**, a
> maintenance confirmation sent at the wrong moment **consumes a
> cleaning tablet**, an interrupted language download leaves a language
> slot showing garbage, and the firmware OTA can **brick the WiFi
> dongle with no remote recovery** (which is why it has no CLI command
> at all and is gated behind `acknowledge_bricking_risk=True` in
> Python). The first table is what you can rely on.
>
> [`docs/JOE_GAPS.md`](docs/JOE_GAPS.md) §9 enumerates every
> unverified area, what breaks if it is wrong, and the cheapest
> read-only experiments that would settle it.

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
machine type   : EF1091  (discovery)
saved credentials for 'Kaffeebert' -> /home/you/.local/share/jura-connect/credentials.json
```

If the machine has a setup PIN configured, pass it on the handshake:

```sh
$ jura-connect pair 192.168.1.42 --name Kaffeebert --pin 12345678
```

The PIN is stored alongside the auth-hash so later reconnects reuse it
automatically; `jura-connect command --name Kaffeebert info` just works.
Pass `--pin` again only to override a stored PIN. `creds --json` never
prints the PIN — it reports `pin_stored: true` instead.

The auth-hash is written to `$XDG_DATA_HOME/jura-connect/credentials.json`
with `0600` permissions. Override the location with the global
`--store /path/to.json` flag.

### Machine variants (per-machine profiles)

Different Jura models speak the same wire protocol but disagree about
which **product codes** mean what and which **alert bits** map to which
display strings. The 89 machine XMLs from the J.O.E. APK are bundled
with this package and looked up by EF code; pairing tries to detect the
code automatically from UDP discovery, but on firmwares that don't
answer unicast UDP (notably TT237W) you'll want to pass it explicitly.

```sh
# Find your machine in the catalogue
$ jura-connect machine-types --filter "S8 (EB)"
# matches for 'S8 (EB)':
   15480  S8 (EB)                         EF1091
   15482  S8 (EB)                         EF1151

# Pair with an explicit machine type
$ jura-connect pair 192.168.1.42 --name Kaffeebert --machine-type EF1091

# Or retro-fit a machine type onto an already-paired credential
$ jura-connect set-machine-type --name Kaffeebert EF1091
set 'Kaffeebert' machine type to EF1091 -> /home/you/.local/share/jura-connect/credentials.json

# Override the stored profile for one invocation
$ jura-connect command --name Kaffeebert --machine-type EF1091 brews
```

Credentials without a `machine_type` field fall through to the EF536
baseline, so older paired machines keep working without migration.

### Machine name ("Kaffeebert")

The string you see on the touchscreen (and in `jura-connect discover`)
is the WiFi dongle's display name. It's writable via the gated
`set-name` command (`@HW:82,<name>`):

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    set-name LatteBot
```

After the next reconnect, both the touchscreen and discovery report
the new name. There is no separate per-machine display name — Jura's
WiFi protocol exposes a single name string that the dongle owns and
the machine surfaces. The protocol does not expose the
machine's local PIN-protected "machine name" field (set on the
machine itself, behind the service menu); only the dongle's name.

### Run commands against a paired machine

The CLI exposes a `command` subcommand that takes a *named* read
command, not a raw hex code. Discover the catalog with:

```sh
$ jura-connect command --list
available commands:
  read-only:
    info                                                full read-only snapshot (status + counters + percent)
    counters                                            maintenance counters (@TG:43)
    percent                                             maintenance percent indicators (@TG:C0)
    status                                              parsed status / active alerts (waits for a pushed @TF: frame)
    brews                                               per-product brew counters (@TR:32 paginated; 16 pages)
    products                                            list brewable products and their allowed 'brew' param=value ranges/choices (from the machine profile; no machine I/O)
    pmode                                               programmable-mode slots (@TM:50 + @TM:42); empty on the S8 EB
    lock                                                lock the front-panel display (@TS:01)
    unlock                                              unlock the front-panel display (@TS:00)
    mem-read <addr>                                     read a memory/setting slot (@TM:<addr>); firmware-specific
    register-read <bank>                                read a register bank (@TR:<bank>); firmware-specific
    cancel                                              cancel the running product step (@TG:FF); the 'abort this brew' verb
    raw <frame>                                         send a verbatim '@…' command; payload checked against the destructive set
    setting <name> [<value>]                            read or write one machine setting ('hardness', 'language', 'units', 'auto_off', 'brightness', 'milk_rinsing', 'frother_instructions' on the S8 EB / EF1091); the second arg writes and is gated
    progress [<seconds>]                                watch the machine's @TV: product-progress stream and decode it (read-only; stops on the ENJOY frame or after <seconds>)
    special-counters                                    special counter bank (@TR:52 paginated; 4 pages) — cold brew, sweet foam & friends; declared by 14 of the 89 profiles
    barista-counters                                    barista counter bank (@TR:34 paginated) — declared by 4 profiles; not read by the J.O.E. app, so untested on hardware
    daily-brews                                         per-product brew counters since the last daily reset (@TR:42 paginated); not read by the J.O.E. app
    daily-barista-counters                              barista counters since the last daily reset (@TR:44 paginated); not read by the J.O.E. app
    settings                                            read every machine setting; tries the XML's batch bank (@TM:00,FC) and falls back to one @TM:<arg> per setting
    limits <product>                                    live per-product parameter limits (@TM:60); the ranges the machine allows right now, as opposed to the XML's static ones
    pmode-product <product>                             read one product's stored programmable-recipe settings (@TM:41,<code>); APK-derived, hardware-untested
    processes                                           list the maintenance processes this machine declares (from the machine profile; no machine I/O)
    process-watch [<seconds>]                           decode the machine's pushed maintenance-state stream (read-only; names each @TV: state via the machine XML)
    coffee-timer-time <time>                            tell the machine the wall-clock time a coffee timer refers to (@TV:84); APK-derived, untested on hardware
    languages                                           list the machine's language slots (@TT:00) and its language-download support (@TM:23 + profile capabilities)
    milk-cooler-status                                  milk cooler (Cool Control) firmware-update state (@HU?); '@hu:800' = no cooler connected

  destructive (require --allow-destructive-commands; see 'jura-connect command --help'):
    clean                                               [destructive] start coffee-system cleaning cycle (@TG:24)
    descale                                             [destructive] start descaling cycle (@TG:25)
    filter-change                                       [destructive] run water-filter change procedure (@TG:26)
    cappu-clean                                         [destructive] start cappuccino-system cleaning (@TG:21)
    cappu-rinse                                         [destructive] rinse the milk system (@TG:23)
    skip-quality-step [<scope>]                         [destructive] skip a quality-assistant step (@TG:7E); 'all' skips every remaining step. Has also been seen to zero the maintenance counters
    restart                                             [destructive] reboot the WiFi dongle (@TF:02)
    power-off                                           [destructive] standby command (@AN:02); likely no-op on WiFi
    brew <product> [<param=value|preselection>...]      [destructive] start brewing a product (@TP:<recipe blob>); run 'products' to discover valid names and param=value ranges
    set-pin <pin>                                       [destructive] write a new front-panel PIN (@HW:01,<pin>)
    set-ssid <ssid>                                     [destructive] write a new WiFi SSID for the dongle (@HW:80,<ssid>)
    set-password <password>                             [destructive] write a new WiFi password (@HW:81,<pwd>)
    set-name <name>                                     [destructive] rename the dongle (@HW:82,<name>)
    reset-daily-counters                                [destructive] zero the daily counter banks (@TF:05)
    pmode-set-product <product> [<param=value>...]      [destructive] overwrite a product's programmable-recipe settings (@TM:41,<blob>)
    pmode-set-slot <slot> <product> [<param=value>...]  [destructive] assign a product (with settings) to a programmable-recipe slot (@TM:42,<slot>,<blob>)
    process-start <process>                             [destructive] start a maintenance process and return the machine's acknowledgement (run 'processes' for the names)
    process-run <process> [<seconds>]                   [destructive] start a maintenance process and follow its state machine to the end, confirming every prompt
    process-accept [<command>]                          [destructive] confirm the maintenance step the machine is waiting on (@TG:10 / @TG:04, whichever its XML declares)
    process-next                                        [destructive] advance the machine to the next step (@TG:01); answers @tg:00 when there was nothing to advance
    coffee-timer <product> <when> [<param=value>...]    [destructive] schedule a product for later (@TM:3C + @TV:84); APK-derived, untested on hardware
    language-lock                                       [destructive] lock the keypad for a language download (@TS:F1)
    language-display <line1> [<line2>]                  [destructive] overwrite the two display lines shown during a language download (@TV:81 / @TV:82)
    language-download <source> [<block>]                [destructive] push a language image into the machine (@TS:F1 / @TT:01 / @TT:02 or @TT:08 / @TT:03); takes an S-record file or blob. APK-derived, never hardware-tested
    milk-cooler-update                                  [destructive] start a milk-cooler firmware update (@HU)
    restart-dongle                                      [destructive] restart the WiFi dongle (@HT:3)
```

That is the complete catalogue as of this release — 27 read-only and 26
destructive commands. It is generated from
`jura_connect.commands`, so the CLI and `jura_connect.list_commands()`
can never drift apart.

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
  errors         : (none)
  info flags     : coffee_ready, energy_safe
  process flags  : (none)
  maintenance    : cleaning=21 filter=1 descale=8 cappu_rinse=344 coffee_rinse=3617 cappu_clean=91
  maintenance %  : cleaning=80 filter=255 descale=30

$ jura-connect command --name Kaffeebert counters
handshake -> CORRECT  (@hp4)
cleaning=21 filter=1 descale=8 cappu_rinse=344 coffee_rinse=3617 cappu_clean=91

$ jura-connect command --name Kaffeebert status
handshake -> CORRECT  (@hp4)
bits=0004000008000000
  errors  : (none)
  info    : coffee_ready, energy_safe
  process : (none)

$ jura-connect command --name Kaffeebert brews
handshake -> CORRECT  (@hp4)
total brews : 3229
  espresso            : 78
  coffee              : 595
  cappuccino          : 64
  americano           : 1019
  lungo               : 3
  espresso_doppio     : 20
  flat_white          : 210
  cortado             : 2
  sweet_latte         : 1
  2_espressi          : 1
  2_coffee            : 10
```

The product names above are lifted from the S8 EB's own XML
(`EF1091`). Without a profile the same machine would surface
`0x2B=2`, `0x2C=1`, `0x31=1`, `0x36=10` as anonymous slots — the EF536
baseline doesn't know what those codes brew.

Status output distinguishes blocking **errors** (machine is stuck,
user must act) from **info** flags (low-supply reminders and
state-of-being bits such as `no_beans`, `coffee_ready`,
`energy_safe`) and **process** flags (periodic maintenance prompts
such as `cleaning_alert` and `descale_alert`). The unsplit
``active_alerts`` is still on the dataclass for backwards
compatibility.

Status-bit decoding uses **MSB-first** indexing within each byte
(matching the J.O.E. APK's `Status.a()`). v0.8.0 and earlier used
LSB-first, which mis-named every bit by 7 positions per byte and
made the CLI report e.g. `no_beans` when the live frame actually
meant `coffee_ready`. v0.9.0 fixes this; see CHANGELOG for the
correction window.

With a machine profile loaded, `status` also answers *"can I brew right
now?"*. Each `<ALERT>` in the XML declares which product kinds it
blocks and which maintenance process clears it, so the status line
gains two more rows:

```sh
$ jura-connect command --name Kaffeebert status
bits=0020000020000000
  errors  : (none)
  info    : no_beans
  process : cleaning_alert
  blocked : C, CM
  clear by: cleaning_alert -> cleaning
```

`MachineStatus.can_brew("espresso")` / `.can_brew_kind("C")` answer the
same question from Python, and `.alert_processes` names the process to
feed to `process-run`. Without a profile these stay empty — the
fallback codebook carries no such metadata, and guessing would be
worse than saying nothing. See §5.11 of
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

The `pmode` command reads the programmable-recipe slot table via
`@TM:50` + `@TM:42,<slot>`. On the S8 EB / EF1091 every slot returns
`@tm:C2` ("not supported by machine"), and `pmode` surfaces that as
``not supported by machine`` instead of crashing — useful as a
discriminator between firmware variants:

```sh
$ jura-connect command --name Kaffeebert pmode
handshake -> CORRECT  (@hp4)
pmode: 20 slot(s) reported by @TM:50, but every slot returned C2 (= 'not supported by machine'). This firmware does not expose pmode entries over WiFi.
```

### Read or write machine settings (`setting`)

Each machine XML declares a `<MACHINESETTINGS>` section listing
user-tunable settings (water hardness, auto-off delay, display units,
language, brightness, milk-rinsing mode, frother instructions). The
`setting` command reads or writes them by name, using the machine
profile to validate the value before going on the wire.

```sh
# Read a value
$ jura-connect command --name Kaffeebert setting hardness
handshake -> CORRECT  (@hp4)
hardness = 16 (0x10)

# Substring match is allowed when unambiguous
$ jura-connect command --name Kaffeebert setting bright
display_brightness_setting = 40 (0x04)

# Writes are gated. Without the flag, the CLI explains the risk
# and the catalogue values; with the flag, it validates against the
# profile (range / step / known item) and computes the @TM:<arg>,<val>
# trailing checksum before sending.
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    setting language french
set language = 0x03 (reply: @tm:09)

$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    setting hardness 99
refused: hardness: 99 is outside [1, 30]
```

The catalogue is per-machine: `EF1091` carries 7 settings, other EF
codes have different lists. Pair with `--machine-type` (or
`set-machine-type` after the fact) so the profile is loaded.

The trailing two hex chars on every write are a checksum the dongle
verifies — see `_settings_checksum` in `jura_connect.client` and §5.7
of [`docs/PROTOCOL.md`](docs/PROTOCOL.md). A bad checksum gets
`@an:error` from the firmware (and from the simulator).

### Read every setting at once (`settings`), and live limits (`limits`)

`settings` dumps the whole catalogue. It first tries the batch bank the
XML declares (`@TM:00,FC`, one round trip for four settings) and falls
back to one `@TM:<arg>` read per setting if the machine rejects it or
the reply doesn't decode — so it works either way, and the result says
which path was taken:

```sh
$ jura-connect command --name Kaffeebert settings
settings (7 read via batch @TM:00,FC):
  hardness                     0x10
  auto_off                     30min (0x211E)
  units                        ml (0x00)
  language                     english (0x02)
  display_brightness_setting   40 (0x04)
  milk_rinsing                 automatic (0x00)
  frother_instructions         on (0x01)
```

`limits <product>` asks the machine what ranges it will accept *right
now* (`@TM:60`), as opposed to the static ranges in the XML. Machines
without product programming answer `@tm:C1`:

```sh
$ jura-connect command --name Kaffeebert limits espresso
error: @TM:60 for espresso: machine answered C1 — this firmware does
not support product programming / limit load
```

The batch reply layout is a **guess** — J.O.E. declares the command in
every XML but never sends it — which is exactly why the fallback
exists. §5.7 of [`docs/PROTOCOL.md`](docs/PROTOCOL.md) has the
derivation and the read-only experiment that would confirm it.

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
    "descale": 8,
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

### Brew a product (`brew`)

Not sure what to type? `products` lists every brewable product on the
connected machine with its resolvable name and each `param=value`
key's allowed values (ranges/steps for water & milk, item choices for
strength & temperature), read straight from the machine profile with
no extra machine I/O:

```sh
$ jura-connect command --name Kaffeebert --machine-type EF538 products
EF538 — 14 brewable product(s)

espresso  (0x02)
    strength / coffee_strength   default 8        choices: 1=01, 2=02, …, 10=0A
    ml / water / water_amount    default 45       range 15–80 ml, step 5 (value ÷ 5 = 5 ml wire ticks)
    temp / temperature           default high     choices: low=00, normal=01, high=02

latte_macchiato  (0x07)
    …
    milk / milk_foam / milk_foam_amount default 22  range 1–120 s, step 1 (seconds, sent as-is)  [not live-verified — may misbrew, verify on your hardware]
```

`brew` starts a product by its 2-hex product code, by its profile
name, or — as an escape hatch — by a full verbatim recipe blob (32+
hex chars). Name resolution is: an exact 2-hex code first, then an
exact snake_case name, then an unambiguous name *prefix* (so
`hotwater` finds `hotwater_portion_normal` but `esp` is rejected as
ambiguous). Pass `substring=True` to `JuraClient.resolve_product` /
`brew` to widen matching to anywhere in the name. Optional
`param=value` arguments (an uncapped variadic list) override the
machine XML's defaults; every value is validated against the XML
catalogue (range, step, allowed items) before anything goes on the
wire:

```sh
# Hot water with the XML default quantity (here: 220 ml)
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew hotwater
handshake -> CORRECT  (@hp4)
@tp

# An espresso, stronger and shorter than the default
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew espresso water=35 strength=7

# Cappuccino with more milk foam, high temperature
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew cappuccino milk=20 temp=high

# Out-of-catalogue values never reach the machine
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew hotwater water=9999
refused: water_amount: 9999 is outside [25, 450]
```

Parameter keys: `water`/`ml` (millilitres), `strength` (level),
`temp`/`temperature` (`low` / `normal` / `high`), `milk` (seconds),
`milk_break` (seconds), `bypass` (millilitres). Which parameters a
product accepts comes from its machine-XML entry.

> **Bypass and milk overrides are not live-verified — they may
> misbrew, so verify them on your hardware.** `bypass`, `milk`
> (milk-foam) and `milk_break` are encoded from the XML (ml kinds ÷5
> ticks, seconds as-is) but have not been confirmed against a physical
> machine. Only water and temperature are live-verified.
> **Twin models** (e.g. J8/J10 "twin") and any product with a
> `grinder_ratio` parameter are untested — their blob layout may
> differ. Machines whose dongle stays silent on UDP discovery need
> `set-machine-type <name> <EF>` once before `products` / `brew` map to
> the right catalogue instead of the EF536 baseline.

The wire command is **not** a bare product code, and **not** an
FF-padded blob: the firmware ACKs both with `@tp:00` and silently
ignores them. The working format is a 16-byte recipe blob with the
product code at byte 0, each XML parameter at its `Argument` offset
minus one (water/bypass in 5 ml ticks), **byte 8 = `0x01`** (a
constant "recipe valid" byte), and every other byte `0x00`. An unset
water byte is `0x00` = no water, so `brew` refuses to leave a water
parameter unset and always sends the full validated blob. An accepted
blob replies with a bare `@tp` (then `@TB`/`@TV` frames); `@tp:00`
means rejected. See §5.9 of [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for
the layout, verified by physically brewing on a JURA S8 EB (EF1091)
and an E6.

From Python:

```python
from jura_connect import JuraClient, load_profile

with JuraClient(addr, conn_id=cid, auth_hash=h,
                profile=load_profile("EF538")) as c:
    c.brew("hotwater", ml=220)                      # '@tp' on accept
    c.brew("espresso", strength=7, temperature="high")
    # or block until the machine says ENJOY:
    c.brew("espresso", follow=True,
           on_progress=lambda p: print(p.format()))
```

#### Preselections

A bare word after the product is a **preselection** — the extra-shot /
double / powder / cold-brew / sweet-foam toggles the machine's XML
declares per product:

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew espresso double
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew cappuccino extra_shot temp=high
```

`products` lists each product's preselections and flags the ones this
machine generation cannot express, so `brew` never advertises something
it will reject. Validation happens client-side in four steps: the name
is known, the product declares it, the requested set fits one legal
`<COMBINATION>` row, and this machine can actually send it.

On older machines a `double` **selects a different product** (its code
is swapped into the blob) rather than setting a flag; newer
`IntakeF18` machines get a 20-byte blob with a mask byte instead.

> **Never seen on a wire.** The preselection encoding is transcribed
> from the APK and a wrong byte overwrites a recipe parameter, i.e.
> misbrews. §5.13 of [`docs/PROTOCOL.md`](docs/PROTOCOL.md) has the
> full derivation and the open questions.

### Watch what the machine is doing (`progress`)

The machine pushes `@TV:` frames unsolicited whenever it is busy.
`progress` listens and decodes them — it sends nothing at all, so it is
safe to point at a brew somebody started at the front panel. It returns
on the `ENJOY` frame or when the watch window expires:

```sh
$ jura-connect command --name Kaffeebert progress 60
handshake -> CORRECT  (@hp4)
COFFEE_WATER_AMOUNT  espresso  coffee_water_amount 6/30  20%
COFFEE_WATER_AMOUNT  espresso  coffee_water_amount 18/30  60%
COFFEE_WATER_AMOUNT  espresso  coffee_water_amount 30/30  100%
ENJOY  espresso
```

87 states are decoded (`ProgressState`), covering products, maintenance
processes, the coffee timer and the aroma preselection screen. An
unknown state code never raises — it comes through as
`UNKNOWN(0x..)` with the raw byte intact, which is what makes this safe
to run against a firmware family nobody has seen. §5.10 of
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

### Run a maintenance process end to end

A cleaning cycle is a conversation, not a command: the machine answers
the start verb, then drives *you* through its state table ("empty the
tray", "add a tablet", "press Rinse") and parks until each prompt is
confirmed. `processes` lists what this machine declares — no machine
I/O, it reads the profile:

```sh
$ jura-connect command --name Kaffeebert processes
processes declared by EF1091
  filter_change (@TG:26)  no progress frames
  cleaning (@TG:24)
  descale (@TG:25)
  cappu_rinse (@TG:23)
  cappu_clean (@TG:21)
```

`process-run` starts one and follows it to its finish state, confirming
every prompt on the way:

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    process-run cleaning 900
handshake -> CORRECT  (@hp4)
process cleaning
  start reply: @tg:24
  70 cleaning_start
  72 cleaning_empty_tray
  75 cleaning_add_tablet
  26 press_rinse  needs @TG:10
  74 cleaning_process
  76 cleaning_process_finished  (done)
-- finished
```

For manual control there are `process-start`, `process-accept` (sends
`@TG:10` or `@TG:04`, whichever the machine's XML declares for that
state), `process-next` (`@TG:01`) and `cancel` (`@TG:FF`).
`process-watch` is the read-only counterpart: it decodes a cycle
somebody started at the machine without sending anything.

> Every confirmation advances a **physical** cycle: tablets and
> descaler are consumed and hot liquid is dispensed. Prepare the
> machine before running `process-run`, which auto-confirms
> unattended. §5.11 of [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

### The other counter banks

`brews` reads the product counter (`@TR:32`) every machine has. Some
machines declare more banks, and the library reads whichever the
profile declares — a machine that doesn't gets a plain explanation
rather than an error:

```sh
# The S8 EB declares @TR:32 and nothing else:
$ jura-connect command --name Kaffeebert special-counters
EF1091 does not implement the @TR:52 counter bank (not declared in its
XML, or answered @tr:00)

# A machine that does declare the daily bank:
$ jura-connect command --name Barista --machine-type EF1143 daily-brews
daily product counter (@TR:42) total: 12
  espresso            : 3
  coffee              : 0
  cappuccino          : 5
  milkcoffee          : 0
  espresso_macchiato  : 0
  latte_macchiato     : 2
```

| Command | Bank | Notes |
| --- | --- | --- |
| `special-counters` | `@TR:52` (+ `53` overflow) | cold brew, sweet foam & friends; 14 of 89 profiles |
| `barista-counters` | `@TR:34` (+ `35`) | 4 profiles; no J.O.E. code path |
| `daily-brews` | `@TR:42` (+ `43`) | since the last daily reset; 37 profiles |
| `daily-barista-counters` | `@TR:44` (+ `45`) | 4 profiles |
| `reset-daily-counters` | `@TF:05` | **gated, irreversible** — read `daily-brews` first |

The daily banks are a machine capability the J.O.E. app ignores
entirely (the XML even says so), which makes them the natural source
for a "brews today" sensor — and also means nothing but the XML
documents them.

### Programmable recipes (PMode writes)

Machines whose XML says `Productprogramming="true"` (20 of the 89
profiles) let you store a recipe against a product or assign one to a
slot on the machine's own menu:

```sh
# What is stored for a product today
$ jura-connect command --name Kaffeebert pmode-product espresso

# Overwrite it (gated)
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    pmode-set-product espresso water=40 strength=8

# Put a product with settings into slot 3 (gated)
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    pmode-set-slot 3 cappuccino milk=25
```

The S8 EB / EF1091 answers `@tm:C1` / `@tm:C2` to all of it — it
reports 20 slots via `@TM:50` but exposes none of them over WiFi — and
the CLI says so instead of crashing. §5.6 of
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

### Coffee timer

Schedule a brew for later, either at a wall-clock time or after a
delay:

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    coffee-timer espresso 07:30
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    coffee-timer espresso 45m water=40
```

Range is 1 minute to 16 hours out; `<PRODUCT Coffeetimer="false">`
marks a product ineligible and is refused client-side.
`coffee-timer-time` sends the clock frame (`@TV:84`) on its own.
There is no cancel verb — `cancel` (`@TG:FF`) is what the app sends,
but whether it clears a *pending* timer is untested.

> The machine pours later, unattended, whether or not a cup is under
> the spout. APK-derived and never confirmed on hardware, so it may
> also brew something other than what you asked for. §5.12 of
> [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

### Language download

`languages` is read-only and tells you what the machine has and whether
it supports a download at all:

```sh
$ jura-connect command --name Kaffeebert languages
Machine languages:
  slot  0: DE
  slot  1: EN
  slot  2: FR
  …
  slot 11: -  <- download block
  download supported (profile): no
  download block: 0B
  transfer form: binary (@TT:08)
  machine @TM:23: success
```

`language-download` pushes a Motorola S-record image into one slot,
handling the keypad lock, block select, chunked transfer and finish;
`language-display` paints the two display lines the machine shows while
it runs. This library never fetches the images — J.O.E. downloads them
from Jura's CDN, `jura-connect` takes whatever bytes you supply.

> A transfer that aborts part-way leaves that slot showing garbage
> until a full download replaces it, and a run that dies before the
> trailing `@TS:00` leaves the display locked until a power cycle.
> APK-derived, never hardware-tested. §5.14 of
> [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

### Milk cooler and dongle

```sh
$ jura-connect command --name Kaffeebert milk-cooler-status
milk cooler: no_cooler (@hu:800)

$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    milk-cooler-update
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    restart-dongle
```

`milk-cooler-status` (`@HU?`) is read-only — `@hu:800` means no Cool
Control is attached, which is also why it doubles as a harmless nudge
for firmwares that want traffic on the socket before they push a status
frame.

The **dongle firmware OTA** (`@HB` → `@HO:` → `@HD:` → `@HE`) is
implemented in `jura_connect.firmware` but deliberately has **no CLI
command**: a named command can only perform one step, and a partially
transferred image is exactly the failure that bricks the dongle with no
remote recovery. From Python it needs both blobs and an explicit
`acknowledge_bricking_risk=True`, or it raises before touching the
socket. §5.15 of [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

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

The gated wire patterns are exported as
`jura_connect.DESTRUCTIVE_PREFIXES` (byte-prefix matched) and
`jura_connect.DESTRUCTIVE_EXACT` (exact match):

| Family | Patterns |
| --- | --- |
| maintenance processes | `@TG:01` `@TG:04` `@TG:10` `@TG:21` `@TG:23` `@TG:24` `@TG:25` `@TG:26` `@TG:7E` |
| machine / counters | `@TF:02` `@TF:05` `@AN:02` |
| brewing | `@TP:` `@TM:3C,` |
| dongle settings | `@HW:` |
| language download | `@TS:F1` `@TT:01` `@TT:02` `@TT:03` `@TT:08` `@TV:81` `@TV:82` |
| dongle firmware | `@HB` `@HO:` `@HD:` `@HE` `@HT:` and the exact `@HU` |

Two of those need explaining. `@TM:3C,` carries the **trailing comma**
on purpose: the tuple is prefix-matched and the `@TM:` space is shared
with harmless register reads, so the bare form would gate `mem-read
3C`. `@HU` is exact-matched because prefix-matching it would swallow
the read-only `@HU?` status frame. `jura_connect.match_destructive()`
is the single matcher the runtime gate, the `raw` inspector and the
simulator all share, so `command raw '@TG:24'` is gated too — the
bypass cannot be used by accident.

Wrong values for `set-pin` / `set-ssid` / `set-password` can leave you
locked out of the machine or unable to reach the dongle over WiFi;
the only recovery is a **factory reset on the machine itself**.
`skip-quality-step` (`@TG:7E`) is **irreversible** under either of its
two known meanings: the J.O.E. app uses it to skip a quality-assistant
step, but on a TT237W S8 EB it zeroed every maintenance counter, and
there is no way to learn back when the machine was last serviced once
that has happened. `@TG:FF` — the `cancel` command — used to be listed
here as a destructive "reset"; it is the app's cancel-product-step verb
and is no longer gated.

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
    discover, run_named, list_commands, load_profile,
)

# Discovery
for m in discover(timeout=4.0):
    print(m.name, m.fw, m.address)

# First-time pair (requires user to press OK on the machine)
# Set pin="12345678" here if the machine requires a setup PIN.
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
                auth_hash=creds.auth_hash,
                profile=load_profile("EF1091")) as c:
    # Either the high-level helpers …
    info = c.read_machine_info()
    print(info.maintenance_counters.cleaning)   # 21 (None if not reported)
    print(info.status.active_alerts)   # ('coffee_ready', 'energy_safe')

    # … or the named-command registry — same API the CLI uses:
    for spec in list_commands():
        print(spec.usage(), "—", spec.description)
    result = run_named(c, "counters")
    print(result.format())             # cleaning=21 filter=1 descale=8 …
```

### Readiness and progress

The two things a long-running integration — the `jura-connect-hass`
Home Assistant component among them — actually needs: *may I start this
product now*, and *how far along is it*. Both need a profile loaded:
without one the alert metadata does not exist and `can_brew()` answers
`True` rather than guessing.

```python
from jura_connect import JuraClient, load_profile

with JuraClient(addr, conn_id=cid, auth_hash=h,
                profile=load_profile("EF1091")) as c:
    status = c.read_status()          # waits for the next pushed @TF:
    status.can_brew("espresso")       # False while a blocking alert is up
    status.can_brew_kind("CM")        # same question by product kind
    status.blocked_kinds              # ('C', 'CM')
    status.blocking_alerts            # ('no_beans',)
    status.alert_processes            # (('cleaning_alert', 'cleaning'),)

    if status.can_brew("espresso"):
        # Blocks until the machine says ENJOY (or follow_timeout).
        c.brew("espresso", ml=45, follow=True,
               on_progress=lambda p: print(p.format(), p.percent))
        for update in c.last_progress:
            update.to_dict()          # JSON-serialisable, stable keys

    # Or watch without sending anything — a brew started at the
    # front panel shows up here just the same.
    for update in c.iter_progress(timeout=60.0):
        print(update.state_name, update.product, update.percent)
        if update.is_complete:
            break
```

`ProductProgress` never raises on an unknown state code or a truncated
frame: `state` becomes `None`, the raw byte stays in `state_code`, and
missing values are `None`. Every result type in the library exposes the
same `format()` / `to_dict()` pair.

Maintenance processes have the same shape — `c.watch_process()` is
read-only, `c.process_runner("cleaning")` gives step-by-step control,
and `c.run_process("cleaning", auto_accept=True)` drives one to the
end. `jura_connect.language` and `jura_connect.firmware` are
library-only modules for the language download and the dongle OTA; the
OTA entry points refuse to send anything without
`acknowledge_bricking_risk=True`.

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
4. `pytest tests/ -q` — the 770-case test suite against the in-tree
   simulator, including 89-XML profile-registry coverage.

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
  simulator, plus error paths and both destructive gates
  (`test_commands.py`),
* the 89-XML profile registry — every bundled machine parses cleanly,
  EF1091 surfaces its S8 EB-specific product codes, alert severities
  follow the XML's `ALERT.Type` attribute (`test_profile.py`),
* `@TV:` progress decoding across all 87 states, unknown codes and
  truncated frames (`test_progress.py`),
* the maintenance-process state machine end to end, including the
  accept commands every bundled XML declares (`test_process.py`),
* the counter banks past `@TR:32`, the batch settings read and its
  per-setting fallback, PMode writes, preselections, the coffee timer,
  the language download and the firmware family (`test_counter_banks.py`,
  `test_settings_bank.py`, `test_pmode.py`, `test_preselections.py`,
  `test_coffee_timer.py`, `test_language_download.py`,
  `test_firmware.py`),
* CLI smoke tests for `command --list`, `command info` against the
  simulator, the `machine-types` / `set-machine-type` subcommands,
  and credential-store interactions (`test_cli.py`).

Note what this does **not** prove. The simulator was written from the
same APK reading as the client, so for everything in the second Status
table above the tests confirm internal consistency, not correctness
against a real Jura.

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

[`docs/JOE_GAPS.md`](docs/JOE_GAPS.md) is the companion scoreboard:
what the official J.O.E. app does, what this library does, what is
left, and — §9 — the honest enumeration of everything that is
implemented but has never been confirmed on hardware, with the
read-only experiments that would settle it. Read that section before
trusting anything in the second Status table.

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
