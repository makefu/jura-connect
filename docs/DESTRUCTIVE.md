# Destructive commands

Commands that change the machine's physical state — start cleaning
cycles, brew product, reset counters, write WiFi credentials or the
machine PIN — live in the same registry as the reads but are refused
by default *before* anything is sent. The error you get spells out the
risk:

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

## The gated wire patterns

Exported as `jura_connect.DESTRUCTIVE_PREFIXES` (byte-prefix matched)
and `jura_connect.DESTRUCTIVE_EXACT` (exact match):

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

## Risk notes

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

A cleaning cycle consumes a tablet, locks the machine for 5+ minutes
and has no remote abort. The language download can leave a slot
showing garbage if it aborts part-way, and a run that dies before the
trailing `@TS:00` leaves the display locked until a power cycle. The
dongle firmware OTA can **brick the dongle with no remote recovery** —
which is why it has no CLI command at all and, from Python, raises
before touching the socket unless you pass
`acknowledge_bricking_risk=True`. The scheduled `coffee-timer` pours
later, unattended, whether or not a cup is under the spout.

Per-command danger strings are on each `CommandSpec`
(`jura_connect.list_commands()`); the CLI prints them on refusal. The
protocol-side detail is §5.8 of [PROTOCOL.md](PROTOCOL.md).
