# CLI feature guide

Task-by-task usage of the `jura-connect` executable against a paired
machine. Pairing, credentials and machine profiles:
[README](../README.md). Full command catalogue:
[COMMANDS.md](COMMANDS.md). Destructive gating:
[DESTRUCTIVE.md](DESTRUCTIVE.md). All examples below use a credential
named `Kaffeebert`; add `--machine-type EF1091` when the stored
profile is missing or wrong.

## Read the machine

```sh
$ jura-connect command --name Kaffeebert info      # status + counters + percent
$ jura-connect command --name Kaffeebert counters  # maintenance counters
$ jura-connect command --name Kaffeebert status    # errors / info / process flags
$ jura-connect command --name Kaffeebert brews     # per-product brew counters
```

`status` separates blocking **errors** (machine stuck, user must act)
from **info** flags (`no_beans`, `coffee_ready`, `energy_safe`) and
**process** flags (maintenance prompts such as `cleaning_alert`,
`descale_alert`). With a machine profile loaded it also answers
*"can I brew right now?"*:

```sh
$ jura-connect command --name Kaffeebert status
bits=0020000020000000
  errors  : (none)
  info    : no_beans
  process : cleaning_alert
  blocked : C, CM
  clear by: cleaning_alert -> cleaning
```

Without a profile the `blocked` / `clear by` rows stay empty — the
alert metadata comes from the machine's XML (§5.11 of
[PROTOCOL.md](PROTOCOL.md)).

## Read or write settings

Each machine profile declares its user-tunable settings (water
hardness, auto-off delay, units, language, brightness, milk-rinsing
mode, frother instructions — the exact list is per EF code). Reads
are free; writes are gated and validated against the profile before
anything goes on the wire:

```sh
$ jura-connect command --name Kaffeebert setting hardness
hardness = 16 (0x10)

$ jura-connect command --name Kaffeebert setting bright     # unambiguous substring
display_brightness_setting = 40 (0x04)

$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    setting language french
set language = 0x03 (reply: @tm:09)

$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    setting hardness 99
refused: hardness: 99 is outside [1, 30]
```

`settings` dumps the whole catalogue in one go, and `limits espresso`
asks the machine which ranges it accepts *right now* (some firmwares
don't support product programming and answer `C1`). See §5.7 of
[PROTOCOL.md](PROTOCOL.md).

## Brew a product

Discover what the machine offers — names, parameter keys, allowed
ranges — with `products` (profile-only, no machine I/O):

```sh
$ jura-connect command --name Kaffeebert --machine-type EF538 products
EF538 — 14 brewable product(s)

espresso  (0x02)
    strength / coffee_strength   default 8        choices: 1=01, …, 10=0A
    ml / water / water_amount    default 45       range 15–80 ml, step 5
    temp / temperature           default high     choices: low=00, normal=01, high=02
```

`brew` takes the product by name (or 2-hex code) plus optional
`param=value` overrides, all validated against the profile before
sending:

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew hotwater
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew espresso water=35 strength=7
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    brew cappuccino milk=20 temp=high
```

Parameter keys: `water`/`ml` (ml), `strength`, `temp`/`temperature`,
`milk` (seconds), `milk_break`, `bypass` (ml), and `grinder`/
`grinder_ratio` on twin-hopper machines (`100_0`, `50_50`, `0_100`).
A bare word after the product is a **preselection** (`double`,
`extra_shot`, …); `products` lists the ones your machine can express.

> Only `water`, `strength` and `temp` are live-verified by brewing.
> `bypass`, `milk` and preselections are encoded from the XML and
> **may misbrew** — verify on your hardware first.
> `grinder_ratio` is verified on a GIGA 6 / EF566
> ([EF566_GRINDER_RATIO.md](EF566_GRINDER_RATIO.md)).

`cancel` aborts the running product step; `progress` shows what the
machine is doing (see below). §5.9 and §5.13 of
[PROTOCOL.md](PROTOCOL.md).

## Watch what the machine is doing

```sh
$ jura-connect command --name Kaffeebert progress 60
COFFEE_WATER_AMOUNT  espresso  coffee_water_amount 6/30  20%
COFFEE_WATER_AMOUNT  espresso  coffee_water_amount 18/30 60%
COFFEE_WATER_AMOUNT  espresso  coffee_water_amount 30/30 100%
ENJOY  espresso
```

Sends nothing — safe to point at a brew somebody started at the front
panel. Unknown state codes never raise; they surface as
`UNKNOWN(0x..)`. §5.10 of [PROTOCOL.md](PROTOCOL.md).

## Maintenance cycles

`processes` lists what the machine declares (profile-only). A cycle
is a conversation: the machine drives you through prompts ("empty the
tray", "add a tablet") and parks until each is confirmed.

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    process-run cleaning 900
```

`process-run` auto-confirms every prompt on the way — prepare
supplies, containers and cups first; tablets are consumed and hot
liquid dispensed. For manual control: `process-start`,
`process-accept`, `process-next`, and the read-only `process-watch`.
§5.11 of [PROTOCOL.md](PROTOCOL.md).

## Counters beyond `brews`

Some machines declare extra counter banks; the library reads
whichever the profile declares and says so plainly when the machine
doesn't have one:

| Command | Bank | Notes |
| --- | --- | --- |
| `special-counters` | `@TR:52` | cold brew, sweet foam & friends; 14 of 89 profiles |
| `barista-counters` | `@TR:34` | 4 profiles; never read by J.O.E. |
| `daily-brews` | `@TR:42` | since the last daily reset; 37 profiles |
| `daily-barista-counters` | `@TR:44` | 4 profiles |
| `reset-daily-counters` | `@TF:05` | **gated, irreversible** — read `daily-brews` first |

§5.5 of [PROTOCOL.md](PROTOCOL.md).

## Programmable recipes (PMode)

On machines with product programming (20 of the 89 profiles) you can
store recipes against products or slots:

```sh
$ jura-connect command --name Kaffeebert pmode-product espresso
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    pmode-set-product espresso water=40 strength=8
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    pmode-set-slot 3 cappuccino milk=25
```

Machines without it (e.g. the S8 EB) answer "not supported by
machine" instead of failing. §5.6 of [PROTOCOL.md](PROTOCOL.md).

## Coffee timer

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    coffee-timer espresso 07:30
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    coffee-timer espresso 45m water=40
```

1 minute to 16 hours out; ineligible products are refused
client-side. **The machine pours later, unattended.** Never confirmed
on hardware — §5.12 of [PROTOCOL.md](PROTOCOL.md).

## Languages, milk cooler, dongle

```sh
$ jura-connect command --name Kaffeebert languages            # slots + download support
$ jura-connect command --name Kaffeebert milk-cooler-status   # '@hu:800' = no cooler attached
$ jura-connect command --name Kaffeebert --allow-destructive-commands milk-cooler-update
$ jura-connect command --name Kaffeebert --allow-destructive-commands restart-dongle
```

`language-download` pushes a Motorola S-record image you supply (this
library does not fetch images from Jura's CDN). A transfer that aborts
part-way leaves the slot showing garbage until replaced; a leaked
keypad lock needs a power cycle. §5.14 and §5.15 of
[PROTOCOL.md](PROTOCOL.md).

The **dongle firmware OTA** is library-only by design — no CLI verb —
because a half-transferred image bricks the dongle with no remote
recovery. See [DESTRUCTIVE.md](DESTRUCTIVE.md).

## Rename the machine

The string on the touchscreen and in `discover` is the WiFi dongle's
name; it's writable via the gated `set-name` command:

```sh
$ jura-connect command --name Kaffeebert --allow-destructive-commands \
    set-name LatteBot
```

After the next reconnect, both the display and discovery report the
new name. The machine's local PIN-protected name field is not exposed
over WiFi.

## Escape hatch

`raw` echoes any wire command verbatim; the payload is still checked
against the destructive set, so the bypass cannot be used by accident:

```sh
$ jura-connect command --name Kaffeebert raw '@TG:43'
@tg:4300150001000801580E21005B
```

`--watch SECONDS` streams unsolicited `@TF:` / `@TV:` frames.
