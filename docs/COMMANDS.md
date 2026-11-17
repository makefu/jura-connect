# Named-command catalogue

The complete CLI catalogue as of this release — 27 read-only and 26
destructive commands, generated from `jura_connect.commands`, so the
CLI and `jura_connect.list_commands()` can never drift apart. Query it
live with `jura-connect command --list` / `--help`.

Read-only commands run against any paired machine. Destructive ones
require `--allow-destructive-commands` (CLI) or `allow_destructive=True`
(library); see [DESTRUCTIVE.md](DESTRUCTIVE.md) for the gate and the
risk notes.

## Read-only

```
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
```

## Destructive (require `--allow-destructive-commands`)

```
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

## Deep dives

Feature-level protocol detail for each area — brew recipe blobs,
preselections, progress decoding, maintenance processes, counter
banks, PMode, coffee timer, language download, milk cooler / dongle:

- recipe blob format (§5.9), preselections (§5.13), progress states
  (§5.10), processes (§5.11), coffee timer (§5.12), language download
  (§5.14), OTA (§5.15), settings & counter banks (§5.5–§5.7):
  [PROTOCOL.md](PROTOCOL.md)
- what J.O.E. does that we don't, and what breaks if an APK-derived
  area is wrong: [JOE_GAPS.md](JOE_GAPS.md)
- raw wire captures from a real S8 EB: [`captures/`](captures/)
- GIGA 6 twin-grinder evidence: [EF566_GRINDER_RATIO.md](EF566_GRINDER_RATIO.md)
