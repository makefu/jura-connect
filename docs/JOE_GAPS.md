# `jura-connect` vs. the J.O.E. Android app — feature gap analysis

What the official J.O.E. app (`ch.toptronic.joe` 4.6.10) does over the
WiFi (TCP/51515) transport, what `jura-connect` does today, and what is
left. It doubles as the record of the places where the two once
disagreed about what a command *means* — those are resolved now, and
the reasoning is kept because it is the interesting part (§8).

Derived from the decompiled APK — the `joe_android_connector` module
survives obfuscation with readable class names, so
`CoffeeMachineAdapterWifi`, the `WifiCommand*` classes and the
`CoffeeMachineAdapterBle2` (Smart Connect 2) adapter are the reference.
The bundled machine XMLs under `jura_connect/data/xml/` are the second
source.

**Provenance warning, and it is the biggest one in this document:**
most of what was added after v0.12.0 is *APK-derived and
simulator-verified only*. See §9 for the honest enumeration — that list,
not the ❌ rows in §1, is the main risk in the library.

The 2026-08-16 hardware run against a real S8 EB moved a first batch of
those rows into evidence (§9.1) and contradicted two of them; raw frame
logs are in [`captures/`](captures/). Anything not cited to a capture is
still a reading of the APK, not a fact about a machine.

Companion document: [`PROTOCOL.md`](PROTOCOL.md) is the source of truth
for what is *implemented* and how. This file is the scoreboard.

---

## 0. Summary

| Area | J.O.E. WiFi | `jura-connect` |
| ---- | ----------- | -------------- |
| Handshake, pairing, credential store | yes | **yes** (hardware-verified) |
| Status alerts (`@TF:`) | yes, + product/process/progress context | yes; bit decode + `blocked_kinds` / `blocking_alerts` / `alert_processes` / `can_brew()` |
| Maintenance counters / percent | yes, XML-ordered | yes, XML-ordered |
| Product brew counters + overflow | yes | yes |
| Special / barista counter banks | yes (special only) | yes (both) — gated on the XML declaring them like J.O.E., plus an opt-in `--probe` / `probe=True` for the under-declaring case the S8 EB proved (§4) |
| Daily counter banks + `@TF:05` reset | no | yes — past J.O.E. |
| Machine settings read/write | yes (+ batch read declared, never sent) | yes (per-setting reads hardware-verified); batch read implemented but **the S8 EB rejects the address** — falls back per setting |
| Per-product live limits (`@TM:60`) | yes | **yes (hardware-verified 2026-08-16)** |
| PMode slot read | yes | yes |
| PMode slot/product **write** | yes | yes (APK-derived, untested) |
| Start product (`@TP:`) | yes, + preselections | yes, + preselections (blob live-verified; preselection encoding untested) |
| Product progress state machine (`@TV:`) | yes, `ProgressState` | yes — 87 states, `ProductProgress`, `iter_progress` / `follow_progress` / `brew(follow=True)`; **the coffee path is hardware-verified (2026-08-16)**, milk/steam states are not |
| Maintenance processes with user interaction | yes | yes — `ProcessRunner` over `@TG:01` / `@TG:04` / `@TG:10` |
| Coffee timer (scheduled brew) | yes | yes (APK-derived, untested) |
| Language download | yes (+ CDN fetch) | yes, minus the fetch — caller supplies the S-records; the `@TT:00`/`@TM:23` **reads** are hardware-verified, the writes are not |
| PMode bookkeeping after a language download | yes (`@TM:24/25/09/22/23`) | **no** — deliberate, see §7 |
| Firmware OTA / bootloader | yes | library-only sequencer, no CLI command, gated on `acknowledge_bricking_risk=True` |
| Milk-cooler firmware update | yes | yes (`milk-cooler-status` hardware-verified, `milk-cooler-update` untested) |
| WiFi credential provisioning (BluFi) | yes | **no** (can set SSID/pass on an already-paired dongle) |
| Session keep-alive / priority queue | yes | **no** |
| Smart Connect 2 / BLE2 transport | yes | **no** — out of scope for a WiFi library |

Roughly: the read paths, the single-shot writes, and — new since
v0.12.0 — everything stateful are covered. What remains is either a
different transport (BluFi, BLE2), app-level bookkeeping, or plumbing
(keep-alive).

---

## 1. Command coverage

Every `WifiCommand*` class in the APK, its wire form, and where we
stand. All 51 are accounted for: 39 in `connection/command/`, 10 in
`connection/command/language_download/`, and the two `UDPCommand*`
classes.

| Wire | J.O.E. class | `jura-connect` |
| ---- | ------------ | -------------- |
| `@HP:<pin>,<connid>,<hash>` | `WifiCommandConnectionSetup` | ✅ `JuraClient.connect` / `pair` |
| *(empty frame)* | `WifiCommandCloseConnection` | ✅ `JuraClient.close` |
| `@HE` → `@he:ok` | `WifiCommandOTAEnd` | ✅ `firmware.run_ota` (library-only) |
| `@HB` → `@hb:ok` | `WifiCommandBootloaderMode` | ✅ same |
| `@HD:<payload>` | `WifiCommandSendApplicationBin` | ✅ same |
| `@HO:<payload>` → `@ho:ok` | `WifiCommandSendApplicationDat` | ✅ same |
| `@HT:3` → `@ht` | `WifiCommandRestartFrog` | ✅ `restart-dongle` (gated) |
| `@HU` → `@hu:(ok\|wait\|busy\|abort\|error)` | `WifiCommandMilkCoolerUpdateStart` | ✅ `milk-cooler-update` (gated) |
| `@HU?` → `@hu:<3 hex>` | `WifiCommandMilkCoolerUpdateStatus` | ✅ `milk-cooler-status`; also the optional `read_status(nudge=True)` nudge |
| `@HW:01,<pin>` | `WifiCommandSetPinCode` | ✅ `set-pin` |
| `@HW:80,<ssid>` | `WifiCommandSetSSID` | ✅ `set-ssid` |
| `@HW:81,<pwd>` | `WifiCommandSetPassword` | ✅ `set-password` |
| `@HW:82,<name>` | `WifiCommandSetFrogName` | ✅ `set-name` |
| `@TF:02` → `@tf:02` | `WifiCommandRestartCoffeeMachine` | ✅ `restart` |
| `@TG:01` → `@tg:(01\|00)` | `WiFiCommandNextProductStep` | ✅ `process-next` / `ProcessRunner.next_step` |
| `@TG:04` / `@TG:10` | `WifiCommandProcessAccept` | ✅ `process-accept` / `ProcessRunner.accept` |
| `@TG:7E` / `@TG:7E,FF×16` → `@tg:7E` | `WifiCommandCancelQualityAssistantStep` | ✅ `skip-quality-step [one\|all]` (gated — see §8.1) |
| `@TG:FF` → `@tg:FF` | `WifiCommandCancelProductStep` | ✅ `cancel` (ungated — §8.2; **never run on hardware**) |
| `@TG:21/23/24/25/26` | `WifiCommandStartProcess` | ✅ `clean` / `descale` / … fire-and-forget, **and** `process-start` / `process-run` as a state machine |
| `@TG:43` → `@tg:43…` | `WifiCommandReadMaintenanceCounter` | ✅ `counters` |
| `@TG:C0` → `@tg:C0…` | `WifiCommandReadMaintenanceStatus` | ✅ `percent` |
| `@TM:<arg>` → `@tm:<arg>,…` | `WifiCommandReadPMode` | ✅ `read_setting` |
| `@TM:<arg>,<val><csum>` | `WifiCommandWritePMode` | ✅ `write_setting` |
| *(per-setting composite)* | `WifiCommandReadPModeComposite` | ✅ `settings` fallback path |
| `@TM:23` | `WifiCommandReadMaxLanguages` | ✅ `languages` |
| `@TM:3C,<40 hex><time><csum>` | `WifiCommandStartCoffeeTimer` | ✅ `coffee-timer` (gated) |
| `@TM:41,<code>` → `@tm:(41,.*\|C1)` | `WifiCommandPModeProductRead` | ✅ `pmode-product` |
| `@TM:41,<blob><csum>` → `@tm:41` | `WifiCommandPModeProductWrite` | ✅ `pmode-set-product` (gated) |
| `@TM:42,<slot>` → `@tm:(42,.*\|C2)` | `WifiCommandPModeSlotProductRead` | ✅ `pmode` |
| `@TM:42,<slot>,<blob>` | `WifiCommandPModeSlotProductWrite` | ✅ `pmode-set-slot` (gated) |
| `@TM:50` → `@tm:(50,.*\|D0)` | `WifiCommandPModeNumSlotsRead` | ✅ |
| `@TM:60,<…>` → `@tm:60,…` | `WifiCommandReadLimitLoad` | ✅ `limits` — **hardware-verified 2026-08-16** |
| `@TM:00,FC` (XML `<BANK Name="Setting">`) | *declared, never sent* | ✅ `settings` — **the S8 EB answers `@tm:80` (address not implemented)**; reply layout still a guess, falls back per setting |
| `@TP:<blob>` → `@tp` | `WifiCommandStartProduct` | ✅ `brew`, incl. preselections |
| `@TR:32,<page>` ×16 | `WifiCommandProductCounterStatistics` | ✅ `brews` |
| `@TR:33,<page>` ×16 | same class, 1 byte/value | ✅ (overflow fold-in) |
| `@TR:52,<page>` ×4 | `WifiCommandSpecialCounterStatistics` | ✅ `special-counters` — the S8 EB **serves** this bank without declaring it, so the profile gate suppresses the read unless `--probe` is passed (§4) |
| `@TR:53,<page>` ×4 | same class, 1 byte/value | ✅ (overflow fold-in) |
| `@TR:34/35` | *(declared in XML; no APK code path)* | ✅ `barista-counters` |
| `@TR:42..45` | *(declared in XML under `<DAILYCOUNTER>`; no APK code path)* | ✅ `daily-brews` / `daily-barista-counters` |
| `@TF:05` | *(XML `<DAILYCOUNTER Reset=…>`; no APK code path)* | ✅ `reset-daily-counters` (gated) |
| `@TS:01` / `@TS:00` | `WifiCommandLock` / `WifiCommandUnlock` | ✅ `lock` / `unlock` |
| `@TS:F1` | `WifiCommandLanguageDownloadLock` | ✅ `language-lock` (gated) |
| `@TS:00` (download release) | `WifiCommandLanguageDownloadUnlock` | ✅ same verb as `unlock` |
| `@TT:00` | `WifiCommandGetListOfLanguages` | ✅ `languages` |
| `@TT:01,<block>` | `WifiCommandSelectLanguageBlock` | ✅ `language-download` |
| `@TT:02,<addr><data>` | `WifiCommandTransferLanguageData` | ✅ same (ASCII form) |
| `@TT:08,<binary>` | `WifiCommandTransferBinaryLanguageData` | ✅ same (binary form) |
| `@TT:03` | `WifiCommandFinishLanguageDownload` | ✅ same |
| `@TV:81,<text>` / `@TV:82,<text>` | `WifiCommandLanguageDownloadLoadingMessageLine{1,2}` | ✅ `language-display` (gated) |
| `@TV:84,<time>` | `WifiSendTimeForCoffeeTimer` | ✅ `coffee-timer-time` |
| *(empty, priority 0)* | `WifiCommandNoExecution` (keep-alive) | ❌ — §7 |
| UDP `0010A5F3…` broadcast | `UDPCommandScan` | ✅ `discover` |
| UDP unicast status probe | `UDPCommandStatus` | ✅ (`probe`; TT237W ignores it) |

Count: 51 J.O.E. command classes vs. 53 named commands in
`jura_connect.commands` plus the library-only OTA sequencer. The counts
do not line up 1:1 in either direction — several app classes collapse
into one named command (`@TT:02` / `@TT:08` are both
`language-download`) and several named commands have no app class at
all (the daily banks).

---

## 2. Interactive maintenance processes — **done**

`jura_connect/process.py` implements the loop J.O.E. runs:

1. `ProcessRunner.start()` sends the XML's
   `<PROCESS ExecuteCommand="@TG:24">`; the machine answers with the
   lower-cased echo (`@tg:24`).
2. The machine then drives the client through its `<STATE>` table via
   pushed `@TV:` frames — EF1091 declares **83 states** ("Insert Tray",
   "Fill watertank", "Add powder", "Press Rinse", …), decoded through
   the profile so each step carries the machine's own label.
3. States carrying `AcceptCommand` are confirmed with `@TG:10` (78 of
   89 profiles) or `@TG:04` (10 profiles) — `ProcessRunner.accept()`,
   CLI `process-accept`. Only four states in the whole corpus ever
   carry one.
4. `@TG:01` advances (`process-next`), `@TG:FF` cancels (`cancel`).

Exposed as `processes` (catalogue, no I/O), `process-watch`
(read-only), `process-start`, `process-run` (drives it to the finish
state, auto-confirming), `process-accept`, `process-next`; from Python
as `JuraClient.process_runner` / `run_process` / `watch_process`.
`MachineProfile` parses `<PROCESS>` and `<PROGRESS_STATE_INTAKE>`.

What is still not known: the *order* the states arrive in. The XMLs
declare which states exist and which need a confirmation, never the
sequence, so `SimulatorConfig.process_sequences` is a reconstruction
(PROTOCOL.md §5.11). Nothing here has run against a real machine —
every confirmation on real hardware advances a real cycle and consumes
supplies.

---

## 3. Product progress (`@TV:`) — **done**

`jura_connect/progress.py` decodes the pushed `@TV:` frames into a
`ProductProgress` with a `ProgressType` of
`PRODUCT / PROCESS / P_MODE / AROMA_PRESELECTION / COFFEE_TIMER /
QUALITY_ASSISTANT / NONE` and one of the app's **87** `ProgressState`
values, plus the `ProductProgressState` value window (current / target /
percent). Nothing raises on an unknown state code or a truncated
payload — `state` is `None` and the raw byte survives in `state_code`.

Consumed as `JuraClient.iter_progress()` (generator),
`follow_progress()` (collect until `ENJOY`), `brew(follow=True)`, and
the read-only `progress` CLI command. `@TV:81` / `@TV:82` / `@TV:84` are
*not* progress frames and `is_progress_frame` filters them.

**Hardware-backed since 2026-08-16 for the coffee path**: a full raw
capture of a hand-started `cafe_barista` on the S8 EB decoded all 32 of
its `@TV:` frames with zero failures, pinning the value window, the
percentage slot, states `39`/`3C`/`41`/`3E`, product resolution and the
`41` bypass branch — see §9.1.1 and
[`captures/2026-08-16-kaffeebert-brew-progress.md`](captures/2026-08-16-kaffeebert-brew-progress.md).

Remaining unknowns are recorded in PROTOCOL.md §9: no milk drink
(states `31`–`37`, `42`, `43`), no `41` frame from a bypass-free recipe,
no `8F` extended-window frame, no process / timer / P-mode frame, an
unexplained bare `@TS` after the brew, and 18 of EF1091's states are
absent from the app's own enum.

---

## 4. Statistics — **done**

All ten banks are read (`JuraClient.read_counter_bank`,
`COUNTER_BANK_SPECS`), each only when the machine's profile declares
it. Page counts marked "assumed" use the product counter's 16 pages and
stop early on `@tr:00`.

> **"Only when the profile declares it" is a lower bound, not the
> truth — settled 2026-08-16.** An S8 EB (EF1091) answers
> `@TR:52,00..03` with real counter data while its XML declares only
> `@TR:32`, so `special-counters` reported "not implemented" about a
> bank the machine plainly serves. `@TR:33`, `@TR:34`, `@TR:42`,
> `@TR:44` and `@TR:53` really are absent there and answer the bare
> `@tr:00`.
>
> **Resolved as an opt-in, not a reversal.** The default still trusts
> the XML — that is what J.O.E. does and it costs no round trip — but
> `read_counter_bank(bank, probe=True)` (CLI: `--probe` on the four
> counter-bank commands) sends an undeclared bank anyway and keeps the
> data if the machine answers, along with the bank's overflow bank. A
> first-page `@tr:00` still means "not implemented". The result records
> which it was: `CounterBank.source` is `declared`, `probed` or
> `unprofiled`, and `to_dict()` carries `"probed": true/false` for the
> Home Assistant integration — a probed count is real data with no
> catalogue vouching for its slot layout, and the API says so instead
> of blurring the two. The over-declaring direction needs nothing: a
> declared bank is asked for, and `@tr:00` settles it.

| Bank | Pages | Bytes/val | Profiles declaring it | Lib |
| ---- | ----- | --------- | --------------------- | --- |
| `@TR:32` product counter | 16 | 2 | 89/89 | ✅ |
| `@TR:33` product overflow | 16 | 1 | 34 | ✅ |
| `@TR:52` special counter | 4 | 2 | 14 | ✅ |
| `@TR:53` special overflow | 4 | 1 | 4 | ✅ |
| `@TR:34` barista counter | 16 (assumed) | 2 | 4 | ✅ |
| `@TR:35` barista overflow | 16 (assumed) | 1 | 3 | ✅ |
| `@TR:42` daily product counter | 16 (assumed) | 2 | 37 | ✅ |
| `@TR:43` daily product overflow | 16 (assumed) | 1 | 4 | ✅ |
| `@TR:44` daily barista counter | 16 (assumed) | 2 | 4 | ✅ |
| `@TR:45` daily barista overflow | 16 (assumed) | 1 | 4 | ✅ |

J.O.E. merges the banks it reads into one `StatisticsCollection`
alongside the maintenance banks; the overflow fold
(`count = value + (overflow << 16)`) is identical for every pair.

**Where we go past J.O.E.:** the `<DAILYCOUNTER Reset="@TF:05">` banks
(`@TR:42`..`@TR:45`) appear in no APK code path — the XML's own
`<!-- Not available in JOE -->` comment is accurate, and grepping the
decompiled app for `@TR:4[2-5]` or `@TF:05` returns nothing. They are a
real machine capability the app ignores, and they are what a "brews
today" sensor wants, so the library reads them (`daily-brews`,
`daily-barista-counters`) and exposes the reset verb as the gated
`reset-daily-counters`. Untested against hardware — and the one
machine available answers `@tr:00` to `@TR:42` and `@TR:44`, so it
cannot settle them either.

Also unlike J.O.E.: the special bank's named slots
(`SPECIAL_COUNTER_SLOTS`) drop the app's `hotBrew`, which reads slot 0 —
the same slot as the total — and looks like a copy/paste bug in
`SpecialCounterStatisticsParser`.

The XML also declares `<TOTALCOUNTER Code="00" Name="Total Products">`
and a `<LIFETIME>` block that we still ignore.

---

## 5. Machine settings — **done**

Single-setting read (`@TM:<arg>`), the checksummed `@TS:01`/`@TS:00`-
wrapped write, the batch read and the limit load are all implemented.

* **Batch read.** Each XML declares
  `<BANK Name="Setting" Command="@TM:00,FC" CommandArgument="02080913"/>`
  — one round trip for the four settings `02` (hardness), `08`
  (units), `09` (language), `13` (auto-off).
  `MachineProfile.settings_bank` parses the declaration and
  `JuraClient.read_settings_bank()` issues it (CLI: `settings`).
  **The reply layout is a guess, not APK-derived**: J.O.E. 4.6.10
  parses `CommandArgument` and then *discards* it in `Bank`'s
  constructor, and its WiFi settings path is
  `WifiCommandReadPModeComposite` = one `@TM:<arg>` per setting, so the
  app never issues this command at all. `read_all_settings()`
  therefore falls back to per-setting reads on any rejection, checksum
  failure or value-count mismatch.
  **Asked on hardware 2026-08-16 (S8 EB / EF1091): the machine answers
  `@tm:80`** — and answers the bare `@TM:00` identically, so address
  `00` is not implemented at all and the `,FC` argument is irrelevant.
  The fallback carried the read (all seven settings correct,
  `batch_error` recorded), which is the design working; the reply
  layout itself remains unverified and needs one of the other 56
  declaring profiles to settle.
  Survey result: 57 of 89 profiles declare the bank, always with
  the identical command and argument list; the remaining 32 have no
  `<MACHINESETTINGS>` block at all; and 16 of the 57 list arguments
  their own catalogue never declares, so the list is boilerplate —
  never hard-code it.
* **`@TM:60,…` limit load** (`WifiCommandReadLimitLoad`). Payload
  decoded from `LimitLoadParser`: `@tm:60,<code><5 min/max byte
  pairs><csum>` for F4, F5, F6, F10, F11 in that fixed order, `FF`
  meaning "not applicable", each pair scaled by the argument's XML
  `Step`. `JuraClient.read_limit_load()` returns a `ProductLimits`
  (CLI: `limits <product>`) whose `allows(kind, value)` bounds a brew
  by what the machine permits *now* rather than by the static XML
  range. **Verified on hardware 2026-08-16** across seven products on
  an S8 EB — request form, request checksum, the five positional pairs,
  the F-argument mapping and the scaling all hold; see
  [`captures/2026-08-16-kaffeebert-s8eb.md`](captures/2026-08-16-kaffeebert-s8eb.md)
  §3. Two things the wire added: a trailing `00` byte between the fifth
  pair and the checksum, and `FFFF` for coffee strength and temperature
  — `@TM:60` reports the continuous sliders only.
* Settings arguments once thought missing (`@TM:1F` TimeFormat,
  `@TM:0A` brightness) are ordinary `<SWITCH>` / `<COMBOBOX>` elements
  on the profiles that have them; EF1091 simply has no TimeFormat. A
  survey of all 89 `<MACHINESETTINGS>` blocks found only four element
  kinds (`SWITCH`, `COMBOBOX`, `SLIDER`×2 flavours, plus `BANK`), all
  parsed.

Writes remain single-setting — the batch command is read-only in every
XML that declares it.

---

## 6. Product start — preselections and timers — **done**

`brew` builds the `@TP:` blob from the XML's `Argument="F<n>"`
parameters. Complete list across all 89 profiles:

| Arg | Tag | Lib |
| --- | --- | --- |
| `F2` | `GRINDER_RATIO` | encoded, **untested** |
| `F3` | `COFFEE_STRENGTH` | ✅ live-verified |
| `F4` | `WATER_AMOUNT` | ✅ live-verified |
| `F5` | `MILK_AMOUNT` | ✅ live-verified on a Z10 (EA) / EF545 |
| `F6` | `MILK_FOAM_AMOUNT` | ✅ live-verified on a Z10 (EA) / EF545 |
| `F7` | `TEMPERATURE` | ✅ live-verified |
| `F8` | `STROKE` | encoded, untested |
| `F10` | `BYPASS` | ✅ live-verified |
| `F11` | `MILK_BREAK` | encoded, untested |
| `F17` | `GRINDER_FREENESS` | encoded, untested (grows the blob to 17 bytes) |

* **Preselections** are implemented (PROTOCOL.md §5.13). Each
  `<PRODUCT>` carries `<PRESELECTION>` elements with `xtrashot`,
  `double="<product code>"`, `powder`, `coldbrew`, `sweetfoam` flags,
  and `<MULTIPLE_PRESELECTS><COMBINATION>` rows say which may be
  combined; both are parsed. Old-T-protocol machines get the double
  product's code swapped into blob byte 0 plus the app's byte
  overwrites; `IntakeF18` machines get a 20-byte blob with a mask byte
  instead. CLI: bare words after the product (`brew espresso double`).
  **Never seen on a wire** — a wrong byte misbrews.
  Note `double="31"` is the same code the Z10 counter-slot quirk is
  about: the "2 Espressi" product *is* a preselection of the single,
  not a separate menu entry.
* **Coffee timer** is implemented: `@TM:3C,<blob padded to 20 bytes>
  <delay><csum>` schedules a brew and `@TV:84,<time>` follows it (not
  precedes it — the app's order). `<PRODUCT Coffeetimer="false">` marks
  a product ineligible; only 5 of 89 profiles carry the attribute at
  all and a missing one defaults to eligible, matching the app's
  nullable Boolean. There is no cancel verb beyond `@TG:FF`.

---

## 7. What `jura-connect` still has no story for

* **BluFi onboarding.** The app provisions a factory-fresh dongle's
  WiFi over BLE (ESP32 BluFi) before it ever reaches TCP. Our
  `set-ssid` / `set-password` only work on an *already paired* dongle,
  i.e. they can move a machine between networks but cannot bootstrap
  one. Out of scope for a WiFi library — it is a different radio.
* **Smart Connect 2 / BLE2.** `CoffeeMachineAdapterBle2` speaks the
  same `@` language over BLE with its own crypto (`Ble2CryptoUtil`) and
  its own handshake, plus `@HA:02` and `@HR:81` (read dongle name /
  hand over WiFi credentials). Out of scope, but it remains the most
  readable reference for the full command set — its method names
  survived obfuscation.
* **The PMode bookkeeping after a successful language download.**
  J.O.E. additionally writes `@TM:24` (a packed download date plus the
  language code taken from the file name), `@TM:25,01`, `@TM:09,FF`
  (language setting = "the downloaded one"), `@TM:22` and `@TM:23,0C`.
  `jura_connect` writes none of them: they are app-level bookkeeping we
  cannot verify, and `@TM:09` is already reachable through the ordinary
  settings API. Consequence: a machine may hold a freshly downloaded
  image without switching to it. See PROTOCOL.md §5.14.
* **Session keep-alive / priority queue.** `WifiCommandNoExecution` is
  an empty, priority-0 frame the app queues to keep its channel warm;
  J.O.E. also dispatches commands through a `PriorityChannel`.
  `jura-connect` sends one command at a time on a synchronous socket
  and has no keep-alive, which is fine for short CLI sessions and is
  the likeliest suspect if a long-lived integration ever sees the
  dongle drop it.
* **Fetching the payloads.** Language images and firmware blobs come
  from Jura's CDN over HTTPS in the app. This library has no network
  dependency: the caller supplies the bytes.
* **App-level things with no protocol component:** shop, recipes, QR
  onboarding, statistics charts, RealWear/AR support.

---

## 8. Where we and J.O.E. once disagreed about a command's meaning

**All five items are resolved.** They stay here with their resolutions
because the reasoning — not the fix — is what is worth keeping, and
because two of them must never be re-probed on hardware.

1. **`@TG:7E` is `WifiCommandCancelQualityAssistantStep`**, not
   "reset maintenance counters". The class sends bare `@TG:7E` to skip
   one quality-assistant step and `@TG:7E,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`
   to skip all. `AGENTS.md` records that an accidental `@TG:7E` *did*
   reset counters on a real TT237W, so both behaviours may exist across
   firmware. **Do not re-probe this on hardware to find out.**
   *Resolved:* renamed `reset-counters` → `skip-quality-step [one|all]`,
   the skip-all argument is implemented, `@TG:7E` **stays** in
   `DESTRUCTIVE_PREFIXES` and stays gated, and the danger string states
   both readings and that neither is reversible. The underlying
   question — firmware difference or side effect — is still open and
   is recorded in PROTOCOL.md §9 as unresolvable by experiment.
2. **`@TG:FF` is `WifiCommandCancelProductStep`** — cancel the running
   product step, i.e. the natural "abort this brew".
   *Resolved:* removed from `DESTRUCTIVE_PREFIXES` (so the `raw` escape
   hatch stops gating it too) and exposed as the ungated `cancel`
   command with a tolerant `(?i)^@tg` reply matcher; the simulator
   answers `@tg:FF`. It is also the app's coffee-timer cancel, though
   whether it clears a *pending* timer is untested.
   The policy contradiction that used to sit here — `AGENTS.md` §2
   still listing `@TG:FF` among the destructive prefixes — has since
   been fixed on the document side, so code and doc now agree. The
   2026-08-16 run skipped `cancel` because of it, and nobody has run
   it since: **the command has still never been sent to a machine.**
3. **`@HE` is `WifiCommandOTAEnd`** (expects `@he:ok`), while J.O.E.'s
   `WifiCommandCloseConnection` sends an *empty* frame. It is an OTA
   verb, and sending it outside an OTA session is not obviously a no-op
   on every firmware.
   *Resolved:* `JuraClient.close()` sends the empty frame (still
   best-effort / exception-safe); the simulator accepts both the empty
   frame and `@HE` as session teardown. `@HE` is now a gated prefix
   belonging to the OTA sequencer (PROTOCOL.md §5.15) — which is only
   safe *because* `close()` stopped sending it.
4. **`@HU?` is `WifiCommandMilkCoolerUpdateStatus`**, matching
   `@hu:[0-9a-fA-F]{3}`. This explained the old "`@HU?` returned
   `@hu:800` in some probes but `@TF:` in others": the `@hu:800` *is*
   the correct answer to `@HU?` — state nibble `8` = "no milk cooler
   connected" — and the `@TF:` was just the next unsolicited status
   frame arriving. J.O.E. never polls for status;
   `TCPReceiveHandler` routes pushed `@TF:` frames.
   *Resolved:* `read_status()` sends nothing and returns the next
   pushed `@TF:` frame; `read_status(nudge=True)` still emits `@HU?`
   for firmwares that want traffic on the socket, documented as a nudge
   rather than a query. `@HU?` is now also a first-class read-only
   command (`milk-cooler-status`) that decodes the three hex digits.
5. **`@TG:43` field order is per-machine.** Both banks decode against
   the XML's `<BANK Command="@TG:43">` / `<BANK Command="@TG:C0">`
   `<TEXTITEM Type=…>` children via
   `MachineProfile.maintenance_counter_fields` /
   `.maintenance_percent_fields`, exactly as J.O.E. does; the old
   hard-coded order survives only as the no-profile fallback
   (PROTOCOL.md §5.3). Kept here for the record — **21 of 89 profiles
   differ** from that fallback, so those machines still need
   `--machine-type` to be labelled correctly:
   * 13 profiles have only 4 fields (`Cleaning, FilterChange, Decalc,
     CoffeeRinse`) — EF1013, EF1031, EF1089, EF1105(V2), EF1115(V2),
     EF1124, EF1125, EF1128, EF529, EF532COFFEEONLY, EF534;
   * 7 swap the last three to `CoffeeRinse, CappuRinse, CappuClean` —
     EF0000, EF1090, EF1123, EF1143, EF1148, EF1171, EF_MASTER;
   * EF567_C has no `FilterChange` at all.
   EF1091/EF536 match the fallback order, which is why the bug went
   unnoticed for so long. `@TG:C0` is uniform
   (`Cleaning, FilterChange, Decalc`) except EF567_C.

---

## 9. Implemented but hardware-unverified — the current top risk

Everything **still listed in §9.2** is **APK-derived and verified only
against `jura_connect/simulator.py`**. The simulator imports the same
`crypto` and `protocol` modules the client does, so it proves the
*framing* and the *sequencing* are self-consistent — it proves nothing
about what a real machine accepts, because its replies were written
from the same APK reading as the client's expectations. A shared
misreading passes both halves of the test-suite.

§9.1 and §9.1.1 record what the 2026-08-16 hardware sessions took *off*
that list. Note the scope of everything they settled: **one machine,
one firmware family** — a JURA S8 EB (EF1091) on TT237W. None of the
other 88 bundled profiles has been touched by hardware, so "confirmed"
below always means "confirmed on that machine".

### 9.1 Closed by the 2026-08-16 hardware run

The whole non-destructive half of the command registry was exercised
against a real S8 EB (EF1091, TT237W). Raw frame log:
[`captures/2026-08-16-kaffeebert-s8eb.md`](captures/2026-08-16-kaffeebert-s8eb.md).
These rows have left the risk table:

| Area | Outcome | Where |
| ---- | ------- | ----- |
| **Limit load (`@TM:60`)** | **confirmed.** Seven products read. Request form, request checksum, the five positional min/max pairs, the slot→`F<n>` mapping and the per-parameter scaling all hold. Two additions: an undocumented trailing `00` byte before the checksum, and `FFFF` for strength/temperature — `@TM:60` covers continuous sliders only. | capture §3, PROTOCOL.md §5.7 |
| **Batch settings read (`@TM:00,FC`)** | **contradicted.** The machine answers `@tm:80` — and answers the *bare* `@TM:00` the same way, so address `00` simply is not implemented and no checksum variant can help. The guessed reply layout was never reached and stays unverified. The per-setting fallback did its job: all seven settings read correctly with `batch_error` recorded. | capture §1, PROTOCOL.md §5.7 |
| **Milk-cooler status (`@HU?`)** | **confirmed**, `@hu:800` = no cooler, exactly as predicted. Also confirms the `DESTRUCTIVE_EXACT` carve-out that keeps `@HU?` ungated while `@HU` is gated. | capture §5, PROTOCOL.md §5.15 |
| **PMode reads (`@TM:41` / `@TM:42` / `@TM:50`)** | **confirmed.** `@tm:50,04040404047A` (5 × 4 = 20 slots, and the trailing byte is the ordinary `ByteOperations.d` checksum, not an opaque one), every `@TM:42,<slot>` → `@tm:C2`, `@TM:41,<code>` → `@tm:C1`. Writes remain untested and cannot be tested on this machine. | capture §7, PROTOCOL.md §5.6.5 |
| **Language inventory (`@TT:00` + `@TM:23`)** | **contradicted.** A machine without the language verbs does not reject `@TT:00` — it stays completely silent. `@TM:23` answers `@tm:A3`. This was a bug: `read_inventory` let the `TimeoutError` escape. Fixed; the download *writes* remain untested. | capture §4, PROTOCOL.md §5.14 |
| **Display lock (`@TS:01`/`@TS:00`)** | **confirmed**, and the lock is now externally observable: it sets status bit 39 (`LockedKeys`), so a leaked lock can be detected from a pushed `@TF:` frame. | capture §9, PROTOCOL.md §5.4 |
| **`@TG:43` / `@TG:C0` after the XML-order rewrite** | **confirmed, no regression.** All six counters moved monotonically up from the §5.3 baseline capture on the same machine. | capture §10 |
| **`@TR:32`, `@TF:` bits, `@HP:`, per-setting `@TM:` reads** | **confirmed, no regression.** | capture §11, §13 |

New, unprompted finding: **`@tm:<addr | 0x80>` is the generic `@TM:`
rejection token.** `@tm:80`, `@tm:A3`, `@tm:C1`, `@tm:C2` and the
APK's `@tm:D0` are all just `request_address | 0x80`. Four constants
the codebase carried as unrelated magic numbers are one rule.

### 9.1.1 Closed by the 2026-08-16 brew capture — `@TV:` progress

The one gap the command run could not close (nobody brewed during it)
was closed the same day by a second, read-only capture of a
hand-started `cafe_barista`:
[`captures/2026-08-16-kaffeebert-brew-progress.md`](captures/2026-08-16-kaffeebert-brew-progress.md).
All 32 `@TV:` frames decoded, zero failures.

**Hardware-backed for the coffee path:** the 16-byte frame length; the
value window starting at payload byte 2; the percentage at window slot
12 (the second-to-last byte) and its being a *whole-product* figure
rather than per-phase; states `39` (strength 7/7 while grinding), `3C`
(water ticks 0→9 = 45 ml), `41` and `3E`; the `41` →
`BYPASS_WATER_VOLUME` branch, which was the shakiest rule in
`progress.py`; `FF` as the "product does not use this slot" sentinel;
product resolution of byte 1 against the machine profile; `ProgressType`
rule 3 (`PRODUCT`); `@TB` as the brew-start marker.

**Corrected by it:** §5.10 used to claim the *other* `41` branch
(`HOTWATER_VOLUME`, slot 6 = `0xFF`) was the live-verified one. It is
not, and it remains unobserved.

**Learned, not previously suspected:** the `@TF:` broadcast stops for
the whole brew (51.6 s of silence), and `ENJOY` is level-triggered —
the machine repeated `@TV:3E28` five times, so a consumer that counts
brews on `is_complete` must edge-trigger.

Regression tests replay the real frames verbatim
(`tests/test_progress_capture.py`), and the frame list is tracked as
`simulator.CAPTURED_S8EB_CAFE_BARISTA_BREW` so the simulator can push
the observed sequence instead of its model.

### 9.2 Still unverified

| Area | Risk if wrong | PROTOCOL.md |
| ---- | ------------- | ----------- |
| `@TV:` progress — the **milk/steam states** (`31`–`37`, `42`, `43`), the `41` → `HOTWATER_VOLUME` branch, the `8F` extended window, and the process / coffee-timer / P-mode / quality-assistant frame types | wrong readings in a UI for anything but a plain coffee. The coffee path itself is now hardware-backed (§9.1.1) | §5.10 |
| Maintenance processes (`@TG:01` / `@TG:04` / `@TG:10`, state ordering) | a confirmation sent at the wrong moment advances a physical cycle and consumes supplies; a wrong finish state hangs the run | §5.11 |
| Coffee timer (`@TM:3C` + `@TV:84`) | the machine pours later, unattended, possibly the wrong product | §5.12 |
| Preselections in `@TP:` (byte overwrites, `IntakeF18` mask) | misbrew — a wrong byte overwrites a recipe parameter | §5.13 |
| Language download **writes** (`@TS:F1` / `@TT:01/02/03/08`) | a half-written slot shows garbage until a full re-download; a lost session leaves the keypad locked until power-cycle | §5.14 |
| Firmware OTA (`@HB` / `@HO:` / `@HD:` / `@HE`) | **bricks the dongle**, no remote recovery — which is why it has no CLI command and is gated on `acknowledge_bricking_risk=True` | §5.15 |
| Milk-cooler update (`@HU`) | an interrupted update can leave the cooler needing service | §5.15 |
| PMode **writes** (`@TM:41` / `@TM:42`) | overwrites a user's stored recipe or slot assignment | §5.6.3–4 |
| Batch settings read **reply layout** (`@TM:00,FC`) | still a pure guess — the one machine we can ask rejects the address. Mitigated: falls back to per-setting reads on any mismatch | §5.7 |
| `@TR:52` **decode** (slot→function map) | the S8 EB *serves* this bank and `--probe` now reads it live, but its pages have still never been checked against what the machine actually counted; a wrong map mislabels real counts. Note slot 0 (the bank total) reads `0xFFFF` there | §5.5 |
| Counter banks `@TR:34/35/42..45` and the `@TF:05` reset | wrong slot mapping, or an irreversible zeroing of counters nobody meant to clear. The S8 EB rejects all of these with `@tr:00`, so they need a different machine | §5.5 |
| `@TP:` recipe parameters F2, F5, F6, F8, F11, F17 | misbrew | §5.9 |
| `cancel` (`@TG:FF`) | **not exercised** — skipped on 2026-08-16 over a policy contradiction that has since been fixed, and not sent since. Its behaviour on an idle machine is unknown | §5.8 |

### 9.3 New open questions the run created

* **XML declaration ≠ firmware support, in the under-declaring
  direction — answered.** The S8 EB implements `@TR:52` and holds live
  values in it (slots 2, 3 and 8 = 1, 14 and 2661) while its XML
  declares only `@TR:32`. Raw probes settle which banks are real:
  `@TR:52` → data, `@TR:33`/`@TR:34`/`@TR:42`/`@TR:44`/`@TR:53` →
  `@tr:00`.

  **Decision taken:** the default keeps trusting the XML (what J.O.E.
  does, no extra round trip), and `probe=True` / `--probe` is the
  explicit opt-in that sends an undeclared bank anyway — read-only, one
  extra round trip per undeclared bank, and the result is tagged
  `source="probed"` so a consumer can tell it from a declared read. See
  §4 and PROTOCOL.md §5.5. Nobody has checked whether an
  *over*-declaring XML exists, but that direction never needed probing:
  a declared bank is sent and `@tr:00` answers it.

* **`cancel` (`@TG:FF`) has still never been sent to a machine.**
  It was skipped during the run because `AGENTS.md` §2 then listed
  `@TG:FF` among the prefixes that change machine state while the code
  did not gate it and `tests/test_commands.py::_UNGATED_READS` carried
  it as "reclassified, not a reset". The document has since been fixed
  and the two now agree — but the command itself remains unexercised.

* **`register-read <bank>` cannot succeed on TT237W.** A bare
  `@TR:<bank>` with no page argument draws no reply at all (verified
  for `32` and `52`); the command blocks for its full timeout and then
  raises. Either give it a page argument or drop it for
  `raw '@TR:<bank>,<page>'`.

* **`MaintenancePercent` passes `0xFF` through as `255`.** The S8 EB
  reports `filter=255` because no water filter is fitted. That is the
  not-applicable sentinel, not a percentage; the behaviour is
  deliberate and pinned by
  `test_percent_parse_without_profile_is_unchanged`, but any consumer
  rendering a gauge needs to know.

What **is** hardware-verified, on a JURA S8 EB (EF1091, TT237W V06.11)
and in two cases an E6 / E8 (EB): the cipher and framing, TCP
discovery, the `@HP:` handshake and pairing, `@TG:43` / `@TG:C0`,
`@TF:` status bits (including bit 39 = `LockedKeys`), `@TR:32`,
`@TS:01` / `@TS:00`, single-setting `@TM:` reads and writes,
`@TM:50` / `@TM:41` / `@TM:42` reads, **`@TM:60` limit load**,
**`@TT:00`'s silence and `@TM:23` → `@tm:A3`**, **`@TR:52`'s existence
on an undeclaring machine**, `@HU?` → `@hu:800`, the 16-byte
`@TP:` blob for water / strength / temperature / bypass, and — since
the brew capture — **the `@TV:` progress decode for the coffee path**
(§9.1.1).

Cheapest things a machine owner could confirm next, in order of
value-per-risk — the first two are **read-only**:

1. A raw capture of a **milk** drink and of a **cleaning cycle**
   (settles the rest of §3 and the state ordering in §2) — `progress`
   and `process-watch` both send nothing, so a milk drink costs only
   patience and one cappuccino. The coffee half of §3 was settled this
   way on 2026-08-16; nothing else in the risk table is this cheap.
2. `@TM:41` / `@TM:42` **reads** on a machine whose XML says
   `Productprogramming="true"` (20 of 89 profiles, e.g. EF1143 /
   EF529). EF1091 answers `@tm:C1` / `@tm:C2` to everything, so the
   configured-slot decode path has never run against real data.
3. `@TM:00,FC` on any of the other 56 declaring profiles — the S8 EB
   rejects the address outright, so the reply layout needs a different
   machine or it stays a guess forever.
4. `@TR:52` on a machine that *declares* it (14 of 89 profiles), to
   check the slot→function map against a machine whose XML agrees with
   its firmware. Cheaper first step on the S8 EB itself:
   `special-counters --probe` and compare the named slots against what
   the machine has really poured — it is read-only and needs no other
   machine.

---

## 10. What is left

1. **Confirm the read paths above.** Read-only, costs a session,
   settles four table rows.
2. **Session keep-alive** (`WifiCommandNoExecution`) if a long-lived
   integration ever sees the dongle drop the connection.
3. **The post-download PMode bookkeeping** (§7) — only worth doing
   alongside a real language download.
4. BluFi and BLE2 remain deliberately out of scope: different radios,
   different crypto, and neither is reachable from a WiFi library.
