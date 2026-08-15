# `jura-connect` vs. the J.O.E. Android app — feature gap analysis

What the official J.O.E. app (`ch.toptronic.joe` 4.6.10) does over the
WiFi (TCP/51515) transport that `jura-connect` 0.12.0 does not, plus the
places where the two disagree about what a command *means*.

Derived from the decompiled APK — the `joe_android_connector` module
survives obfuscation with readable class names, so
`CoffeeMachineAdapterWifi`, the `WifiCommand*` classes and the
`CoffeeMachineAdapterBle2` (Smart Connect 2) adapter are the reference.
The bundled machine XMLs under `jura_connect/data/xml/` are the second
source. **Nothing below was probed on hardware** unless it says so;
treat the wire formats as APK-derived until verified.

Companion document: [`PROTOCOL.md`](PROTOCOL.md) is the source of truth
for what is *implemented*. This file is the to-do list.

---

## 0. Summary

| Area | J.O.E. WiFi | `jura-connect` |
| ---- | ----------- | -------------- |
| Handshake, pairing, credential store | yes | **yes** |
| Status alerts (`@TF:`) | yes, + product/process/progress context | bit decode only |
| Maintenance counters / percent | yes, XML-ordered | yes, XML-ordered |
| Product brew counters + overflow | yes | yes |
| Special / barista counter banks | yes (special only) | yes |
| Daily counter banks + `@TF:05` reset | no | yes |
| Machine settings read/write | yes (+ batch read) | yes; batch read implemented (guessed reply, falls back) |
| Per-product live limits (`@TM:60`) | yes | yes (APK-derived, untested) |
| PMode slot read | yes | yes |
| PMode slot/product **write** | yes | yes (APK-derived, hardware-untested) |
| Start product (`@TP:`) | yes, + preselections | yes, no preselections |
| Product progress state machine (`@TV:`) | yes, ~50 states | no |
| Maintenance processes with user interaction | yes | fire-and-forget only |
| Coffee timer (scheduled brew) | yes | no |
| Language download | yes | no |
| Firmware OTA / bootloader | yes | no |
| Milk-cooler firmware update | yes | no |
| WiFi credential provisioning (BluFi) | yes | no (can set SSID/pass on a paired dongle) |
| Session keep-alive / priority queue | yes | no |

Roughly: `jura-connect` covers the read paths and single-shot writes.
Everything stateful — anything where the machine talks back mid-operation
— is missing.

---

## 1. Command coverage

Every `WifiCommand*` class in the APK, its wire form, and where we stand.
`⚠` marks a command we send with a *different meaning attached* (see §8).

| Wire | J.O.E. class | `jura-connect` |
| ---- | ------------ | -------------- |
| `@HP:<pin>,<connid>,<hash>` | `WifiCommandConnectionSetup` | ✅ `JuraClient.connect` / `pair` |
| *(empty frame)* | `WifiCommandCloseConnection` | ✅ `JuraClient.close` |
| `@HE` → `@he:ok` | `WifiCommandOTAEnd` | ❌ (no longer sent; simulator still accepts it) |
| `@HB` → `@hb:ok` | `WifiCommandBootloaderMode` | ❌ |
| `@HD:<payload>` | `WifiCommandSendApplicationBin` | ❌ |
| `@HO:<payload>` → `@ho:ok` | `WifiCommandSendApplicationDat` | ❌ |
| `@HT:3` → `@ht` | `WifiCommandRestartFrog` | ❌ (we restart the *machine*, not the dongle) |
| `@HU` → `@hu:(ok\|wait\|busy\|abort\|error)` | `WifiCommandMilkCoolerUpdateStart` | ❌ |
| `@HU?` → `@hu:<3 hex>` | `WifiCommandMilkCoolerUpdateStatus` | ❌ as such; sent only by `read_status(nudge=True)` |
| `@HW:01,<pin>` | `WifiCommandSetPinCode` | ✅ `set-pin` |
| `@HW:80,<ssid>` | `WifiCommandSetSSID` | ✅ `set-ssid` |
| `@HW:81,<pwd>` | `WifiCommandSetPassword` | ✅ `set-password` |
| `@HW:82,<name>` | `WifiCommandSetFrogName` | ✅ `set-name` |
| `@TF:02` → `@tf:02` | `WifiCommandRestartCoffeeMachine` | ✅ `restart` |
| `@TG:01` → `@tg:(01\|00)` | `WiFiCommandNextProductStep` | ❌ |
| `@TG:04` / `@TG:10` | `WifiCommandProcessAccept` | ❌ |
| `@TG:7E` / `@TG:7E,FF×16` → `@tg:7E` | `WifiCommandCancelQualityAssistantStep` | ✅ `skip-quality-step [one\|all]` (gated — see §8.1) |
| `@TG:FF` → `@tg:FF` | `WifiCommandCancelProductStep` | ✅ `cancel` (not gated) |
| `@TG:21/23/24/25/26` | `WifiCommandStartProcess` | ✅ fire-and-forget (`clean`, `descale`, …) |
| `@TG:43` → `@tg:43…` | `WifiCommandReadMaintenanceCounter` | ✅ `counters` |
| `@TG:C0` → `@tg:C0…` | `WifiCommandReadMaintenanceStatus` | ✅ `percent` |
| `@TM:<arg>` → `@tm:<arg>,…` | `WifiCommandReadPMode` | ✅ `read_setting` |
| `@TM:<arg>,<val><csum>` | `WifiCommandWritePMode` | ✅ `write_setting` |
| `@TM:23` | `WifiCommandReadMaxLanguages` | ❌ |
| `@TM:3C,<40 hex><time><csum>` | `WifiCommandStartCoffeeTimer` | ❌ |
| `@TM:41,<code>` → `@tm:(41,.*\|C1)` | `WifiCommandPModeProductRead` | ✅ `pmode-product` (untested) |
| `@TM:41,<blob><csum>` → `@tm:41` | `WifiCommandPModeProductWrite` | ✅ `pmode-set-product` (untested) |
| `@TM:42,<slot>` → `@tm:(42,.*\|C2)` | `WifiCommandPModeSlotProductRead` | ✅ `pmode` |
| `@TM:42,<slot>,<blob>` | `WifiCommandPModeSlotProductWrite` | ✅ `pmode-set-slot` (untested) |
| `@TM:50` → `@tm:(50,.*\|D0)` | `WifiCommandPModeNumSlotsRead` | ✅ |
| `@TM:60,<…>` → `@tm:60,…` | `WifiCommandReadLimitLoad` | ✅ `limits` (untested on hardware) |
| `@TM:00,FC` (XML `<BANK Name="Setting">`) | *declared, never sent* | ✅ `settings` (guessed reply, falls back) |
| `@TP:<blob>` → `@tp` | `WifiCommandStartProduct` | ✅ `brew` |
| `@TR:32,<page>` ×16 | `WifiCommandProductCounterStatistics` | ✅ `brews` |
| `@TR:33,<page>` ×16 | same class, 1 byte/value | ✅ (overflow fold-in) |
| `@TR:52,<page>` ×4 | `WifiCommandSpecialCounterStatistics` | ✅ `special-counters` |
| `@TR:53,<page>` ×4 | same class, 1 byte/value | ✅ (overflow fold-in) |
| `@TR:34/35` | *(declared in XML; no APK code path — BLE2 reads only 32/33/52/53)* | ✅ `barista-counters` |
| `@TR:42..45` | *(declared in XML under `<DAILYCOUNTER>`; no APK code path)* | ✅ `daily-brews` / `daily-barista-counters` |
| `@TF:05` | *(XML `<DAILYCOUNTER Reset=…>`; no APK code path)* | ✅ `reset-daily-counters` (gated) |
| `@TS:01` / `@TS:00` | `WifiCommandLock` / `WifiCommandUnlock` | ✅ `lock` / `unlock` |
| `@TS:F1` | `WifiCommandLanguageDownloadLock` | ❌ |
| `@TT:00/01,<n>/02,<data>/03/08,<data>` | language download suite | ❌ |
| `@TV:81,<text>` / `@TV:82,<text>` | display line 1 / line 2 during download | ❌ |
| `@TV:84,<time>` | `WifiSendTimeForCoffeeTimer` | ❌ |
| *(empty, priority 0)* | `WifiCommandNoExecution` (keep-alive) | ❌ |
| UDP `0010A5F3…` broadcast | `UDPCommandScan` | ✅ `discover` |
| UDP unicast status probe | `UDPCommandStatus` | ✅ (`probe`; TT237W ignores it) |

Count: 51 J.O.E. WiFi command classes vs. 38 named commands in
`jura_connect.commands`.

---

## 2. Interactive maintenance processes

Today `jura-connect clean` sends `@TG:24` and returns. J.O.E. runs a
loop:

1. `WifiCommandStartProcess` sends the XML's
   `<PROCESS ExecuteCommand="@TG:24">`; the reply is the lower-cased
   echo (`@tg:24`).
2. The machine then drives the phone through its `<STATE>` table via
   `@TF:` frames — EF1091 declares **83 states** ("Insert Tray",
   "Fill watertank", "Add powder", "Press Rinse", …).
3. States carrying `AcceptCommand` need an explicit confirmation:
   `@TG:10` (78 of 89 profiles) or `@TG:04` (10 profiles) —
   `WifiCommandProcessAccept`.
4. `@TG:01` advances to the next step (`WiFiCommandNextProductStep`),
   `@TG:FF` cancels the current step.

Consequences of not implementing this: a cleaning cycle started from
`jura-connect` stalls at the first state that wants a confirmation, and
the caller has no way to see *which* state it is stuck in beyond raw
`@TF:` bits. `MachineProfile` does not parse `<PROCESS>` or `<STATE>` at
all today.

---

## 3. Product progress (`@TV:`)

`jura-connect` treats `@TV:` frames as noise to be skipped
(`client.py:328`, `client.py:370`). J.O.E. decodes them into a
`Progress` object with a mode of
`PRODUCT / PROCESS / P_MODE / AROMA_PRESELECTION / COFFEE_TIMER /
QUALITY_ASSISTANT / NONE` and one of ~50 `ProgressState` values, e.g.

```
COFFEE_BEAN_AMOUNT(0x39)  COFFEE_WATER_AMOUNT(0x3C)  ENJOY(0x3E)
MILK_FOAM_MILK_VOLUME(0x32)  MILK_FOAM_PAUSE(0x33)  POPUP_WINDOW(0x30)
HOTWATER_TEMPERATURE(0x40)  HOTWATER_VOLUME(0x41)  STEAM_TIME(0x42)
INSERT_TRAY(0x01)  FILL_WATERTANK(0x02)  EMPTY_GROUNDS(0x03)
ADD_POWDER_COFFEE(0x10)  ADD_BEANS(0x13)  ALARM(0x0E)  …
```

plus `ProductProgressState` for the per-parameter live values
(`COFFEE_WATER_AMOUNT`, `MILK_FOAM_VOLUME`, `BYPASS_WATER_VOLUME`,
`SMART_ALERT_PAUSE`, …). `PROTOCOL.md` §5.9 already records the byte
layout we know (`@TV:41<code>…` tick/target/percent, `@TV:3E<code>`
completion); what's missing is a decoder and a state enum.

This is the single biggest usability gap: without it there is no way to
report "brewing, 60 %" or "waiting for you to empty the grounds".

---

## 4. Statistics

**Done.** All ten banks are read (`JuraClient.read_counter_bank`,
`COUNTER_BANK_SPECS`), each only when the machine's profile declares
it. Page counts marked "assumed" use the product counter's 16 pages and
stop early on `@tr:00`.

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

**Where we now go past J.O.E.:** the `<DAILYCOUNTER Reset="@TF:05">`
banks (`@TR:42`..`@TR:45`) appear in no APK code path — the XML's own
`<!-- Not available in JOE -->` comment is accurate, and grepping the
decompiled app for `@TR:4[2-5]` or `@TF:05` returns nothing. They are a
real machine capability the app ignores, and they are what a "brews
today" sensor wants, so the library reads them
(`daily-brews`, `daily-barista-counters`) and exposes the reset verb as
the gated `reset-daily-counters`. Untested against hardware.

Also unlike J.O.E.: the special bank's named slots
(`SPECIAL_COUNTER_SLOTS`) drop the app's `hotBrew`, which reads slot 0 —
the same slot as the total — and looks like a copy/paste bug in
`SpecialCounterStatisticsParser`.

The XML also declares `<TOTALCOUNTER Code="00" Name="Total Products">`
and a `<LIFETIME>` block that we ignore.

---

## 5. Machine settings

Implemented: single-setting read (`@TM:<arg>`) and the checksummed,
`@TS:01`/`@TS:00`-wrapped write, plus (new) the batch read and the
limit load. Status of each:

* ~~**Batch read.**~~ **Done, with a caveat.** Each XML declares
  `<BANK Name="Setting" Command="@TM:00,FC" CommandArgument="02080913"/>`
  — one round trip for the four settings `02` (hardness), `08`
  (units), `09` (language), `13` (auto-off). `MachineProfile.
  settings_bank` parses the declaration and
  `JuraClient.read_settings_bank()` issues it (CLI: `settings`).
  **The reply layout is a guess, not APK-derived**: J.O.E. 4.6.10
  parses `CommandArgument` and then *discards* it in `Bank`'s
  constructor, and its WiFi settings path is
  `WifiCommandReadPModeComposite` = one `@TM:<arg>` per setting, so
  the app never issues this command at all. `read_all_settings()`
  therefore falls back to per-setting reads on any rejection,
  checksum failure or value-count mismatch. Verifying it on hardware
  is a read-only experiment: send `@TM:00,FC` and diff against four
  single reads. Survey result: 57 of 89 profiles declare the bank,
  always with the identical command and argument list; the remaining
  32 have no `<MACHINESETTINGS>` block at all; and 16 of the 57 list
  arguments their own catalogue never declares, so the list is
  boilerplate — never hard-code it.
* ~~**`@TM:60,…` limit load**~~ **Done** (`WifiCommandReadLimitLoad`).
  Payload decoded from `LimitLoadParser`: `@tm:60,<code><5 min/max
  byte pairs><csum>` for F4, F5, F6, F10, F11 in that fixed order,
  `FF` meaning "not applicable", each pair scaled by the argument's
  XML `Step`. `JuraClient.read_limit_load()` returns a `ProductLimits`
  (CLI: `limits <product>`) whose `allows(kind, value)` bounds a brew
  by what the machine permits *now* rather than by the static XML
  range. APK-derived but never seen on a real machine.
* ~~Settings arguments seen in the app's mock that our EF1091
  catalogue doesn't expose: `@TM:1F` (→ `@tm:1F,00FC`), `@TM:0A`.~~
  Not a gap: `1F` (TimeFormat) is an ordinary `<SWITCH>` on the 10
  profiles that have it and `0A` (brightness) an ordinary
  `<COMBOBOX>` — EF1091 simply has no TimeFormat. A survey of all 89
  `<MACHINESETTINGS>` blocks found only four element kinds
  (`SWITCH`, `COMBOBOX`, `SLIDER`×2 flavours, plus `BANK`), all of
  them parsed. Two real omissions were fixed: the `BANK` element
  itself, and `Mask` being read for sliders only (the ESM switch
  carries `Mask="01"`). `Read="TM:<arg>"` on every `COMBOBOX` is
  redundant with `P_Argument` and carries nothing.

Still missing here: nothing for reads. Writes remain single-setting.

---

## 6. Product start — preselections and timers

`brew` builds the 16-byte `@TP:` blob from the XML's `Argument="F<n>"`
parameters. Complete list across all 89 profiles:

| Arg | Tag | Lib |
| --- | --- | --- |
| `F2` | `GRINDER_RATIO` | encoded, **untested** |
| `F3` | `COFFEE_STRENGTH` | ✅ live-verified |
| `F4` | `WATER_AMOUNT` | ✅ live-verified |
| `F5` | `MILK_AMOUNT` | encoded, untested |
| `F6` | `MILK_FOAM_AMOUNT` | encoded, untested |
| `F7` | `TEMPERATURE` | ✅ live-verified |
| `F8` | `STROKE` | encoded, untested |
| `F10` | `BYPASS` | ✅ live-verified |
| `F11` | `MILK_BREAK` | encoded, untested |
| `F17` | `GRINDER_FREENESS` | encoded, untested |

What is *not* implemented:

* **Preselections.** Each `<PRODUCT>` carries `<PRESELECTION>` elements
  with `xtrashot`, `double="<product code>"`, `powder`, `coldbrew`,
  `sweetfoam` flags. J.O.E. models these as
  `PreselectArgument.{EXTRA_SHOT,DOUBLE_SHOT,POWDER,COLD_BREW,
  LIGHT_BREW,SWEET_FOAM,FAKE_SWEET_FOAM,STRONG_COLD_BREW}` and passes
  them in `ProductStartData` (which also carries `frotherInstructions`,
  `grinderInstructions`, `f18Enabled`). `_parse_product_params` skips
  `<PRESELECTION>` explicitly. Note `double="31"` is the same code the
  Z10 counter-slot quirk is about — the "2 Espressi" product *is* a
  preselection of the single, not a separate menu entry.
* **Coffee timer.** `@TM:3C,<product blob padded to 20 bytes><time>` +
  checksum schedules a brew; `@TV:84,<time>` syncs the machine clock
  first. `<PRODUCT ... shouldBeShownInCoffeeTimer>` marks eligible
  products.

---

## 7. Things `jura-connect` deliberately or incidentally has no story for

* **Language download** — `@TS:F1` lock, `@TM:23` max languages,
  `@TT:00` list, `@TT:01,<block>` select, `@TT:02`/`@TT:08` transfer
  (ASCII vs. binary), `@TT:03` finish, `@TV:81`/`@TV:82` to paint the
  machine display while it runs. Needs the language blobs from Jura's
  CDN, which the app fetches over HTTPS.
* **Firmware OTA** — `@HB` (enter bootloader), `@HO:` (.dat), `@HD:`
  (.bin), `@HE` (end), `@HT:3` (restart dongle). Bricking risk;
  arguably should stay out of scope.
* **Milk-cooler update** — `@HU` / `@HU?`.
* **BluFi onboarding** — the app provisions a factory-fresh dongle's
  WiFi over BLE (ESP32 BluFi) before it ever reaches TCP. Our
  `set-ssid`/`set-password` only work on an *already paired* dongle,
  i.e. they can move a machine between networks but cannot bootstrap
  one.
* **Smart Connect 2 / BLE2** — `CoffeeMachineAdapterBle2` speaks the
  same `@` language over BLE with its own crypto (`Ble2CryptoUtil`) and
  its own handshake, plus `@HA:02` and `@HR:81` (read dongle name /
  hand over WiFi credentials). Out of scope for a WiFi library, but it
  is the most readable reference for the full command set — its method
  names survived obfuscation.
* App-level things with no protocol component: shop, recipes, QR
  onboarding, statistics charts, RealWear/AR support.

---

## 8. Where we and J.O.E. disagree about a command's meaning

These are the highest-value items, because they are *wrong today*, not
merely absent. All were read out of the APK; none has been re-probed on
hardware (and two of them must not be).

**Items 1–4 are fixed** (see `PROTOCOL.md` §5.1 / §5.8); they stay here
with their resolution because the reasoning is the interesting part.

1. **`@TG:7E` is `WifiCommandCancelQualityAssistantStep`**, not
   "reset maintenance counters". The class sends bare `@TG:7E` to skip
   one quality-assistant step and `@TG:7E,FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF`
   to skip all. `AGENTS.md` records that an accidental `@TG:7E` *did*
   reset counters on a real TT237W, so both behaviours may exist across
   firmware. **Do not re-probe this on hardware to find out.**
   *Fixed:* renamed `reset-counters` → `skip-quality-step [one|all]`,
   the skip-all argument is implemented, `@TG:7E` **stays** in
   `DESTRUCTIVE_PREFIXES` and stays gated, and the danger string now
   states both readings and that neither is reversible.
2. **`@TG:FF` is `WifiCommandCancelProductStep`** — cancel the running
   product step, i.e. the natural "abort this brew".
   *Fixed:* removed from `DESTRUCTIVE_PREFIXES` (so the `raw` escape
   hatch stops gating it too) and exposed as the ungated `cancel`
   command with a tolerant `(?i)^@tg` reply matcher; the simulator
   answers `@tg:FF`.
3. **`@HE` is `WifiCommandOTAEnd`** (expects `@he:ok`), while J.O.E.'s
   `WifiCommandCloseConnection` sends an *empty* frame. It is an OTA
   verb, and sending it outside an OTA session is not obviously a no-op
   on every firmware.
   *Fixed:* `JuraClient.close()` now sends the empty frame (still
   best-effort / exception-safe). The simulator accepts both the empty
   frame and `@HE` as session teardown.
4. **`@HU?` is `WifiCommandMilkCoolerUpdateStatus`**, matching
   `@hu:[0-9a-fA-F]{3}`. This finally explains `PROTOCOL.md` §9's
   "`@HU?` returned `@hu:800` in some probes but `@TF:` in others": the
   `@hu:800` *is* the correct answer to `@HU?`, and the `@TF:` we key
   on is just the next unsolicited status frame arriving. J.O.E. never
   polls for status — `TCPReceiveHandler` routes pushed `@TF:` frames.
   *Fixed:* `read_status()` sends nothing and returns the next pushed
   `@TF:` frame; `read_status(nudge=True)` still emits `@HU?` for
   firmwares that want traffic on the socket, documented as a nudge
   rather than a query. The simulator answers `@HU?` with `@hu:800`
   and the §9 bullet is gone.
5. ~~**`@TG:43` field order is per-machine.**~~ **Fixed** — both banks
   now decode against the XML's `<BANK Command="@TG:43">` /
   `<BANK Command="@TG:C0">` `<TEXTITEM Type=…>` children via
   `MachineProfile.maintenance_counter_fields` /
   `.maintenance_percent_fields`, exactly as J.O.E. does; the old
   hard-coded order survives only as the no-profile fallback (see
   `PROTOCOL.md` §5.3). Kept here for the record — **21 of 89
   profiles differ** from that fallback, so those machines still need
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

## 9. Profile / XML parsing gaps

`MachineProfile` parses `ALERT`, `PRODUCT` (+ `F<n>` params),
`PRODUCTCOUNTER/BANK`, the `@TG:43` / `@TG:C0` maintenance banks, and
`MACHINESETTINGS`. Unparsed sections that carry protocol meaning:

| Section | Carries | Blocks |
| ------- | ------- | ------ |
| `<PROCESS>` | `ExecuteCommand`, `Progress` flag | §2 |
| `<STATE>` (83 on EF1091) | state code → name, `AcceptCommand` | §2, §3 |
| `<PRESELECTION>` | extra-shot / double / powder / cold-brew flags | §6 |
| `<COMBINATION>` | legal preselection combinations | §6 |
| ~~`<BANK Command="@TG:43"/"@TG:C0">` `<TEXTITEM>`~~ | ~~per-machine counter field order~~ | done (§8.5) |
| ~~`<BANK Name="Setting">`~~ | ~~batch settings read~~ | done (§5) |
| `<TOTALCOUNTER>`, `<LIFETIME>` | totals metadata | §4 |
| `<BUTTON>`, `<PREDICTIVEBUTTON>` | machine-side favourites | UI only |
| `<ENJOYSCREEN>`, `<TEXTITEM>`, `<LINK>` | display strings, manual URLs | UI only |
| ~~`<PROGRAMMODE>`~~ | ~~kind-count vector~~ | **there is no such element** — see below |

`<PROGRAMMODE>` was a phantom: no bundled XML, and neither documented
template (`EF0000` / `EF_MASTER`), has one, so `MachineProfile.has_pmode`
was always `False`. The real declarations are now parsed
(`PROTOCOL.md` §5.6.1):

| Section / attribute | Carries | `MachineProfile` |
| ------------------- | ------- | ---------------- |
| `<MACHINESETTINGS Productprogramming>` | machine supports PMode writes (20/89 true) | `.product_programming`, `.has_pmode` |
| `<MACHINESETTINGS NumberOfSlotsForProductProgramming>` | declared slot count (5 profiles) | `.pmode_slot_count` |
| `<PRODUCT ProductSettings>` | product is programmable | `ProductDef.product_settings` |
| `PModeAdjust="false"` on a parameter | parameter is not PMode-adjustable | `ProductParam.pmode_adjust` |
| `<MACHINEMANIFEST><CAPABILITIES IntakeF18>` | changes the `@TM:42` blob tail | `.intake_f18` |

---

## 10. Suggested order of work

1. ~~**Fix §8.5** (XML-driven `@TG:43` field order).~~ **Done** — the
   maintenance banks decode against the profile; 21 machine families
   fixed, pinned by tests over all 89 bundled XMLs.
2. ~~**Re-label §8.1–8.4**~~ — **done**: `@TG:FF` is out of the
   destructive list and exposed as `cancel`, `@TG:7E` is still gated as
   `skip-quality-step` with both readings documented, `close()` sends
   the empty frame, and `read_status()` waits for the pushed `@TF:`.
3. **Decode `@TV:`** into a `ProductProgress` dataclass with the
   `ProgressState` enum. Unlocks "is it done yet" for `brew` and is a
   prerequisite for anything interactive.
4. **`<PROCESS>` + `<STATE>` + `@TG:01` / `@TG:04` / `@TG:10`** — turn
   `clean` / `descale` into a real state machine that can report and
   confirm. Highest user value, most testing effort (each confirmation
   consumes supplies on a real machine — extend the simulator first).
5. ~~**Special / barista counter banks**~~ — **done**: all ten banks
   read through one generic, profile-gated reader, plus the daily banks
   J.O.E. never touches and their gated `@TF:05` reset. Simulator-only
   verification; no machine here declares anything past `@TR:32`.
6. **Preselections in `@TP:`** — needs the argument byte reverse
   engineered (`ProductStartData.f18Enabled` suggests `F18`); verify on
   hardware before shipping, a wrong byte misbrews.
7. ~~**PMode writes (`@TM:41`/`@TM:42` write)**~~ — **done**, with the
   caveat that nothing is hardware-verified: `pmode-product`,
   `pmode-set-product` and `pmode-set-slot` implement the APK's blob
   layout and checksums, the simulator models both a machine that
   exposes slots and the EF1091-style `@tm:C2` machine, and the
   `<MACHINESETTINGS>` PMode declarations are parsed. Still blocked on
   finding a machine that answers `@TM:42` with data (EF1091 answers
   `@tm:C2` for every slot) before any of it can be called verified.
8. **Confirm the two new read paths on a machine** (§5). Both are
   read-only, so this costs nothing but a session: compare
   `@TM:00,FC` against four single reads (and retry with the
   checksummed request form, `read_settings_bank(checksum=True)`), and
   compare `@TM:60,<code>` against the product's XML ranges. If the
   batch reply layout differs from the guess, fix
   `client._parse_settings_bank_reply` and PROTOCOL.md §5.7 — the
   fallback means nothing breaks in the meantime.
9. Coffee timer, language download, OTA — only if someone wants them.
