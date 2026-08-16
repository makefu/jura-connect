# Hardware capture — Kaffeebert (JURA S8 EB / EF1091), 2026-08-16

First end-to-end validation of the non-destructive half of the
`jura-connect` command registry against a real machine. Everything
below is a verbatim wire trace: frames were captured by wrapping
`JuraConnection.send` / `.recv_frame` on a live `JuraClient`, so the
`TX` / `RX` lines are exactly the cleartext bodies that went into and
came out of the cipher.

## Machine

| | |
| --- | --- |
| Nickname | `kaffeebert` |
| Model | JURA S8 EB |
| EF code | `EF1091` (XML `1.6.xml`) |
| Firmware family | TT237W V06.11 (per earlier probes; **not** re-verified this session — see below) |
| Address | `192.168.111.192:51515` |
| Handshake | `@HP:,<conn_id_hex>,<auth_hash>` → `@hp4` (CORRECT, no fresh hash) |
| Idle status frame | `@TF:0004000008000000` (`coffee_ready`, `energy_safe`) |
| Total brews | 3753 |

The UDP scan probe (`jura-connect probe 192.168.111.192`) got **no
reply**, so the firmware string could not be re-read from the discovery
blob this session. That is expected, not a fault: `PROTOCOL.md` §1
already records that **TT237W ignores unicast UDP probes** and replies
only to the broadcast form, and the capture host is not on the
machine's L2 segment (RTT 210–320 ms over a routed link). TCP 51515 was
reachable throughout. Every result below came over TCP.

## Session behaviour

* The dongle serves **one TCP session at a time**. Two commands hit
  `ConnectionResetError` during the `@HP:` round-trip when a previous
  session had closed less than ~3 s earlier; both succeeded on retry.
  This matches `docs/PROTOCOL.md` §4's note on reset-on-session-churn.
* At idle the dongle broadcasts `@TF:` **every ~2.05 s**, unprompted,
  for the whole life of the session. Measured across five separate
  20 s windows.

## Commands not run, and why

| Command | Reason |
| --- | --- |
| `cancel` (`@TG:FF`) | **`AGENTS.md` §2 lists `@TG:FF` in the destructive set**, even though `commands.DESTRUCTIVE_PREFIXES` does not contain it and the registry classes `cancel` read-only. The two disagree; §8 says do not run destructive commands against a real machine, so it was skipped. See "Open discrepancy" below. |
| `coffee-timer-time` (`@TV:84`) | Registry classes it read-only, but it writes a wall-clock value to the machine and its semantics are unresolved. Excluded deliberately. |
| every `destructive=True` command | `--allow-destructive-commands` was never passed and `run_named(..., allow_destructive=False)` was hard-coded in the capture harness, which additionally ran every outgoing frame through `commands.match_destructive()` and raised rather than writing. |
| `@TM:00,FCEA` (checksummed settings bank) | A valid checksum is what makes `@TM:<addr>,<value><csum>` look like a well-formed *write*. Bare `@TM:00` was already rejected (below), which answers the question without putting a write-shaped frame on the wire. |

---

## 1. `settings` — the batch bank `@TM:00,FC` — **CONTRADICTED**

The highest-value result of the run.

```
$ jura-connect command --name kaffeebert settings
TX '@TM:00,FC'
RX '@tm:80'
TX '@TM:02'   RX '@tm:02,0DFD'
TX '@TM:13'   RX '@tm:13,1EF9'
TX '@TM:08'   RX '@tm:08,000B'
TX '@TM:09'   RX '@tm:09,0109'
TX '@TM:0A'   RX '@tm:0A,06FC'
TX '@TM:04'   RX '@tm:04,000F'
TX '@TM:62'   RX '@tm:62,000B'
```

Decoded:

```
settings (7 read via per-setting @TM:<arg>):
  hardness                     0x0D
  auto_off                     30min (0x1E)
  units                        ml (0x00)
  language                     german (0x01)
  display_brightness_setting   60 (0x06)
  milk_rinsing                 automatic (0x00)
  frother_instructions         off (0x00)
  batch read unavailable: settings bank '@TM:00,FC': reply echoes address
  '80', expected '00' ('@tm:80')
```

**Verdict: contradicted.** EF1091's XML declares
`<BANK Name="Setting" Command="@TM:00,FC" CommandArgument="02080913"/>`,
but the machine does not implement it. It answers `@tm:80` — a
rejection token, not a value payload. The guessed reply layout in
`client._parse_settings_bank_reply` was never reached, and no checksum
variant can help (see §2).

**Confirmed by the same run:** the per-setting fallback is correct and
sufficient. `read_all_settings` caught the `ValueError`, recorded it in
`batch_error`, and read all seven catalogue entries individually. The
graceful-degradation design is validated on hardware.

Note that the bank's `CommandArgument="02080913"` covers only 4 of the
7 settings this machine actually exposes (`0A`, `04`, `62` are absent
from it), so even a working batch read would not have replaced the
per-setting path.

## 2. `@tm:<addr|0x80>` is the universal `@TM:` rejection token — **NEW**

Four separate `@TM:` reads were rejected in this session, and the
rejection byte is always the requested address with **bit 7 set**:

| Request | Reply | `addr \| 0x80` |
| --- | --- | --- |
| `@TM:00` (bare) | `@tm:80` | `0x00 \| 0x80` = `0x80` ✓ |
| `@TM:00,FC` | `@tm:80` | same address, same answer |
| `@TM:23` | `@tm:A3` | `0x23 \| 0x80` = `0xA3` ✓ |
| `@TM:41,02` | `@tm:C1` | `0x41 \| 0x80` = `0xC1` ✓ |
| `@TM:42,<slot>` | `@tm:C2` | `0x42 \| 0x80` = `0xC2` ✓ |

`_parse_pmode_num_slots` already documents `@tm:D0` as the "no slots"
token for `@TM:50` — and `0x50 | 0x80 = 0xD0`, which fits the same rule.

This unifies four constants the codebase carried as unrelated magic
numbers. It also settles the settings-bank question definitively:
**bare `@TM:00` is rejected too**, so the `,FC` argument is irrelevant
and appending a checksum cannot change the outcome — address `00` is
simply not a readable `@TM:` address on this firmware.

**Verdict: confirmed** (five independent observations, no
counter-example).

## 3. `limits <product>` — `@TM:60` — **CONFIRMED**

Fully decompiled from the APK, never before seen on a wire. It works.

Request form is `@TM:60,<code><checksum>`; the `ByteOperations.d`
checksum over `"60,<code>"` **is required and is accepted**.

| Product | TX | RX |
| --- | --- | --- |
| espresso (02) | `@TM:60,020B` | `@tm:60,020310FFFFFFFFFFFFFFFF0087` |
| coffee (03) | `@TM:60,030A` | `@tm:60,030530FFFFFFFFFFFFFFFF0082` |
| latte_macchiato (07) | `@TM:60,0706` | `@tm:60,070530FFFF012DFFFF003C0001` |
| milk_foam (08) | `@TM:60,0805` | `@tm:60,08FFFFFFFF012DFFFFFFFF006E` |
| milk (0A) | `@TM:60,0AFC` | `@tm:60,0AFFFF012DFFFFFFFFFFFF0065` |
| hotwater_portion (0D) | `@TM:60,0DF9` | `@tm:60,0D053CFFFFFFFFFFFFFFFF005E` |
| cafe_barista (28) | `@TM:60,2803` | `@tm:60,280310FFFFFFFF0030FFFF00D4` |

Reply layout, now observed rather than inferred:

```
@tm:60,<code:1B><5 × (min:1B, max:1B)><trailer:1B = 00><checksum:1B>
```

The five min/max pairs are **positional**, and their order matches the
XML's `Argument="F<n>"` numbering exactly:

| Pair | Argument | Confirmed by |
| --- | --- | --- |
| 0 | F4 water amount | espresso, coffee, hotwater, cafe_barista |
| 1 | F5 milk amount | milk (`012D` in pair 1 only) |
| 2 | F6 milk foam amount | milk_foam, latte_macchiato (`012D` in pair 2) |
| 3 | F10 bypass | cafe_barista (`0030` in pair 3 only) |
| 4 | F11 milk break | latte_macchiato (`003C` in pair 4 only) |

`FFFF` marks a parameter the product does not expose. Water and bypass
are in units of 5 ml (`0x03..0x10` → 15..80 ml); milk, foam and milk
break are 1:1. Decoded output:

```
limits for espresso (0x02):        water_amount     15..80  (step 5)
limits for coffee (0x03):          water_amount     25..240 (step 5)
limits for hotwater_portion (0x0D):water_amount     25..300 (step 5)
limits for cafe_barista (0x28):    water_amount     15..80  (step 5)
                                   bypass            0..240 (step 5)
limits for latte_macchiato (0x07): water_amount     25..240 (step 5)
                                   milk_foam_amount  1..45  (step 1)
                                   milk_break        0..60  (step 1)
limits for milk (0x0A):            milk_amount       1..45  (step 1)
limits for milk_foam (0x08):       milk_foam_amount  1..45  (step 1)
```

Note the machine reports **no** limits for `coffee_strength` or
`temperature` (all `FFFF`) even though the XML declares both as
settable choice lists — `@TM:60` covers the continuous sliders only.

## 4. `languages` — `@TT:00` + `@TM:23` — **CONTRADICTED**

```
TX '@TT:00'
RX '@TF:0004000008000000'   (x7, ~2 s apart)
-- TimeoutError: no reply to '@TT:00' within 15.0s
```

**Verdict: contradicted.** A machine that does not implement the
language verbs does not reject `@TT:00` with a token — it **stays
completely silent** while continuing to broadcast `@TF:` frames.
Reproduced three times (15 s, 15 s, 10 s windows).

`@TM:23` on the same machine answers `@tm:A3` = `MaxLanguagesCode.NOT_SUPPORTED`
(and fits the `addr | 0x80` rule from §2).

This was a genuine bug: `language.read_inventory` let the
`TimeoutError` escape, so a read-only introspection command blew up
with a traceback on exactly the machine whose answer it was meant to
report. Fixed on this branch (regression test
`test_language_inventory_survives_a_machine_that_ignores_tt00`, driven
by the simulator, which already models the silent machine when
`allow_language_download` is off). Post-fix hardware output:

```
Machine languages:
  (no reply to @TT:00: no reply to '@TT:00' within 8.0s)
  download supported (profile): no
  download block: 0B
  transfer form: binary (@TT:08)
  machine @TM:23: not supported
```

(`transfer form: binary` comes from `MachineCapabilities`' documented
J.O.E.-compatible default for a machine with no `<MACHINEMANIFEST>`;
it is inert because `supports_download` is false.)

## 5. `milk-cooler-status` — `@HU?` — **CONFIRMED**

```
TX '@HU?'
RX '@hu:800'
```

```
milk cooler: no_cooler (@hu:800)
{"raw":"800","state":"no_cooler","state_code":8,"percent":null,
 "running":false,"finished":false}
```

**Verdict: confirmed**, exactly as predicted. State nibble `8` = no
cooler connected. Also confirms `@HU?` is a real read that must not be
prefix-gated against `@HU` (the `DESTRUCTIVE_EXACT` carve-out is
correct).

## 6. Counter banks — XML declaration ≠ firmware support — **CONTRADICTED**

EF1091's XML declares exactly one counter bank, `@TR:32`. The library
therefore refuses to send `@TR:52` / `@TR:34` / `@TR:42` / `@TR:44`.

**The gate itself works.** For all four commands the wire trace is
handshake → close, with **nothing sent**:

```
$ ... special-counters / barista-counters / daily-brews / daily-barista-counters
TX '@HP:…'   RX '@hp4'   TX ''
→ "EF1091 does not implement the @TR:52 counter bank
   (not declared in its XML, or answered @tr:00)"
```

Asking the machine directly with `raw` tells a different story:

| Frame | Reply | Meaning |
| --- | --- | --- |
| `@TR:52,00` | `@tr:52,00,FFFFFFFF0001000E` | **answered with real data** |
| `@TR:52,01` | `@tr:52,01,FFFFFFFFFFFFFFFF` | answered (all slots empty) |
| `@TR:52,02` | `@tr:52,02,0A65FFFFFFFFFFFF` | **answered — slot 8 = 0x0A65 = 2661** |
| `@TR:52,03` | `@tr:52,03,FFFFFFFFFFFFFFFF` | answered (all slots empty) |
| `@TR:53,00` | `@tr:00` | rejected (special overflow) |
| `@TR:42,00` | `@tr:00` | rejected (daily product) |
| `@TR:44,00` | `@tr:00` | rejected (daily barista) |
| `@TR:34,00` | `@tr:00` | rejected (barista) |
| `@TR:33,00` | `@tr:00` | rejected (product overflow) |

**Verdict: contradicted, and this is the important one.** The S8 EB
implements the `@TR:52` special-counter bank and holds live values in
it (slot 2 = 1, slot 3 = 14, slot 8 = 2661), but its XML does not
declare the bank, so `jura-connect` will never read it. "Declared in
the XML" and "supported by the firmware" are **not** the same set — at
least not in the under-declaring direction.

The other four banks are genuinely absent and answer the `@tr:00`
rejection J.O.E.'s matcher expects, so the XML is not wrong about
those. Only `@TR:52` is under-declared.

Changing `read_counter_bank` from "trust the XML" to "probe and let
`@tr:00` decide" is a deliberate design reversal, not a bug fix, so it
is **reported rather than implemented** — see `docs/JOE_GAPS.md`.

## 7. `pmode` / `pmode-product` — **CONFIRMED**

```
TX '@TM:50'      RX '@tm:50,04040404047A'
TX '@TM:42,00'   RX '@tm:C2'      (…through @TM:42,13 — all C2)
TX '@TM:41,02'   RX '@tm:C1'      (espresso)
TX '@TM:41,04'   RX '@tm:C1'      (cappuccino)
```

**Verdict: confirmed.** Exactly the behaviour `AGENTS.md` §1 describes:
20 slots reported, every slot rejected.

Two refinements on top:

* `@tm:50`'s body is **five bytes of `04`**, not one count byte.
  `_parse_pmode_num_slots` sums them (5 × 4 = 20), which is what the
  APK's `PModeNumSlotReadParser` does — now confirmed against hardware.
* The trailing byte is **not** an opaque checksum. It is the ordinary
  `ByteOperations.d` / `_settings_checksum` over `"50,0404040404"`,
  which computes to `0x7A` — the exact byte on the wire. The docstring's
  "the algorithm is opaque" is wrong and has been corrected.
* `@TM:41,<code>` → `@tm:C1` is now hardware-observed (was APK-derived).

## 8. `process-watch`, `progress` — **CONFIRMED (idle)**

Both were watched for 20 s on an idle machine. Neither saw a single
`@TV:` frame; only the ~2 s `@TF:0004000008000000` broadcast.

```
progress       → "(no @TV: progress frames seen)"
process-watch  → "process (watch)\n  (no state frames seen)\n-- timed out"
```

**Verdict: confirmed** — both cleanly report nothing rather than
erroring. No brew was started to feed them, and the maintainer did not
brew during the run, so the populated path remains untested on
hardware.

## 9. `lock` / `unlock` — `@TS:01` / `@TS:00` — **CONFIRMED**

Run as a single session with the unlock in a `finally`.

```
TX '@TS:01'   RX '@ts'
              RX '@TF:0004000009000000'   <-- note byte 4
TX '@TS:00'   RX '@ts'
```

**Verdict: confirmed**, plus a new observation: while the panel is
locked the machine's status frame changes from `…08…` to `…09…`, i.e.
**global bit 39 is set**. EF1091's XML names bit 39 `LockedKeys`. This
is an independent confirmation of the MSB-first bit indexing in §5.4
(byte 4 `0x09` → MSB positions 4 and 7 → global bits 36 `energy safe`
and 39 `LockedKeys`).

A follow-up `status` read confirmed the frame returned to
`@TF:0004000008000000`: **the display was left unlocked.**

## 10. `counters` / `percent` — **CONFIRMED, no regression**

```
TX '@TG:43'   RX '@tg:43001A000100090168109F005F'
TX '@TG:C0'   RX '@tg:C000FF46'
```

```
cleaning=26 filter=1 descale=9 cappu_rinse=360 coffee_rinse=4255 cappu_clean=95
cleaning=0 filter=255 descale=70
```

Compared with the `PROTOCOL.md` §5.3 capture from this same machine
(`@tg:4300150001000801580E21005B` → 21, 1, 8, 344, 3617, 91):

| Field | Then | Now | |
| --- | --- | --- | --- |
| cleaning | 21 | 26 | ↑ |
| filter_change | 1 | 1 | = |
| descale | 8 | 9 | ↑ |
| cappu_rinse | 344 | 360 | ↑ |
| coffee_rinse | 3617 | 4255 | ↑ |
| cappu_clean | 91 | 95 | ↑ |

**Verdict: confirmed.** Every field moved monotonically upward by a
plausible amount; the XML-declared field-order change shipped today
decodes this machine identically to before.

`@TG:C0` carries `0xFF` for `filter_change` (no filter fitted, matching
`filter=1` lifetime changes). The library prints it as `filter=255`
rather than suppressing it — deliberate and pinned by
`test_percent_parse_without_profile_is_unchanged`, but worth knowing
when reading output: **255 in a percent field is the not-applicable
sentinel, not a percentage.**

## 11. `brews` — `@TR:32` — **CONFIRMED**

16 pages, `@TR:32,00` … `@TR:32,0F`, all answered.

```
@tr:32,00,0EA9FFFF006702BE    @tr:32,08,FFFFFFFFFFFFFFFF
@tr:32,01,0046FFFF00030013    @tr:32,09,FFFFFFFFFFFFFFFF
@tr:32,02,0034FFFF0000FFFF    @tr:32,0A,04CF0004FFFF0002
@tr:32,03,FFFF0424FFFF00F5    @tr:32,0B,0001FFFF00DBFFFF
@tr:32,04,FFFFFFFFFFFFFFFF    @tr:32,0C,00140001FFFFFFFF
@tr:32,05,FFFFFFFFFFFFFFFF    @tr:32,0D,FFFFFFFF000AFFFF
@tr:32,06,FFFFFFFFFFFFFFFF    @tr:32,0E,FFFFFFFFFFFFFFFF
@tr:32,07,FFFFFFFFFFFFFFFF    @tr:32,0F,FFFFFFFFFFFFFFFF
```

```
total brews : 3753
  espresso 103   coffee 702   cappuccino 70   espresso_macchiato 3
  latte_macchiato 19   milk_foam 52   milk 0   hotwater_portion 1060
  powderproduct 245   cafe_barista 1231   barista_lungo 4   cortado 2
  sweet_latte 1   flat_white 219   espresso_doppio 20   2_espressi 1
  2_coffee 10
```

**Verdict: confirmed.** `0xFFFF` = unused slot, per §5.5. The overflow
fold (`@TR:33`) is not exercised here because the machine rejects that
bank; no counter is anywhere near `0xFFFF`, so nothing is being lost.

## 12. `register-read <bank>` — bare bank reads draw no reply — **CONTRADICTED**

```
TX '@TR:32'   → 4 × @TF: broadcast, then TimeoutError after 10 s
TX '@TR:52'   → 4 × @TF: broadcast, then TimeoutError after 10 s
```

**Verdict: contradicted.** A `@TR:<bank>` frame with no `,<page>`
argument gets **no answer at all**, for both a supported bank (`32`)
and a bank the machine implements but does not declare (`52`). Bank
reads are page-addressed only; `register-read <bank>` as currently
specified cannot succeed on this firmware. The command is documented
as "firmware-specific", so this is a documentation gap rather than a
code defect, but the CLI will simply hang for the full timeout.

Use `raw '@TR:<bank>,<page>'` instead.

## 13. Everything else — **CONFIRMED, no regression**

| Command | TX | RX | Verdict |
| --- | --- | --- | --- |
| `info` | `@TG:43`, `@TG:C0` (+ pushed `@TF:`) | as §10 | confirmed |
| `status` | *(nothing — waits for the push)* | `@TF:0004000008000000` | confirmed |
| `products` | *(no machine I/O)* | 14 products from EF1091's XML | confirmed |
| `processes` | *(no machine I/O)* | filter_change, cleaning, descale, cappu_rinse, cappu_clean | confirmed |
| `mem-read 02` | `@TM:02` | `@tm:02,0DFD` | confirmed |
| `mem-read 00` | `@TM:00` | `@tm:80` | see §2 |
| `mem-read 23` | `@TM:23` | `@tm:A3` | see §2 |
| `setting hardness` | `@TM:02` | `@tm:02,0DFD` → `0x0D` | confirmed |
| `setting language` | `@TM:09` | `@tm:09,0109` → german | confirmed |
| `setting auto_off` | `@TM:13` | `@tm:13,1EF9` → 30min | confirmed |
| `setting units` | `@TM:08` | `@tm:08,000B` → ml | confirmed |
| `raw '@TG:43'` | `@TG:43` | `@tg:43001A000100090168109F005F` | confirmed |
| `raw '@TG:C0'` | `@TG:C0` | `@tg:C000FF46` | confirmed |
| `raw '@HU?'` | `@HU?` | `@hu:800` | confirmed |

Every setting read carried a valid `ByteOperations.d` checksum and was
verified by `read_setting` — the checksum-on-read behaviour recorded in
`PROTOCOL.md` is confirmed across all seven catalogue entries.

---

## Open discrepancy: `@TG:FF`

`AGENTS.md` §2 lists `@TG:FF` among the prefixes that "change the
machine's state", but:

* `commands.DESTRUCTIVE_PREFIXES` does **not** contain `@TG:FF`;
* `commands.py` registers `cancel` (`@TG:FF`) as **read-only**;
* `tests/test_commands.py::_UNGATED_READS` contains `@TG:FF` with the
  comment "cancel the running step (§5.8) — reclassified, not a reset".

So the code has deliberately reclassified it and `AGENTS.md` was not
updated. Until the two agree, `cancel` was not exercised on hardware.
Whoever resolves this should either drop `@TG:FF` from the `AGENTS.md`
list or re-add it to `DESTRUCTIVE_PREFIXES`; the current state means a
reader following `AGENTS.md` and a caller trusting the gate reach
opposite conclusions.

## Machine state after the run

Left exactly as found:

* display **unlocked** — verified by a `status` read after the
  lock/unlock pair returning to `@TF:0004000008000000` (bit 39
  `LockedKeys` clear), several minutes before the end of the run;
* nothing in progress — no `@TV:` frame was ever seen;
* no setting changed — every `@TM:` frame sent was a bare read or the
  XML's own bank command; no `@TS:01`-wrapped write was issued;
* no counter reset, no maintenance cycle started, no product brewed.

### The machine left the network at the end of the run

The last command (`languages`, a re-run of `@TT:00` + `@TM:23` to check
the fix) succeeded normally. Roughly ten minutes later the machine
stopped answering: first a TCP connect timeout, then
`OSError: [Errno 113] No route to host`, then ICMP
`Destination Host Unreachable` — i.e. it disappeared from ARP, the
dongle is off the WiFi, not merely refusing sessions.

The overwhelmingly likely cause is the machine's own power-save: this
run read `auto_off = 30min` out of `@TM:13`, the idle status frame
carried `energy_safe` throughout, and nobody used the machine
physically during the session. An S8 that hits its auto-off timer
takes the WiFi dongle down with it.

It is recorded here because "the machine stopped answering" is a stop
condition regardless of the explanation, and because the reader should
be able to rule the run out as a cause:

* no destructive frame was ever put on the wire — the harness raised
  rather than writing anything `match_destructive()` flagged;
* the last frames sent were two reads (`@TT:00`, `@TM:23`), one of
  which the machine ignores entirely;
* the display was confirmed unlocked well before the disappearance,
  and a power cycle clears a leaked lock anyway (PROTOCOL.md §9).

Nothing further was sent after the machine went quiet.
