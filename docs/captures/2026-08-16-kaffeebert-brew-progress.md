# Hardware capture — a real brew's `@TV:` stream (S8 EB / EF1091), 2026-08-16

First hardware evidence for the `@TV:` product-progress decoder. Until
this run `jura_connect/progress.py` was **APK-derived and
simulator-verified only** — and the simulator's frames were built from
the same reading of the APK the decoder implements, so the two agreeing
proved nothing about a machine.

The maintainer started a `cafe_barista` on the machine's own panel while
a **read-only** watcher logged every pushed frame. **The decoder parsed
all 32 `@TV:` frames of the brew with zero failures.**

## Machine

| | |
| --- | --- |
| Nickname | `kaffeebert` |
| Model | JURA S8 EB |
| EF code | `EF1091` (XML `1.6.xml`) |
| Handshake | `CORRECT`, profile resolved to `EF1091` from the stored credential |
| Idle status frame | `@TF:0004000000000000` — `coffee_ready`, **no** `energy_safe` |
| Product | `cafe_barista` (`0x28`), strength 7, 45 ml water, 45 ml bypass |

Note the idle frame: the [2026-08-16 command capture](2026-08-16-kaffeebert-s8eb.md)
saw `@TF:0004000008000000` (`coffee_ready` + `energy_safe`) all session.
Here bit 36 is clear for the whole run, before and after the brew —
same machine, same frame, one bit different. `energy_safe` is live
state, not a constant of this firmware.

## How it was obtained

A ~180 s watcher (`tmp/captures/watch_progress.py`, scratch — not
tracked) that:

1. connects with the stored `kaffeebert` credential and the `EF1091`
   profile,
2. **sends nothing but the handshake**, then iterates
   `JuraClient.iter_frames()`,
3. prints every frame verbatim with a millisecond timestamp, and for
   each frame `is_progress_frame()` accepts, prints
   `ProductProgress.format()` and `.to_dict()`.

The brew was started **by hand on the machine**. No `@TP:` was ever put
on the wire, no destructive prefix was sent, nothing was written. The
run ended when the watcher was killed, ~75 s after the brew finished.

The frame list is now tracked in-tree as
`jura_connect.simulator.CAPTURED_S8EB_CAFE_BARISTA_BREW` and replayed by
`tests/test_progress_capture.py`, so the evidence survives the scratch
directory.

---

## The trace

Idle for ~55 s before the brew: `@TF:0004000000000000`, every ~2.05 s,
28 frames (12:29:03.789 … 12:29:58.687).

```
12:29:59.245  @TB
12:29:59.264  @TV:392807070009FFFF000911FFFF110000   COFFEE_BEAN_AMOUNT   7/7    0%
12:30:01.348  @TV:392807070009FFFF000911FFFF110000   COFFEE_BEAN_AMOUNT   7/7    0%
12:30:03.394  @TV:392807070009FFFF000911FFFF110000   COFFEE_BEAN_AMOUNT   7/7    0%
12:30:05.375  @TV:392807070009FFFF000911FFFF110000   COFFEE_BEAN_AMOUNT   7/7    0%
12:30:05.866  @TV:3C2807070009FFFF000911FFFF110000   COFFEE_WATER_AMOUNT  0/9    0%
12:30:07.899  @TV:3C2807070009FFFF000911FFFF110000   COFFEE_WATER_AMOUNT  0/9    0%
12:30:09.948  @TV:3C2807070009FFFF000911FFFF110000   COFFEE_WATER_AMOUNT  0/9    0%
12:30:11.966  @TV:3C2807070009FFFF000911FFFF110000   COFFEE_WATER_AMOUNT  0/9    0%
12:30:12.105  @TV:3C2807070009FFFF000911FFFF110000   COFFEE_WATER_AMOUNT  0/9    0%
12:30:13.844  @TV:3C2807070009FFFF000911FFFF110A00   COFFEE_WATER_AMOUNT  0/9   10%
12:30:15.785  @TV:3C2807070109FFFF000911FFFF110A00   COFFEE_WATER_AMOUNT  1/9   10%
12:30:16.912  @TV:3C2807070209FFFF000911FFFF111400   COFFEE_WATER_AMOUNT  2/9   20%
12:30:18.922  @TV:3C2807070309FFFF000911FFFF111400   COFFEE_WATER_AMOUNT  3/9   20%
12:30:20.194  @TV:3C2807070409FFFF000911FFFF111E00   COFFEE_WATER_AMOUNT  4/9   30%
12:30:22.141  @TV:3C2807070509FFFF000911FFFF111E00   COFFEE_WATER_AMOUNT  5/9   30%
12:30:23.266  @TV:3C2807070509FFFF000911FFFF112800   COFFEE_WATER_AMOUNT  5/9   40%
12:30:25.213  @TV:3C2807070709FFFF000911FFFF112800   COFFEE_WATER_AMOUNT  7/9   40%
12:30:26.132  @TV:3C2807070709FFFF000911FFFF113200   COFFEE_WATER_AMOUNT  7/9   50%
12:30:28.180  @TV:3C2807070809FFFF000911FFFF113200   COFFEE_WATER_AMOUNT  8/9   50%
12:30:29.204  @TV:3C2807070909FFFF000911FFFF113C00   COFFEE_WATER_AMOUNT  9/9   60%
12:30:30.743  @TV:412807070909FFFF000911FFFF113C00   bypass_water_volume  0/9   60%
12:30:32.791  @TV:412807070909FFFF010911FFFF113C00   bypass_water_volume  1/9   60%
12:30:32.918  @TV:412807070909FFFF010911FFFF114600   bypass_water_volume  1/9   70%
12:30:34.628  @TV:412807070909FFFF040911FFFF115000   bypass_water_volume  4/9   80%
12:30:36.130  @TV:412807070909FFFF060911FFFF115A00   bypass_water_volume  6/9   90%
12:30:37.599  @TV:412807070909FFFF080911FFFF116400   bypass_water_volume  8/9  100%
12:30:38.417  @TV:412807070909FFFF090911FFFF116400   bypass_water_volume  9/9  100%
12:30:40.368  @TV:3E28                               ENJOY, complete
12:30:42.417  @TV:3E28                               ENJOY, complete
12:30:44.388  @TV:3E28                               ENJOY, complete
12:30:46.418  @TV:3E28                               ENJOY, complete
12:30:48.458  @TV:3E28                               ENJOY, complete
12:30:50.299  @TS
12:30:50.302  @TF:0004000000000000
```

Idle `@TF:0004000000000000` every ~2.05 s from there to the end of the
run (12:32:03.514).

The right-hand column is `ProductProgress.format()` output, not
annotation — that is what the library printed live, from a profile
loaded off the EF code, with no hand-holding.

### Cadence

* `@TV:` replaces `@TF:` for the duration of the brew. **Not one `@TF:`
  frame arrived between 12:29:58.687 and 12:30:50.302** — 51.6 s of
  silence on a broadcast that is otherwise metronomic. A consumer that
  watches `@TF:` for liveness will see a ~50 s gap during every brew and
  must not read it as a dead connection.
* `@TV:` then runs on the same ~2 s heartbeat, **plus** extra frames off
  the beat: 12:30:12.105 (0.14 s after the previous), 13.844, 16.912,
  23.266, 26.132, 32.918 (0.13 s). Most off-beat frames carry a changed
  percentage; 12:30:12.105 was byte-identical to its predecessor, so
  "extra frame ⇒ something changed" does **not** hold.
* Wall time `@TB` → `@TS`: 51.05 s. Grinding 6.1 s, water 23.3 s,
  bypass 7.7 s, then `ENJOY`.

---

## Per-state analysis

### `39` COFFEE_BEAN_AMOUNT — grinding — **confirmed**

```
payload  39 28 | 07 07 00 09 FF FF 00 09 11 FF FF 11 00 00
window          0  1  2  3  4  5  6  7  8  9 10 11 12 13
```

Window slots 0/1 = `07`/`07`, decoded as 7/7. This is the **configured
strength**, not a countdown: it never moves, and 7 is exactly the
strength in the live `cafe_barista` blob of PROTOCOL.md §5.9
(`@TP:28000709…`). Four frames over 6.1 s while the grinder ran, all
identical, percentage still `00`.

Confirms: window slots 0/1 are actual/max coffee strength; state `39`
reads them; `@TB` marks the start.

### `3C` COFFEE_WATER_AMOUNT — the shot — **confirmed**

Window slots 2/3 = payload bytes **4/5**, tick and target. The target
byte is `09` throughout: 9 ticks × 5 ml = **45 ml**, the water amount in
the §5.9 blob. The tick climbs `0 → 9` over 16 frames.

It climbs **0,0,0,0,0,1,2,3,4,5,5,7,7,8,9** — the machine skipped 6.
Values are reported, not interpolated; do not smooth them.

### `41` — the bypass branch — **confirmed, and it corrects the doc**

This was the shakiest rule in the decoder: state `41` is overloaded, and
the APK says read window slots 2/3 (`HOTWATER_VOLUME`) when slot 6 is
`0xFF`, slots 6/7 (`BYPASS_WATER_VOLUME`) otherwise.

```
payload  41 28 | 07 07 09 09 FF FF 04 09 11 FF FF 11 50 00
window          0  1  2  3  4  5  6  7  8  9 10 11 12 13
                      └ 9/9 frozen ┘  └ 4/9 moving ┘
```

* Slot 6 was **not** `FF` (this recipe has a 45 ml bypass), so the
  decoder took the **bypass branch** — the branch that had no evidence
  at all before today.
* It is the correct branch: slots 6/7 move `0 → 9` while slots 2/3 sit
  frozen at `9/9` (the completed water phase). Had the decoder taken the
  `HOTWATER_VOLUME` branch it would have reported a dead 9/9 for the
  whole phase.
* Slot 7 = `09` = 9 ticks × 5 ml = **45 ml**, matching the bypass of the
  §5.9 blob exactly.
* Ticks: 0,1,1,4,6,8,9 — again with gaps.

**Correction to PROTOCOL.md §5.9/§5.10.** Both said the live `41`
frames put tick/target at payload bytes 4/5 — i.e. the
`HOTWATER_VOLUME` reading — and §5.10 concluded "on that firmware slot 6
was `0xFF`". This capture shows the opposite on the same machine with
the same product: during state `41` bytes 4/5 are **static**, and the
moving pair is bytes 8/9. Bytes 4/5 *are* the moving pair during state
`3C`, which is the likeliest origin of the earlier note. The
`[live for the 0xFF branch, APK-only for the bypass branch]` label was
backwards and is now fixed.

The `0xFF` (`HOTWATER_VOLUME`) branch remains **unobserved** — it needs
a product with no bypass, e.g. `hotwater_portion` (`0x0D`).

### `3E` ENJOY — **confirmed, and it is level-triggered**

`@TV:3E28` — a two-byte payload, no value window at all. Five repeats,
~2 s apart, until the machine went quiet.

For a consumer this is the important detail: **`is_complete` is a
state, not an event.** `ProductProgress.parse` returns
`complete: true` for each of the five, and anything that counts brews,
fires a notification or increments a statistic on `is_complete` must
edge-trigger (act on the transition into `ENJOY`) or it will act five
times per cup. `JuraClient.follow_progress()` already does the right
thing — it breaks on the first `ENJOY` — so the exposure is limited to
callers driving `iter_progress()` themselves.

The repeat count is not a constant to rely on: five is simply how many
fitted between completion and whatever cleared the state ~10 s later.

### Percentage — **confirmed as a whole-product figure**

Window slot **12** — payload byte 14, the second-to-last byte of the
16-byte frame — exactly as the APK's odd `PERCENT_INDEX = 12` (not the
slot *named* `INTAKE_PERCENTAGE`, which is 11) implies.

```
00 … 0A 0A 14 14 1E 1E 28 28 32 32 3C   (state 3C, water)
3C 3C 46 50 5A 64 64                    (state 41, bypass)
```

Monotone, always a multiple of 10, `0x00 → 0x64` = 0 → 100 %. It ran
0→60 % across the water phase and 60→100 % across the bypass: **the
percentage is for the whole product and does not reset per phase.** A
progress bar should follow it directly and must not be recomputed from
`actual/maximum`, which *is* per-phase (`fraction` hits 1.0 twice).

### The constant bytes

Window slots 4/5 (milk time) and 9/10 (pause) were `FF FF` in every
frame — `cafe_barista` has neither parameter, so `FF` reads as "this
product does not use this slot". That is the same sentinel the `41`
disambiguation keys on, which is now a coherent story rather than a
guess.

Slots **8** and **11** both held a constant `0x11` (17) for the entire
brew, and slot 13 a constant `0x00`. Slot 8 is `max water temperature`
in the APK's table and slot 11 is `INTAKE_PERCENTAGE`; neither 17 is
explained by anything in the recipe (the blob's temperature byte was
`0x00`, and no percentage was 17). **Unexplained — recorded, not
guessed at.**

---

## The stray `@TS`

Ten seconds after the first `ENJOY` (1.84 s after the last), the machine
pushed a bare **`@TS`** — uppercase, no colon, no payload — and 3 ms
later resumed the `@TF:` idle broadcast. Nothing in the library sent
`@TS:01` or `@TS:00`; the watcher only ever sent the handshake.

What can be established:

* **J.O.E. has no handler for it.** `TCPReceiveHandler.a()` routes
  `@hu:…` to its pending parser, `@TV:.*` to `ProgressParser`, `@TF:.*`
  to `StatusParser`, and logs everything else as "no parser matched"
  before dropping it. There is no `@TB` or `@TS` string anywhere in the
  decompiled app.
* **It can be mistaken for a reply.** Before that fallthrough,
  `TCPReceiveHandler` checks the frame against the matcher of the
  command at the head of the waiting queue. `@TS:01` / `@TS:00` are the
  app's "Key block" / "Release screen" verbs (`CoffeeMachine.java`,
  BLE-flavour `n:01` / `n:00`, both matching `@ts`), so a pushed `@TS`
  arriving while such a command is in flight would be consumed as its
  reply. `jura_connect` is safe here only by accident of case:
  `lock_screen` / `unlock_screen` match `^@ts` and the push is
  uppercase.
* **The shape says "unsolicited marker", not "reply".** In this
  protocol machine-originated pushes are uppercase (`@TF:`, `@TV:`,
  `@TB`) and replies are lowercase (`@tf`, `@tv`, `@ts`). `@TS` is
  uppercase and payloadless, exactly like `@TB`.
* **The timing says "bookend".** `@TB` opened the run 19 ms before the
  first `@TV:`; `@TS` closed it 3 ms before the `@TF:` broadcast
  resumed. Nothing else in the 180 s window looks like either.

What cannot: **why** the machine sends it, or what state it announces.
Two readings fit the evidence and this capture cannot separate them —
"product finished / machine idle again" (`@TB` = begin, `@TS` = stop),
or "the panel is free again", which would make it the counterpart of the
`@TS:` key-block verb and consistent with PROTOCOL.md §5.1's long-
standing note that `@TS:01` answers **`@TB` then `@ts`** (i.e. `@TB` is
already known to fire for a *lock*, not only for a brew).

Recorded as an open question in PROTOCOL.md §9. Deciding it needs one
more capture: watch a `@TS:01` / `@TS:00` pair on an idle machine and
see whether a bare `@TS` follows the unlock.

---

## Verdicts

| Decode rule | Before | Now |
| --- | --- | --- |
| Value window starts at payload byte 2 | live (§5.9) | **confirmed** — every frame, three states |
| Percent at window slot 12 = second-to-last byte | APK, partial live | **confirmed** — 0x00→0x64, monotone |
| Percent is whole-product, not per-phase | assumed | **confirmed** — 0→60 % water, 60→100 % bypass |
| `39` COFFEE_BEAN_AMOUNT, slots 0/1 | APK, untested | **confirmed** — 7/7, matches the §5.9 strength |
| `3C` COFFEE_WATER_AMOUNT, slots 2/3 | APK, untested | **confirmed** — 0→9 ticks = 45 ml |
| `41` → BYPASS_WATER_VOLUME when slot 6 ≠ `FF`, slots 6/7 | APK, untested (and §5.10 claimed the *other* branch was the live one) | **confirmed** — 0→9 ticks = 45 ml bypass |
| `41` → HOTWATER_VOLUME when slot 6 = `FF`, slots 2/3 | claimed live | **still unobserved** — needs a bypass-free product |
| `3E` ENJOY ends the product | live (§5.9) | **confirmed**, and it repeats — level-triggered |
| `FF` in a window slot = parameter not used | inferred | **confirmed** — milk and pause slots, all frames |
| Product resolution: byte 1 `0x28` → `cafe_barista` via the EF1091 profile | APK, untested | **confirmed** — 32/32 frames |
| `ProgressType.PRODUCT` classification | APK, untested | **confirmed** — 32/32 frames |
| `@TB` = brew start | live (§5.9) | **confirmed** — 19 ms before the first `@TV:` |
| `@TF:` broadcast pauses for the whole brew | unknown | **new** — 51.6 s gap |
| bare `@TS` after a brew | unknown | **new, unexplained** — see above |
| Window slots 8 / 11 constant `0x11` | unknown | **new, unexplained** |
| `8F` extended window | APK, untested | **still untested** — never appeared |
| Milk / steam states (`31`–`37`, `42`, `43`) | APK, untested | **still untested** — no milk product brewed |
| Process / coffee-timer / P-mode / quality-assistant frames | APK, untested | **still untested** — none pushed |

## Machine state after the run

One `cafe_barista` brewed, by hand, by the maintainer — the counters
moved by exactly that one cup. The session sent nothing but the
handshake; the watcher was killed at 12:32:04 while the machine sat
idle, `coffee_ready`, on its normal `@TF:` broadcast.
