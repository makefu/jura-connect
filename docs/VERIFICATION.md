# Verification status

How well each area of `jura-connect` is verified. This is the thing
worth knowing before you point the library at your machine. The
command catalogue lives in [COMMANDS.md](COMMANDS.md); per-area
protocol derivations in [PROTOCOL.md](PROTOCOL.md) and the gap
scoreboard in [JOE_GAPS.md](JOE_GAPS.md). Which physical models were
tested by whom is in the README's supported-machines table.

## Verified against physical hardware

A JURA S8 EB / EF1091 running TT237W V06.11, plus an E6 for the brew
blob, a Z10/EF545 for the milk parameters, and a GIGA 6/EF566 for the
twin-grinder ratio. The raw frames behind the captured rows are in
[`captures/`](captures/):

| Capability | Status |
| --- | --- |
| UDP/51515 broadcast discovery + parser | ✓ ; falls back to TCP-port-sweep on the TT237W firmware which doesn't reply to UDP |
| Wire framing (`* … \r\n`) and obfuscation cipher | ✓ ; 2 000-input random round-trip + every key value exhaustively tested |
| `@HP:` handshake, pairing (with or without a setup PIN), credential storage | ✓ |
| Read commands: maintenance counters, maintenance %, machine status / alerts, per-product brew counters, screen lock/unlock | ✓ |
| Per-machine profiles — 89 bundled XMLs from the J.O.E. APK; alert names + product codes are looked up per `EF_code` so a Cortado on an S8 EB names itself, not `0x2B=2` | ✓ |
| Machine settings: single-setting read and checksummed write | ✓ |
| Brewing by product name — `brew hotwater water=220 temp=high` — with water / strength / temperature / bypass overrides validated against the machine XML | ✓ ; the `@TP:` recipe-blob format is verified by physically brewing, see §5.9 of [PROTOCOL.md](PROTOCOL.md) |
| Twin-grinder ratio (`GRINDER_RATIO`, F2) | ✓ on a GIGA 6 / EF566; `100_0=00` selects the left hopper only and `0_100=04` the right hopper only ; no raw trace — physical observation, see [EF566_GRINDER_RATIO.md](EF566_GRINDER_RATIO.md) |
| Product progress — `@TV:` decoding, `brew(follow=True)`, `progress` | ✓ **for the coffee path**: a whole `cafe_barista` decoded frame-for-frame (grind → water → bypass → `ENJOY`), percentage, product resolution. Milk, steam and the maintenance states are *not* covered — see the second table |
| Live per-product limits (`@TM:60`) | ✓ ; seven products, checksum required and accepted |
| Milk-cooler **status** read (`@HU?`) | ✓ ; `@hu:800` = no cooler connected. The *update* verb is untested |
| Counter-bank probe (`--probe`) | ✓ ; an S8 EB serves `@TR:52` while declaring only `@TR:32`, so an XML declaration is a lower bound. The slot→name map is still unverified |

## Implemented, simulator-verified, never run against hardware

| Capability | Wire | Doc |
| --- | --- | --- |
| The other 83 progress states — milk, steam, maintenance, the `8F` window | `@TV:` | §5.10 |
| Interactive maintenance processes (start, watch, confirm, advance) | `@TG:01` / `@TG:04` / `@TG:10` | §5.11 |
| Barista and daily counter banks + daily reset; the `@TR:52` slot→name map | `@TR:34/35/42..45`, `@TF:05` | §5.5 |
| Batch settings read — the address is *confirmed absent* on an S8 EB, so the reply layout remains a guess with a per-setting fallback | `@TM:00,FC` | §5.7 |
| Programmable-recipe (PMode) writes | `@TM:41` / `@TM:42` | §5.6 |
| Brew preselections (extra shot, double, powder, cold brew, sweet foam) | `@TP:` mask / overwrites | §5.13 |
| Coffee timer (scheduled brew) | `@TM:3C` + `@TV:84` | §5.12 |
| Language download **transfer** (a machine that declares no support was seen to answer `@TT:00` with silence) | `@TS:F1` / `@TT:xx` / `@TV:8x` | §5.14 |
| Milk cooler **update**, dongle restart, dongle firmware OTA | `@HU` / `@HT:3` / `@HB`…`@HE` | §5.15 |

Section numbers in the `Doc` column refer to
[PROTOCOL.md](PROTOCOL.md).

> ### ⚠ Read this before using anything in the second table
>
> Everything in it was reverse-engineered from the J.O.E. Android APK
> and is exercised only against `jura_connect.simulator` — a TCP server
> in this repo that speaks the same protocol. **The simulator's replies
> were written from the same APK reading as the client's expectations,
> so a shared misreading passes both halves of the test-suite.** No byte
> in that table has been confirmed by a real Jura machine.
>
> That is not a theoretical worry. The first hardware session found four
> such misreadings within an hour — a settings bank that does not exist
> on the machine, a command that answers with silence rather than a
> rejection, a bank-register read that cannot work at all, and a pushed
> frame the client could mistake for a reply. Everything in the first
> table earned its place; nothing in the second has yet.
>
> Practically: a wrong preselection or recipe byte **misbrews**, a
> maintenance confirmation sent at the wrong moment **consumes a
> cleaning tablet**, an interrupted language download leaves a language
> slot showing garbage, and the firmware OTA can **brick the WiFi
> dongle with no remote recovery** (which is why it has no CLI command
> at all and is gated behind `acknowledge_bricking_risk=True` in
> Python). The first table is what you can rely on.
>
> [JOE_GAPS.md](JOE_GAPS.md) §9 enumerates every unverified area, what
> breaks if it is wrong, and the cheapest read-only experiments that
> would settle it.
