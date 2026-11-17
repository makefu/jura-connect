### EF566 weekday switch-on timers (GIGA 6)

`client.read_weekday_timers()` reads the seven weekday slots plus all-days.
`client.set_weekday_timer("monday", datetime.time(6, 35))` changes only Monday's
switch-on time; `None` disables that switch-on time. Existing switch-off times,
other weekdays, all-days, clock and date are preserved. The operation reads the
block before writing, refuses any configured all-days schedule, confirms keypad
release and polls for delayed application before comparing the full block.
It sends at most one write. Read back after an uncertain result; never retry
blindly. UI staging of a disabled time remains the consumer's responsibility.

The library provides `TimerSlot` (typed on/off values) and `TimerUpdate`
(verified block and previous switch-on time), with `format()` and `to_dict()`.
Named commands: `weekday-timers` and `set-weekday-timer monday 06:35` (or `off`).
The setter and raw timer-write forms require the destructive-command gate.

**Hardware evidence is limited to one GIGA 6 / EF566.** One slot was changed
from 06:30 to 06:35 and restored; delayed readback and unchanged remaining
slots were verified. The combined Home Assistant candidate also confirmed a
timer edit and weekday display. Every weekday's complete switching sequence
has not been individually observed on hardware. Other models are rejected.

## Observed wire format

These slots were observed through the WiFi dongle of one EF566 on 5–6 November
2026. They are not declarations from the J.O.E. machine-settings XML and must
not be assumed to work on other profiles.

Slots `14`–`1A` correspond to Monday–Sunday; `1B` is all-days. Each
payload is `24 <on-hour> <on-minute> <off-hour> <off-minute>` with binary
values. `80 00` is the disabled marker for either time independently.
Example: `24061E1405` = on 06:30, off 20:05; `2480001405` disables switch-on
while retaining switch-off. Do not apply this marker interpretation to
unrelated registers such as `1E`.

Writes use the existing ASCII checksum over `<slot>,<payload>` and must be
wrapped in acknowledged keypad lock/release. The ACK is receipt only; poll
reads after unlocking, then compare the entire eight-slot block. The public
setter accepts named weekdays only and writes switch-on only, not all-days,
switch-off, clock or date. A configured all-days entry blocks editing.

## Shared implementation and failure details

This PR is stacked on the clock API in #18. Timer layout, disabled markers and
`SUPPORTED_TIMER_PROFILES` live in `timers.py`; the clock guard delegates to its
codec and reader. Only EF566 is allowed; EF566V2 and all other unverified variants
are rejected. Both setters use `settings.locked_setting_write`, including the
optional post-lock `before_write` guard and lossless primary-error handling.
See [EF566_CLOCK.md](EF566_CLOCK.md#failure-contract-and-supported-variants).

The read command returns `TimerRead` without update-only metadata and displays
all-days as well as all seven weekdays. `TimerUpdate` includes `previous_on` in
both text and JSON. All-days blocks edits when switch-on, switch-off, or both
are configured; the error names the configured pair(s).

`set_weekday_timer(..., total_timeout=60)` checks a shared budget before each
request and caps reply waits and polling sleeps. It is not a hard wall-clock
limit: sending retains the connection's existing transport timeout, and a caller
callback cannot be interrupted. Connect/authenticate before calling, serialize
operations on the session, configure bounded transport timeouts and keep the
guard prompt. Final keypad release gets its own per-request reply `timeout`,
even after the budget is exhausted. A guard/deadline rejection before writing
sends no setting write. Once sent, no write is retried.
`TimerVerificationError.last_observed` retains the last target observation;
a block mismatch lists every differing day/slot and its actual/expected values.
Timeouts remain `TimeoutError`, with notes naming the last target observation
when polling/verification times out.

Simulator `setting_write_reply` models rejection without applying a value.
`setting_write_timeout` models an applied write with a lost acknowledgement.
Collateral updates apply atomically with the primary value, including delayed
application. These are opt-in fault models; ordinary defaults are unchanged.
