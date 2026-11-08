### EF566 weekday switch-on timers (GIGA 6)

`client.read_weekday_timers()` reads the seven weekday slots plus all-days.
`client.set_weekday_timer("monday", datetime.time(6, 35))` changes only Monday's
switch-on time; `None` disables that switch-on time. Existing switch-off times,
other weekdays, all-days, clock and date are preserved. The operation reads the
block before writing, refuses an active all-days schedule, confirms keypad
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
