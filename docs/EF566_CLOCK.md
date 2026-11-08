### EF566 machine clock (GIGA 6)

The machine's own clock can be read with `client.read_clock()` and its date
with `client.read_clock_date()`. `client.read_clock_timers()` returns eight
validated on/off pairs (Monday through Sunday, then all-days) for callers
that need to guard a clock correction against scheduled events.

`client.set_clock(datetime.time(7, 20))` sends one local HH:MM value, requiring
a keypad lock and confirmed release. Seconds and timezone-aware values are
rejected before any I/O. The caller owns timezone/DST conversion, ready-state,
same-date and timer-window checks, and delayed readback/continued-running
verification. An ACK confirms receipt, not application; do not repeat a write
after an uncertain result. The date and timers are never written. The machine's
settings menu remains available. There is no network time service in this API.

Named commands: `machine-clock` (read) and `set-machine-clock 07:20` (requires
`--allow-destructive-commands`). The raw clock-write form is gated too.

**Hardware evidence is limited to one GIGA 6 / EF566.** On 6 November 2026,
a clock initially one hour ahead was corrected backwards and its continued
running verified; the date and all eight timer slots stayed unchanged.
Other models, including the maintainer's EF1091, are deliberately rejected.
An actual scheduled DST transition has not been observed on hardware; a
consumer such as Home Assistant can trigger this API when its UTC offset changes.

## Observed wire format

These slots were observed through the WiFi dongle of one EF566 on 5–6 November
2026. They are not declarations from the J.O.E. machine-settings XML and must
not be assumed to work on other profiles.

- `@TM:05`: `22 HH MM`, binary hours/minutes (not BCD). Example payload
  `220714` means 07:20. Write frame `@TM:05,2207143E`; ACK `@tm:05`.
- `@TM:06`: `23 YY MM DD`, year = 2000 + YY. `231A0B06` is 2026-11-06.
  Only reading the date has been validated; there is no date-write API.
- `14`–`1B`: eight `24 HH MM HH MM` on/off pairs; `80 00` disables a pair.
  The clock API reads these for consumer-side timer guards, never writes them.

Wrap the clock write in `@TS:01` / `@TS:00` and require the release ACK.
Application can lag the write ACK. Successful hardware verification read after
release at 0/3/6/10 seconds and confirmed continued running after a minute.
Earlier immediate-read tests saw stale values and did not establish failure
of the write itself. Host time conversion and automatic DST policy belong to
the caller; the wire takes minute-precision local wall time.

`set_clock(..., before_write=guard)` optionally runs a caller-provided check
after keypad locking and immediately before the single write. Raising from
the guard prevents that write and still runs the keypad-release transaction.
The callback should be quick and must not start another machine operation.
