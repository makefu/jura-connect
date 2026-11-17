"""EF566 machine clock protocol, verified on one GIGA 6.

This is the machine's clock, not the separate scheduled-product coffee timer.
The caller supplies local wall time and owns timezone/DST policy. No NTP or
date write is involved. A write acknowledgement alone does not prove that the
machine has applied the setting: callers must verify after unlocking.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date, time
from typing import TYPE_CHECKING

from . import timers
from .settings import locked_setting_write

if TYPE_CHECKING:
    from .client import JuraClient

SUPPORTED_CLOCK_PROFILES = timers.SUPPORTED_TIMER_PROFILES
TIMER_ADDRESSES = timers.TIMER_SLOTS
TimerTimes = tuple[time | None, time | None]


def require_supported(client: JuraClient) -> None:
    timers.require_supported(client)


def _tagged(raw: str, tag: int, length: int) -> bytes:
    if len(raw) != 2 * (length + 1):
        raise ValueError("Unexpected machine clock/date/timer payload length")
    try:
        data = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid machine clock/date payload: {raw!r}") from exc
    if len(data) != length + 1 or data[0] != tag:
        raise ValueError("Unexpected machine clock/date/timer payload tag")
    return data[1:]


def parse_clock(raw: str) -> time:
    hour, minute = _tagged(raw, 0x22, 2)
    if hour >= 24 or minute >= 60:
        raise ValueError(f"Invalid JURA clock slot 05 payload: {raw!r}")
    return time(hour, minute)


def parse_date(raw: str) -> date:
    year, month, day = _tagged(raw, 0x23, 3)
    if year > 99:
        raise ValueError("Unexpected machine clock year")
    try:
        return date(2000 + year, month, day)
    except ValueError as exc:
        raise ValueError(f"Invalid JURA date slot 06 payload: {raw!r}") from exc


def parse_timer(raw: str) -> TimerTimes:
    slot = timers.TimerSlot.parse(raw)
    return slot.on, slot.off


def read_clock(client: JuraClient, *, timeout: float) -> time:
    require_supported(client)
    return parse_clock(client.read_setting("05", timeout=timeout))


def read_date(client: JuraClient, *, timeout: float) -> date:
    require_supported(client)
    return parse_date(client.read_setting("06", timeout=timeout))


def read_timers(client: JuraClient, *, timeout: float) -> tuple[TimerTimes, ...]:
    """Read on/off pairs for the seven weekdays and the all-days slot."""
    slots = timers.read_timers(client, timeout=timeout)
    return tuple((slots[n].on, slots[n].off) for n in TIMER_ADDRESSES)


def set_clock(
    client: JuraClient,
    value: time,
    *,
    timeout: float,
    before_write: Callable[[], None] | None = None,
) -> str:
    """Send one minute-precision clock write, requiring a confirmed unlock.

    Caller must ensure a ready machine, a matching date and a safe distance
    from midnight and timer events. Never retry this call after an uncertain
    reply: read the clock first. The machine's own clock menu still works.
    A caller guard may reject the write after locking; unlocking still runs.
    """
    require_supported(client)
    timers.timer_minute(value)
    body = f"05,22{value.hour:02X}{value.minute:02X}"
    return locked_setting_write(
        client, body, timeout=timeout, before_write=before_write
    )
