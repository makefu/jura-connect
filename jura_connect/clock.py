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

if TYPE_CHECKING:
    from .client import JuraClient

TIMER_ADDRESSES = tuple(f"{n:02X}" for n in range(0x14, 0x1C))
TimerTimes = tuple[time | None, time | None]


def require_supported(client: JuraClient) -> None:
    if client.profile is None or client.profile.code != "EF566":
        raise ValueError("Machine clock support is only verified for EF566")


def _tagged(raw: str, tag: int, length: int) -> bytes:
    if len(raw) != 2 * (length + 1):
        raise ValueError("Unexpected machine clock/date/timer payload length")
    data = bytes.fromhex(raw)
    if len(data) != length + 1 or data[0] != tag:
        raise ValueError("Unexpected machine clock/date/timer payload tag")
    return data[1:]


def parse_clock(raw: str) -> time:
    hour, minute = _tagged(raw, 0x22, 2)
    return time(hour, minute)


def parse_date(raw: str) -> date:
    year, month, day = _tagged(raw, 0x23, 3)
    if year > 99:
        raise ValueError("Unexpected machine clock year")
    return date(2000 + year, month, day)


def parse_timer(raw: str) -> TimerTimes:
    data = _tagged(raw, 0x24, 4)

    def pair(hour: int, minute: int) -> time | None:
        return None if (hour, minute) == (0x80, 0) else time(hour, minute)

    return pair(data[0], data[1]), pair(data[2], data[3])


def read_clock(client: JuraClient, *, timeout: float) -> time:
    require_supported(client)
    return parse_clock(client.read_setting("05", timeout=timeout))


def read_date(client: JuraClient, *, timeout: float) -> date:
    require_supported(client)
    return parse_date(client.read_setting("06", timeout=timeout))


def read_timers(client: JuraClient, *, timeout: float) -> tuple[TimerTimes, ...]:
    """Read on/off pairs for the seven weekdays and the all-days slot."""
    require_supported(client)
    return tuple(
        parse_timer(client.read_setting(n, timeout=timeout)) for n in TIMER_ADDRESSES
    )


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
    from .client import _settings_checksum

    require_supported(client)
    if (
        not isinstance(value, time)
        or value.second
        or value.microsecond
        or value.tzinfo is not None
    ):
        raise ValueError("Machine clock requires local hours and minutes only")
    body = f"05,22{value.hour:02X}{value.minute:02X}"
    try:
        if (
            client.request("@TS:01", match=r"^@(ts|an)(?::|$)", timeout=timeout)
            != "@ts"
        ):
            raise ValueError("Machine rejected the keypad lock")
        if before_write is not None:
            before_write()
        reply = client.request(
            f"@TM:{body}{_settings_checksum(body)}",
            match=r"(?i)^@(tm|an):",
            timeout=timeout,
        )
        if reply.lower() != "@tm:05":
            raise ValueError("Machine did not acknowledge the clock write")
        return reply
    finally:
        try:
            unlocked = client.request(
                "@TS:00", match=r"^@(ts|an)(?::|$)", timeout=timeout
            )
        except OSError as err:
            raise ValueError(
                "Machine clock result unknown: keypad unlock not confirmed"
            ) from err
        if unlocked != "@ts":
            raise ValueError(
                "Machine clock result unknown: keypad unlock not confirmed"
            )
