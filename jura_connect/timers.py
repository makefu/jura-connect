"""GIGA 6 weekday switch-on settings, separate from the clock and coffee timer."""

from __future__ import annotations

import re
import time as wall_time
from dataclasses import dataclass, replace
from datetime import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import JuraClient

TIMER_MODEL = "EF566"
WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)
WEEKDAY_SLOTS = dict(
    zip(WEEKDAYS, (f"{n:02X}" for n in range(0x14, 0x1B)), strict=True)
)
ALL_DAYS_SLOT = "1B"
TIMER_SLOTS = (*WEEKDAY_SLOTS.values(), ALL_DAYS_SLOT)


def timer_minute(value: time) -> time:
    """Require a local time the machine can store without losing precision."""
    if value.second or value.microsecond or value.tzinfo is not None:
        raise ValueError("Select a local time with hours and minutes only")
    return value


def _parse_pair(pair: bytes) -> time | None:
    if pair == b"\x80\x00":
        return None
    return time(pair[0], pair[1])


def _encode_pair(value: time | None) -> bytes:
    if value is None:
        return b"\x80\x00"
    timer_minute(value)
    return bytes((value.hour, value.minute))


@dataclass(frozen=True, slots=True)
class TimerSlot:
    """The machine stores separate switch-on and switch-off pairs."""

    on: time | None
    off: time | None

    @classmethod
    def parse(cls, raw: str) -> TimerSlot:
        if not re.fullmatch(r"24[0-9a-fA-F]{8}", raw):
            raise ValueError("Invalid JURA timer payload")
        data = bytes.fromhex(raw)
        return cls(_parse_pair(data[1:3]), _parse_pair(data[3:5]))

    def encode(self) -> str:
        return "24" + (_encode_pair(self.on) + _encode_pair(self.off)).hex().upper()

    def format(self) -> str:
        return f"on={self.on.isoformat(timespec='minutes') if self.on else 'off'}, off={self.off.isoformat(timespec='minutes') if self.off else 'off'}"

    def to_dict(self) -> dict[str, str | None]:
        return {
            "on": self.on.isoformat() if self.on else None,
            "off": self.off.isoformat() if self.off else None,
        }

    def with_on(self, on: time | None) -> TimerSlot:
        return replace(self, on=on)


@dataclass(frozen=True, slots=True)
class TimerUpdate:
    """Verified state with the previously active time for disabling."""

    slots: dict[str, TimerSlot]
    previous_on: time | None

    def format(self) -> str:
        return "\n".join(
            f"{day}: {self.slots[slot].format()}" for day, slot in WEEKDAY_SLOTS.items()
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "weekdays": {
                day: self.slots[slot].to_dict() for day, slot in WEEKDAY_SLOTS.items()
            },
            "all_days": self.slots[ALL_DAYS_SLOT].to_dict(),
            "previous_on": self.previous_on.isoformat() if self.previous_on else None,
        }


def _supported(client: JuraClient) -> None:
    if client.profile is None or client.profile.code != TIMER_MODEL:
        raise ValueError("Weekday timers are only verified for EF566")


def read_timers(client: JuraClient, *, timeout: float) -> dict[str, TimerSlot]:
    _supported(client)
    return {
        slot: TimerSlot.parse(client.read_setting(slot, timeout=timeout))
        for slot in TIMER_SLOTS
    }


def set_timer(
    client: JuraClient, day: str, on: time | None, *, timeout: float
) -> TimerUpdate:
    """Change one weekday's switch-on time, preserving the whole remaining block.

    None disables only switch-on. Never writes the all-days slot, switch-off,
    the clock or date. A fresh read is required after an uncertain result;
    this transaction never retries a write.
    """
    from .client import _settings_checksum

    _supported(client)
    if day not in WEEKDAY_SLOTS:
        raise ValueError("Expected a weekday name, monday through sunday")
    if on is not None:
        timer_minute(on)
    before = read_timers(client, timeout=timeout)
    if before[ALL_DAYS_SLOT] != TimerSlot(None, None):
        raise ValueError("Clear the all-days timer on the JURA before editing weekdays")
    slot = WEEKDAY_SLOTS[day]
    desired = before[slot].with_on(on)
    if desired == before[slot]:
        return TimerUpdate(before, before[slot].on)
    body = f"{slot},{desired.encode()}"
    try:
        if (
            client.request("@TS:01", match=r"^@(ts|an)(?::|$)", timeout=timeout)
            != "@ts"
        ):
            raise ValueError("Machine rejected the keypad lock")
        reply = client.request(
            f"@TM:{body}{_settings_checksum(body)}",
            match=r"(?i)^@(tm|an):",
            timeout=timeout,
        )
        if reply.lower() != f"@tm:{slot.lower()}":
            raise ValueError("Machine rejected the weekday timer write")
    finally:
        try:
            unlocked = client.request(
                "@TS:00", match=r"^@(ts|an)(?::|$)", timeout=timeout
            )
        except OSError as err:
            raise ValueError(
                "Machine timer result unknown: keypad unlock not confirmed"
            ) from err
        if unlocked != "@ts":
            raise ValueError(
                "Machine timer result unknown: keypad unlock not confirmed"
            )
    # ACK only confirms receipt. Poll reads, never repeat the write.
    anchor = wall_time.monotonic()
    for offset in (0.25, 1, 3, 6, 10, 15):
        wall_time.sleep(max(0, anchor + offset - wall_time.monotonic()))
        if TimerSlot.parse(client.read_setting(slot, timeout=timeout)) == desired:
            break
    else:
        raise ValueError("Machine did not confirm the weekday timer change")
    verified = read_timers(client, timeout=timeout)
    if verified != {**before, slot: desired}:
        raise ValueError("Machine timer readback differs from the expected timer block")
    return TimerUpdate(verified, before[slot].on)
