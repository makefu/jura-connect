"""EF566 timer layout and codec shared with machine-clock guards."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import JuraClient

SUPPORTED_TIMER_PROFILES = frozenset({"EF566"})
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


def require_supported(client: JuraClient) -> None:
    if client.profile is None or client.profile.code not in SUPPORTED_TIMER_PROFILES:
        raise ValueError("Clock and weekday timers are only verified for EF566")


def timer_minute(value: time) -> time:
    if (
        not isinstance(value, time)
        or value.second
        or value.microsecond
        or value.tzinfo is not None
    ):
        raise ValueError("Select local hours and minutes only")
    return value


def _parse_pair(pair: bytes) -> time | None:
    if pair == b"\x80\x00":
        return None
    if len(pair) != 2 or pair[0] >= 24 or pair[1] >= 60:
        raise ValueError(f"Invalid JURA timer time pair: {pair.hex().upper()}")
    return time(pair[0], pair[1])


def _encode_pair(value: time | None) -> bytes:
    if value is None:
        return b"\x80\x00"
    timer_minute(value)
    return bytes((value.hour, value.minute))


@dataclass(frozen=True, slots=True)
class TimerSlot:
    """Separate local switch-on and switch-off pairs; 80 00 disables one."""

    on: time | None
    off: time | None

    @classmethod
    def parse(cls, raw: str) -> TimerSlot:
        if not re.fullmatch(r"24[0-9a-fA-F]{8}", raw):
            raise ValueError(f"Invalid JURA timer payload: {raw!r}")
        data = bytes.fromhex(raw)
        return cls(_parse_pair(data[1:3]), _parse_pair(data[3:5]))

    def encode(self) -> str:
        return "24" + (_encode_pair(self.on) + _encode_pair(self.off)).hex().upper()

    def format(self) -> str:
        on = self.on.isoformat(timespec="minutes") if self.on else "off"
        off = self.off.isoformat(timespec="minutes") if self.off else "off"
        return f"on={on}, off={off}"

    def to_dict(self) -> dict[str, str | None]:
        return {
            "on": self.on.isoformat() if self.on else None,
            "off": self.off.isoformat() if self.off else None,
        }

    def with_on(self, on: time | None) -> TimerSlot:
        return replace(self, on=on)


def read_timers(client: JuraClient, *, timeout: float) -> dict[str, TimerSlot]:
    require_supported(client)
    slots = {}
    for slot in TIMER_SLOTS:
        try:
            slots[slot] = TimerSlot.parse(client.read_setting(slot, timeout=timeout))
        except ValueError as exc:
            raise ValueError(f"JURA timer slot {slot}: {exc}") from exc
    return slots
