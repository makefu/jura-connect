"""EF566 timer layout and codec shared with machine-clock guards."""

from __future__ import annotations

import math
import re
import time as wall_time
from collections.abc import Callable
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


def read_timers(
    client: JuraClient, *, timeout: float, deadline: float | None = None
) -> dict[str, TimerSlot]:
    require_supported(client)
    slots = {}
    for slot in TIMER_SLOTS:
        try:
            slots[slot] = TimerSlot.parse(
                client.read_setting(slot, timeout=_remaining(timeout, deadline))
            )
        except ValueError as exc:
            raise ValueError(f"JURA timer slot {slot}: {exc}") from exc
    return slots


@dataclass(frozen=True, slots=True)
class TimerRead:
    """Complete weekday/all-days snapshot without update-only metadata."""

    slots: dict[str, TimerSlot]

    def format(self) -> str:
        labels = {**WEEKDAY_SLOTS, "all_days": ALL_DAYS_SLOT}
        return "\n".join(
            f"{day}: {self.slots[slot].format()}" for day, slot in labels.items()
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "weekdays": {
                day: self.slots[slot].to_dict() for day, slot in WEEKDAY_SLOTS.items()
            },
            "all_days": self.slots[ALL_DAYS_SLOT].to_dict(),
        }


@dataclass(frozen=True, slots=True)
class TimerUpdate(TimerRead):
    """Verified snapshot with the previous switch-on value of the edited day."""

    previous_on: time | None

    def format(self) -> str:
        previous = (
            self.previous_on.isoformat(timespec="minutes")
            if self.previous_on
            else "off"
        )
        return TimerRead.format(self) + f"\nprevious_on: {previous}"

    def to_dict(self) -> dict[str, object]:
        return {
            **TimerRead.to_dict(self),
            "previous_on": self.previous_on.isoformat() if self.previous_on else None,
        }


class TimerVerificationError(ValueError):
    """Readback did not match; retain the target observation for consumers."""

    def __init__(self, message: str, last_observed: TimerSlot | None) -> None:
        super().__init__(message)
        self.last_observed = last_observed


def _remaining(timeout: float, deadline: float | None) -> float:
    if deadline is None:
        return timeout
    remaining = deadline - wall_time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Weekday timer total deadline exceeded")
    return min(timeout, remaining)


def set_timer(
    client: JuraClient,
    day: str,
    on: time | None,
    *,
    timeout: float,
    total_timeout: float = 60.0,
    before_write: Callable[[], None] | None = None,
) -> TimerUpdate:
    """Change one weekday switch-on value; never retry an uncertain write.

    The budget is checked before each request and caps reply waits and polling.
    Sending retains the connection's existing transport timeout; this is not a
    hard wall-clock deadline. Final release gets a separate reply timeout even
    after budget exhaustion. Callers must connect/authenticate first, use bounded
    transport timeouts, serialize operations and keep their guard prompt.
    """
    from .settings import locked_setting_write

    require_supported(client)
    if not isinstance(day, str) or day not in WEEKDAY_SLOTS:
        raise ValueError("Expected a weekday name, monday through sunday")
    if on is not None:
        timer_minute(on)
    if not math.isfinite(total_timeout) or total_timeout <= 0:
        raise ValueError("total_timeout must be finite and positive")
    deadline = wall_time.monotonic() + total_timeout
    before = read_timers(client, timeout=timeout, deadline=deadline)
    all_days = before[ALL_DAYS_SLOT]
    if all_days != TimerSlot(None, None):
        configured = ", ".join(
            name
            for name, value in (
                ("switch-on", all_days.on),
                ("switch-off", all_days.off),
            )
            if value is not None
        )
        raise ValueError(
            f"Clear the configured all-days {configured} timer on the JURA before editing weekdays"
        )
    slot = WEEKDAY_SLOTS[day]
    desired = before[slot].with_on(on)
    if desired == before[slot]:
        return TimerUpdate(before, before[slot].on)
    body = f"{slot},{desired.encode()}"
    locked_setting_write(
        client, body, timeout=timeout, before_write=before_write, deadline=deadline
    )
    last_observed = None
    anchor = wall_time.monotonic()
    try:
        for offset in (0.25, 1, 3, 6, 10, 15):
            delay = max(0.0, min(anchor + offset, deadline) - wall_time.monotonic())
            wall_time.sleep(delay)
            budget = _remaining(timeout, deadline)
            try:
                last_observed = TimerSlot.parse(
                    client.read_setting(slot, timeout=budget)
                )
            except ValueError as exc:
                raise ValueError(f"JURA timer slot {slot}: {exc}") from exc
            if last_observed == desired:
                break
        else:
            raise TimerVerificationError(
                f"Machine did not confirm weekday timer {day} (slot {slot}); last={last_observed!r}, expected={desired!r}; read back before retrying",
                last_observed,
            )
        verified = read_timers(client, timeout=timeout, deadline=deadline)
    except TimeoutError as exc:
        exc.add_note(
            f"Weekday write sent once; read back before retrying. Last target slot {slot}: {last_observed!r}"
        )
        raise
    last_observed = verified[slot]
    expected = {**before, slot: desired}
    differences = [
        f"{name} ({address}): got {verified[address].format()}, expected {expected[address].format()}"
        for name, address in {**WEEKDAY_SLOTS, "all_days": ALL_DAYS_SLOT}.items()
        if verified[address] != expected[address]
    ]
    if differences:
        raise TimerVerificationError(
            "Machine timer block differs after target confirmation: "
            + "; ".join(differences),
            last_observed,
        )
    return TimerUpdate(verified, before[slot].on)
