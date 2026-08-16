"""Decoder for the ``@TV:`` product-progress frame.

The machine pushes ``@TV:<hex>`` frames unsolicited while it is doing
something: brewing a product, running a maintenance process, counting
down a coffee-timer, showing an aroma preselection. Each frame is a
snapshot of one *progress state* plus a window of live recipe values
(current / target / percent).

Provenance
----------

The byte layout is **APK-derived** — read out of ``Progress``,
``ProgressParser``, ``ProgressState``, ``ProductProgressState`` and
``ProductArgument`` in the decompiled J.O.E. app (``ch.toptronic.joe``
4.6.10) — and the **coffee path is hardware-confirmed**. A full raw
capture of a hand-started ``cafe_barista`` on an S8 EB / EF1091
(``docs/captures/2026-08-16-kaffeebert-brew-progress.md``) decoded all
32 of its ``@TV:`` frames with zero failures, pinning: the value window
starting at payload byte 2, the percent index (``values[12]``, the
second-to-last byte of a 16-byte frame), states ``39`` / ``3C`` / ``41``
/ ``3E``, product resolution off byte 1, and the ``41`` →
``BYPASS_WATER_VOLUME`` branch below. ``tests/test_progress_capture.py``
replays those frames verbatim.

Untested against hardware: the milk and steam states, the ``8F``
extended window, the ``0xFF`` / ``HOTWATER_VOLUME`` branch of ``41``,
and every non-product frame type — see ``docs/PROTOCOL.md`` §5.10.

Design notes for consumers (e.g. the Home Assistant integration):

* nothing raises on an unknown state code — :attr:`ProductProgress.state`
  is simply ``None`` and :attr:`ProductProgress.state_code` keeps the raw
  byte;
* a short/truncated payload yields ``None`` for the values it cannot
  reach rather than an exception;
* :meth:`ProductProgress.to_dict` is JSON-serialisable end to end, and
  :meth:`ProductProgress.format` is the human one-liner;
* ``@TV:81,`` / ``@TV:82,`` (language-download display lines) and
  ``@TV:84,`` (coffee-timer clock sync) are *not* progress frames.
  :func:`is_progress_frame` filters them; :meth:`ProductProgress.parse`
  raises :class:`ValueError` if one is fed to it anyway.
"""

from __future__ import annotations

import dataclasses
import enum

from .profile import MachineProfile

_PREFIX = "@TV:"


class ProgressState(enum.IntEnum):
    """Every ``ProgressState`` the J.O.E. app knows (87 codes).

    The value is the raw byte 0 of the ``@TV:`` payload. Use
    :meth:`from_code` for a total lookup that returns ``None`` instead of
    raising on a code this firmware family invented.
    """

    INVALID = 0x00
    INSERT_TRAY = 0x01
    FILL_WATERTANK = 0x02
    EMPTY_GROUNDS = 0x03
    EMPTY_TRAY = 0x04
    INSERT_GROUNDS_BOX = 0x08
    CLOSE_NOZZLE_COVER = 0x09
    CLOSE_BEAN_COVER = 0x0A
    CLOSE_TAP = 0x0C
    OPEN_TAP = 0x0D
    ALARM = 0x0E
    CLOSE_POWDER_COVER = 0x0F
    ADD_POWDER_COFFEE = 0x10
    FILLING_PROCESS = 0x11
    SYSTEM_EMPTYING = 0x12
    ADD_BEANS = 0x13
    NOT_ENOUGH_POWDER = 0x14
    WAITING = 0x15
    REMOVE_WATERTANK = 0x16
    MOUNT_SIRUP_CONTAINER = 0x17
    REMOVE_SIRUP_CONTAINER = 0x18
    SMART_ALERT = 0x19
    PLACE_CUP_FOR_COFFEE = 0x1E
    PLACE_CUP_FOR_CLEANING = 0x1F
    STARTUP = 0x20
    HEATING_UP = 0x21
    RINSE_PROCESS = 0x23
    POPUP_WINDOW = 0x30
    MILK_FOAM_BEAN_AMOUNT = 0x31
    MILK_FOAM_MILK_VOLUME = 0x32
    MILK_FOAM_PAUSE = 0x33
    MILK_FOAM_VOLUME = 0x34
    MILK_FOAM_WATER_VOLUME = 0x37
    MILK_FOAM_NO_ADJUSTMENT = 0x38
    COFFEE_BEAN_AMOUNT = 0x39
    COFFEE_WATER_AMOUNT = 0x3C
    COFFEE_NO_ADJUSTMENT = 0x3D
    ENJOY = 0x3E
    HOTWATER_TEMPERATURE = 0x40
    HOTWATER_VOLUME = 0x41
    STEAM_TIME = 0x42
    STEAM_TEMPERATURE = 0x43
    LAST_PROGRESS_STATE = 0x49
    GRINDER_SETTING_REQUEST = 0x4B
    DESCALIFY_START = 0x50
    DESCALIFY_MATERIALS = 0x51
    DESCALIFY_EMPTY_TRAY = 0x52
    DESCALIFY_ADD_FLUID = 0x53
    DESCALIFY_PROCESS = 0x54
    DESCALIFY_RINSE_WATERTANK = 0x55
    DESCALIFY_FINISH = 0x56
    DESCALIFY_CONNECT_THE_MILK_TUBE = 0x5A
    FILTER_RINSE_START = 0x60
    FILTER_RINSE_MATERIALS = 0x61
    FILTER_RINSE_CHANGE = 0x62
    FILTER_RINSE_PROCESS = 0x63
    FILTER_RINSE_FINISH = 0x65
    FILTER_RINSE_REMOVE_FILTER = 0x66
    FILTER_RINSE_INSERT = 0x67
    CLEANING_START = 0x70
    CLEANING_MATERIALS = 0x71
    CLEANING_EMPTY_TRAY = 0x72
    CLEANING_PRESS_ROTARY = 0x73
    CLEANING_PROCESS = 0x74
    CLEANING_ADD_TABLET = 0x75
    CLEANING_FINISH = 0x76
    QUALITY_ASSISTANT = 0x7E
    CAPPU_CLEAN_START = 0x90
    CAPPU_CLEAN_MATERIALS = 0x91
    CAPPU_CLEAN_ADD_CLEANER = 0x92
    CAPPU_CLEAN_PROCESS = 0x93
    CAPPU_CLEAN_ADD_WATER = 0x94
    CAPPU_CLEAN_FINISH = 0x95
    CAPPU_CLEAN_RINSE_PROCESS = 0x9A
    COFFEE_TIMER_SCREEN_SAVER = 0xC0
    COFFEE_TIMER_STATUS_SCREEN = 0xC1
    COFFEE_TIMER = 0xC4
    COFFEE_TIMER_PMODE_COUNTDOWN = 0xC5
    WARNING = 0xE1
    ACTION = 0xE2
    INFO = 0xE3
    FILTER_ERROR = 0xE4
    FILTER_THANKS = 0xE5
    TOO_HOT = 0xE6
    WIFI_CONFIGURATION = 0xEF
    AROMA_PRESELECT = 0xFE
    P_MODE = 0xFF

    @classmethod
    def from_code(cls, code: int) -> ProgressState | None:
        """Total lookup: the state for ``code``, or ``None`` if unknown."""
        try:
            return cls(code)
        except ValueError:
            return None


class ProgressType(enum.Enum):
    """What the frame is *about* (J.O.E.'s ``Progress.Type``)."""

    PRODUCT = "product"
    PROCESS = "process"
    P_MODE = "p_mode"
    AROMA_PRESELECTION = "aroma_preselection"
    COFFEE_TIMER = "coffee_timer"
    QUALITY_ASSISTANT = "quality_assistant"
    NONE = "none"


class ProductProgressState(enum.Enum):
    """Which pair of value-window slots a progress state reports.

    ``actual_index`` / ``max_index`` index the value window (see
    :data:`PRODUCT_ARGUMENTS`), *not* the raw payload.
    """

    SMART_ALERT_PAUSE = "smart_alert_pause"
    STEAM_TEMPERATURE = "steam_temperature"
    HOTWATER_TEMPERATURE = "hotwater_temperature"
    HOTWATER_VOLUME = "hotwater_volume"
    BYPASS_WATER_VOLUME = "bypass_water_volume"
    COFFEE_BEAN_AMOUNT = "coffee_bean_amount"
    COFFEE_WATER_AMOUNT = "coffee_water_amount"
    MILK_FOAM_BEAN_AMOUNT = "milk_foam_bean_amount"
    MILK_FOAM_MILK_VOLUME = "milk_foam_milk_volume"
    MILK_FOAM_PAUSE = "milk_foam_pause"
    MILK_FOAM_VOLUME = "milk_foam_volume"
    MILK_FOAM_WATER_VOLUME = "milk_foam_water_volume"

    @property
    def actual_index(self) -> int:
        return _PRODUCT_STATE_INDICES[self][0]

    @property
    def max_index(self) -> int:
        return _PRODUCT_STATE_INDICES[self][1]


#: Value-window slot names, in index order (J.O.E.'s ``ProductArgument``).
PRODUCT_ARGUMENTS: tuple[str, ...] = (
    "actual_coffee_strength",
    "max_coffee_strength",
    "actual_water_volume",
    "max_water_volume",
    "actual_milk_time",
    "max_milk_time",
    "actual_milk_foam_time",  # doubles as steam temperature / bypass water
    "max_milk_foam_time",  # doubles as steam temperature / bypass water
    "max_water_temperature",
    "actual_pause_time",
    "max_pause_time",
    "intake_percentage",
    "milk_foam_temperature",
    "invalid",
)

_PRODUCT_STATE_INDICES: dict[ProductProgressState, tuple[int, int]] = {
    ProductProgressState.SMART_ALERT_PAUSE: (0, 1),
    ProductProgressState.STEAM_TEMPERATURE: (6, 7),
    ProductProgressState.HOTWATER_TEMPERATURE: (8, 8),
    ProductProgressState.HOTWATER_VOLUME: (2, 3),
    ProductProgressState.BYPASS_WATER_VOLUME: (6, 7),
    ProductProgressState.COFFEE_BEAN_AMOUNT: (0, 1),
    ProductProgressState.COFFEE_WATER_AMOUNT: (2, 3),
    ProductProgressState.MILK_FOAM_BEAN_AMOUNT: (0, 1),
    ProductProgressState.MILK_FOAM_MILK_VOLUME: (4, 5),
    ProductProgressState.MILK_FOAM_PAUSE: (9, 10),
    ProductProgressState.MILK_FOAM_VOLUME: (6, 7),
    ProductProgressState.MILK_FOAM_WATER_VOLUME: (2, 3),
}

#: state code -> the value pair it reports.
_STATE_TO_PRODUCT_STATE: dict[int, ProductProgressState] = {
    ProgressState.SMART_ALERT: ProductProgressState.SMART_ALERT_PAUSE,
    ProgressState.MILK_FOAM_BEAN_AMOUNT: ProductProgressState.MILK_FOAM_BEAN_AMOUNT,
    ProgressState.MILK_FOAM_MILK_VOLUME: ProductProgressState.MILK_FOAM_MILK_VOLUME,
    ProgressState.MILK_FOAM_PAUSE: ProductProgressState.MILK_FOAM_PAUSE,
    ProgressState.MILK_FOAM_VOLUME: ProductProgressState.MILK_FOAM_VOLUME,
    ProgressState.MILK_FOAM_WATER_VOLUME: ProductProgressState.MILK_FOAM_WATER_VOLUME,
    ProgressState.COFFEE_BEAN_AMOUNT: ProductProgressState.COFFEE_BEAN_AMOUNT,
    ProgressState.COFFEE_WATER_AMOUNT: ProductProgressState.COFFEE_WATER_AMOUNT,
    ProgressState.HOTWATER_TEMPERATURE: ProductProgressState.HOTWATER_TEMPERATURE,
    ProgressState.HOTWATER_VOLUME: ProductProgressState.HOTWATER_VOLUME,
    ProgressState.STEAM_TEMPERATURE: ProductProgressState.STEAM_TEMPERATURE,
}

#: Maintenance-process codes, i.e. the tail of a ``<PROCESS
#: ExecuteCommand="@TG:xx">`` element. J.O.E. resolves byte 1 of a
#: process frame against exactly this set (``CoffeeMachine.b()`` splits
#: ExecuteCommand on ``:``); all 89 bundled machine XMLs use only these
#: six, so the table is machine-independent.
PROCESS_CODES: dict[int, str] = {
    0x21: "cappu_clean",
    0x22: "coffee_rinse",
    0x23: "cappu_rinse",
    0x24: "cleaning",
    0x25: "descale",
    0x26: "filter_change",
}

#: Byte 2 marker that pushes the value window one byte further in.
EXTENDED_WINDOW_MARKER = 0x8F
#: Value-window index J.O.E. reads the percentage from. Yes, 12 — the
#: slot *named* INTAKE_PERCENTAGE is 11. Mirror the app, don't "fix" it.
PERCENT_INDEX = 12
#: Value-window index that disambiguates state ``41`` (see :func:`parse`).
BYPASS_MARKER_INDEX = 6

_COFFEE_TIMER_STATES = frozenset(
    {
        ProgressState.COFFEE_TIMER_SCREEN_SAVER,
        ProgressState.COFFEE_TIMER_STATUS_SCREEN,
        ProgressState.COFFEE_TIMER,
        ProgressState.COFFEE_TIMER_PMODE_COUNTDOWN,
    }
)

#: ``@TV:`` head bytes that are NOT progress: 81/82 are language-download
#: display lines, 84 is the coffee-timer clock sync.
_NON_PROGRESS_HEADS = frozenset({0x81, 0x82, 0x84})


def is_progress_frame(reply: str) -> bool:
    """True when ``reply`` is a ``@TV:`` frame this module can decode.

    Rejects everything that is not ``@TV:``, the comma-delimited
    language-download / clock-sync frames (``@TV:81,…``, ``@TV:82,…``,
    ``@TV:84,…``) and any payload that is not whole hex bytes.
    """
    text = reply.strip()
    if not text.startswith(_PREFIX):
        return False
    body = text[len(_PREFIX) :]
    if len(body) < 2 or len(body) % 2 != 0:
        return False
    try:
        payload = bytes.fromhex(body)
    except ValueError:
        return False
    return payload[0] not in _NON_PROGRESS_HEADS


def _byte(values: bytes, index: int) -> int | None:
    """``values[index]`` or ``None`` when the payload is too short."""
    if 0 <= index < len(values):
        return values[index]
    return None


@dataclasses.dataclass(slots=True, frozen=True)
class ProductProgress:
    """One decoded ``@TV:`` progress frame.

    ``state`` is ``None`` for a code outside the known table (the raw
    byte survives in ``state_code``); ``actual`` / ``maximum`` /
    ``percent`` are ``None`` when the frame is too short to carry them.
    ``product`` / ``process`` are the resolved names for ``item_code``
    — ``product`` needs a :class:`~jura_connect.profile.MachineProfile`
    that knows the code, ``process`` comes from :data:`PROCESS_CODES`.
    """

    raw: str  # the frame as received, e.g. "@TV:4128…"
    payload: bytes  # decoded hex body
    state_code: int  # payload byte 0
    state: ProgressState | None
    progress_type: ProgressType
    item_code: int | None  # payload byte 1: product or process code
    product: str | None  # resolved product name (needs a profile)
    process: str | None  # resolved maintenance-process name
    product_state: ProductProgressState | None  # which values are reported
    actual: int | None
    maximum: int | None
    percent: int | None
    extended: bool  # byte 2 was the 0x8F window marker

    # -- derived -------------------------------------------------------
    @property
    def state_name(self) -> str:
        """``state.name`` or ``UNKNOWN(0x..)`` for an unmapped code."""
        if self.state is not None:
            return self.state.name
        return f"UNKNOWN(0x{self.state_code:02X})"

    @property
    def fraction(self) -> float | None:
        """``actual / maximum`` as a float, or ``None``.

        ``None`` when either side is missing or ``maximum`` is zero —
        the machine sends ``00`` maxima for parameters a product does
        not use, so this must never divide by zero.
        """
        if self.actual is None or not self.maximum:
            return None
        return self.actual / self.maximum

    @property
    def is_complete(self) -> bool:
        """True on the ``ENJOY`` (``3E``) frame that ends a product.

        This is a **state, not an event**: the captured S8 EB brew
        repeated ``@TV:3E28`` five times, ~2 s apart, until something
        cleared it (docs/captures/2026-08-16-kaffeebert-brew-progress.md).
        Anything that counts cups or fires a notification must
        edge-trigger on the transition into ``ENJOY``;
        :meth:`~jura_connect.client.JuraClient.follow_progress` already
        breaks on the first one, so only callers driving
        :meth:`~jura_connect.client.JuraClient.iter_progress`
        themselves are exposed.
        """
        return self.state is ProgressState.ENJOY

    @property
    def subject(self) -> str | None:
        """Resolved product or process name, whichever applies."""
        return self.product if self.product is not None else self.process

    # -- parsing -------------------------------------------------------
    @classmethod
    def parse(
        cls, reply: str, profile: MachineProfile | None = None
    ) -> ProductProgress:
        """Decode one ``@TV:`` frame.

        ``profile`` makes byte 1 resolvable: without it a product code
        cannot be recognised, so a product frame classifies as
        :attr:`ProgressType.NONE` (the value window still decodes).

        Raises :class:`ValueError` only for input that is not a progress
        frame at all (see :func:`is_progress_frame`) — never for an
        unknown state code or a truncated payload.
        """
        text = reply.strip()
        if not is_progress_frame(text):
            raise ValueError(
                f"not a decodable @TV: progress frame: {reply!r} "
                "(@TV:81/82/84 are language-download and clock-sync frames)"
            )
        payload = bytes.fromhex(text[len(_PREFIX) :])
        state_code = payload[0]
        state = ProgressState.from_code(state_code)
        item_code = payload[1] if len(payload) > 1 else None

        product: str | None = None
        if item_code is not None and profile is not None:
            definition = profile.product_by_code.get(item_code)
            product = definition.name if definition is not None else None
        process = PROCESS_CODES.get(item_code) if item_code is not None else None

        progress_type = _classify(state_code, product, process)

        # Value window: byte 2 onward, or byte 3 when byte 2 is the 8F
        # marker (product/process frames only).
        marker = _byte(payload, 2)
        extended = (
            progress_type in (ProgressType.PRODUCT, ProgressType.PROCESS)
            and marker == EXTENDED_WINDOW_MARKER
        )
        values = payload[3:] if extended else payload[2:]

        product_state = _product_state_for(state_code, values)
        if product_state is not None:
            actual = _byte(values, product_state.actual_index)
            maximum = _byte(values, product_state.max_index)
            percent = _byte(values, PERCENT_INDEX)
        elif extended:
            actual, maximum, percent = _byte(values, 0), _byte(values, 1), None
        else:
            actual, maximum, percent = _byte(values, 0), None, None

        return cls(
            raw=text,
            payload=payload,
            state_code=state_code,
            state=state,
            progress_type=progress_type,
            item_code=item_code,
            product=product,
            process=process,
            product_state=product_state,
            actual=actual,
            maximum=maximum,
            percent=percent,
            extended=extended,
        )

    # -- presentation --------------------------------------------------
    def format(self) -> str:
        """One human-readable line, e.g.
        ``COFFEE_WATER_AMOUNT  cafe_barista  water 9/30  50%``."""
        bits = [self.state_name]
        if self.product is not None:
            bits.append(self.product)
        elif self.process is not None:
            bits.append(f"process {self.process}")
        elif self.item_code:
            bits.append(f"0x{self.item_code:02X}")
        if self.actual is not None:
            span = f"{self.actual}/{self.maximum}" if self.maximum else f"{self.actual}"
            label = (
                self.product_state.value if self.product_state is not None else "value"
            )
            bits.append(f"{label} {span}")
        if self.percent is not None:
            bits.append(f"{self.percent}%")
        return "  ".join(bits)

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable snapshot (stable keys for API consumers)."""
        return {
            "raw": self.raw,
            "payload_hex": self.payload.hex().upper(),
            "state": self.state.name if self.state is not None else None,
            "state_code": f"{self.state_code:02X}",
            "progress_type": self.progress_type.value,
            "item_code": f"{self.item_code:02X}"
            if self.item_code is not None
            else None,
            "product": self.product,
            "process": self.process,
            "quantity": (
                self.product_state.value if self.product_state is not None else None
            ),
            "actual": self.actual,
            "maximum": self.maximum,
            "percent": self.percent,
            "fraction": (
                round(self.fraction, 4) if self.fraction is not None else None
            ),
            "extended": self.extended,
            "complete": self.is_complete,
        }


def _classify(
    state_code: int, product: str | None, process: str | None
) -> ProgressType:
    """Mirror ``Progress``'s type decision in the J.O.E. app.

    Order matters and is deliberately odd: the coffee-timer and
    quality-assistant states win outright; ``FE`` (aroma preselect)
    never counts as a product frame even when byte 1 *is* a product
    code; a process match beats the ``FE`` / ``FF`` fallbacks.
    """
    if state_code in _COFFEE_TIMER_STATES:
        return ProgressType.COFFEE_TIMER
    if state_code == ProgressState.QUALITY_ASSISTANT:
        return ProgressType.QUALITY_ASSISTANT
    if state_code != ProgressState.AROMA_PRESELECT and product is not None:
        return ProgressType.PRODUCT
    if process is not None:
        return ProgressType.PROCESS
    if state_code == ProgressState.AROMA_PRESELECT:
        return ProgressType.AROMA_PRESELECTION
    if state_code == ProgressState.P_MODE:
        return ProgressType.P_MODE
    return ProgressType.NONE


def _product_state_for(state_code: int, values: bytes) -> ProductProgressState | None:
    """Which value pair this state reports, ``None`` if it reports none.

    State ``41`` is overloaded: the app reads it as ``HOTWATER_VOLUME``
    (window slots 2/3) only when slot 6 is ``0xFF``, and as
    ``BYPASS_WATER_VOLUME`` (slots 6/7) otherwise — including when the
    payload is too short to carry slot 6.

    The bypass branch is hardware-confirmed (the captured
    ``cafe_barista`` had a 45 ml bypass, slot 6 was never ``0xFF``, and
    slots 6/7 climbed 0→9 while 2/3 stayed frozen at the finished water
    figure). The ``0xFF`` branch has never been observed.
    """
    mapped = _STATE_TO_PRODUCT_STATE.get(state_code)
    if state_code != ProgressState.HOTWATER_VOLUME:
        return mapped
    if _byte(values, BYPASS_MARKER_INDEX) == 0xFF:
        return mapped
    return ProductProgressState.BYPASS_WATER_VOLUME


@dataclasses.dataclass(slots=True, frozen=True)
class ProgressLog:
    """A collected run of :class:`ProductProgress` frames.

    Returned by the ``progress`` named command and by
    :meth:`jura_connect.client.JuraClient.follow_progress` callers that
    want a formattable result. ``complete`` is True when the run ended
    on the ``ENJOY`` frame rather than on the timeout.
    """

    frames: tuple[ProductProgress, ...]

    @property
    def complete(self) -> bool:
        return bool(self.frames) and self.frames[-1].is_complete

    @property
    def last(self) -> ProductProgress | None:
        return self.frames[-1] if self.frames else None

    def format(self) -> str:
        if not self.frames:
            return "(no @TV: progress frames seen)"
        lines = [f.format() for f in self.frames]
        tail = "done" if self.complete else "still running (or timed out)"
        return "\n".join([*lines, f"-- {tail}"])

    def to_dict(self) -> dict[str, object]:
        return {
            "frames": [f.to_dict() for f in self.frames],
            "complete": self.complete,
        }
