"""``@TV:`` product-progress decoding.

Unit decode tests build payloads by hand (the byte layout is
APK-derived, see docs/PROTOCOL.md §5.10) and the end-to-end test drives
a real brew through the in-tree simulator — no mocks.
"""

from __future__ import annotations

import time

import pytest

from jura_connect import commands
from jura_connect.client import JuraClient
from jura_connect.commands import run_named
from jura_connect.profile import load_profile
from jura_connect.progress import (
    ProductProgress,
    ProductProgressState,
    ProgressState,
    ProgressType,
    is_progress_frame,
)

# --------------------------------------------------------------------- #
# Payload helpers
# --------------------------------------------------------------------- #


def _frame(state: int, item: int, values: dict[int, int] | None = None) -> str:
    """Build a full 16-byte ``@TV:`` frame.

    ``values`` indexes the 14-byte value window that starts at payload
    byte 2 (the ``ProductArgument`` table).
    """
    window = bytearray(14)
    for index, value in (values or {}).items():
        window[index] = value
    return f"@TV:{state:02X}{item:02X}{window.hex().upper()}"


def _extended_frame(state: int, item: int, values: dict[int, int]) -> str:
    """Same, but with the ``8F`` marker at byte 2 shifting the window."""
    window = bytearray(14)
    for index, value in values.items():
        window[index] = value
    return f"@TV:{state:02X}{item:02X}8F{window.hex().upper()}"


EF1091 = load_profile("EF1091")
EF536 = load_profile("EF536")

#: 0x28 = cafe_barista on the S8 EB, absent from the EF536 baseline.
CAFE_BARISTA = 0x28


# --------------------------------------------------------------------- #
# Unit decode
# --------------------------------------------------------------------- #


def test_product_progress_frame_decodes_actual_max_and_percent() -> None:
    frame = _frame(
        ProgressState.COFFEE_WATER_AMOUNT,
        CAFE_BARISTA,
        {2: 9, 3: 30, 12: 50},
    )
    p = ProductProgress.parse(frame, EF1091)
    assert p.state is ProgressState.COFFEE_WATER_AMOUNT
    assert p.state_code == 0x3C
    assert p.progress_type is ProgressType.PRODUCT
    assert p.item_code == CAFE_BARISTA
    assert p.product == "cafe_barista"
    assert p.process is None
    assert p.product_state is ProductProgressState.COFFEE_WATER_AMOUNT
    assert (p.actual, p.maximum, p.percent) == (9, 30, 50)
    assert p.fraction == pytest.approx(0.3)
    assert p.is_complete is False
    # Presentation lives with the data (AGENTS.md §4).
    text = p.format()
    assert "COFFEE_WATER_AMOUNT" in text
    assert "cafe_barista" in text
    assert "9/30" in text
    assert "50%" in text
    d = p.to_dict()
    assert d["state"] == "COFFEE_WATER_AMOUNT"
    assert d["state_code"] == "3C"
    assert d["progress_type"] == "product"
    assert d["product"] == "cafe_barista"
    assert d["actual"] == 9
    assert d["maximum"] == 30
    assert d["percent"] == 50


def test_extended_8f_window_shifts_the_value_indices() -> None:
    """Byte 2 == 0x8F is a window marker, not data: values start at 3."""
    frame = _extended_frame(
        ProgressState.COFFEE_WATER_AMOUNT,
        CAFE_BARISTA,
        {2: 11, 3: 22, 12: 60},
    )
    p = ProductProgress.parse(frame, EF1091)
    assert p.extended is True
    assert (p.actual, p.maximum, p.percent) == (11, 22, 60)


def test_extended_window_without_a_product_state_uses_values_0_and_1() -> None:
    frame = _extended_frame(ProgressState.POPUP_WINDOW, CAFE_BARISTA, {0: 4, 1: 7})
    p = ProductProgress.parse(frame, EF1091)
    assert p.extended is True
    assert p.product_state is None
    assert (p.actual, p.maximum, p.percent) == (4, 7, None)


def test_plain_window_without_a_product_state_has_no_maximum() -> None:
    frame = _frame(ProgressState.HEATING_UP, CAFE_BARISTA, {0: 3, 1: 9})
    p = ProductProgress.parse(frame, EF1091)
    assert p.extended is False
    assert (p.actual, p.maximum, p.percent) == (3, None, None)


def test_state_41_is_hotwater_volume_when_values6_is_ff() -> None:
    frame = _frame(
        ProgressState.HOTWATER_VOLUME,
        0x0D,  # hotwater_portion on EF1091
        {2: 12, 3: 44, 6: 0xFF, 7: 0x00, 12: 27},
    )
    p = ProductProgress.parse(frame, EF1091)
    assert p.product_state is ProductProgressState.HOTWATER_VOLUME
    assert (p.actual, p.maximum, p.percent) == (12, 44, 27)


def test_state_41_is_bypass_water_volume_when_values6_is_not_ff() -> None:
    frame = _frame(
        ProgressState.HOTWATER_VOLUME,
        CAFE_BARISTA,
        {2: 12, 3: 44, 6: 5, 7: 9, 12: 27},
    )
    p = ProductProgress.parse(frame, EF1091)
    assert p.state is ProgressState.HOTWATER_VOLUME
    assert p.product_state is ProductProgressState.BYPASS_WATER_VOLUME
    assert (p.actual, p.maximum, p.percent) == (5, 9, 27)


def test_process_frame_resolves_the_process_code() -> None:
    frame = _frame(ProgressState.CLEANING_PROCESS, 0x24, {0: 2, 1: 6})
    p = ProductProgress.parse(frame, EF1091)
    assert p.state is ProgressState.CLEANING_PROCESS
    assert p.progress_type is ProgressType.PROCESS
    assert p.process == "cleaning"
    assert p.product is None


def test_enjoy_frame_marks_completion() -> None:
    p = ProductProgress.parse(_frame(ProgressState.ENJOY, CAFE_BARISTA), EF1091)
    assert p.state is ProgressState.ENJOY
    assert p.is_complete is True
    assert p.progress_type is ProgressType.PRODUCT
    assert "ENJOY" in p.format()


def test_unknown_state_code_decodes_to_none_without_raising() -> None:
    p = ProductProgress.parse("@TV:AB000000", None)
    assert p.state is None
    assert p.state_code == 0xAB
    assert p.progress_type is ProgressType.NONE
    assert "AB" in p.format()
    assert p.to_dict()["state"] is None


def test_truncated_payload_leaves_percent_and_maximum_none() -> None:
    # State + product + a 4-byte value window: the actual/max indices
    # (2 and 3) are present, index 12 (percent) is not.
    p = ProductProgress.parse("@TV:3C280000091E", EF1091)
    assert p.state is ProgressState.COFFEE_WATER_AMOUNT
    assert (p.actual, p.maximum) == (9, 30)
    assert p.percent is None
    assert p.fraction == pytest.approx(0.3)


def test_payload_shorter_than_the_state_indices_yields_none_values() -> None:
    p = ProductProgress.parse("@TV:3C28", EF1091)
    assert p.actual is None
    assert p.maximum is None
    assert p.percent is None
    assert p.fraction is None


def test_state_codes_cover_the_whole_apk_table() -> None:
    assert len(ProgressState) == 87
    assert ProgressState.from_code(0x3E) is ProgressState.ENJOY
    assert ProgressState.from_code(0xAB) is None


def test_frame_type_classification_of_the_special_states() -> None:
    timer = ProductProgress.parse(_frame(0xC4, 0x00), EF1091)
    assert timer.progress_type is ProgressType.COFFEE_TIMER
    quality = ProductProgress.parse(_frame(0x7E, 0x00), EF1091)
    assert quality.progress_type is ProgressType.QUALITY_ASSISTANT
    aroma = ProductProgress.parse(_frame(0xFE, CAFE_BARISTA), EF1091)
    # FE never classifies as PRODUCT even when byte 1 is a product code.
    assert aroma.progress_type is ProgressType.AROMA_PRESELECTION
    pmode = ProductProgress.parse(_frame(0xFF, 0x00), EF1091)
    assert pmode.progress_type is ProgressType.P_MODE


# --------------------------------------------------------------------- #
# Profile awareness
# --------------------------------------------------------------------- #


def test_same_frame_resolves_under_ef1091_and_stays_unresolved_on_ef536() -> None:
    frame = _frame(ProgressState.COFFEE_WATER_AMOUNT, CAFE_BARISTA, {2: 9, 3: 30})
    known = ProductProgress.parse(frame, EF1091)
    assert known.product == "cafe_barista"
    assert known.progress_type is ProgressType.PRODUCT
    unknown = ProductProgress.parse(frame, EF536)
    assert unknown.product is None
    assert unknown.progress_type is ProgressType.NONE
    # The value window does not depend on the profile.
    assert (unknown.actual, unknown.maximum) == (9, 30)
    # No profile at all behaves like a profile without the code.
    assert ProductProgress.parse(frame).product is None


# --------------------------------------------------------------------- #
# Non-progress @TV: frames
# --------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "reply",
    [
        "@TV:81,PLEASE WAIT",
        "@TV:82,RINSING",
        "@TV:84,12:30:00",
        "@TV:8100",  # language-download frame, hex-only variant
        "@TV:8200",
        "@TV:8400",
        "@TF:0004000008000000",
        "@TB",
    ],
)
def test_non_progress_frames_are_rejected(reply: str) -> None:
    assert is_progress_frame(reply) is False
    with pytest.raises(ValueError):
        ProductProgress.parse(reply)


def test_progress_frames_are_recognised() -> None:
    assert is_progress_frame(_frame(ProgressState.ENJOY, CAFE_BARISTA)) is True
    assert is_progress_frame("@TV:3C280900") is True


# --------------------------------------------------------------------- #
# End-to-end against the simulator
# --------------------------------------------------------------------- #


def _paired(sim, code: str = "EF1091") -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host,
        port=port,
        conn_id="progress-tests",
        auth_hash="",
        profile=load_profile(code),
    )
    assert c.pair(timeout=2.0).state == "CORRECT"
    return c


def test_brew_follows_progress_to_completion(sim_factory) -> None:
    sim = sim_factory(allow_brew=True, status_interval=0.05)
    c = _paired(sim)
    try:
        seen: list = []
        reply = c.brew(
            "cafe_barista",
            ml=45,
            follow=True,
            follow_timeout=5.0,
            on_progress=seen.append,
        )
    finally:
        c.close()
    assert reply.strip().lower().startswith("@tp")
    frames = list(c.last_progress)
    assert frames == seen
    assert len(frames) >= 3
    percents = [f.percent for f in frames if f.percent is not None]
    assert percents == sorted(percents)
    assert percents[-1] == 100
    assert all(f.product == "cafe_barista" for f in frames)
    assert frames[-1].state is ProgressState.ENJOY
    assert frames[-1].is_complete is True
    # Ticks rise towards the target for the mid-brew frames.
    ticks = [f.actual for f in frames if f.state is ProgressState.HOTWATER_VOLUME]
    assert ticks == sorted(ticks)
    assert ticks[-1] == frames[0].maximum


def test_iter_progress_skips_status_and_non_progress_frames(sim_factory) -> None:
    sim = sim_factory(allow_brew=True, status_interval=0.05)
    c = _paired(sim)
    try:
        c.request("@TP:28000709000001000109000000000000", timeout=2.0)
        collected = []
        for p in c.iter_progress(timeout=5.0):
            collected.append(p)
            if p.is_complete:
                break
    finally:
        c.close()
    assert collected, "no @TV: frames decoded from the brew stream"
    assert collected[-1].state is ProgressState.ENJOY
    # @TF: status broadcasts and the @TB brew-start frame never leak in.
    assert all(p.raw.startswith("@TV:") for p in collected)


def test_progress_named_command_is_read_only(sim_factory) -> None:
    spec = commands.get_command("progress")
    assert spec.destructive is False
    sim = sim_factory(allow_brew=True, status_interval=0.05)
    c = _paired(sim)
    try:
        c.request("@TP:28000709000001000109000000000000", timeout=2.0)
        result = run_named(c, "progress", ["5"], timeout=5.0)
    finally:
        c.close()
    log = result.value
    assert log.frames  # type: ignore[union-attr]
    assert log.complete is True  # type: ignore[union-attr]
    text = result.format()
    assert "ENJOY" in text
    payload = result.to_dict()
    assert payload["name"] == "progress"
    assert payload["value"]["complete"] is True  # type: ignore[index]


def test_ignored_blob_is_acked_but_never_followed(sim_factory) -> None:
    """``@tp:00`` means the machine ignored the blob: no progress at all.

    The FF-padded layout earlier versions sent is the real-world case
    (PROTOCOL.md §5.9); ``brew(follow=True)`` must not block on a
    stream that will never arrive.
    """
    sim = sim_factory(allow_brew=True, status_interval=0.05)
    c = _paired(sim)
    try:
        reply = c.request("@TP:28FF0709FFFF01FFFF09FFFFFFFFFFFF", timeout=2.0)
    finally:
        c.close()
    assert reply == "@tp:00"


def test_brew_does_not_follow_a_refused_start(sim) -> None:
    """follow=True must return at once when the start was not accepted.

    Waiting out ``follow_timeout`` on a machine that will never send a
    progress frame would hang a Home Assistant service call.
    """
    started = time.monotonic()
    c = _paired(sim)
    try:
        reply = c.brew("cafe_barista", ml=45, follow=True, follow_timeout=30.0)
    finally:
        c.close()
    assert reply == "@an:error"  # simulator refuses @TP: by default
    assert c.last_progress == ()
    assert time.monotonic() - started < 10.0


def test_simulator_still_refuses_brew_by_default(sim) -> None:
    """The destructive guardrail stays on unless a test opts in."""
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="progress-tests", auth_hash="")
    assert c.pair(timeout=2.0).state == "CORRECT"
    try:
        reply = c.request("@TP:28000709000001000109000000000000", timeout=2.0)
    finally:
        c.close()
    assert reply == "@an:error"
