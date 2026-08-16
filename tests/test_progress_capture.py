"""Replay of a **real** brew: the `@TV:` decoder against hardware.

Every frame here came off the wire of a JURA S8 EB (EF1091,
"kaffeebert") on 2026-08-16 while the maintainer started a
`cafe_barista` on the machine's own panel and a read-only watcher
logged what the dongle pushed. The annotated trace lives in
`docs/captures/2026-08-16-kaffeebert-brew-progress.md`; the frame list
itself is `simulator.CAPTURED_S8EB_CAFE_BARISTA_BREW`, so the simulator
and these tests share one copy of the evidence.

Until this capture the `@TV:` layout was APK-derived and only
simulator-verified — the simulator's frames were built from the same
reading being tested. These tests are the only ones in the suite backed
by a machine, so they pin the decode rules the capture actually
exercised: the value window's origin, the percent slot, the `39` / `3C`
/ `41` / `3E` states, and the `41` bypass disambiguation.

Do not regenerate or tidy these payloads. Where they look wrong they are
right: the water ticks skip 6, the bypass ticks skip 2/3/5/7, and
`ENJOY` repeats five times.
"""

from __future__ import annotations

from jura_connect.client import JuraClient, MachineStatus
from jura_connect.profile import load_profile
from jura_connect.progress import (
    ProductProgress,
    ProductProgressState,
    ProgressState,
    ProgressType,
    is_progress_frame,
)
from jura_connect.simulator import CAPTURED_S8EB_CAFE_BARISTA_BREW

EF1091 = load_profile("EF1091")

#: 0x28 = cafe_barista on the S8 EB.
CAFE_BARISTA = 0x28

#: The brew-start marker and the bare frame that closed the run out.
BREW_START = "@TB"
BREW_END = "@TS"

#: What the machine broadcast at idle before and after the brew — note
#: the missing energy_safe bit compared with the §5.4 baseline.
IDLE_STATUS = "@TF:0004000000000000"

#: Just the progress frames, in capture order.
TV_FRAMES: tuple[str, ...] = tuple(
    f for f in CAPTURED_S8EB_CAFE_BARISTA_BREW if f.startswith("@TV:")
)


def _decoded() -> list[ProductProgress]:
    return [ProductProgress.parse(f, EF1091) for f in TV_FRAMES]


def _phase(state: ProgressState) -> list[ProductProgress]:
    return [p for p in _decoded() if p.state is state]


# --------------------------------------------------------------------- #
# The capture as a whole
# --------------------------------------------------------------------- #


def test_every_captured_frame_decodes_without_a_failure() -> None:
    """The headline result: 32 real frames, zero decode failures."""
    frames = _decoded()
    assert len(frames) == 32
    assert all(is_progress_frame(f) for f in TV_FRAMES)
    # Product resolution off byte 1 works for every single frame.
    assert {p.item_code for p in frames} == {CAFE_BARISTA}
    assert all(p.product == "cafe_barista" for p in frames)
    assert all(p.progress_type is ProgressType.PRODUCT for p in frames)
    assert all(p.state is not None for p in frames)
    # Four states, in this order and no others.
    order = [p.state for p in frames]
    assert set(order) == {
        ProgressState.COFFEE_BEAN_AMOUNT,
        ProgressState.COFFEE_WATER_AMOUNT,
        ProgressState.HOTWATER_VOLUME,
        ProgressState.ENJOY,
    }
    firsts = [s for i, s in enumerate(order) if i == 0 or order[i - 1] is not s]
    assert firsts == [
        ProgressState.COFFEE_BEAN_AMOUNT,
        ProgressState.COFFEE_WATER_AMOUNT,
        ProgressState.HOTWATER_VOLUME,
        ProgressState.ENJOY,
    ]


def test_value_window_starts_at_payload_byte_2() -> None:
    """Window slot N is payload byte N+2 — no 8F shift anywhere."""
    for p in _decoded():
        assert p.extended is False
        if p.product_state is None:  # the ENJOY frames carry no window
            continue
        window = p.payload[2:]
        assert p.actual == window[p.product_state.actual_index]
        assert p.maximum == window[p.product_state.max_index]


def test_percent_is_window_slot_12_the_second_to_last_byte() -> None:
    for p in _decoded():
        if len(p.payload) < 16:
            continue
        assert len(p.payload) == 16
        assert p.percent == p.payload[14] == p.payload[-2]


def test_percent_is_a_whole_product_figure_not_a_per_phase_one() -> None:
    """0→60 % across the water phase, 60→100 % across the bypass.

    A consumer must not reset the bar when the state changes: the
    machine keeps counting the whole product.
    """
    percents = [p.percent for p in _decoded() if p.percent is not None]
    assert percents == sorted(percents)
    assert percents[0] == 0
    assert percents[-1] == 100
    assert all(value % 10 == 0 for value in percents)
    water = [p.percent for p in _phase(ProgressState.COFFEE_WATER_AMOUNT)]
    bypass = [p.percent for p in _phase(ProgressState.HOTWATER_VOLUME)]
    assert (water[0], water[-1]) == (0, 60)
    assert (bypass[0], bypass[-1]) == (60, 100)


def test_unused_recipe_parameters_read_as_ff_in_the_window() -> None:
    """`FF` marks "this product has no such parameter".

    cafe_barista takes no milk, and window slots 4/5 (milk time) and
    9/10 (pause) were `FF` in every frame that carried them. That is the
    same sentinel the `41` disambiguation keys on.
    """
    for p in _decoded():
        window = p.payload[2:]
        if len(window) < 14:
            continue
        assert window[4] == window[5] == 0xFF
        assert window[9] == window[10] == 0xFF
        # Slots 8 and 11 held a constant 0x11 for the whole brew; what
        # they mean on this firmware is unexplained (see the capture).
        assert window[8] == window[11] == 0x11
        assert window[13] == 0x00


# --------------------------------------------------------------------- #
# Per-state decode
# --------------------------------------------------------------------- #


def test_grinding_reports_the_recipe_strength_seven_of_seven() -> None:
    """State `39` carries the *configured* strength, not a countdown.

    Four frames, ~2 s apart, all 7/7 — matching the strength-7
    `cafe_barista` blob in PROTOCOL.md §5.9, and confirming window slots
    0/1 are actual/max coffee strength.
    """
    beans = _phase(ProgressState.COFFEE_BEAN_AMOUNT)
    assert len(beans) == 4
    for p in beans:
        assert p.product_state is ProductProgressState.COFFEE_BEAN_AMOUNT
        assert (p.actual, p.maximum) == (7, 7)
        assert p.fraction == 1.0
        assert p.percent == 0
        assert p.is_complete is False
    assert "coffee_bean_amount 7/7" in beans[0].format()


def test_water_phase_ticks_climb_from_zero_to_the_45_ml_target() -> None:
    """State `3C`, window slots 2/3 = payload bytes 4/5."""
    water = _phase(ProgressState.COFFEE_WATER_AMOUNT)
    assert len(water) == 16
    assert all(
        p.product_state is ProductProgressState.COFFEE_WATER_AMOUNT for p in water
    )
    ticks = [p.actual for p in water]
    assert ticks == sorted(ticks)
    assert (ticks[0], ticks[-1]) == (0, 9)
    # The machine skipped 6 — reported, not smoothed.
    assert 6 not in ticks
    # 9 ticks × 5 ml = the 45 ml of the §5.9 recipe blob.
    assert {p.maximum for p in water} == {9}
    assert [p.payload[4] for p in water] == ticks
    assert [p.payload[5] for p in water] == [9] * len(water)
    assert water[-1].fraction == 1.0
    assert water[-1].is_complete is False


def test_state_41_takes_the_bypass_branch_on_real_hardware() -> None:
    """The shakiest APK-derived rule, now observed.

    Window slot 6 was **not** `FF` (the recipe has a 45 ml bypass), so
    the decoder must read slots 6/7 — payload bytes 8/9 — and not the
    water pair at 2/3, which stayed frozen at 9/9 for the whole phase.
    """
    bypass = _phase(ProgressState.HOTWATER_VOLUME)
    assert len(bypass) == 7
    for p in bypass:
        window = p.payload[2:]
        assert window[6] != 0xFF
        assert p.product_state is ProductProgressState.BYPASS_WATER_VOLUME
        assert p.maximum == 9  # 9 ticks × 5 ml = the 45 ml bypass
        assert p.actual == p.payload[8]
        assert p.maximum == p.payload[9]
        # What HOTWATER_VOLUME would have reported instead: a dead 9/9.
        assert (window[2], window[3]) == (9, 9)
    ticks = [p.actual for p in bypass]
    assert ticks == sorted(ticks)
    assert (ticks[0], ticks[-1]) == (0, 9)
    assert "bypass_water_volume 9/9" in bypass[-1].format()


def test_enjoy_repeats_and_every_repeat_reads_as_complete() -> None:
    """`3E` is level-triggered, not edge-triggered.

    The machine sent `@TV:3E28` five times, ~2 s apart, and every one
    decodes as complete. A consumer that treats `is_complete` as an
    event must de-duplicate, or it counts one brew five times.
    """
    enjoy = _phase(ProgressState.ENJOY)
    assert len(enjoy) == 5
    assert {p.raw for p in enjoy} == {"@TV:3E28"}
    for p in enjoy:
        assert p.is_complete is True
        assert p.product == "cafe_barista"
        # A two-byte payload: no value window at all, and that is fine.
        assert (p.actual, p.maximum, p.percent) == (None, None, None)
        assert p.fraction is None


# --------------------------------------------------------------------- #
# The frames around the brew
# --------------------------------------------------------------------- #


def test_brew_start_and_stop_markers_are_not_progress_frames() -> None:
    """`@TB`, the trailing `@TS` and the idle `@TF:` must be skipped."""
    for frame in (BREW_START, BREW_END, IDLE_STATUS):
        assert is_progress_frame(frame) is False


def test_the_captured_run_is_bracketed_by_tb_and_ts() -> None:
    assert CAPTURED_S8EB_CAFE_BARISTA_BREW[0] == BREW_START
    assert CAPTURED_S8EB_CAFE_BARISTA_BREW[-1] == BREW_END
    assert BREW_END not in TV_FRAMES


def test_idle_status_lacked_energy_safe_during_this_run() -> None:
    """The machine was awake, unlike the §5.4 baseline frame.

    Same machine, same command, one bit different — proof that
    `energy_safe` is a live state and not a constant of this firmware.
    """
    st = MachineStatus.parse(IDLE_STATUS, EF1091)
    assert "coffee_ready" in st.active_alerts
    assert "energy_safe" not in st.active_alerts
    assert st.errors == ()


# --------------------------------------------------------------------- #
# End-to-end: the simulator replays the capture
# --------------------------------------------------------------------- #


def _paired(sim) -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host,
        port=port,
        conn_id="capture-tests",
        auth_hash="",
        profile=EF1091,
    )
    assert c.pair(timeout=2.0).state == "CORRECT"
    return c


def test_simulator_replays_the_capture_through_the_client(sim_factory) -> None:
    """The whole stack decodes the real frames off a real socket.

    `ProductProgress.parse` is exercised above; this drives the same
    bytes through cipher, framing, `iter_progress`'s filtering and
    `follow_progress`'s stop condition, which is where a regression in
    the plumbing (rather than the decoder) would show up.
    """
    sim = sim_factory(
        allow_brew=True,
        status_interval=0.05,
        brew_script=CAPTURED_S8EB_CAFE_BARISTA_BREW,
    )
    c = _paired(sim)
    try:
        reply = c.brew(
            "cafe_barista", ml=45, bypass=45, follow=True, follow_timeout=5.0
        )
    finally:
        c.close()
    assert reply == "@tp"
    frames = list(c.last_progress)
    # follow_progress stops on the first ENJOY, so the four repeats and
    # the trailing @TS never make it into the collected run.
    assert [p.raw for p in frames] == list(TV_FRAMES[: TV_FRAMES.index("@TV:3E28") + 1])
    assert frames[-1].is_complete is True
    assert [p.to_dict() for p in frames] == [
        p.to_dict() for p in _decoded()[: len(frames)]
    ]
    percents = [p.percent for p in frames if p.percent is not None]
    assert percents == sorted(percents)
    assert percents[-1] == 100
