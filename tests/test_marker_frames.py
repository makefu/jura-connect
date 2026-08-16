"""Unsolicited marker frames (`@TB` / `@TS`) must never pass as replies.

A real S8 EB (EF1091, "kaffeebert") pushes bare, payload-less,
upper-case markers on its own: `@TB` right when a brew (or a `@TS:01`
screen lock, PROTOCOL.md §5.1) starts, and `@TS` about ten seconds
after the last `ENJOY` frame of a brew — see
`docs/captures/2026-08-16-kaffeebert-brew-progress.md`, where the
watcher sent nothing but the handshake and still saw both.

Because they are pushed, either one can land on the socket while a
command is in flight. A reader that only skips `@TF:` / `@TV:` hands
the marker back as "the reply", which for `brew()` inverts the
accept/reject decision: `@TB` is not an `@tp` acknowledgement, and a
`@TS` left over from the previous cup is not one either.

The frames replayed here are the captured ones
(`simulator.CAPTURED_S8EB_CAFE_BARISTA_BREW`); `pushes_before_reply`
puts the marker *ahead* of the reply, which is the ordering the client
has to survive.
"""

from __future__ import annotations

from jura_connect.client import JuraClient
from jura_connect.process import ProcessRunner, resolve_process
from jura_connect.profile import load_profile
from jura_connect.progress import ProgressState
from jura_connect.simulator import CAPTURED_S8EB_CAFE_BARISTA_BREW

#: The two markers the capture recorded, verbatim.
BREW_START = "@TB"
BREW_END = "@TS"


def _paired(sim, code: str = "EF1091") -> JuraClient:
    host, port = sim.address
    c = JuraClient(
        host,
        port=port,
        conn_id="marker-tests",
        auth_hash="",
        profile=load_profile(code),
    )
    assert c.pair(timeout=2.0).state == "CORRECT"
    return c


# --------------------------------------------------------------------- #
# brew(): the accept/reject decision must hang off the @tp reply
# --------------------------------------------------------------------- #


def test_brew_ack_survives_a_pushed_brew_start_marker(sim_factory) -> None:
    """`@TB` ahead of the reply must not be mistaken for the ACK."""
    sim = sim_factory(
        allow_brew=True,
        status_interval=0.05,
        brew_script=CAPTURED_S8EB_CAFE_BARISTA_BREW,
        pushes_before_reply=(BREW_START,),
    )
    c = _paired(sim)
    try:
        reply = c.brew(
            "cafe_barista", ml=45, bypass=45, follow=True, follow_timeout=5.0
        )
    finally:
        c.close()
    assert reply == "@tp"
    # The accept classification drove the follow branch, so the captured
    # stream was collected instead of being dropped as a refusal.
    frames = list(c.last_progress)
    assert frames, "an accepted brew collected no progress frames"
    assert frames[-1].state is ProgressState.ENJOY
    # Nothing was silently dropped: the marker is observable.
    assert BREW_START in c.status_history


def test_brew_ack_survives_a_stray_end_marker(sim_factory) -> None:
    """The `@TS` tail of the *previous* cup must not become this ACK."""
    sim = sim_factory(
        allow_brew=True,
        status_interval=0.05,
        brew_script=CAPTURED_S8EB_CAFE_BARISTA_BREW,
        pushes_before_reply=(BREW_END,),
    )
    c = _paired(sim)
    try:
        reply = c.brew(
            "cafe_barista", ml=45, bypass=45, follow=True, follow_timeout=5.0
        )
    finally:
        c.close()
    assert reply == "@tp"
    assert list(c.last_progress)[-1].state is ProgressState.ENJOY
    assert BREW_END in c.status_history


def test_brew_retry_is_not_triggered_by_a_marker(sim_factory) -> None:
    """`retry=True` must not resend a blob the machine already accepted.

    A second `@TP:` for an accepted cup is a second cup. The retry
    branch keys off `_is_brew_accept(reply)`, so a marker read as the
    reply would brew twice.
    """
    sim = sim_factory(
        allow_brew=True,
        status_interval=0.05,
        brew_script=CAPTURED_S8EB_CAFE_BARISTA_BREW,
        pushes_before_reply=(BREW_START, BREW_END),
    )
    c = _paired(sim)
    try:
        reply = c.brew("cafe_barista", ml=45, bypass=45, retry=True)
    finally:
        c.close()
    assert reply == "@tp"
    brews = [f for f in sim.sent_commands if b"@TP:" in f]
    assert len(brews) == 1, "the accepted blob was sent twice"


def test_brew_rejection_still_reads_as_a_rejection(sim_factory) -> None:
    """The matcher must not turn `@tp:00` into an accept either.

    `@tp:00` is the machine ACKing and then ignoring the blob
    (PROTOCOL.md §5.9); it has to keep reaching the caller unchanged
    with a marker in front of it.
    """
    sim = sim_factory(
        allow_brew=True,
        status_interval=0.05,
        pushes_before_reply=(BREW_START,),
    )
    c = _paired(sim)
    try:
        # FF-padded legacy layout: ACKed, never brewed.
        reply = c.request(
            "@TP:28FF0709FFFF01FFFF09FFFFFFFFFFFF",
            match=r"(?i)^@(?:tp|an)\b",
            timeout=2.0,
        )
    finally:
        c.close()
    assert reply == "@tp:00"


def test_brew_refusal_reply_still_reaches_the_caller(sim_factory) -> None:
    """A guardrail refusal (`@an:error`) must not time out behind a marker."""
    sim = sim_factory(status_interval=0.05, pushes_before_reply=(BREW_START,))
    c = _paired(sim)
    try:
        reply = c.brew("cafe_barista", ml=45, bypass=45, timeout=2.0)
    finally:
        c.close()
    assert reply == "@an:error"


# --------------------------------------------------------------------- #
# The matcher-less path in general
# --------------------------------------------------------------------- #


def test_matcherless_request_skips_markers_and_records_them(sim_factory) -> None:
    sim = sim_factory(status_interval=0.05, pushes_before_reply=(BREW_START, BREW_END))
    c = _paired(sim)
    try:
        reply = c.request("@TG:43", timeout=2.0)
    finally:
        c.close()
    assert reply.startswith("@tg:43")
    assert [f for f in c.status_history if not f.startswith("@TF:")] == [
        BREW_START,
        BREW_END,
    ]


def test_marker_skip_is_narrow_enough_to_keep_payload_frames(sim_factory) -> None:
    """Only a bare two-letter upper-case verb counts as a marker.

    Anything carrying a payload could be a reply from a firmware we
    have never seen, so it must still be handed to the caller rather
    than swallowed.
    """
    sim = sim_factory(status_interval=0.05, pushes_before_reply=("@TB:0001",))
    c = _paired(sim)
    try:
        reply = c.request("@TG:43", timeout=2.0)
    finally:
        c.close()
    assert reply == "@TB:0001"


def test_lock_screen_still_binds_to_the_lowercase_reply(sim_factory) -> None:
    """`lock`/`unlock` match `^@ts`; the marker is `@TS` and must be skipped."""
    sim = sim_factory(status_interval=0.05, pushes_before_reply=(BREW_END,))
    c = _paired(sim)
    try:
        assert c.lock_screen() == "@ts"
        assert c.unlock_screen() == "@ts"
    finally:
        c.close()
    assert sim.config.screen_locked is False
    # Skipped under an explicit matcher, but still recorded.
    assert BREW_END in c.status_history


def test_handshake_is_not_confused_by_a_marker(sim_factory) -> None:
    """`@TB` fires on a screen lock too, so it can precede `@hp4`."""
    sim = sim_factory(status_interval=0.05, handshake_pushes=(BREW_START,))
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="marker-tests", auth_hash="")
    try:
        result = c.pair(timeout=2.0)
    finally:
        c.close()
    assert result.state == "CORRECT"
    assert BREW_START in c.status_history


# --------------------------------------------------------------------- #
# Maintenance processes: the "anything but a push" matcher
# --------------------------------------------------------------------- #


def test_process_start_is_not_acknowledged_by_a_marker(sim_factory) -> None:
    """`PROCESS_REPLY_MATCH` accepts every non-push frame — except markers.

    A `@TB` read as the start reply makes `ProcessRunner.start` raise
    "machine refused to start" for a cycle that is in fact running.
    """
    sim = sim_factory(
        allow_process=True,
        status_interval=0.05,
        pushes_before_reply=(BREW_START,),
    )
    c = _paired(sim)
    try:
        runner = ProcessRunner(c, resolve_process("cleaning", c.profile))
        reply = runner.start(timeout=3.0)
    finally:
        c.close()
    assert reply == "@tg:24"
    assert runner.started is True
    assert BREW_START in c.status_history
