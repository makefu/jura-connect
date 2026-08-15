"""Read-command tests against the simulator.

Only read-only commands are exercised. The simulator refuses to honour
destructive commands and serves ``@an:error`` for them; that path is
also covered.
"""

from __future__ import annotations

import time

import pytest

from jura_connect.client import JuraClient


def _paired(sim, conn_id: str = "reader") -> JuraClient:
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id=conn_id, auth_hash="")
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def test_maintenance_counters(sim) -> None:
    c = _paired(sim)
    try:
        mc = c.read_maintenance_counter(timeout=2.0)
    finally:
        c.close()
    # Defaults straight out of the simulator config (mirror Kaffeebert).
    assert mc.cleaning == 0x0015
    assert mc.filter_change == 0x0001
    assert mc.descale == 0x0008
    assert mc.cappu_rinse == 0x0158
    assert mc.coffee_rinse == 0x0E21
    assert mc.cappu_clean == 0x005B
    assert len(mc.raw) == 12


def test_maintenance_percent(sim) -> None:
    c = _paired(sim)
    try:
        mp = c.read_maintenance_percent(timeout=2.0)
    finally:
        c.close()
    assert mp.cleaning == 0x50
    assert mp.filter_change == 0xFF
    assert mp.descale == 0x1E


def test_status_alerts(sim) -> None:
    c = _paired(sim)
    try:
        st = c.read_status(timeout=2.0)
    finally:
        c.close()
    assert "no_beans" in st.active_alerts
    assert len(st.raw) == 8


def test_status_waits_for_a_pushed_frame_without_polling(sim) -> None:
    """There is no "read status" verb: the dongle broadcasts ``@TF:``
    frames and J.O.E. only routes them. ``read_status`` must therefore
    put nothing on the wire — in particular not ``@HU?``, which is the
    milk-cooler update-status probe."""
    c = _paired(sim)
    try:
        st = c.read_status(timeout=2.0)
    finally:
        c.close()
    assert "no_beans" in st.active_alerts
    assert b"@HU?" not in sim.sent_commands


def test_status_nudge_sends_the_milk_cooler_probe(sim) -> None:
    """The opt-in nudge sends ``@HU?`` for firmwares that need traffic
    on the socket. The dongle answers it with ``@hu:<3 hex>`` — that
    reply is *not* the status; the status still arrives as ``@TF:``."""
    c = _paired(sim)
    try:
        st = c.read_status(timeout=2.0, nudge=True)
    finally:
        c.close()
    assert "no_beans" in st.active_alerts
    # The nudge and the pushed @TF: race each other: read_status can
    # return on a frame the dongle had already queued before @HU? landed,
    # so poll for the command instead of asserting on the first look.
    deadline = time.monotonic() + 2.0
    while b"@HU?" not in sim.sent_commands and time.monotonic() < deadline:
        time.sleep(0.01)
    assert b"@HU?" in sim.sent_commands


def test_hu_probe_answers_milk_cooler_update_status(sim) -> None:
    c = _paired(sim)
    try:
        reply = c.request("@HU?", match=r"^@hu:", timeout=2.0)
    finally:
        c.close()
    assert reply == "@hu:800"


def test_close_sends_an_empty_frame_and_drops_the_session(sim) -> None:
    """J.O.E.'s WifiCommandCloseConnection sends an empty frame; ``@HE``
    is the OTA-end verb and must not be used to hang up. The dongle
    drops the session, so a fresh client can pair right after."""
    c = _paired(sim)
    c.close()
    # The simulator reads on its own thread; give it a moment to see the
    # frame we just wrote before inspecting what arrived.
    deadline = time.monotonic() + 2.0
    while b"" not in sim.sent_commands and time.monotonic() < deadline:
        time.sleep(0.02)
    assert b"" in sim.sent_commands
    assert b"@HE" not in sim.sent_commands
    # Session really ended: the simulator serves one connection at a
    # time, so a second pairing only succeeds if the first was dropped.
    second = _paired(sim, conn_id="reader-2")
    try:
        assert second.read_maintenance_counter(timeout=2.0).cleaning == 0x0015
    finally:
        second.close()


def test_machine_info_bundle(sim) -> None:
    c = _paired(sim)
    try:
        info = c.read_machine_info(timeout=3.0)
    finally:
        c.close()
    assert info.handshake_state == "CORRECT"
    assert info.maintenance_counters.cleaning == 0x0015
    assert info.maintenance_percent.cleaning == 0x50
    assert "no_beans" in info.status.active_alerts


def test_status_history_collects_unsolicited_frames(sim_factory) -> None:
    sim = sim_factory(status_interval=0.05)
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="watcher", auth_hash="")
    c.pair(timeout=2.0)
    # Trigger a read so we drain a couple of statuses on the way.
    c.read_maintenance_counter(timeout=2.0)
    time.sleep(0.2)
    # Drain whatever else is queued.
    for _ in range(5):
        try:
            c.conn.recv_str(timeout=0.1)
        except (TimeoutError, OSError):
            break
    c.close()
    assert any(f.startswith("@TF:") for f in c.status_history)


def test_screen_lock_unlock(sim) -> None:
    c = _paired(sim)
    try:
        assert c.lock_screen().startswith("@ts")
        assert sim.config.screen_locked is True
        assert c.unlock_screen().startswith("@ts")
        assert sim.config.screen_locked is False
    finally:
        c.close()


def test_simulator_refuses_destructive_commands(sim) -> None:
    """The simulator must echo back @an:error for any destructive prefix
    rather than silently ignoring -- a guardrail for the test suite itself.
    """
    c = _paired(sim)
    try:
        for danger in [
            "@TG:24",
            "@TG:25",
            "@TG:7E",
            "@TG:7E," + "F" * 32,  # quality-assistant "skip all" form
            "@TF:02",
            "@TP:01",
        ]:
            reply = c.request(danger, match=r"^@an:error", timeout=1.5)
            assert reply == "@an:error", danger
    finally:
        c.close()


def test_simulator_answers_the_product_step_cancel(sim) -> None:
    """``@TG:FF`` is no longer in the destructive set, so the simulator
    must model the real acknowledgement instead of ``@an:error``."""
    c = _paired(sim)
    try:
        assert c.request("@TG:FF", match=r"(?i)^@tg", timeout=1.5) == "@tg:FF"
    finally:
        c.close()


def test_unknown_command_yields_timeout(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(TimeoutError):
            c.request("@QQ?", match=r"^@qq", timeout=0.5)
    finally:
        c.close()
