"""Read-command tests against the simulator.

Only read-only commands are exercised. The simulator refuses to honour
destructive commands and serves ``@an:error`` for them; that path is
also covered.
"""

from __future__ import annotations

import time

import pytest

from jura_wifi.client import JuraClient


def _paired(sim) -> JuraClient:
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="reader", auth_hash="")
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
    assert mc.decalc == 0x0008
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
    assert mp.decalc == 0x1E


def test_status_alerts(sim) -> None:
    c = _paired(sim)
    try:
        st = c.read_status(timeout=2.0)
    finally:
        c.close()
    assert "no_beans" in st.active_alerts
    assert len(st.raw) == 8


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
        for danger in ["@TG:24", "@TG:25", "@TG:7E", "@TF:02", "@TP:01"]:
            reply = c.request(danger, match=r"^@an:error", timeout=1.5)
            assert reply == "@an:error", danger
    finally:
        c.close()


def test_unknown_command_yields_timeout(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(TimeoutError):
            c.request("@QQ?", match=r"^@qq", timeout=0.5)
    finally:
        c.close()
