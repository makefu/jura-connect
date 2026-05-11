"""Named-command registry tests, end-to-end via the simulator.

Each registered command is dispatched against the in-tree simulator
(no mocks), exercising the same code path the CLI takes.
"""

from __future__ import annotations

import pytest

from jura_connect import commands
from jura_connect.client import (
    JuraClient,
    MachineInfo,
    MachineStatus,
    MaintenanceCounters,
    MaintenancePercent,
)
from jura_connect.commands import CommandError, DestructiveCommandError, run_named


def _paired(sim) -> JuraClient:
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="cmd-tests", auth_hash="")
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def test_list_commands_contains_safe_and_destructive_groups() -> None:
    specs = commands.list_commands()
    names = [s.name for s in specs]
    # Safe operations are present.
    for expected in ["info", "counters", "percent", "status",
                     "lock", "unlock", "mem-read", "register-read", "raw"]:
        assert expected in names
    # Destructive operations are present *and* flagged with a danger string.
    for expected in ["clean", "decalc", "filter-change", "cappu-clean",
                     "cappu-rinse", "reset-counters", "restart", "power-off",
                     "brew", "set-pin", "set-ssid", "set-password", "set-name"]:
        assert expected in names, f"{expected!r} missing from registry"
        spec = commands.get_command(expected)
        assert spec.destructive, f"{expected!r} must be flagged destructive"
        assert spec.danger, f"{expected!r} must carry a danger explanation"
    # The read-only group must NOT be marked destructive.
    for safe in ["info", "counters", "percent", "status", "lock", "unlock",
                 "mem-read", "register-read", "raw"]:
        assert not commands.get_command(safe).destructive


def test_unknown_command_raises() -> None:
    with pytest.raises(CommandError, match="unknown command"):
        commands.get_command("not-a-real-command")


def test_wrong_argument_count_raises(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(CommandError, match="expected 1"):
            run_named(c, "mem-read", [], timeout=1.0)
        with pytest.raises(CommandError, match="expected 0"):
            run_named(c, "counters", ["extra-arg"], timeout=1.0)
    finally:
        c.close()


def test_info_returns_machine_info(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "info", timeout=3.0)
    finally:
        c.close()
    assert isinstance(result.value, MachineInfo)
    assert "machine info" in result.format()
    assert "no_beans" in result.format()


def test_counters(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "counters", timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, MaintenanceCounters)
    assert result.value.cleaning == 0x0015
    assert "cleaning=21" in result.format()


def test_percent(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "percent", timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, MaintenancePercent)
    assert result.value.cleaning == 0x50


def test_status(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "status", timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, MachineStatus)
    assert "no_beans" in result.value.active_alerts


def test_lock_unlock(sim) -> None:
    c = _paired(sim)
    try:
        lock = run_named(c, "lock", timeout=2.0)
        assert lock.value.startswith("@ts")  # type: ignore[union-attr]
        assert sim.config.screen_locked is True
        unlock = run_named(c, "unlock", timeout=2.0)
        assert unlock.value.startswith("@ts")  # type: ignore[union-attr]
        assert sim.config.screen_locked is False
    finally:
        c.close()


def test_mem_read_with_argument(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "mem-read", ["50"], timeout=2.0)
    finally:
        c.close()
    # Simulator echoes the address back as the @tm: reply tail.
    assert isinstance(result.value, str)
    assert result.value.lower().startswith("@tm:50")


def test_register_read_with_argument(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "register-read", ["32"], timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, str)
    assert result.value.lower().startswith("@tr:32")


def test_raw_passthrough(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(c, "raw", ["@TG:43"], timeout=2.0)
    finally:
        c.close()
    assert isinstance(result.value, str)
    assert result.value.startswith("@tg:43")


def test_raw_rejects_non_at_prefix(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(CommandError, match="must start with '@'"):
            run_named(c, "raw", ["TG:43"], timeout=1.0)
    finally:
        c.close()


def test_command_spec_usage_string() -> None:
    assert commands.get_command("counters").usage() == "counters"
    assert commands.get_command("mem-read").usage() == "mem-read <addr>"


# --------------------------------------------------------------------- #
# Destructive command gate
# --------------------------------------------------------------------- #


# (name, args) pairs covering every destructive command in the registry.
_DESTRUCTIVE_INVOCATIONS = [
    ("clean", []),
    ("decalc", []),
    ("filter-change", []),
    ("cappu-clean", []),
    ("cappu-rinse", []),
    ("reset-counters", []),
    ("restart", []),
    ("power-off", []),
    ("brew", ["01"]),
    ("set-pin", ["1234"]),
    ("set-ssid", ["mywifi"]),
    ("set-password", ["s3cret"]),
    ("set-name", ["Kaffeebert"]),
]


@pytest.mark.parametrize(("name", "args"), _DESTRUCTIVE_INVOCATIONS)
def test_destructive_command_blocked_without_flag(sim, name, args) -> None:
    """Every destructive command refuses without --allow-destructive-commands."""
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError) as exc:
            run_named(c, name, args, timeout=1.0)
        # The message must name the command and tell the user how to override.
        msg = str(exc.value)
        assert name in msg
        assert "allow-destructive-commands" in msg or "allow_destructive" in msg
    finally:
        c.close()


@pytest.mark.parametrize(("name", "args"), _DESTRUCTIVE_INVOCATIONS)
def test_destructive_command_reaches_wire_with_flag(sim, name, args) -> None:
    """With the flag, the destructive command is sent. The simulator still
    refuses with @an:error — that's the proof it reached the wire."""
    c = _paired(sim)
    try:
        result = run_named(
            c, name, args, timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    # Either we get @an:error (simulator's wire-level refusal) or, for
    # restart/power-off, the connection-closed sentinel.
    assert isinstance(result.value, str)
    assert (
        result.value.startswith("@an:error")
        or "connection closed" in result.value
    ), f"unexpected reply for {name!r}: {result.value!r}"


def test_raw_payload_destructive_prefix_blocked_without_flag(sim) -> None:
    """raw is non-destructive as a command, but its argument is inspected."""
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError, match="@TG:24"):
            run_named(c, "raw", ["@TG:24"], timeout=1.0)
        with pytest.raises(DestructiveCommandError, match="@HW:"):
            run_named(c, "raw", ["@HW:01,1234"], timeout=1.0)
    finally:
        c.close()


def test_raw_payload_destructive_prefix_allowed_with_flag(sim) -> None:
    c = _paired(sim)
    try:
        result = run_named(
            c, "raw", ["@TG:24"], timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    assert isinstance(result.value, str)
    assert result.value.startswith("@an:error")


def test_safe_raw_payload_is_not_gated(sim) -> None:
    """A non-destructive @ command via raw works without the flag."""
    c = _paired(sim)
    try:
        result = run_named(c, "raw", ["@TG:43"], timeout=2.0)
    finally:
        c.close()
    assert result.value.startswith("@tg:43")  # type: ignore[union-attr]


def test_set_pin_validates_numeric(sim) -> None:
    c = _paired(sim)
    try:
        with pytest.raises(CommandError, match="must be numeric"):
            run_named(
                c, "set-pin", ["abcd"], timeout=1.0, allow_destructive=True
            )
    finally:
        c.close()


def test_destructive_error_message_includes_danger_explanation(sim) -> None:
    """The message a user sees must explain WHAT can go wrong."""
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError) as exc:
            run_named(c, "set-ssid", ["foo"], timeout=1.0)
    finally:
        c.close()
    msg = str(exc.value)
    # The danger field for set-ssid mentions both the action and recovery.
    assert "WiFi" in msg or "ssid" in msg.lower()
    assert "factory reset" in msg
