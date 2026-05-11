"""Named-command registry tests, end-to-end via the simulator.

Each registered command is dispatched against the in-tree simulator
(no mocks), exercising the same code path the CLI takes.
"""

from __future__ import annotations

import pytest

from jura_wifi import commands
from jura_wifi.client import (
    JuraClient,
    MachineInfo,
    MachineStatus,
    MaintenanceCounters,
    MaintenancePercent,
)
from jura_wifi.commands import CommandError, run_named


def _paired(sim) -> JuraClient:
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="cmd-tests", auth_hash="")
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def test_list_commands_is_non_empty_and_safe() -> None:
    names = [s.name for s in commands.list_commands()]
    # Sanity: well-known safe ones are present.
    for expected in ["info", "counters", "percent", "status",
                     "lock", "unlock", "mem-read", "register-read", "raw"]:
        assert expected in names
    # Sanity: destructive prefixes are NOT exposed by name. The registry
    # never starts a cleaning cycle or writes a PIN by accident.
    for forbidden in ["clean", "decalc", "brew", "set-pin", "write"]:
        assert forbidden not in names


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
