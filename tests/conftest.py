"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from jura_wifi.simulator import Simulator, SimulatorConfig


@pytest.fixture
def sim() -> Iterator[Simulator]:
    """A default simulator with no PIN, no pre-paired devices, fast statuses."""
    s = Simulator(SimulatorConfig(status_interval=0.05))
    s.start()
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture
def sim_factory():
    """Yield a function that builds and starts a configurable simulator."""
    started: list[Simulator] = []

    def _make(**overrides) -> Simulator:
        defaults = {"status_interval": 0.05}
        defaults.update(overrides)
        cfg = SimulatorConfig(**defaults)
        s = Simulator(cfg)
        s.start()
        started.append(s)
        return s

    yield _make

    for s in started:
        s.stop()
