"""Firmware OTA, dongle restart and milk-cooler update tests.

Everything here runs against the in-tree simulator (no mocks, no
hardware). The whole command family is destructive at the wire level,
so the simulator only models it when ``firmware_enabled=True`` is set
explicitly; the default configuration answers ``@an:error`` and that
guardrail is asserted below.
"""

from __future__ import annotations

import pytest

from jura_connect import commands, firmware
from jura_connect.client import JuraClient
from jura_connect.commands import DestructiveCommandError, run_named


def _paired(sim) -> JuraClient:
    host, port = sim.address
    c = JuraClient(host, port=port, conn_id="firmware-tests", auth_hash="")
    r = c.pair(timeout=2.0)
    assert r.state == "CORRECT"
    return c


def _sent(sim) -> list[str]:
    return [f.decode("ascii", "replace").rstrip("\r\n") for f in sim.sent_commands]


# --------------------------------------------------------------------- #
# Wire forms (pure, no I/O)
# --------------------------------------------------------------------- #


def test_ota_wire_forms() -> None:
    assert firmware.bootloader_command() == "@HB"
    assert firmware.ota_dat_command(b"\x01\x02\xab") == "@HO:0102AB"
    # "@HD:" + 8-char offset + 4-char length + hex payload, all ASCII —
    # ByteOperations.h(offset, 8) / h(len, 4) in the APK.
    assert firmware.ota_bin_command(0, b"\xaa\xbb") == "@HD:000000000002AABB"
    assert firmware.ota_bin_command(512, b"\x00") == "@HD:0000020000010" + "0"
    assert firmware.ota_end_command() == "@HE"
    assert firmware.restart_dongle_command() == "@HT:3"
    assert firmware.milk_cooler_start_command() == "@HU"
    assert firmware.milk_cooler_status_command() == "@HU?"


def test_split_chunks_uses_512_byte_packets() -> None:
    data = bytes(range(256)) * 5  # 1280 bytes
    chunks = firmware.split_chunks(data)
    assert [len(c) for c in chunks] == [512, 512, 256]
    assert b"".join(chunks) == data
    assert firmware.OTA_CHUNK_BYTES == 512
    assert firmware.split_chunks(b"") == []


def test_split_chunks_rejects_bad_size() -> None:
    with pytest.raises(ValueError):
        firmware.split_chunks(b"abc", size=0)


# --------------------------------------------------------------------- #
# The OTA sequence
# --------------------------------------------------------------------- #

_DAT = bytes.fromhex("deadbeef")
_BIN = bytes(range(256)) * 3  # 768 bytes -> 2 chunks


def _fw_sim(sim_factory, **overrides):
    overrides.setdefault("firmware_enabled", True)
    return sim_factory(**overrides)


def test_ota_sequence_runs_in_order(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    seen: list[tuple[str, int, int]] = []
    try:
        result = c.run_firmware_ota(
            dat=_DAT,
            application=_BIN,
            acknowledge_bricking_risk=True,
            progress=lambda p: seen.append((p.stage, p.index, p.total)),
            timeout=2.0,
        )
        # Snapshot before close(): JuraClient.close() still emits a bare
        # @HE of its own (JOE_GAPS §8.3), which is not part of the run.
        wire = [f for f in _sent(sim) if f.startswith(("@HB", "@HO:", "@HD:", "@HE"))]
    finally:
        c.close()

    assert result.completed is True
    assert result.chunks_sent == result.chunks_total == 2
    assert result.bytes_sent == len(_BIN)

    assert wire[0] == "@HB"
    assert wire[1] == "@HO:" + _DAT.hex().upper()
    assert wire[2].startswith("@HD:00000000" + "0200")
    assert wire[3].startswith("@HD:00000200" + "0100")
    assert wire[4] == "@HE"
    assert len(wire) == 5

    # The simulator reassembled exactly the image we fed in.
    assert sim.ota_dat == _DAT
    assert bytes(sim.ota_image) == _BIN
    assert sim.ota_completed is True

    stages = [s for s, _i, _t in seen]
    assert stages[0] == "bootloader"
    assert stages[1] == "dat"
    assert stages.count("bin") == 2
    assert stages[-1] == "end"


def test_ota_restart_step_is_opt_in(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        result = c.run_firmware_ota(
            dat=_DAT,
            application=_BIN,
            acknowledge_bricking_risk=True,
            restart=True,
            timeout=2.0,
        )
    finally:
        c.close()
    assert result.completed is True
    assert result.restarted is True
    assert "@HT:3" in _sent(sim)
    assert sim.dongle_restarts == 1


def test_ota_refuses_without_acknowledgement(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        with pytest.raises(firmware.FirmwareSafetyError) as exc:
            c.run_firmware_ota(dat=_DAT, application=_BIN, timeout=2.0)
    finally:
        c.close()
    assert "acknowledge_bricking_risk" in str(exc.value)
    # Nothing at all reached the wire.
    assert not [f for f in _sent(sim) if f.startswith(("@HB", "@HO:", "@HD:"))]


def test_ota_rejects_empty_image(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        with pytest.raises(ValueError):
            c.run_firmware_ota(
                dat=_DAT,
                application=b"",
                acknowledge_bricking_risk=True,
                timeout=2.0,
            )
    finally:
        c.close()
    assert not [f for f in _sent(sim) if f.startswith("@HB")]


def test_ota_bootloader_abort_stops_before_payload(sim_factory) -> None:
    sim = _fw_sim(sim_factory, bootloader_reply="@hb:abort")
    c = _paired(sim)
    try:
        result = c.run_firmware_ota(
            dat=_DAT,
            application=_BIN,
            acknowledge_bricking_risk=True,
            timeout=2.0,
        )
        # The session survives the abort: a normal read still works.
        assert c.read_maintenance_counter(timeout=2.0).cleaning == 0x0015
        wire = _sent(sim)
    finally:
        c.close()
    assert result.completed is False
    assert result.failed_step is not None
    assert result.failed_step.name == "bootloader"
    assert result.chunks_sent == 0
    assert not [f for f in wire if f.startswith(("@HO:", "@HD:", "@HE"))]


def test_ota_dat_error_stops_before_bin(sim_factory) -> None:
    sim = _fw_sim(sim_factory, ota_dat_reply="@ho:error")
    c = _paired(sim)
    try:
        result = c.run_firmware_ota(
            dat=_DAT,
            application=_BIN,
            acknowledge_bricking_risk=True,
            timeout=2.0,
        )
        assert c.read_maintenance_counter(timeout=2.0).cleaning == 0x0015
        wire = _sent(sim)
    finally:
        c.close()
    assert result.completed is False
    assert result.failed_step is not None and result.failed_step.name == "dat"
    assert not [f for f in wire if f.startswith(("@HD:", "@HE"))]


def test_ota_bin_error_midway_stops_and_reports_progress(sim_factory) -> None:
    sim = _fw_sim(sim_factory, ota_error_chunk=2)
    c = _paired(sim)
    try:
        result = c.run_firmware_ota(
            dat=_DAT,
            application=_BIN,
            acknowledge_bricking_risk=True,
            timeout=2.0,
        )
        assert c.read_maintenance_counter(timeout=2.0).cleaning == 0x0015
        wire = _sent(sim)
    finally:
        c.close()
    assert result.completed is False
    assert result.chunks_sent == 1
    assert result.bytes_sent == 512
    assert result.failed_step is not None and result.failed_step.name == "bin[2/2]"
    assert "@HE" not in wire


def test_ota_end_error_is_reported(sim_factory) -> None:
    sim = _fw_sim(sim_factory, ota_end_reply="@he:error")
    c = _paired(sim)
    try:
        result = c.run_firmware_ota(
            dat=_DAT,
            application=_BIN,
            acknowledge_bricking_risk=True,
            restart=True,
            timeout=2.0,
        )
    finally:
        c.close()
    assert result.completed is False
    assert result.failed_step is not None and result.failed_step.name == "end"
    # A failed OTA must never restart the dongle: that is what leaves a
    # half-written application image running.
    assert result.restarted is False
    assert "@HT:3" not in _sent(sim)


def test_simulator_rejects_payload_before_bootloader(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        assert c.request("@HO:AABB", match=r"(?i)^@ho:", timeout=2.0) == "@ho:error"
        assert (
            c.request("@HD:00000000" + "0001" + "AA", match=r"(?i)^@hd:", timeout=2.0)
            == "@hd:error"
        )
        assert c.request("@HE", match=r"(?i)^@he:", timeout=2.0) == "@he:error"
    finally:
        c.close()


def test_ota_result_format_and_to_dict(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        result = c.run_firmware_ota(
            dat=_DAT,
            application=_BIN,
            acknowledge_bricking_risk=True,
            timeout=2.0,
        )
    finally:
        c.close()
    text = result.format()
    assert "bootloader" in text and "end" in text
    d = result.to_dict()
    assert d["completed"] is True
    assert d["chunks_total"] == 2
    assert isinstance(d["steps"], list)
    # A 768-byte payload must not be echoed verbatim into the result.
    assert len(d["steps"][2]["command"]) < 128


# --------------------------------------------------------------------- #
# Milk cooler
# --------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("reply", "state", "percent", "running", "finished"),
    [
        ("@hu:800", "no_cooler", None, False, False),
        ("@hu:132", "updating", 50, True, False),
        ("@hu:100", "updating", 0, True, False),
        ("@hu:000", "idle", 0, False, False),
        ("@hu:064", "idle", 100, False, True),
        ("@hu:FFF", "unknown", None, False, False),
    ],
)
def test_milk_cooler_status_decode(reply, state, percent, running, finished) -> None:
    status = firmware.MilkCoolerStatus.parse(reply)
    assert status.state == state
    assert status.percent == percent
    assert status.running is running
    assert status.finished is finished
    assert status.to_dict()["state"] == state
    assert state.replace("_", " ") in status.format() or state in status.format()


def test_milk_cooler_status_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        firmware.MilkCoolerStatus.parse("@tf:0000")


def test_milk_cooler_status_over_the_wire(sim_factory) -> None:
    sim = _fw_sim(sim_factory, milk_cooler_status_replies=["@hu:800"])
    c = _paired(sim)
    try:
        status = c.read_milk_cooler_status(timeout=2.0)
    finally:
        c.close()
    assert status.state == "no_cooler"
    assert status.raw == "800"


def test_milk_cooler_status_is_not_gated(sim_factory) -> None:
    """@HU? is a read. Prefix-matching @HU must not gate it."""
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        result = run_named(c, "milk-cooler-status", [], timeout=2.0)
        assert isinstance(result.value, firmware.MilkCoolerStatus)
        # The raw escape hatch must agree with the registry.
        run_named(c, "raw", ["@HU?"], timeout=2.0)
        with pytest.raises(DestructiveCommandError, match="@HU"):
            run_named(c, "raw", ["@HU"], timeout=2.0)
    finally:
        c.close()


def test_milk_cooler_update_start_ok(sim_factory) -> None:
    sim = _fw_sim(sim_factory, milk_cooler_start_replies=["@hu:ok"])
    c = _paired(sim)
    try:
        started = c.start_milk_cooler_update(
            acknowledge_bricking_risk=True, timeout=2.0
        )
    finally:
        c.close()
    assert started.token == "ok"
    assert started.accepted is True
    assert "@HU" in _sent(sim)
    assert started.to_dict()["token"] == "ok"
    assert "ok" in started.format()


def test_milk_cooler_update_requires_acknowledgement(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        with pytest.raises(firmware.FirmwareSafetyError):
            c.start_milk_cooler_update(timeout=2.0)
    finally:
        c.close()
    assert "@HU" not in _sent(sim)


def test_milk_cooler_update_abort(sim_factory) -> None:
    sim = _fw_sim(sim_factory, milk_cooler_start_replies=["@hu:abort"])
    c = _paired(sim)
    try:
        run = c.run_milk_cooler_update(
            acknowledge_bricking_risk=True,
            timeout=2.0,
            poll_interval=0.0,
            max_wait=1.0,
        )
        assert c.read_maintenance_counter(timeout=2.0).cleaning == 0x0015
    finally:
        c.close()
    assert run.start.token == "abort"
    assert run.start.accepted is False
    assert run.completed is False
    assert run.polls == ()


def test_milk_cooler_update_busy_then_polls_to_completion(sim_factory) -> None:
    sim = _fw_sim(
        sim_factory,
        milk_cooler_start_replies=["@hu:busy", "@hu:ok"],
        milk_cooler_status_replies=["@hu:132", "@hu:164", "@hu:064"],
    )
    c = _paired(sim)
    seen: list[int | None] = []
    try:
        run = c.run_milk_cooler_update(
            acknowledge_bricking_risk=True,
            timeout=2.0,
            poll_interval=0.0,
            max_wait=5.0,
            progress=lambda st: seen.append(st.percent),
        )
    finally:
        c.close()
    assert run.start.token == "busy"
    assert run.completed is True
    assert run.final is not None and run.final.finished is True
    assert seen == [50, 100, 100]
    assert "percent" in run.format() or "100" in run.format()
    assert run.to_dict()["completed"] is True


def test_milk_cooler_update_stops_when_no_cooler_connected(sim_factory) -> None:
    sim = _fw_sim(
        sim_factory,
        milk_cooler_start_replies=["@hu:wait"],
        milk_cooler_status_replies=["@hu:800"],
    )
    c = _paired(sim)
    try:
        run = c.run_milk_cooler_update(
            acknowledge_bricking_risk=True,
            timeout=2.0,
            poll_interval=0.0,
            max_wait=1.0,
        )
    finally:
        c.close()
    assert run.completed is False
    assert run.final is not None and run.final.state == "no_cooler"
    assert len(run.polls) == 1


# --------------------------------------------------------------------- #
# Dongle restart
# --------------------------------------------------------------------- #


def test_restart_dongle(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        reply = c.restart_dongle(acknowledge_bricking_risk=True, timeout=2.0)
    finally:
        c.close()
    assert reply.startswith("@ht")
    assert sim.dongle_restarts == 1


def test_restart_dongle_requires_acknowledgement(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        with pytest.raises(firmware.FirmwareSafetyError):
            c.restart_dongle(timeout=2.0)
    finally:
        c.close()
    assert "@HT:3" not in _sent(sim)


# --------------------------------------------------------------------- #
# Guardrails
# --------------------------------------------------------------------- #


def test_simulator_refuses_the_family_by_default(sim) -> None:
    """Without the opt-in flag the simulator answers @an:error for every
    mutating verb in the family — the same guardrail the brew / process
    paths have."""
    c = _paired(sim)
    try:
        for danger in (
            "@HB",
            "@HO:AABB",
            "@HD:00000000" + "0001" + "AA",
            "@HE",
            "@HT:3",
            "@HU",
        ):
            reply = c.request(danger, match=r"^@an:error", timeout=1.5)
            assert reply == "@an:error", danger
    finally:
        c.close()


def test_firmware_prefixes_are_registered_as_destructive() -> None:
    for prefix in (b"@HB", b"@HO:", b"@HD:", b"@HE", b"@HT:"):
        assert prefix in commands.DESTRUCTIVE_PREFIXES, prefix
    # @HU is exact-matched: a byte prefix would swallow the @HU? read.
    assert b"@HU" in commands.DESTRUCTIVE_EXACT
    assert b"@HU" not in commands.DESTRUCTIVE_PREFIXES
    assert commands.match_destructive("@HU") == "@HU"
    assert commands.match_destructive("@HU?") is None
    assert commands.match_destructive("@HB") == "@HB"
    assert commands.match_destructive("@TG:43") is None


def test_ota_is_deliberately_not_a_named_command() -> None:
    """The OTA sequencer stays library-only: a partially applied image
    bricks the dongle, and there is no image source we can validate.
    See docs/PROTOCOL.md §5.15."""
    names = {spec.name for spec in commands.list_commands()}
    assert {"milk-cooler-status", "milk-cooler-update", "restart-dongle"} <= names
    assert not any("ota" in n or "bootloader" in n for n in names)


def test_named_milk_cooler_update_reaches_the_wire(sim_factory) -> None:
    sim = _fw_sim(sim_factory, milk_cooler_start_replies=["@hu:ok"])
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError):
            run_named(c, "milk-cooler-update", [], timeout=2.0)
        result = run_named(
            c, "milk-cooler-update", [], timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    assert result.value == "@hu:ok"


def test_named_restart_dongle_reaches_the_wire(sim_factory) -> None:
    sim = _fw_sim(sim_factory)
    c = _paired(sim)
    try:
        with pytest.raises(DestructiveCommandError):
            run_named(c, "restart-dongle", [], timeout=2.0)
        result = run_named(c, "restart-dongle", [], timeout=2.0, allow_destructive=True)
    finally:
        c.close()
    assert isinstance(result.value, str)
    assert result.value.startswith("@ht") or "connection closed" in result.value
