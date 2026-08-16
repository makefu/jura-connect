"""Language-download protocol tests (``@TS:F1`` / ``@TT:xx`` / ``@TV:8x``).

Everything here is exercised against :mod:`jura_connect.simulator`, which
models the whole sequence — the keypad lock, the slot inventory, the
block select, the chunk transfers (ASCII *and* binary) and the finish.
No hardware was involved: the wire formats are APK-derived (see
``docs/PROTOCOL.md`` §5.14), so these tests pin *our* understanding of
the protocol, not a machine's behaviour.
"""

from __future__ import annotations

import pytest

from jura_connect import language
from jura_connect.client import JuraClient
from jura_connect.commands import CommandError, DestructiveCommandError, run_named
from jura_connect.language import (
    LanguageDownloadError,
    LanguagePayload,
    SelectBlockCode,
    TransferCode,
)
from jura_connect.profile import load_profile

# EF1208 declares LanguageDownload="true" BinaryLanguageDownload="false"
# -> ASCII @TT:02 transfers. EF1123 declares BinaryLanguageDownload="true"
# -> @TT:08 with 128-byte records. EF1091 (the maintainer's S8 EB) has no
# <MACHINEMANIFEST> at all -> the feature must be refused outright.
ASCII_MACHINE = "EF1208"
BINARY_MACHINE = "EF1123"
NO_CAPABILITY_MACHINE = "EF1091"

BASE_ADDRESS = 0x00010000


def _paired(sim, *, machine: str | None = None) -> JuraClient:
    host, port = sim.address
    profile = load_profile(machine) if machine else None
    c = JuraClient(host, port=port, conn_id="langtest", auth_hash="", profile=profile)
    result = c.pair(timeout=2.0)
    assert result.state == "CORRECT"
    return c


def _srec_line(address: int, data: bytes) -> str:
    """Build one S3 record: ``S3<count><addr32><data><checksum>``."""
    body = address.to_bytes(4, "big") + data
    count = len(body) + 1
    checksum = ~(count + sum(body)) & 0xFF
    return f"S3{count:02X}{body.hex().upper()}{checksum:02X}"


def _sample_srec(records: int = 3, record_bytes: int = 64) -> str:
    lines = ["S00600004844521B"]  # S0 header, must be ignored
    for i in range(records):
        data = bytes((i * record_bytes + n) & 0xFF for n in range(record_bytes))
        lines.append(_srec_line(BASE_ADDRESS + i * record_bytes, data))
    lines.append("S70500000000FA")  # S7 termination, must be ignored
    return "\n".join(lines) + "\n"


def _wire(sim) -> list[str]:
    """Language-download commands seen by the simulator, in order."""
    out = []
    for frame in sim.sent_commands:
        if frame.startswith((b"@TS:", b"@TT:", b"@TV:8", b"@TM:23")):
            out.append(frame.decode("ascii", errors="replace"))
    return out


def _verbs(sim) -> list[str]:
    return [cmd.split(",", 1)[0] for cmd in _wire(sim)]


# --------------------------------------------------------------------- #
# Payload handling
# --------------------------------------------------------------------- #


def test_srec_payload_parses_addresses_and_data() -> None:
    payload = LanguagePayload.from_srec(_sample_srec())
    assert len(payload.chunks) == 3
    assert [c.address for c in payload.chunks] == [
        BASE_ADDRESS,
        BASE_ADDRESS + 0x40,
        BASE_ADDRESS + 0x80,
    ]
    assert all(len(c.data) == 64 for c in payload.chunks)
    assert payload.total_bytes == 192


def test_srec_payload_rejects_bad_checksum() -> None:
    good = _srec_line(BASE_ADDRESS, b"\x01\x02\x03\x04")
    bad = good[:-2] + "00"
    with pytest.raises(ValueError, match="checksum"):
        LanguagePayload.from_srec(bad)


def test_binary_merge_folds_adjacent_records() -> None:
    """@TT:08 sends 128-byte records: J.O.E. merges two adjacent 64-byte
    S-records whenever addr[i] + 0x40 == addr[i+1]."""
    payload = LanguagePayload.from_srec(_sample_srec(records=4))
    merged = payload.merged()
    assert [len(c.data) for c in merged.chunks] == [128, 128]
    assert [c.address for c in merged.chunks] == [BASE_ADDRESS, BASE_ADDRESS + 0x80]
    # A gap in the address space stops the merge.
    gapped = LanguagePayload(
        chunks=(
            language.LanguageChunk(0x100, b"\x00" * 64),
            language.LanguageChunk(0x400, b"\x00" * 64),
        )
    )
    assert [len(c.data) for c in gapped.merged().chunks] == [64, 64]


def test_binary_command_escapes_reserved_bytes() -> None:
    """The @TT:08 body is raw binary, so 00/0A/0D/1B are ESC-escaped."""
    chunk = language.LanguageChunk(0x0000000A, b"\x00\x0d\x1b\x41")
    raw = chunk.binary_command()
    assert raw.startswith(b"@TT:08,")
    body = raw[len(b"@TT:08,") :]
    assert b"\r\n" not in raw
    assert language.unescape_binary(body) == (
        b"\x00\x00\x00\x0a" + b"\x00\x04" + b"\x00\x0d\x1b\x41"
    )


# --------------------------------------------------------------------- #
# Capability gating
# --------------------------------------------------------------------- #


def test_profile_parses_capabilities() -> None:
    ascii_machine = load_profile(ASCII_MACHINE)
    assert ascii_machine.capabilities.language_download is True
    assert ascii_machine.capabilities.binary_language_download is False
    # Attribute absent -> J.O.E.'s CMCapabilities default of "0B".
    assert ascii_machine.capabilities.language_download_block == "0B"

    binary_machine = load_profile(BINARY_MACHINE)
    assert binary_machine.capabilities.binary_language_download is True
    assert binary_machine.capabilities.language_download_block == "0B"

    plain = load_profile(NO_CAPABILITY_MACHINE)
    assert plain.capabilities.declared is False
    assert plain.capabilities.language_download is False


def test_capability_less_machine_refuses_before_any_wire_traffic(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True)
    c = _paired(sim, machine=NO_CAPABILITY_MACHINE)
    try:
        with pytest.raises(LanguageDownloadError, match="does not declare"):
            c.download_language(
                LanguagePayload.from_srec(_sample_srec()), chunk_delay=0.0
            )
    finally:
        c.close()
    assert _wire(sim) == []


def test_missing_profile_refuses_before_any_wire_traffic(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True)
    c = _paired(sim)
    try:
        with pytest.raises(LanguageDownloadError, match="MachineProfile"):
            c.download_language(
                LanguagePayload.from_srec(_sample_srec()), chunk_delay=0.0
            )
    finally:
        c.close()
    assert _wire(sim) == []


# --------------------------------------------------------------------- #
# The full sequence
# --------------------------------------------------------------------- #


def test_ascii_download_sends_the_documented_sequence(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True)
    c = _paired(sim, machine=ASCII_MACHINE)
    seen: list[tuple[int, int]] = []
    try:
        result = c.download_language(
            LanguagePayload.from_srec(_sample_srec()),
            message=("Language", "update"),
            progress=lambda p: seen.append((p.index, p.total)),
            chunk_delay=0.0,
        )
    finally:
        c.close()

    assert result.ok is True
    assert result.binary is False
    assert result.block == "0B"
    assert result.chunks_sent == 3
    assert result.bytes_sent == 192
    assert result.select_code is SelectBlockCode.SUCCESS
    assert result.transfer_code is TransferCode.SUCCESS
    assert seen == [(0, 3), (1, 3), (2, 3)]

    assert _verbs(sim) == [
        "@TV:81",
        "@TV:82",
        "@TS:F1",
        "@TT:00",
        "@TM:23",
        "@TT:01",
        "@TT:02",
        "@TT:02",
        "@TT:02",
        "@TT:03",
        "@TS:00",
        "@TV:81",
        "@TV:82",
    ]
    wire = _wire(sim)
    assert wire[0] == "@TV:81,Language" + language.display_checksum("Language")
    assert wire[5] == "@TT:01,0B"
    assert wire[6].startswith("@TT:02,00010000")
    assert wire[7].startswith("@TT:02,00010040")
    # The machine ends unlocked and holds every byte we sent.
    assert sim.language.locked is False
    assert sim.language.finished is True
    assert sum(len(data) for _addr, data in sim.language.chunks) == 192


def test_single_line_message_blanks_the_second_line(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True)
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        result = c.download_language(
            LanguagePayload.from_srec(_sample_srec(records=1)),
            message=("Updating",),
            chunk_delay=0.0,
        )
    finally:
        c.close()
    assert result.ok is True
    wire = _wire(sim)
    assert wire[0] == "@TV:81,Updating" + language.display_checksum("Updating")
    assert wire[1] == "@TV:82," + language.display_checksum("")


def test_message_with_more_than_two_lines_is_refused(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True)
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        with pytest.raises(LanguageDownloadError, match="display lines"):
            c.download_language(
                LanguagePayload.from_srec(_sample_srec()),
                message=("one", "two", "three"),
                chunk_delay=0.0,
            )
    finally:
        c.close()
    assert _wire(sim) == []


def test_binary_capability_selects_tt08_and_128_byte_records(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True)
    c = _paired(sim, machine=BINARY_MACHINE)
    try:
        result = c.download_language(
            LanguagePayload.from_srec(_sample_srec(records=4)), chunk_delay=0.0
        )
    finally:
        c.close()

    assert result.ok is True
    assert result.binary is True
    assert result.chunks_sent == 2
    assert result.bytes_sent == 256
    assert _verbs(sim) == [
        "@TS:F1",
        "@TT:00",
        "@TM:23",
        "@TT:01",
        "@TT:08",
        "@TT:08",
        "@TT:03",
        "@TS:00",
    ]
    assert [len(data) for _addr, data in sim.language.chunks] == [128, 128]
    assert [addr for addr, _data in sim.language.chunks] == [
        BASE_ADDRESS,
        BASE_ADDRESS + 0x80,
    ]


def test_rejected_chunk_aborts_and_releases_the_keypad(sim_factory) -> None:
    """A refused chunk must stop the transfer, skip @TT:03 and still
    unlock — a leaked @TS:F1 locks the display until a power cycle
    (PROTOCOL.md §9)."""
    sim = sim_factory(
        allow_language_download=True,
        language_reject_chunk=1,
        language_reject_code="FE",
    )
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        result = c.download_language(
            LanguagePayload.from_srec(_sample_srec()), chunk_delay=0.0
        )
    finally:
        c.close()

    assert result.ok is False
    assert result.failed_chunk == 1
    assert result.chunks_sent == 1
    assert result.transfer_code is TransferCode.WRITE_ERROR
    assert result.finish_code is None
    assert "write error" in result.format().lower()

    verbs = _verbs(sim)
    assert "@TT:03" not in verbs
    assert verbs[-1] == "@TS:00"
    assert verbs.count("@TT:02") == 2  # the good one and the refused one
    assert sim.language.locked is False


def test_unavailable_block_aborts_and_releases_the_keypad(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True, language_download_block="03")
    c = _paired(sim, machine=ASCII_MACHINE)  # profile default block "0B"
    try:
        result = c.download_language(
            LanguagePayload.from_srec(_sample_srec()), chunk_delay=0.0
        )
    finally:
        c.close()

    assert result.ok is False
    assert result.select_code is SelectBlockCode.BLOCK_NOT_AVAILABLE
    assert result.chunks_sent == 0
    verbs = _verbs(sim)
    assert "@TT:02" not in verbs
    assert verbs[-1] == "@TS:00"
    assert sim.language.locked is False


def test_busy_block_is_retried_once(sim_factory) -> None:
    """EXECUTION_IN_PROGRESS gets one @TT:03 + retry, like J.O.E."""
    sim = sim_factory(allow_language_download=True, language_select_busy_once=True)
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        result = c.download_language(
            LanguagePayload.from_srec(_sample_srec(records=1)), chunk_delay=0.0
        )
    finally:
        c.close()

    assert result.ok is True
    assert _verbs(sim) == [
        "@TS:F1",
        "@TT:00",
        "@TM:23",
        "@TT:01",  # answered FC (busy)
        "@TT:03",  # J.O.E. finishes the stale session before retrying
        "@TT:01",
        "@TT:02",
        "@TT:03",
        "@TS:00",
    ]


def test_machine_reporting_not_supported_aborts(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True, max_languages_reply="@tm:A3")
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        result = c.download_language(
            LanguagePayload.from_srec(_sample_srec()), chunk_delay=0.0
        )
    finally:
        c.close()

    assert result.ok is False
    assert result.max_languages is language.MaxLanguagesCode.NOT_SUPPORTED
    verbs = _verbs(sim)
    assert "@TT:01" not in verbs
    assert verbs[-1] == "@TS:00"


# --------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------- #


def test_language_inventory_read(sim_factory) -> None:
    sim = sim_factory(
        allow_language_download=True,
        language_slots={0: "DE", 1: "EN", 11: "XX"},
    )
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        inventory = c.read_language_inventory()
    finally:
        c.close()

    assert inventory.slot(0).code == "DE"
    assert inventory.slot(1).code == "EN"
    assert inventory.slot(2).code is None  # FFFF -> empty
    assert inventory.slot(11).code == "XX"
    assert inventory.download_block == "0B"
    assert inventory.max_languages is language.MaxLanguagesCode.SUCCESS
    assert "0B" in inventory.format()
    assert inventory.to_dict()["slots"][0] == {"index": 0, "code": "DE"}


def test_languages_command_is_not_gated(sim_factory) -> None:
    sim = sim_factory(allow_language_download=True)
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        result = run_named(c, "languages", timeout=2.0)
    finally:
        c.close()
    assert result.to_dict()["name"] == "languages"
    assert _verbs(sim) == ["@TT:00", "@TM:23"]


def test_language_inventory_survives_a_machine_that_ignores_tt00(sim_factory) -> None:
    """A machine without the language verbs never answers ``@TT:00``.

    Observed on Kaffeebert (S8 EB / EF1091, TT237W V06.11) on
    2026-08-16: ``@TT:00`` draws no reply at all — only the dongle's
    periodic ``@TF:`` broadcasts — and ``@TM:23`` answers ``@tm:A3``
    (NOT_SUPPORTED). The simulator models exactly that when
    ``allow_language_download`` is off. Reading the inventory must
    still produce a usable answer instead of raising, because
    "this machine has no language slots" is the whole point of asking.
    """
    sim = sim_factory(max_languages_reply="@tm:A3")
    c = _paired(sim, machine=NO_CAPABILITY_MACHINE)
    try:
        result = run_named(c, "languages", timeout=0.5)
    finally:
        c.close()

    payload = result.to_dict()["value"]
    assert payload["slots"] == []
    assert payload["max_languages"] == "NOT_SUPPORTED"
    assert payload["supports_download"] is False
    assert "@TT:00" in str(payload["list_error"])
    assert "no reply" in result.format()
    # @TM:23 must still be asked: the machine's own answer is the part
    # that distinguishes "no slots" from "verb unknown".
    assert _verbs(sim) == ["@TT:00", "@TM:23"]


# --------------------------------------------------------------------- #
# Destructive gating
# --------------------------------------------------------------------- #


_SREC_ARG = _srec_line(BASE_ADDRESS, bytes(range(1, 9)))


def test_language_download_command_blocked_without_flag(sim) -> None:
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        with pytest.raises(DestructiveCommandError) as exc:
            run_named(c, "language-download", [_SREC_ARG], timeout=1.0)
        assert "language-download" in str(exc.value)
        assert "allow-destructive-commands" in str(exc.value)
    finally:
        c.close()
    assert _wire(sim) == []


def test_language_download_command_reaches_the_wire_with_flag(sim) -> None:
    """The default simulator refuses every language command with
    @an:error — proof the gated call really hit the wire."""
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        result = run_named(
            c, "language-download", [_SREC_ARG], timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    assert result.value.ok is False
    assert "@an:error" in (result.value.error or "")
    assert _verbs(sim) == ["@TS:F1", "@TS:00"]


def test_language_download_command_reads_an_srec_file(tmp_path, sim_factory) -> None:
    sim = sim_factory(allow_language_download=True)
    path = tmp_path / "de.s19"
    path.write_text(_sample_srec(records=2))
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        result = run_named(
            c, "language-download", [str(path)], timeout=2.0, allow_destructive=True
        )
    finally:
        c.close()
    assert result.value.ok is True
    assert result.value.chunks_sent == 2
    assert result.to_dict()["value"]["ok"] is True


def test_language_download_command_rejects_garbage(sim) -> None:
    c = _paired(sim, machine=ASCII_MACHINE)
    try:
        with pytest.raises(CommandError, match="neither a readable S-record"):
            run_named(
                c,
                "language-download",
                ["nonsense"],
                timeout=1.0,
                allow_destructive=True,
            )
    finally:
        c.close()
    assert _wire(sim) == []
