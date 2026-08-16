"""Language download — push a translated UI language into the machine.

Wire sequence (**APK-derived and untested against hardware** apart from
the two read-only probes, see below; ``docs/PROTOCOL.md`` §5.14 has the
derivation)::

    @TV:81,<line1><csum>   optional: paint the machine display
    @TV:82,<line2><csum>
    @TS:F1                 lock the keypad for the whole download
    @TT:00                 read the language-slot inventory
    @TM:23                 "max languages" support probe
    @TT:01,<block>         select the slot the download overwrites
    @TT:02,<addr><data>    ASCII transfer, 64 bytes per record
      (or @TT:08,<binary>  binary transfer, 128 bytes per record)
    @TT:03                 finish (machine verifies its CRC)
    @TS:00                 release the keypad
    @TV:81,' ' / @TV:82,' '  clear the display lines

Only the two probes have hardware evidence, and only in the negative:
an S8 EB / EF1091 — which declares no download capability — answers
``@TT:00`` with **complete silence** (no reply at all, reproduced three
times) and ``@TM:23`` with ``@tm:A3`` = ``NOT_SUPPORTED``
(``docs/captures/2026-08-16-kaffeebert-s8eb.md`` §4). Every mutating
verb, and the whole populated ``@tt:00`` inventory reply, remains
untested: no machine has ever been asked to swallow a language image.

The corresponding J.O.E. classes are
``joe_android_connector.src.connection.command.language_download.*``
(wire strings + reply regexes), the matching ``parser.language_download``
package (status-byte → response-code mapping) and
``CoffeeMachineAdapter.downloadLanguage`` (ordering, chunking, retry and
error handling — only readable in smali; jadx gives up on the coroutine).

This module implements the **protocol only**. Fetching language blobs
from Jura's CDN is deliberately out of scope: callers supply the data
(:class:`LanguagePayload`), the sequencer pushes it.

Safety: every step past ``@TT:00`` mutates the machine. A failed
transfer leaves the selected block half-written, and a leaked ``@TS:F1``
locks the display until a power cycle — :func:`download_language`
therefore always releases the lock, even on abort.
"""

from __future__ import annotations

import dataclasses
import enum
import re
import time
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .client import JuraClient

# -- wire verbs --------------------------------------------------------- #

LOCK_COMMAND = "@TS:F1"
UNLOCK_COMMAND = "@TS:00"
MAX_LANGUAGES_COMMAND = "@TM:23"
LIST_COMMAND = "@TT:00"
SELECT_BLOCK_COMMAND = "@TT:01"
TRANSFER_ASCII_COMMAND = "@TT:02"
TRANSFER_BINARY_COMMAND = "@TT:08"
FINISH_COMMAND = "@TT:03"
DISPLAY_LINE1_COMMAND = "@TV:81"
DISPLAY_LINE2_COMMAND = "@TV:82"

# J.O.E. truncates both display lines to 19 characters.
DISPLAY_LINE_CHARS = 19
# The machine's own "blank" for a display line (downloadFinished()).
DISPLAY_BLANK = " "
# S-record payload size in the language files J.O.E. transfers.
ASCII_RECORD_BYTES = 64
# @TT:08 merges two adjacent ASCII records into one 128-byte write.
BINARY_RECORD_BYTES = 128
# The @TT:00 reply enumerates 14 slots (0..13) in J.O.E.'s parser.
LANGUAGE_SLOT_COUNT = 14
# Pause J.O.E. inserts between two chunk writes.
INTER_CHUNK_DELAY = 0.08
# Byte-stuffing used inside the binary @TT:08 body: these four values
# would otherwise terminate or confuse the machine's line parser.
ESCAPE_BYTE = 0x1B
ESCAPED_BYTES = (0x00, 0x0A, 0x0D, 0x1B)

_TT_REPLY = re.compile(
    r"^@tt:(?P<verb>0[1238]),(?P<status>[0-9A-F]{2})(?:,(?P<extra>[0-9A-F]{4}))?$"
)


class LanguageDownloadError(RuntimeError):
    """The download cannot even be attempted (capability / payload problem)."""


# --------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------- #


def display_checksum(text: str) -> str:
    """Checksum appended to ``@TV:81`` / ``@TV:82`` display lines.

    The APK's ``ByteOperations.e``: sum every character, keep the low
    byte, format as two upper-case hex chars. Note this is *not* the
    ``ByteOperations.d`` checksum the ``@TM:`` setting writes use.
    """
    return f"{sum(ord(c) for c in text) & 0xFF:02X}"


def escape_binary(data: bytes) -> bytes:
    """ESC-escape the bytes that must not appear raw in a ``@TT:08`` body.

    ``0x00``, ``0x0A``, ``0x0D`` and ``0x1B`` become ``0x1B <b + 0x80>``
    (``CoffeeMachineAdapterBle2.Companion.a``). This sits *above* the
    transport's own reserved-byte escaping in :mod:`jura_connect.crypto`
    — the two layers are independent.
    """
    out = bytearray()
    for b in data:
        if b in ESCAPED_BYTES:
            out.append(ESCAPE_BYTE)
            out.append((b + 0x80) & 0xFF)
        else:
            out.append(b)
    return bytes(out)


def unescape_binary(data: bytes) -> bytes:
    """Inverse of :func:`escape_binary`."""
    out = bytearray()
    it = iter(data)
    for b in it:
        if b == ESCAPE_BYTE:
            try:
                nxt = next(it)
            except StopIteration:
                raise ValueError("truncated escape sequence") from None
            out.append((nxt - 0x80) & 0xFF)
        else:
            out.append(b)
    return bytes(out)


# --------------------------------------------------------------------- #
# Response codes
# --------------------------------------------------------------------- #


class _StatusEnum(enum.Enum):
    """Enum whose values are the status byte the machine answers with."""

    @classmethod
    def from_status(cls, status: str) -> Self:
        wanted = status.strip().upper()
        for member in cls:
            if member.value == wanted:
                return member
        return next(m for m in cls if m.name == "UNEXPECTED")

    @property
    def ok(self) -> bool:
        return self.name == "SUCCESS"

    @property
    def label(self) -> str:
        return self.name.replace("_", " ").lower()


class SelectBlockCode(_StatusEnum):
    """``@tt:01,<status>`` (``SelectLanguageBlockParser``)."""

    SUCCESS = "FF"
    BLOCK_NOT_AVAILABLE = "FE"
    EXECUTION_IN_PROGRESS = "FC"
    WRONG_CONTENT = "FB"
    UNEXPECTED = "??"


class TransferCode(_StatusEnum):
    """``@tt:02,<status>`` / ``@tt:08,<status>`` (``TransferLanguageDataParser``)."""

    SUCCESS = "FF"
    WRITE_ERROR = "FE"
    WRONG_SYNTAX = "FD"
    WRONG_LENGTH = "FC"
    WRONG_CONTENT = "FB"
    WRONG_LOGIC = "FA"
    UNEXPECTED = "??"


class FinishCode(_StatusEnum):
    """``@tt:03,<status>`` (``FinishLanguageDownloadParser``)."""

    SUCCESS = "FF"
    CRC_NOT_MATCHING = "FE"
    UNEXPECTED = "??"


class MaxLanguagesCode(enum.Enum):
    """``@TM:23`` reply (``ReadMaxLanguagesParser``).

    ``LANGUAGE_SET`` is the ``@tm:23,0C<xx>`` form. J.O.E.'s parser tests
    the bare ``@tm:23`` pattern first with a *substring* match, so on the
    app side that longer form can never be reached; we check the longer
    pattern first, which is what the parser evidently meant.
    """

    SUCCESS = "SUCCESS"
    LANGUAGE_SET = "LANGUAGE_SET"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    CHECKSUM_FALSE = "CHECKSUM_FALSE"
    UNEXPECTED = "UNEXPECTED"

    @classmethod
    def parse(cls, reply: str) -> "MaxLanguagesCode":
        text = reply.strip()
        if re.match(r"^@tm:23,0C[0-9A-F]{2}", text, re.IGNORECASE):
            return cls.LANGUAGE_SET
        if text.lower().startswith("@tm:a3"):
            return cls.NOT_SUPPORTED
        if text.lower().startswith("@tm:00"):
            return cls.CHECKSUM_FALSE
        if text.lower().startswith("@tm:23"):
            return cls.SUCCESS
        return cls.UNEXPECTED

    @property
    def supported(self) -> bool:
        """Whether the machine claims to know about language slots."""
        return self in (MaxLanguagesCode.SUCCESS, MaxLanguagesCode.LANGUAGE_SET)

    @property
    def label(self) -> str:
        return self.name.replace("_", " ").lower()


def _parse_tt_reply(reply: str, verb: str) -> tuple[str, str | None]:
    """Split a ``@tt:<verb>,<status>[,<extra>]`` reply.

    Returns ``(status, extra)``; ``("??", None)`` when the reply does not
    match the shape J.O.E. expects (including ``@an:error``).
    """
    m = _TT_REPLY.match(reply.strip())
    if m is None or m.group("verb") != verb:
        return "??", None
    return m.group("status"), m.group("extra")


# --------------------------------------------------------------------- #
# Payload
# --------------------------------------------------------------------- #


@dataclasses.dataclass(slots=True, frozen=True)
class LanguageChunk:
    """One flash write: a 32-bit target address plus its payload bytes."""

    address: int
    data: bytes

    def ascii_command(self) -> str:
        """``@TT:02,<addr8><data hex>`` — the plain-text transfer form."""
        return f"{TRANSFER_ASCII_COMMAND},{self.address:08X}{self.data.hex().upper()}"

    def binary_command(self) -> bytes:
        """``@TT:08`` body: raw bytes, escaped, with an explicit length.

        Layout after the ASCII verb: ``<addr:4><len:2><data>``, each part
        run through :func:`escape_binary` exactly like the APK does.
        """
        return (
            TRANSFER_BINARY_COMMAND.encode("ascii")
            + b","
            + escape_binary(self.address.to_bytes(4, "big"))
            + escape_binary(len(self.data).to_bytes(2, "big"))
            + escape_binary(self.data)
        )

    def to_dict(self) -> dict[str, object]:
        return {"address": self.address, "bytes": len(self.data)}


def _parse_srec_line(line: str) -> LanguageChunk | None:
    """Parse one Motorola S-record; ``None`` for header/termination types."""
    text = line.strip()
    if not text:
        return None
    if len(text) < 4 or text[0] not in "sS":
        raise ValueError(f"not an S-record: {line!r}")
    kind = text[1]
    addr_bytes = {"1": 2, "2": 3, "3": 4}.get(kind)
    if addr_bytes is None:
        # S0 header, S5/S6 counts, S7/S8/S9 termination — no payload.
        return None
    try:
        raw = bytes.fromhex(text[2:])
    except ValueError as exc:
        raise ValueError(f"non-hex S-record: {line!r}") from exc
    count = raw[0]
    if count + 1 != len(raw):
        raise ValueError(
            f"S-record length byte {count:#04x} does not match {len(raw) - 1} bytes"
        )
    checksum = raw[-1]
    expected = ~sum(raw[:-1]) & 0xFF
    if checksum != expected:
        raise ValueError(
            f"S-record checksum {checksum:#04x} != computed {expected:#04x}: {line!r}"
        )
    address = int.from_bytes(raw[1 : 1 + addr_bytes], "big")
    return LanguageChunk(address=address, data=raw[1 + addr_bytes : -1])


@dataclasses.dataclass(slots=True, frozen=True)
class LanguagePayload:
    """The language image to push, split into address/data records.

    Jura ships language images as Motorola S-records (``S3`` with 64-byte
    payloads); :meth:`from_srec` parses that form. :meth:`from_bytes`
    covers callers that already hold a flat image plus its base address.
    """

    chunks: tuple[LanguageChunk, ...]
    name: str = ""

    @classmethod
    def from_srec(cls, text: str, *, name: str = "") -> "LanguagePayload":
        chunks = [
            chunk
            for line in text.splitlines()
            if line.strip()
            if (chunk := _parse_srec_line(line)) is not None
        ]
        if not chunks:
            raise ValueError("S-record input carries no data records")
        return cls(chunks=tuple(chunks), name=name)

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        base_address: int = 0,
        record_bytes: int = ASCII_RECORD_BYTES,
        name: str = "",
    ) -> "LanguagePayload":
        if record_bytes <= 0:
            raise ValueError("record_bytes must be positive")
        if not data:
            raise ValueError("empty language payload")
        chunks = tuple(
            LanguageChunk(base_address + off, data[off : off + record_bytes])
            for off in range(0, len(data), record_bytes)
        )
        return cls(chunks=chunks, name=name)

    @property
    def total_bytes(self) -> int:
        return sum(len(c.data) for c in self.chunks)

    def merged(self, *, record_bytes: int = BINARY_RECORD_BYTES) -> "LanguagePayload":
        """Fold adjacent records together for the binary transfer.

        J.O.E. walks the record list and merges record *i* with *i+1*
        whenever ``addr[i] + 0x40 == addr[i+1]``, producing the 128-byte
        writes ``@TT:08`` expects. We generalise its hard-coded ``0x40``
        to "the next record starts exactly where this one ends" — same
        behaviour on the 64-byte records Jura ships, but correct for
        other record sizes too. Only *pairs* are folded, like J.O.E.;
        records that don't line up are sent as they are.
        """
        merged: list[LanguageChunk] = []
        i = 0
        n = len(self.chunks)
        while i < n:
            current = self.chunks[i]
            if (
                i + 1 < n
                and len(current.data) < record_bytes
                and current.address + len(current.data) == self.chunks[i + 1].address
                and len(current.data) + len(self.chunks[i + 1].data) <= record_bytes
            ):
                nxt = self.chunks[i + 1]
                merged.append(LanguageChunk(current.address, current.data + nxt.data))
                i += 2
                continue
            merged.append(current)
            i += 1
        return LanguagePayload(chunks=tuple(merged), name=self.name)

    def format(self) -> str:
        first = self.chunks[0].address if self.chunks else 0
        label = f"{self.name}: " if self.name else ""
        return (
            f"{label}{len(self.chunks)} record(s), {self.total_bytes} byte(s), "
            f"from 0x{first:08X}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "records": len(self.chunks),
            "bytes": self.total_bytes,
            "chunks": [c.to_dict() for c in self.chunks],
        }


# --------------------------------------------------------------------- #
# Inventory (@TT:00 + @TM:23)
# --------------------------------------------------------------------- #


@dataclasses.dataclass(slots=True, frozen=True)
class LanguageSlot:
    """One entry of the ``@TT:00`` list: slot index and its language code."""

    index: int
    code: str | None  # two-letter code, or None for an empty slot (FFFF)

    def to_dict(self) -> dict[str, object]:
        return {"index": self.index, "code": self.code}


@dataclasses.dataclass(slots=True, frozen=True)
class LanguageInventory:
    """What the machine currently holds, plus the download entry points."""

    slots: tuple[LanguageSlot, ...]
    max_languages: MaxLanguagesCode | None = None
    download_block: str | None = None
    supports_download: bool = False
    binary_download: bool = False
    #: Why the ``@TT:00`` inventory is empty, when it is empty because
    #: the machine would not answer. Machines without the language
    #: verbs stay silent rather than rejecting — observed on Kaffeebert
    #: (S8 EB / EF1091), see docs/captures/2026-08-16-kaffeebert-s8eb.md.
    list_error: str | None = None

    @classmethod
    def parse(cls, reply: str) -> "LanguageInventory":
        """Parse ``@tt:00(,<idx2><code4>)+``.

        Each group is a slot index followed by the two ASCII characters
        of its language code; ``FFFF`` marks an empty slot.
        """
        body = reply.strip()
        if not body.lower().startswith("@tt:00"):
            raise ValueError(f"not a language list reply: {reply!r}")
        groups = body.split(",")[1:]
        if not groups:
            raise ValueError(f"language list reply carries no slots: {reply!r}")
        slots: list[LanguageSlot] = []
        for group in groups:
            entry = group.strip().upper()
            if len(entry) != 6:
                raise ValueError(f"malformed language slot entry {group!r}")
            index = int(entry[:2], 16)
            raw = entry[2:]
            code = None if raw == "FFFF" else bytes.fromhex(raw).decode("ascii")
            slots.append(LanguageSlot(index=index, code=code))
        return cls(slots=tuple(slots))

    def slot(self, index: int) -> LanguageSlot | None:
        for s in self.slots:
            if s.index == index:
                return s
        return None

    def format(self) -> str:
        try:
            # The capability is a hex string in the XML; a machine with a
            # malformed one must still print an inventory.
            block_index = int(self.download_block, 16) if self.download_block else None
        except ValueError:
            block_index = None
        lines = ["Machine languages:"]
        if self.list_error is not None:
            lines.append(f"  (no reply to @TT:00: {self.list_error})")
        for s in self.slots:
            marker = "  <- download block" if s.index == block_index else ""
            lines.append(f"  slot {s.index:2d}: {s.code or '-'}{marker}")
        support = "yes" if self.supports_download else "no"
        transfer = "binary (@TT:08)" if self.binary_download else "ASCII (@TT:02)"
        lines.append(f"  download supported (profile): {support}")
        lines.append(f"  download block: {self.download_block or '-'}")
        lines.append(f"  transfer form: {transfer}")
        if self.max_languages is not None:
            lines.append(f"  machine @TM:23: {self.max_languages.label}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "slots": [s.to_dict() for s in self.slots],
            "max_languages": (
                self.max_languages.name if self.max_languages is not None else None
            ),
            "download_block": self.download_block,
            "supports_download": self.supports_download,
            "binary_download": self.binary_download,
            "list_error": self.list_error,
        }


# --------------------------------------------------------------------- #
# Progress + result
# --------------------------------------------------------------------- #


@dataclasses.dataclass(slots=True, frozen=True)
class LanguageProgress:
    """One transferred record, handed to the ``progress`` callback."""

    index: int  # 0-based
    total: int
    address: int
    byte_count: int
    code: TransferCode

    @property
    def human(self) -> str:
        return f"block {self.index + 1} of {self.total}"

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "total": self.total,
            "address": self.address,
            "bytes": self.byte_count,
            "code": self.code.name,
        }


ProgressCallback = Callable[[LanguageProgress], None]


@dataclasses.dataclass(slots=True, frozen=True)
class LanguageDownloadResult:
    """Outcome of one :func:`download_language` run."""

    block: str
    binary: bool
    chunks_total: int
    chunks_sent: int = 0
    bytes_sent: int = 0
    max_languages: MaxLanguagesCode | None = None
    select_code: SelectBlockCode | None = None
    transfer_code: TransferCode | None = None
    finish_code: FinishCode | None = None
    failed_chunk: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.finish_code is FinishCode.SUCCESS

    def format(self) -> str:
        verb = TRANSFER_BINARY_COMMAND if self.binary else TRANSFER_ASCII_COMMAND
        head = "Language download " + ("succeeded" if self.ok else "FAILED")
        lines = [
            f"{head} (block {self.block}, {verb})",
            f"  records: {self.chunks_sent}/{self.chunks_total}"
            f"  bytes: {self.bytes_sent}",
        ]
        if self.max_languages is not None:
            lines.append(f"  @TM:23: {self.max_languages.label}")
        if self.select_code is not None:
            lines.append(f"  @TT:01: {self.select_code.label}")
        if self.transfer_code is not None:
            lines.append(f"  {verb}: {self.transfer_code.label}")
        if self.finish_code is not None:
            lines.append(f"  @TT:03: {self.finish_code.label}")
        if self.failed_chunk is not None:
            lines.append(f"  failed at record {self.failed_chunk + 1}")
        if self.error:
            lines.append(f"  error: {self.error}")
        if not self.ok:
            lines.append(
                "  the selected block may be half-written; re-run the "
                "download before using the machine's language menu."
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "block": self.block,
            "binary": self.binary,
            "chunks_total": self.chunks_total,
            "chunks_sent": self.chunks_sent,
            "bytes_sent": self.bytes_sent,
            "max_languages": (
                self.max_languages.name if self.max_languages is not None else None
            ),
            "select_code": (
                self.select_code.name if self.select_code is not None else None
            ),
            "transfer_code": (
                self.transfer_code.name if self.transfer_code is not None else None
            ),
            "finish_code": (
                self.finish_code.name if self.finish_code is not None else None
            ),
            "failed_chunk": self.failed_chunk,
            "error": self.error,
        }


# --------------------------------------------------------------------- #
# Wire primitives
# --------------------------------------------------------------------- #


def lock(client: "JuraClient", *, timeout: float = 6.0) -> str:
    """``@TS:F1`` — lock the keypad for the duration of the download."""
    return client.request(LOCK_COMMAND, match=r"^@(ts|an)", timeout=timeout)


def unlock(client: "JuraClient", *, timeout: float = 6.0) -> str:
    """``@TS:00`` — release the keypad (same verb as the display unlock)."""
    return client.request(UNLOCK_COMMAND, match=r"^@(ts|an)", timeout=timeout)


def read_max_languages(
    client: "JuraClient", *, timeout: float = 6.0
) -> MaxLanguagesCode:
    """``@TM:23`` — does this machine know about downloadable languages?"""
    reply = client.request(MAX_LANGUAGES_COMMAND, match=r"^@(tm|an)", timeout=timeout)
    return MaxLanguagesCode.parse(reply)


def list_languages(client: "JuraClient", *, timeout: float = 6.0) -> LanguageInventory:
    """``@TT:00`` — the slot inventory, without any capability decoration."""
    reply = client.request(LIST_COMMAND, match=r"^@(tt:00|an)", timeout=timeout)
    return LanguageInventory.parse(reply)


def set_display_lines(
    client: "JuraClient",
    line1: str,
    line2: str = "",
    *,
    timeout: float = 6.0,
) -> tuple[str, str]:
    """``@TV:81`` / ``@TV:82`` — paint two lines on the machine display.

    Both lines are truncated to 19 characters like J.O.E. does, and each
    carries a :func:`display_checksum`.
    """
    replies = []
    for verb, text in (
        (DISPLAY_LINE1_COMMAND, line1),
        (DISPLAY_LINE2_COMMAND, line2),
    ):
        body = text[:DISPLAY_LINE_CHARS]
        replies.append(
            client.request(
                f"{verb},{body}{display_checksum(body)}",
                match=r"^@(tv|an)",
                timeout=timeout,
            )
        )
    return replies[0], replies[1]


def select_block(
    client: "JuraClient", block: str, *, timeout: float = 6.0
) -> SelectBlockCode:
    """``@TT:01,<block>`` — pick the slot the transfer overwrites."""
    reply = client.request(
        f"{SELECT_BLOCK_COMMAND},{block}", match=r"^@(tt:01|an)", timeout=timeout
    )
    status, _extra = _parse_tt_reply(reply, "01")
    return SelectBlockCode.from_status(status)


def transfer_chunk(
    client: "JuraClient",
    chunk: LanguageChunk,
    *,
    binary: bool,
    timeout: float = 6.0,
) -> tuple[TransferCode, str | None]:
    """Send one record; returns its status code and the 16-bit field.

    The trailing ``,<4 hex>`` on a successful reply is believed to be
    the machine's running CRC over the block (``@TT:03`` fails with
    ``FE = CRC_NOT_MATCHING`` when its own sum disagrees). J.O.E. never
    looks at it; we surface it and leave the interpretation open.
    """
    if binary:
        reply = client.request_raw(
            chunk.binary_command(), match=r"^@(tt:08|an)", timeout=timeout
        )
        verb = "08"
    else:
        reply = client.request(
            chunk.ascii_command(), match=r"^@(tt:02|an)", timeout=timeout
        )
        verb = "02"
    status, extra = _parse_tt_reply(reply, verb)
    return TransferCode.from_status(status), extra


def finish(client: "JuraClient", *, timeout: float = 6.0) -> FinishCode:
    """``@TT:03`` — close the block; the machine verifies its checksum."""
    reply = client.request(FINISH_COMMAND, match=r"^@(tt:03|an)", timeout=timeout)
    status, _extra = _parse_tt_reply(reply, "03")
    return FinishCode.from_status(status)


def read_inventory(client: "JuraClient", *, timeout: float = 6.0) -> LanguageInventory:
    """``@TT:00`` + ``@TM:23``, decorated with the profile's capabilities.

    A machine that does not implement the language verbs answers
    ``@TT:00`` with silence, not with a rejection token — verified on
    Kaffeebert (S8 EB / EF1091, TT237W V06.11) on 2026-08-16, where the
    read timed out while the dongle kept broadcasting ``@TF:`` frames.
    That is an answer, not a failure, so the timeout is recorded in
    :attr:`LanguageInventory.list_error` and ``@TM:23`` is still asked:
    its reply (``@tm:A3`` = NOT_SUPPORTED on that machine) is what
    distinguishes "no languages installed" from "verb unknown".
    """
    list_error: str | None = None
    try:
        inventory = list_languages(client, timeout=timeout)
    except (TimeoutError, ValueError) as exc:
        list_error = str(exc)
        inventory = LanguageInventory(slots=())
    max_languages = read_max_languages(client, timeout=timeout)
    caps = client.profile.capabilities if client.profile is not None else None
    return dataclasses.replace(
        inventory,
        list_error=list_error,
        max_languages=max_languages,
        download_block=caps.language_download_block if caps is not None else None,
        supports_download=caps.language_download if caps is not None else False,
        binary_download=caps.binary_language_download if caps is not None else False,
    )


# --------------------------------------------------------------------- #
# Sequencer
# --------------------------------------------------------------------- #


def _require_capabilities(client: "JuraClient") -> tuple[str, bool]:
    """Resolve (block, binary) from the loaded profile or refuse.

    Raises before any wire traffic — pushing a language image at a
    machine whose XML doesn't declare the feature is exactly the kind of
    write that leaves a block half-programmed.
    """
    profile = client.profile
    if profile is None:
        raise LanguageDownloadError(
            "no MachineProfile loaded — pass profile=load_profile('EFxxxx') to "
            "JuraClient() so the LanguageDownload capability can be checked."
        )
    caps = profile.capabilities
    if not caps.language_download:
        raise LanguageDownloadError(
            f"machine profile {profile.code} does not declare the "
            f"LanguageDownload capability (<MACHINEMANIFEST><CAPABILITIES/>). "
            f"Refusing to push a language image."
        )
    return caps.language_download_block, caps.binary_language_download


def download_language(
    client: "JuraClient",
    payload: LanguagePayload,
    *,
    block: str | None = None,
    binary: bool | None = None,
    message: Sequence[str] | None = None,
    progress: ProgressCallback | None = None,
    timeout: float = 6.0,
    chunk_delay: float = INTER_CHUNK_DELAY,
    select_retries: int = 1,
) -> LanguageDownloadResult:
    """Run the whole language-download sequence.

    ``block`` and ``binary`` default to the machine profile's
    ``LanguageDownloadBlock`` / ``BinaryLanguageDownload`` capabilities;
    pass them only to override a profile that is known to be wrong.

    ``message`` is an optional one- or two-element sequence of display
    lines painted on the machine while the transfer runs, blanked
    afterwards.

    Machine-side refusals are *returned* (``result.ok is False``) rather
    than raised, mirroring the rest of the library; only unusable input
    raises :class:`LanguageDownloadError`. The keypad lock is always
    released, including on abort.
    """
    default_block, default_binary = _require_capabilities(client)
    use_block = (block or default_block).upper()
    use_binary = default_binary if binary is None else binary
    if not payload.chunks:
        raise LanguageDownloadError("language payload carries no records")

    chunks = payload.merged().chunks if use_binary else payload.chunks
    total = len(chunks)
    sent = 0
    bytes_sent = 0
    max_languages: MaxLanguagesCode | None = None
    select_code: SelectBlockCode | None = None
    transfer_code: TransferCode | None = None
    finish_code: FinishCode | None = None
    failed_chunk: int | None = None
    error: str | None = None

    def result() -> LanguageDownloadResult:
        return LanguageDownloadResult(
            block=use_block,
            binary=use_binary,
            chunks_total=total,
            chunks_sent=sent,
            bytes_sent=bytes_sent,
            max_languages=max_languages,
            select_code=select_code,
            transfer_code=transfer_code,
            finish_code=finish_code,
            failed_chunk=failed_chunk,
            error=error,
        )

    lines: tuple[str, str] | None = None
    if message is not None:
        if not 1 <= len(message) <= 2:
            raise LanguageDownloadError(
                f"message must be one or two display lines, got {len(message)}"
            )
        lines = (message[0], message[1] if len(message) > 1 else "")
        set_display_lines(client, lines[0], lines[1], timeout=timeout)

    lock_reply = lock(client, timeout=timeout)
    try:
        if not lock_reply.lower().startswith("@ts"):
            error = f"machine refused the keypad lock ({lock_reply!r})"
            return result()

        list_languages(client, timeout=timeout)
        max_languages = read_max_languages(client, timeout=timeout)
        if not max_languages.supported:
            error = f"machine reports {max_languages.label} for {MAX_LANGUAGES_COMMAND}"
            return result()

        for attempt in range(select_retries + 1):
            select_code = select_block(client, use_block, timeout=timeout)
            if select_code is SelectBlockCode.SUCCESS:
                break
            # J.O.E. closes the session with @TT:03 after *any* select
            # failure (its downloadLanguage calls finishLanguageDownload
            # before it even looks at the code), then retries the select
            # once if the machine merely said it was still busy.
            finish(client, timeout=timeout)
            if (
                select_code is not SelectBlockCode.EXECUTION_IN_PROGRESS
                or attempt >= select_retries
            ):
                error = f"block {use_block} not selectable: {select_code.label}"
                return result()

        for index, chunk in enumerate(chunks):
            transfer_code, _extra = transfer_chunk(
                client, chunk, binary=use_binary, timeout=timeout
            )
            if progress is not None:
                progress(
                    LanguageProgress(
                        index=index,
                        total=total,
                        address=chunk.address,
                        byte_count=len(chunk.data),
                        code=transfer_code,
                    )
                )
            if transfer_code is not TransferCode.SUCCESS:
                failed_chunk = index
                error = (
                    f"record {index + 1}/{total} at 0x{chunk.address:08X} "
                    f"refused: {transfer_code.label}"
                )
                return result()
            sent += 1
            bytes_sent += len(chunk.data)
            if chunk_delay > 0 and index + 1 < total:
                time.sleep(chunk_delay)

        finish_code = finish(client, timeout=timeout)
        if finish_code is not FinishCode.SUCCESS:
            error = f"{FINISH_COMMAND} refused: {finish_code.label}"
        return result()
    finally:
        # Never leak the lock: a live @TS:F1 leaves the display locked
        # until the machine is power-cycled (PROTOCOL.md §9).
        try:
            unlock(client, timeout=timeout)
        except Exception:  # noqa: BLE001 - best effort, must not mask errors
            pass
        if lines is not None:
            try:
                set_display_lines(client, DISPLAY_BLANK, DISPLAY_BLANK, timeout=timeout)
            except Exception:  # noqa: BLE001 - cosmetic, must not mask errors
                pass
