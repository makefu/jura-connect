"""In-process Jura coffee-machine simulator.

A small TCP server that speaks the same WiFi protocol as the real
machine. Uses the *same* :mod:`jura_connect.crypto` and
:mod:`jura_connect.protocol` modules as the client, so encoding /
decoding is verified symmetric by construction (no mocking).

Used by the test-suite via :func:`run_in_thread`, but can also be
launched as a standalone process via ``python -m jura_connect.simulator``.

The simulator models:

* ``@HP:<pin>,<conn_id_hex>,<hash>`` handshake including the "press OK
  on machine" pairing window for an empty hash.
* The batch settings read ``@TM:00,FC`` (the XML's
  ``<BANK Name="Setting">``) and the per-product limit load
  ``@TM:60,<code><csum>``, including their rejection tokens
  (``@tm:00`` / ``@tm:C1``) so the client's fallback paths are covered.
* Read commands ``@TG:43`` (maintenance counters), ``@TG:C0``
  (maintenance percent), ``@TS:01``/``@TS:00`` (lock/unlock display),
  ``@TG:FF`` (cancel the running product step),
  ``@HU?`` (status request that yields one ``@TF:`` frame, or the
  milk-cooler update state when firmware modelling is enabled).
* The programmable-recipe (PMode) interface — ``@TM:50`` slot count,
  ``@TM:41``/``@TM:42`` product and slot reads, and (opt-in, see
  ``SimulatorConfig.pmode_writable``) the matching writes, in both the
  "machine exposes slots" and the EF1091-style "answers ``@tm:C2`` for
  everything" flavours.
* Every paginated counter bank (``@TR:32``/``@TR:33`` product,
  ``@TR:34``/``@TR:35`` barista, ``@TR:42``..``@TR:45`` daily,
  ``@TR:52``/``@TR:53`` special). Each has its own
  :class:`SimulatorConfig` table, and a table left at ``None`` models a
  machine without that bank: it answers the bare ``@tr:00``.
* Session teardown: an **empty frame**, which is what J.O.E.'s
  ``WifiCommandCloseConnection`` sends and what
  :meth:`jura_connect.client.JuraClient.close` emits. ``@HE`` is *not*
  a close here: it is ``WifiCommandOTAEnd``, the verb that makes the
  dongle apply a downloaded image, and it is modelled with the rest of
  the firmware family below.
* Optionally — behind ``SimulatorConfig.firmware_enabled`` — the
  dongle-maintenance family: ``@HB`` bootloader, ``@HO:`` / ``@HD:``
  OTA payloads, ``@HE`` OTA end, ``@HT:3`` restart and ``@HU``
  milk-cooler update, including their failure modes.
* Periodic unsolicited ``@TF:<hex>`` status broadcasts on the
  connection so reader code in the client can be exercised. This is the
  only way status reaches a client — nothing requests it.
* The full language-download sequence (``@TS:F1`` lock, ``@TT:00``
  inventory, ``@TT:01`` block select, ``@TT:02`` / ``@TT:08`` chunk
  transfers, ``@TT:03`` finish, ``@TV:81`` / ``@TV:82`` display lines)
  — but only when :attr:`SimulatorConfig.allow_language_download` is
  set, since every mutating step of it is a destructive prefix.

It deliberately refuses to model write/process commands (``@TG:24``
cleaning, ``@TG:25`` descale, etc.) -- it answers ``@an:error`` so
tests that accidentally trigger those during development surface a
clear failure instead of silently "working". ``@TP:`` (start product)
is refused the same way *unless* a test opts in with
``SimulatorConfig(allow_brew=True)``, which turns on the full
start -> ``@TB`` -> ``@TV:`` progress stream -> ``@TV:3E`` chain.
``SimulatorConfig(allow_process=True)`` does the same for the
interactive maintenance processes: the start verb is acknowledged with
its lower-cased echo and the machine then walks its ``<STATE>``
sequence, parking on every state that declares an ``AcceptCommand``
until the client sends exactly that command (see
:data:`DEFAULT_PROCESS_SEQUENCES` and docs/PROTOCOL.md §5.11).
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import secrets
import socket
import threading
import time
from collections.abc import Iterator

from . import language, protocol
from .client import (
    COFFEE_TIMER_BLOB_HEX_LEN,
    OVERFLOW_COUNTER_BANK,
    _settings_checksum,
)
from .commands import DESTRUCTIVE_EXACT, DESTRUCTIVE_PREFIXES, match_destructive
from .process import ACCEPT_COMMANDS as _PROCESS_ACCEPT_COMMANDS
from .process import NEXT_STEP_COMMAND as _NEXT_STEP_COMMAND
from .profile import RECIPE_BLOB_BYTES
from .progress import (
    BYPASS_MARKER_INDEX,
    PERCENT_INDEX,
    PRODUCT_ARGUMENTS,
    ProgressState,
)

log = logging.getLogger(__name__)

# Maintenance defaults that line up with what the real Kaffeebert returned
# during our probe -- this lets tests assert against realistic data.
DEFAULT_MAINT_COUNTERS = bytes.fromhex("0015000100080158 0E21 005B".replace(" ", ""))
DEFAULT_MAINT_PERCENT = bytes.fromhex("50FF1E")
# Synthetic frame that activates bit 10 (no_beans, info) and bit 34
# (cleaning_alert, process) — picked to exercise both severities the
# test-suite cares about. MSB-first within each byte per the APK's
# Status.a() decoder, so bit N lives at byte N//8 mask 1<<(7-N%8).
DEFAULT_STATUS_PAYLOAD = bytes.fromhex("0020000020000000")

# The real frame Kaffeebert returns at idle: bit 13 (coffee_ready) +
# bit 36 (energy_safe). Used in regression tests so we keep verifying
# the live decode end-to-end.
KAFFEEBERT_IDLE_STATUS_PAYLOAD = bytes.fromhex("0004000008000000")

# Every frame a real JURA S8 EB (EF1091, "kaffeebert") pushed while the
# maintainer brewed a cafe_barista (0x28, strength 7, 45 ml water, 45 ml
# bypass) by hand on 2026-08-16, in order and verbatim — the brew-start
# marker, the four grind frames, the water phase, the bypass phase, the
# five ENJOY repeats and the trailing "@TS". The full trace with
# timestamps is docs/captures/2026-08-16-kaffeebert-brew-progress.md.
#
# This is evidence, not fiction: it is the only brew sequence in the
# tree that a machine actually emitted. Do not tidy the payloads, and do
# not "fix" the tick series (the water ticks skip 6, the bypass ticks
# skip 2/3/5/7 — the machine reported them that way).
CAPTURED_S8EB_CAFE_BARISTA_BREW: tuple[str, ...] = (
    "@TB",
    "@TV:392807070009FFFF000911FFFF110000",
    "@TV:392807070009FFFF000911FFFF110000",
    "@TV:392807070009FFFF000911FFFF110000",
    "@TV:392807070009FFFF000911FFFF110000",
    "@TV:3C2807070009FFFF000911FFFF110000",
    "@TV:3C2807070009FFFF000911FFFF110000",
    "@TV:3C2807070009FFFF000911FFFF110000",
    "@TV:3C2807070009FFFF000911FFFF110000",
    "@TV:3C2807070009FFFF000911FFFF110000",
    "@TV:3C2807070009FFFF000911FFFF110A00",
    "@TV:3C2807070109FFFF000911FFFF110A00",
    "@TV:3C2807070209FFFF000911FFFF111400",
    "@TV:3C2807070309FFFF000911FFFF111400",
    "@TV:3C2807070409FFFF000911FFFF111E00",
    "@TV:3C2807070509FFFF000911FFFF111E00",
    "@TV:3C2807070509FFFF000911FFFF112800",
    "@TV:3C2807070709FFFF000911FFFF112800",
    "@TV:3C2807070709FFFF000911FFFF113200",
    "@TV:3C2807070809FFFF000911FFFF113200",
    "@TV:3C2807070909FFFF000911FFFF113C00",
    "@TV:412807070909FFFF000911FFFF113C00",
    "@TV:412807070909FFFF010911FFFF113C00",
    "@TV:412807070909FFFF010911FFFF114600",
    "@TV:412807070909FFFF040911FFFF115000",
    "@TV:412807070909FFFF060911FFFF115A00",
    "@TV:412807070909FFFF080911FFFF116400",
    "@TV:412807070909FFFF090911FFFF116400",
    "@TV:3E28",
    "@TV:3E28",
    "@TV:3E28",
    "@TV:3E28",
    "@TV:3E28",
    "@TS",
)

# Sentinel for "no count" inside an @TR:32 page.
_PC_UNUSED = 0xFFFF

# Every counter bank the simulator can serve:
#   wire command -> (SimulatorConfig attribute, bytes per value, pad).
# The pad is what a page shorter than 8 bytes is filled with: the
# not-configured sentinel for a counter bank, "no overflow yet" for an
# overflow bank. Mirrors jura_connect.client.COUNTER_BANK_SPECS.
_COUNTER_BANK_TABLES: dict[str, tuple[str, int, int]] = {
    "@TR:32": ("product_counters", 2, _PC_UNUSED),
    "@TR:33": ("product_counter_overflow", 1, 0x00),
    "@TR:34": ("barista_counters", 2, _PC_UNUSED),
    "@TR:35": ("barista_counter_overflow", 1, 0x00),
    "@TR:42": ("daily_product_counters", 2, _PC_UNUSED),
    "@TR:43": ("daily_product_counter_overflow", 1, 0x00),
    "@TR:44": ("daily_barista_counters", 2, _PC_UNUSED),
    "@TR:45": ("daily_barista_counter_overflow", 1, 0x00),
    "@TR:52": ("special_counters", 2, _PC_UNUSED),
    "@TR:53": ("special_counter_overflow", 1, 0x00),
}


# Default @TM:60 limit-load table: product code -> the five min/max byte
# pairs for F4, F5, F6, F10, F11 (see client.LIMIT_LOAD_ARGUMENTS).
# Populated for Cappuccino (0x04) with EF1091's own XML ranges expressed
# the way LimitLoadParser reads them — in Step units, so F4's 25..240 ml
# arrive as 05..30 (×5) and F6's 1..45 s as 01..2D (×1). "FFFF" marks a
# parameter the product does not have.
def _default_limit_load() -> dict[int, str]:
    #        F4     F5     F6     F10    F11
    return {0x04: "0530" + "FFFF" + "012D" + "FFFF" + "FFFF"}


#: The state walk each maintenance process performs, as
#: ``(state code, AcceptCommand or None)`` pairs. Modelled on EF1091's
#: ``<STATE>`` table: the machine pushes each state as a ``@TV:`` frame
#: and stops at a state carrying an accept command until the client
#: sends exactly that command. The final state of every sequence is the
#: process's "…finished" state. APK/XML-derived — the real ordering of
#: the states within a cycle has never been observed on hardware.
DEFAULT_PROCESS_SEQUENCES: dict[str, tuple[tuple[int, str | None], ...]] = {
    "@TG:24": (  # Cleaning
        (0x70, None),  # Cleaning Start
        (0x72, None),  # Cleaning empty tray
        (0x75, None),  # Cleaning add tablet
        (0x26, "@TG:10"),  # Press Rinse — waits for the confirmation
        (0x74, None),  # Cleaning Process
        (0x76, None),  # Cleaning Process finished
    ),
    "@TG:25": (  # Decalc
        (0x50, None),  # Decalcify Start
        (0x52, None),  # Decalcify empty tray
        (0x53, None),  # Decalcify add fluid
        (0x26, "@TG:10"),  # Press Rinse
        (0x54, None),  # Decalcify Process
        (0x55, None),  # Rinse watertank
        (0x56, None),  # Descale finished
    ),
    "@TG:26": (  # FilterChange
        (0x60, None),  # Filter Rinse start
        (0x62, None),  # Filter Rinse change
        (0x26, "@TG:10"),  # Press Rinse
        (0x63, None),  # Filter Rinse process
        (0x65, None),  # Filter Rinse finished
    ),
    "@TG:21": (  # CappuClean
        (0x90, None),  # Cappu Clean Start
        (0x92, "@TG:04"),  # Cappu Clean add cleaner (the @TG:04 machines)
        (0x93, None),  # Cappu Clean process
        (0x95, None),  # Cappu Clean finish
    ),
    "@TG:23": (  # CappuRinse
        (0x9A, None),  # Cappu Rinse process
        (0x0B, None),  # Cappurinse finished
    ),
    "@TG:22": (  # CoffeeRinse — 3 profiles; no "finished" state exists
        (0x23, None),  # Rinse process
        (0x3E, None),  # Enjoy, the generic end-of-run frame
    ),
}


def _default_process_sequences() -> dict[str, tuple[tuple[int, str | None], ...]]:
    return dict(DEFAULT_PROCESS_SEQUENCES)


def _flip_checksum(csum: str) -> str:
    """Return a deliberately wrong checksum for the negative paths."""
    return f"{int(csum, 16) ^ 0xFF:02X}"


def _next_reply(replies: list[str]) -> str:
    """Pop the next scripted reply, repeating the last one forever."""
    if not replies:
        return "@an:error"
    return replies.pop(0) if len(replies) > 1 else replies[0]


def _default_product_counters() -> list[int]:
    """64-slot product counter table populated with Kaffeebert's numbers.

    Slot 0 is the total brews; other slots are indexed by product code.
    Used as the simulator's default so the test-suite asserts against
    realistic values lifted from the real machine.
    """
    slots = [_PC_UNUSED] * 64
    slots[0] = 3229  # total brews
    slots[0x02] = 78  # espresso
    slots[0x03] = 595  # coffee
    slots[0x04] = 64  # cappuccino
    slots[0x06] = 3  # espresso macchiato
    slots[0x07] = 19  # latte macchiato
    slots[0x08] = 52  # milk foam
    slots[0x0A] = 0  # milk portion
    slots[0x0D] = 903  # hotwater portion
    slots[0x0F] = 238  # powder product
    slots[0x28] = 1019  # americano
    slots[0x29] = 3  # lungo
    slots[0x2B] = 2  # unnamed slot present on Kaffeebert
    slots[0x2C] = 1  # unnamed slot
    slots[0x2E] = 210  # flat white
    slots[0x30] = 20  # espresso doppio
    slots[0x31] = 1  # 2 espressi (EF1091 code)
    slots[0x36] = 10  # 2 coffee (EF1091 code)
    return slots


# DESTRUCTIVE_PREFIXES is re-exported for backwards compatibility with
# tests that still import it from this module; the canonical home is
# :mod:`jura_connect.commands`. The simulator refuses-by-default for the
# same prefixes the client gate refuses-by-default.
__all__ = [
    "DESTRUCTIVE_EXACT",
    "DESTRUCTIVE_PREFIXES",
    "LanguageDownloadState",
    "Simulator",
    "SimulatorConfig",
    "run_in_thread",
]


# Wire patterns of the firmware / dongle-maintenance family. The
# simulator only models these when ``SimulatorConfig.firmware_enabled``
# is set; otherwise they fall through to the destructive refusal like
# every other mutating command.
_FIRMWARE_PATTERNS = frozenset({"@HB", "@HO:", "@HD:", "@HE", "@HT:", "@HU"})


def _default_language_slots() -> dict[int, str]:
    """Slot table a European machine might ship with (slots 0..13)."""
    return {0: "DE", 1: "EN", 2: "FR", 3: "IT", 4: "ES", 5: "PT"}


@dataclasses.dataclass(slots=True)
class LanguageDownloadState:
    """Live state of a language download; tests assert against it."""

    locked: bool = False
    block: str | None = None
    chunks: list[tuple[int, bytes]] = dataclasses.field(default_factory=list)
    finished: bool = False
    display: list[str] = dataclasses.field(default_factory=lambda: ["", ""])

    @property
    def crc(self) -> int:
        """CRC-16/CCITT-FALSE over everything received for this block.

        The 16-bit field a successful ``@tt:0x`` reply carries is
        **not** understood (see PROTOCOL.md §5.14); a running CRC is the
        reading that fits ``@tt:03,FE = CRC_NOT_MATCHING``, so the
        simulator answers one. Nothing in the client interprets it.
        """
        crc = 0xFFFF
        for _addr, data in self.chunks:
            for byte in data:
                crc ^= byte << 8
                for _ in range(8):
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else crc << 1
                    crc &= 0xFFFF
        return crc


@dataclasses.dataclass(slots=True)
class SimulatorConfig:
    """Tweakable knobs for the simulator's behaviour.

    Tests override these to verify each handshake branch (CORRECT,
    WRONG_PIN, WRONG_HASH, ABORTED) and edge cases.
    """

    pin: str = ""  # required PIN; "" disables
    require_user_accept: bool = False  # set True to simulate the on-machine prompt
    user_accept_delay: float = 0.0  # how long the simulated user takes to press OK
    paired_hashes: dict[str, str] = dataclasses.field(default_factory=dict)
    name: str = "TestMachine"
    machine_type: str = "S8 (simulated)"
    fw_version: str = "TT237W V06.11"
    maint_counters: bytes = DEFAULT_MAINT_COUNTERS
    maint_percent: bytes = DEFAULT_MAINT_PERCENT
    status_payload: bytes = DEFAULT_STATUS_PAYLOAD
    status_interval: float = 1.0
    screen_locked: bool = False
    # 64 u16 slots making up the @TR:32 response. Slot 0 = total brews;
    # slots 1..63 are per-product counts indexed by product code, with
    # 0xFFFF marking "this code is not configured on this machine".
    product_counters: list[int] = dataclasses.field(
        default_factory=_default_product_counters
    )
    # Per-slot high bytes of the @TR:33 "Overflow Product Counter" bank,
    # for machines whose XML declares it (34 of the 89 bundled profiles;
    # no S8/Z10 among them). None models a machine without the bank,
    # which answers a bare "@tr:00" — the same shape J.O.E.'s matcher
    # accepts as "bank not implemented".
    product_counter_overflow: list[int] | None = None
    # Reply served for @TR:33 when no overflow table is configured.
    # "@tr:00" is the shape J.O.E.'s matcher accepts as "bank not
    # implemented"; tests override it to model a firmware that answers
    # something else entirely.
    overflow_bank_reply: str = "@tr:00"
    # The remaining counter banks a machine XML may declare, with the
    # same convention: a list of slot values, or None for a machine that
    # answers the bare "@tr:00" (= bank not implemented). All default to
    # None, matching the S8 EB, which declares @TR:32 alone.
    #
    # The special bank's slots are fixed functions, not product codes
    # (see jura_connect.client.SPECIAL_COUNTER_SLOTS); the barista and
    # daily banks index the same product-code space as @TR:32. Neither
    # the barista nor the daily banks appear anywhere in the J.O.E. APK,
    # so their wire behaviour here is XML-derived, not observed.
    special_counters: list[int] | None = None
    special_counter_overflow: list[int] | None = None
    barista_counters: list[int] | None = None
    barista_counter_overflow: list[int] | None = None
    daily_product_counters: list[int] | None = None
    daily_product_counter_overflow: list[int] | None = None
    daily_barista_counters: list[int] | None = None
    daily_barista_counter_overflow: list[int] | None = None
    # @TM:50 reply bytes (per-kind slot counts; summed = total slots).
    # Default matches Kaffeebert: 5 kinds × 4 slots = 20 reported.
    # Empty models a machine that answers the "D0" rejection token.
    pmode_slot_bytes: bytes = bytes.fromhex("0404040404")
    # @TM:42,<slot> → product code at that slot. None entries (or
    # missing slots) cause the simulator to answer "@tm:C2" mirroring
    # the real EF1091 firmware that reports slots but doesn't expose
    # them over WiFi.
    pmode_slots: dict[int, int] = dataclasses.field(default_factory=dict)
    # Full per-slot payloads (product code + F2..Fn argument bytes) as
    # written by @TM:42. Populated by a slot write; a slot listed in
    # `pmode_slots` without an entry here is answered with just its
    # product code, which is all we ever observed on hardware.
    pmode_slot_blobs: dict[int, str] = dataclasses.field(default_factory=dict)
    # Stored @TM:41 product settings, keyed by product code. ``None``
    # models the EF1091-style machine whose XML says
    # Productprogramming="false": every @TM:41 answers "@tm:C1" and
    # every @TM:42 write answers "@tm:C2". A dict (even an empty one)
    # models a machine that *does* expose product programming.
    pmode_products: dict[int, str] | None = None
    # PMode writes are refused with "@an:error" unless this is set, the
    # same guardrail DESTRUCTIVE_PREFIXES gives the @TG: process
    # commands: a write that overwrites a user recipe slot must be
    # opted into by the test that means to exercise it.
    pmode_writable: bool = False
    # Model a firmware that ACKs the write frame with the bare "@tm:00"
    # rejection token instead of storing anything.
    pmode_reject_writes: bool = False
    # Drop the TCP session after this many @TM:42 *reads*, mirroring the
    # real S8 EB resetting the connection mid-table. ``None`` disables.
    pmode_reset_after_slot: int | None = None

    # -- brewing ------------------------------------------------------
    # Off by default: @TP: is a destructive prefix and the simulator's
    # job is to make an accidental brew in a test scream (@an:error).
    # Tests that want the whole start -> progress -> done chain opt in.
    allow_brew: bool = False
    # How many @TV:41 progress frames a modelled brew emits before the
    # @TV:3E (ENJOY) completion frame.
    brew_progress_steps: int = 4
    # Delay between the frames of a modelled brew. 0 keeps tests fast;
    # raise it to watch the stream at human speed.
    brew_progress_interval: float = 0.0
    # Target water ticks reported as the maximum in the progress frames.
    brew_target_ticks: int = 0x1E
    # Push these frames verbatim after an accepted @TP: instead of the
    # generated ones. Set it to CAPTURED_S8EB_CAFE_BARISTA_BREW to replay
    # a real machine's brew (docs/captures/2026-08-16-kaffeebert-brew-progress.md)
    # rather than the model above.
    brew_script: tuple[str, ...] | None = None
    # Frames the dongle pushes *ahead of* the next command reply, once.
    # Models the markers a real machine emits without being asked: the
    # S8 EB pushed a bare "@TS" ~10 s after the last ENJOY of a brew
    # (docs/captures/2026-08-16-kaffeebert-brew-progress.md), i.e. it can
    # land on the socket while an unrelated command is in flight, and
    # "@TB" opens every brew and every @TS:01 screen lock (PROTOCOL.md
    # §5.1). Drained before the first reply and then cleared.
    pushes_before_reply: tuple[str, ...] = ()
    # Same idea for the handshake: frames pushed before the @hp4/@hp5
    # answer. A machine that is mid-brew (or mid-lock) when a client
    # pairs has markers on the wire before it ever replies.
    handshake_pushes: tuple[str, ...] = ()

    # -- maintenance processes ----------------------------------------
    # Off by default for the same reason as brewing: @TG:21..@TG:26 are
    # destructive prefixes and an accidental one in a test must scream
    # (@an:error) rather than quietly walk a cycle.
    allow_process: bool = False
    # Wire start command -> the state walk it performs. See
    # DEFAULT_PROCESS_SEQUENCES.
    process_sequences: dict[str, tuple[tuple[int, str | None], ...]] = (
        dataclasses.field(default_factory=_default_process_sequences)
    )
    # True: states without an AcceptCommand advance on their own, the
    # way a real machine works through "Cleaning Process" while it runs.
    # False: the machine pushes exactly one state and then waits for
    # @TG:01 (or that state's own AcceptCommand) — the "Press Rotary or
    # Next" flavour.
    process_auto_advance: bool = True
    # Delay between pushed process state frames. 0 keeps tests fast.
    process_step_interval: float = 0.0

    # Coffee timer (@TM:3C schedule + @TV:84 wall clock). Off by
    # default: an accepted schedule makes the machine brew unattended,
    # so it stays behind the same refuse-by-default guardrail as the
    # other destructive paths and a test has to opt in. With the flag
    # off, @TM:3C is caught by DESTRUCTIVE_PREFIXES and answered
    # "@an:error" like every other destructive frame.
    coffee_timer: bool = False
    # Model a firmware that knows the command but declines it: answer
    # the "@tm:00" rejection token instead of accepting. J.O.E.'s
    # matcher ("@tm:.*") lets that through, so the client has to tell
    # the two apart itself.
    coffee_timer_reject: bool = False
    # What an accepted schedule stored, for tests to assert against.
    coffee_timer_blob: str | None = None
    coffee_timer_delay: int | None = None
    coffee_timer_clock: str | None = None

    # -- language download (PROTOCOL.md §5.14) -------------------------
    # Off by default: every mutating step (@TS:F1, @TT:01/02/03/08,
    # @TV:81/82) is in DESTRUCTIVE_PREFIXES, so a default simulator
    # answers @an:error exactly like it does for a cleaning cycle. Set
    # this to model a machine that actually supports the feature.
    allow_language_download: bool = False
    # Slot index -> two-letter code for the @TT:00 inventory. Slots not
    # listed (up to LANGUAGE_SLOT_COUNT) report the empty marker FFFF.
    language_slots: dict[int, str] = dataclasses.field(
        default_factory=_default_language_slots
    )
    # The only block @TT:01 accepts; anything else answers FE
    # (COMMON_ERROR_BLOCK_NOT_AVAILABLE).
    language_download_block: str = "0B"
    # Reply to @TM:23. "@tm:23" = supported; "@tm:A3" = not supported;
    # "@tm:00" = checksum false; "@tm:23,0C01" = a language is set.
    max_languages_reply: str = "@tm:23"
    # Answer the first @TT:01 with FC (EXECUTION_IN_PROGRESS) to
    # exercise the finish-and-retry path.
    language_select_busy_once: bool = False
    # 0-based index of a chunk the machine refuses, and with which code.
    language_reject_chunk: int | None = None
    language_reject_code: str = "FE"
    # Make @TT:03 fail with FE (CRC_NOT_MATCHING).
    language_finish_crc_error: bool = False

    # -- firmware OTA / dongle restart / milk cooler --------------------
    # Opt-in, exactly like the machine's own dangerous paths: with this
    # left False every verb of the family (@HB, @HO:, @HD:, @HE, @HT:,
    # @HU) is answered with "@an:error" so a test that stumbles into the
    # OTA sequence fails loudly instead of silently "working".
    firmware_enabled: bool = False
    # Reply to @HB. "@hb:abort" models a dongle that declines to enter
    # its bootloader; a bare "@hb" is the third form J.O.E.'s matcher
    # accepts and also means "not ok".
    bootloader_reply: str = "@hb:ok"
    ota_dat_reply: str = "@ho:ok"  # answer to @HO: — "@ho:error" to refuse
    ota_end_reply: str = "@he:ok"  # answer to @HE — "@he:error" to refuse
    # 1-based index of the @HD: chunk that is answered "@hd:error";
    # None means every chunk is accepted.
    ota_error_chunk: int | None = None
    # Replies handed out for successive @HU / @HU? requests. The list is
    # consumed front-to-back and the last entry repeats, so a single
    # element models a machine that always answers the same thing.
    milk_cooler_start_replies: list[str] = dataclasses.field(
        default_factory=lambda: ["@hu:ok"]
    )
    # "@hu:800" is what the S8 EB answers: state 8 = no milk cooler.
    milk_cooler_status_replies: list[str] = dataclasses.field(
        default_factory=lambda: ["@hu:800"]
    )

    # Machine settings: P_Argument (uppercase hex) -> stored hex value.
    # Defaults populated to mirror EF1091's <MACHINESETTINGS> defaults
    # so the test-suite can read/write the same arguments the J.O.E.
    # app exercises against a real S8 EB.
    settings: dict[str, str] = dataclasses.field(
        default_factory=lambda: {
            "02": "10",  # hardness = 16 decimal
            "13": "211E",  # auto-off = 30min
            "08": "00",  # units = ML
            "09": "02",  # language = English
            "0A": "04",  # brightness = 40%
            "04": "00",  # milk rinsing = Automatic
            "62": "01",  # frother instructions = On
        }
    )

    # Batch settings read (@TM:00,FC). The CommandArgument the simulated
    # machine's XML declares — the values are answered in this order.
    # None models a machine with no batch read at all, which replies
    # with the bare rejection token below (32 of the 89 bundled profiles
    # carry no <MACHINESETTINGS> block, so no bank either).
    settings_bank_arguments: str | None = "02080913"
    # Rejection token for the batch read. "@tm:00" is the short "frame
    # refused" answer the dongle already uses for settings writes.
    settings_bank_reject_reply: str = "@tm:00"
    # Model a firmware that only accepts the checksummed request form
    # (@TM:00,FC<csum>) — which of the two forms a real machine wants is
    # unknown, so both are exercised.
    settings_bank_requires_checksum: bool = False
    # Corrupt the reply checksum to exercise the client's verification.
    settings_bank_corrupt_checksum: bool = False

    # Limit load (@TM:60,<product code><csum>): product code -> the five
    # min/max byte pairs. Codes outside the table get "@tm:C1" — the
    # APK's "machine does not support product programming" token.
    limit_load: dict[int, str] = dataclasses.field(default_factory=_default_limit_load)
    limit_load_corrupt_checksum: bool = False
    limit_load_echo_wrong_code: bool = False


def _blob_is_accepted(blob: str) -> bool:
    """Mirror the machine's accept/ignore rule for a ``@TP:`` blob.

    PROTOCOL.md §5.9, live-verified on an S8 EB: only the 16-byte,
    ``0x00``-padded blob whose byte 8 is ``0x01`` actually brews. A bare
    product code or the old FF-padded layout is ACKed with ``@tp:00``
    and then silently ignored — no ``@TB``, no ``@TV:``.
    """
    if len(blob) != RECIPE_BLOB_BYTES * 2:
        return False
    try:
        data = bytes.fromhex(blob)
    except ValueError:
        return False
    return data[8] == 0x01


def _process_frame(state_code: int, process_code: int) -> str:
    """One pushed ``@TV:`` frame of a maintenance process.

    Same 16-byte shape as the brew frames (state, item code, then the
    14-byte value window); the item code is the process byte, which is
    what makes the decoder classify it as ``ProgressType.PROCESS``. The
    value window is left zeroed: what a machine puts there during a
    maintenance cycle has never been observed, and the app reads no
    quantities for these states, so filling it in would be a fabricated
    layout.
    """
    window = bytearray(len(PRODUCT_ARGUMENTS))
    return f"@TV:{state_code:02X}{process_code:02X}{window.hex().upper()}"


def _brew_frames(blob: str, config: SimulatorConfig) -> list[str]:
    """The unsolicited frames a real dongle pushes after an accepted brew.

    Models what PROTOCOL.md §5.9 records from a live S8 EB: a ``@TB``
    brew-start marker, a run of ``@TV:41<product>…`` progress frames
    with a rising tick count and percentage, then ``@TV:3E<product>``
    (``ENJOY``) when the cup is done. The frame *layout* is APK-derived
    (§5.10): a 16-byte payload whose 14-byte value window carries the
    current/target water ticks at slots 2/3 and the percentage at slot
    12. Slot 6 is ``0xFF`` so state ``41`` reads as ``HOTWATER_VOLUME``
    rather than ``BYPASS_WATER_VOLUME``.

    This is a *model*, not a transcript: a real S8 EB walks
    ``39`` → ``3C`` → ``41`` and repeats ``ENJOY``. Set
    ``SimulatorConfig.brew_script`` (e.g. to
    :data:`CAPTURED_S8EB_CAFE_BARISTA_BREW`) to push a captured
    sequence verbatim instead.
    """
    if config.brew_script is not None:
        return list(config.brew_script)
    product = blob[:2].upper() if len(blob) >= 2 else "00"
    frames = ["@TB"]
    steps = max(1, config.brew_progress_steps)
    target = config.brew_target_ticks & 0xFF
    for step in range(1, steps + 1):
        window = bytearray(len(PRODUCT_ARGUMENTS))
        window[2] = round(target * step / steps)
        window[3] = target
        window[BYPASS_MARKER_INDEX] = 0xFF
        window[PERCENT_INDEX] = round(100 * step / steps)
        head = f"{ProgressState.HOTWATER_VOLUME:02X}{product}"
        frames.append(f"@TV:{head}{window.hex().upper()}")
    done = bytearray(len(PRODUCT_ARGUMENTS))
    frames.append(f"@TV:{ProgressState.ENJOY:02X}{product}{done.hex().upper()}")
    return frames


class Simulator:
    """A single-connection-at-a-time TCP server speaking the WiFi protocol."""

    def __init__(
        self,
        config: SimulatorConfig | None = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.config = config or SimulatorConfig()
        self.host = host
        self.port = port
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        # Public for tests to inspect:
        self.sent_commands: list[bytes] = []
        self.handshakes: list[tuple[str, str, str]] = []  # (pin, conn_id, hash)
        # Frames queued by a command handler to be pushed after its
        # reply (the brew progress stream, the process state walk).
        self._queued: list[str] = []
        # Unsolicited frames pushed *before* the next reply, drained once.
        self._pending_pushes: list[str] = list(self.config.pushes_before_reply)
        self._pmode_reads = 0  # for SimulatorConfig.pmode_reset_after_slot
        # Running maintenance process: the start command, how far into
        # its state sequence we are, and the confirmation the current
        # state is parked on (None = the client may send @TG:01).
        self._process_command: str | None = None
        self._process_index = 0
        self._process_awaiting: str | None = None
        self.language = LanguageDownloadState()
        self._language_select_seen = False
        # Firmware OTA state (only touched when firmware_enabled).
        self.ota_bootloader = False  # @HB accepted
        self.ota_dat: bytes | None = None  # payload of the last @HO:
        self.ota_image = bytearray()  # concatenated @HD: chunks
        self.ota_chunks = 0  # number of @HD: chunks accepted
        self.ota_completed = False  # @HE acked
        self.dongle_restarts = 0  # @HT:3 count

    # -- lifecycle -----------------------------------------------------
    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("simulator not started")
        return self._server.getsockname()[:2]

    def start(self) -> None:
        if self._server is not None:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(1)
        s.settimeout(0.2)
        self._server = s
        self.port = s.getsockname()[1]
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        s, self._server = self._server, None
        if s is not None:
            with contextlib.suppress(OSError):
                s.close()
        t, self._thread = self._thread, None
        if t is not None:
            t.join(timeout=2.0)

    def __enter__(self) -> Simulator:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- serving loop --------------------------------------------------
    def _serve_forever(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            try:
                self._handle(conn)
            except Exception:  # noqa: BLE001
                log.exception("simulator: client handler crashed")
            finally:
                with contextlib.suppress(OSError):
                    conn.close()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(0.5)
        reader = protocol.FrameReader(conn)
        last_status_ts = 0.0
        authenticated = False
        while not self._stop.is_set():
            # Periodic unsolicited @TF: status frame.
            now = time.monotonic()
            if (
                authenticated
                and self.config.status_interval > 0
                and now - last_status_ts >= self.config.status_interval
            ):
                self._emit_status(conn)
                last_status_ts = now
            try:
                frame = reader.next_frame(timeout=0.2)
            except (TimeoutError, socket.timeout):
                continue
            except ConnectionError:
                return
            self.sent_commands.append(frame)
            text = frame.decode("ascii", errors="replace").rstrip("\r\n")
            log.debug("simulator <- %r", text)
            if text.startswith("@HP:"):
                reply = self._handle_handshake(text)
                for frame in self.config.handshake_pushes:
                    self._send(conn, frame)
                self._send(conn, reply)
                if reply.startswith("@hp4"):
                    authenticated = True
                else:
                    # WRONG_*/ABORTED -> close, matching real machine behaviour
                    return
                continue
            if not authenticated:
                # Real dongle drops unauthenticated commands silently.
                continue
            if frame.startswith(b"@TT:08,"):
                # Binary language transfer: the body is raw escaped bytes,
                # so it must be handled before the ASCII decode mangles it.
                reply = self._handle_binary_language_transfer(frame)
            else:
                reply = self._handle_command(text)
            if reply is None:
                continue  # mimic dongle's silent ignore for unknown commands
            if reply == "@@CLOSE":
                return
            self._push_pending(conn)
            self._send(conn, reply)
            self._drain_queue(conn)

    # -- handshake -----------------------------------------------------
    def _handle_handshake(self, cmd: str) -> str:
        # "@HP:<pin>,<conn_id_hex>,<hash>" -- the only command parsed here.
        try:
            _, body = cmd.split(":", 1)
            pin, conn_id_hex, given_hash = body.split(",", 2)
        except ValueError:
            return "@hp5:02"
        self.handshakes.append((pin, conn_id_hex, given_hash))

        # PIN check
        if self.config.pin and pin != self.config.pin:
            return "@hp5"

        # Pairing flow: empty hash from a new conn_id triggers the dongle's
        # "Connect" dialog on its own screen.
        existing = self.config.paired_hashes.get(conn_id_hex)
        if not given_hash:
            if existing is not None:
                # Caller wiped its hash but the dongle still has one -> reject.
                return "@hp5:02"
            if self.config.require_user_accept:
                time.sleep(self.config.user_accept_delay)
            # Generate a fresh 64-char hash and register the conn_id.
            new_hash = secrets.token_hex(32).upper()
            self.config.paired_hashes[conn_id_hex] = new_hash
            return f"@hp4:{new_hash}"

        if existing is None:
            return "@hp5:01"
        if existing.lower() != given_hash.lower():
            return "@hp5:01"
        return "@hp4"

    # -- language download ----------------------------------------------
    def _handle_language_command(self, cmd: str) -> str | None:
        """Model the language-download sequence (PROTOCOL.md §5.14).

        Only reached when ``allow_language_download`` is set; otherwise
        every mutating verb here falls through to the destructive guard.
        The ordering rules (lock before select, select before transfer)
        are the simulator's own invariants — the real machine's reaction
        to an out-of-order sequence has never been observed.
        """
        state = self.language
        if cmd == language.LOCK_COMMAND:
            state.locked = True
            state.chunks.clear()
            state.block = None
            state.finished = False
            self._language_select_seen = False
            return "@ts"
        if cmd.startswith(language.SELECT_BLOCK_COMMAND + ","):
            block = cmd.split(",", 1)[1].strip().upper()
            if not state.locked:
                return "@tt:01,FB"  # WRONG_CONTENT: not in download mode
            if self.config.language_select_busy_once and not self._language_select_seen:
                self._language_select_seen = True
                return "@tt:01,FC"  # EXECUTION_IN_PROGRESS
            if block != self.config.language_download_block.upper():
                return "@tt:01,FE"  # BLOCK_NOT_AVAILABLE
            state.block = block
            state.chunks.clear()
            state.finished = False
            return "@tt:01,FF"
        if cmd.startswith(language.TRANSFER_ASCII_COMMAND + ","):
            body = cmd.split(",", 1)[1].strip()
            if len(body) < 10 or len(body) % 2:
                return "@tt:02,FD"  # WRONG_SYNTAX
            try:
                address = int(body[:8], 16)
                data = bytes.fromhex(body[8:])
            except ValueError:
                return "@tt:02,FD"
            return self._accept_language_chunk("02", address, data)
        if cmd == language.FINISH_COMMAND:
            if state.block is None:
                return "@tt:03,FE"
            if self.config.language_finish_crc_error:
                return "@tt:03,FE"
            state.finished = True
            return f"@tt:03,FF,{state.crc:04X}"
        for index, verb in enumerate(
            (language.DISPLAY_LINE1_COMMAND, language.DISPLAY_LINE2_COMMAND)
        ):
            if cmd.startswith(verb + ","):
                body = cmd[len(verb) + 1 :]
                text, csum = body[:-2], body[-2:].upper()
                if csum != language.display_checksum(text):
                    log.warning("simulator: bad display checksum for %r", cmd)
                    return "@an:error"
                state.display[index] = text
                return f"@tv:{verb[-2:].lower()}"
        return None

    def _accept_language_chunk(self, verb: str, address: int, data: bytes) -> str:
        state = self.language
        if state.block is None:
            return f"@tt:{verb},FA"  # WRONG_LOGIC: no block selected
        if not data:
            return f"@tt:{verb},FC"  # WRONG_LENGTH
        index = len(state.chunks)
        if index == self.config.language_reject_chunk:
            return f"@tt:{verb},{self.config.language_reject_code.upper()}"
        state.chunks.append((address, data))
        return f"@tt:{verb},FF,{state.crc:04X}"

    def _handle_binary_language_transfer(self, frame: bytes) -> str | None:
        """``@TT:08,<escaped addr><escaped len><escaped data>``."""
        if not self.config.allow_language_download:
            log.warning("simulator: refusing destructive command %r", frame[:16])
            return "@an:error"
        body = frame[len(b"@TT:08,") :]
        try:
            plain = language.unescape_binary(body)
        except ValueError:
            return "@tt:08,FD"  # WRONG_SYNTAX
        if len(plain) < 6:
            return "@tt:08,FD"
        address = int.from_bytes(plain[:4], "big")
        declared = int.from_bytes(plain[4:6], "big")
        data = plain[6:]
        if declared != len(data):
            return "@tt:08,FC"  # WRONG_LENGTH
        return self._accept_language_chunk("08", address, data)

    # -- read commands -------------------------------------------------
    def _handle_command(self, cmd: str) -> str | None:
        if self.config.coffee_timer:
            # Runs ahead of the destructive scan on purpose: @TM:3C is
            # in DESTRUCTIVE_PREFIXES, and this flag is the opt-in that
            # lets a test exercise the wire format instead of the
            # refusal. Everything else still falls through to the scan.
            reply = self._handle_coffee_timer(cmd)
            if reply is not None:
                return reply
        if cmd.startswith("@TP:") and self.config.allow_brew:
            # Opt-in only. An accepted blob is ACKed with a bare "@tp"
            # and followed by the frames the real dongle pushes: @TB,
            # then the @TV: progress stream, then @TV:3E (ENJOY). A blob
            # the machine would ignore gets "@tp:00" and nothing else.
            blob = cmd[len("@TP:") :].strip()
            if not _blob_is_accepted(blob):
                return "@tp:00"
            self._queued.extend(_brew_frames(blob, self.config))
            return "@tp"
        if self.config.allow_process:
            # Opt-in only, and checked before the blanket refusal below
            # because the start verbs are destructive prefixes.
            process_reply = self._handle_process(cmd)
            if process_reply is not None:
                return process_reply
        if self.config.allow_language_download:
            reply = self._handle_language_command(cmd)
            if reply is not None:
                return reply
        if cmd == language.MAX_LANGUAGES_COMMAND:
            return self.config.max_languages_reply
        if cmd == language.LIST_COMMAND:
            if not self.config.allow_language_download:
                return None  # machine doesn't know the verb: stays silent
            slots = "".join(
                f",{index:02X}"
                + (
                    self.config.language_slots[index].encode("ascii").hex().upper()
                    if index in self.config.language_slots
                    else "FFFF"
                )
                for index in range(language.LANGUAGE_SLOT_COUNT)
            )
            return f"@tt:00{slots}"
        # One matcher for the whole guardrail: prefix patterns plus the
        # exact-match ones (@HU, which must not swallow the @HU? read).
        pattern = match_destructive(cmd)
        if pattern is not None:
            if pattern in _FIRMWARE_PATTERNS and self.config.firmware_enabled:
                return self._handle_firmware(cmd)
            log.warning("simulator: refusing destructive command %r", cmd)
            return "@an:error"

        if cmd == "":
            # J.O.E.'s WifiCommandCloseConnection: an empty frame ends
            # the session. This is what JuraClient.close() sends — @HE
            # is the OTA-end verb and is handled above, not here.
            return "@@CLOSE"
        if cmd == "@HU?":
            # WifiCommandMilkCoolerUpdateStatus — matcher @hu:[0-9a-fA-F]{3}.
            # Kaffeebert answers @hu:800 (the default reply script), which
            # means "no cooler". Machine status is NOT part of this reply;
            # it arrives with the next unsolicited @TF: frame.
            return _next_reply(self.config.milk_cooler_status_replies)
        if cmd == "@TG:FF":
            # WifiCommandCancelProductStep — cancel the running step,
            # which also tears down a running maintenance process.
            self._clear_process()
            return "@tg:FF"
        if cmd == "@TG:43":
            return "@tg:43" + self.config.maint_counters.hex().upper()
        if cmd == "@TG:C0":
            return "@tg:C0" + self.config.maint_percent.hex().upper()
        if cmd == "@TS:01":
            self.config.screen_locked = True
            return "@ts"
        if cmd == "@TS:00":
            self.config.screen_locked = False
            # Same verb releases a language-download lock (@TS:F1).
            self.language.locked = False
            return "@ts"
        if cmd == "@TM:50":
            # Per-kind slot counts. Append a fake checksum byte so the
            # client's parser sees a well-formed reply (the checksum
            # algorithm is opaque; the client doesn't currently verify).
            if not self.config.pmode_slot_bytes:
                return "@tm:D0"  # PModeNumSlotReadParser's "no slots"
            body = self.config.pmode_slot_bytes.hex().upper()
            return f"@tm:50,{body}7A"
        if cmd.upper().startswith("@TM:00,FC"):
            return self._handle_settings_bank(cmd)
        if cmd.upper().startswith("@TM:60,"):
            return self._handle_limit_load(cmd)
        if cmd.startswith(("@TM:41,", "@TM:42,")):
            return self._handle_pmode(cmd)
        if cmd.startswith("@TM:"):
            arg_full = cmd[4:]
            # Distinguish writes (@TM:<arg>,<val><checksum>) from reads
            # by the presence of a comma. Per the J.O.E. APK's
            # WifiCommandWritePMode and ByteOperations.d, the trailing
            # two hex chars are a checksum over <arg>,<val>.
            if "," in arg_full:
                arg, _, rest = arg_full.partition(",")
                arg = arg.upper()
                if len(rest) < 2:
                    return "@an:error"
                value_hex = rest[:-2].upper()
                csum_recv = rest[-2:].upper()
                payload_for_csum = f"{arg},{value_hex}"
                expected = _settings_checksum(payload_for_csum)
                if csum_recv != expected:
                    log.warning(
                        "simulator: bad settings checksum for %s (got %s, expected %s)",
                        cmd,
                        csum_recv,
                        expected,
                    )
                    return "@an:error"
                self.config.settings[arg] = value_hex
                return f"@tm:{arg.lower()}"
            arg = arg_full.upper()
            stored = self.config.settings.get(arg)
            if stored is not None:
                # Real dongle appends the same ByteOperations.d checksum
                # used on the write side; the client verifies it.
                csum = _settings_checksum(f"{arg},{stored}")
                return f"@tm:{arg.lower()},{stored}{csum}"
            # Unknown address — echo the high nibble like the real dongle.
            return f"@tm:{arg_full[:2].lower()}"
        if cmd.startswith("@TR:") and "," in cmd:
            return self._counter_bank_page(cmd)
        if cmd.startswith("@TR:"):
            return f"@tr:{cmd[4:6]}00"
        # Unknown -> dongle stays silent
        return None

    # -- maintenance processes -----------------------------------------
    def _handle_process(self, cmd: str) -> str | None:
        """Model ``WifiCommandStartProcess`` / ``ProcessAccept`` / ``NextStep``.

        Returns the reply, or ``None`` when ``cmd`` is not part of the
        process conversation (so the caller keeps looking / falls through
        to the destructive refusal).

        The wire behaviour mirrors the J.O.E. app: the start command is
        acknowledged with its own lower-cased echo, the confirmation
        commands echo themselves too, and ``@TG:01`` answers ``@tg:01``
        when it advanced something and ``@tg:00`` when it did not.
        """
        upper = cmd.strip().upper()
        if upper in self.config.process_sequences:
            self._process_command = upper
            self._process_index = 0
            self._process_awaiting = None
            self._advance_process()
            return upper.lower()
        if upper in _PROCESS_ACCEPT_COMMANDS:
            if self._process_command is None or self._process_awaiting != upper:
                # No cycle is parked on this confirmation.
                return "@an:error"
            self._process_awaiting = None
            self._advance_process()
            return upper.lower()
        if upper == _NEXT_STEP_COMMAND:
            if self._process_command is None or self._process_awaiting is not None:
                # WiFiCommandNextProductStep's "rejected" answer.
                return "@tg:00"
            self._advance_process()
            return "@tg:01"
        return None

    def _advance_process(self) -> None:
        """Queue the state frames the machine pushes next.

        With ``process_auto_advance`` the machine runs on by itself and
        only stops at a state that declares an ``AcceptCommand``;
        without it, it pushes exactly one state and waits for ``@TG:01``
        (or that state's own confirmation).
        """
        command = self._process_command
        if command is None:
            return
        sequence = self.config.process_sequences[command]
        code = int(command.rsplit(":", 1)[-1], 16)
        while self._process_index < len(sequence):
            state, accept = sequence[self._process_index]
            self._process_index += 1
            self._queued.append(_process_frame(state, code))
            if accept is not None:
                self._process_awaiting = accept
                return
            if not self.config.process_auto_advance:
                return
        # Sequence exhausted: the last frame was the "…finished" state.
        self._clear_process()

    def _clear_process(self) -> None:
        self._process_command = None
        self._process_index = 0
        self._process_awaiting = None

    # -- queued (unsolicited) frames -----------------------------------
    def _push_pending(self, conn: socket.socket) -> None:
        """Push :attr:`SimulatorConfig.pushes_before_reply` ahead of a reply.

        A real dongle interleaves its own markers with command replies —
        the frame the client is waiting for is not necessarily the next
        one on the socket. Drained once so a test models "a marker was
        in flight when the command went out", not "every reply is
        preceded by a marker".
        """
        pending, self._pending_pushes = self._pending_pushes, []
        for frame in pending:
            self._send(conn, frame)

    def _drain_queue(self, conn: socket.socket) -> None:
        """Push frames a handler queued behind its reply, in order."""
        queued, self._queued = self._queued, []
        for frame in queued:
            if self.config.brew_progress_interval > 0:
                time.sleep(self.config.brew_progress_interval)
            elif self.config.process_step_interval > 0:
                time.sleep(self.config.process_step_interval)
            self._send(conn, frame)

    # -- counter banks -------------------------------------------------
    def _counter_bank_page(self, cmd: str) -> str | None:
        """Serve one page of a paginated counter bank.

        Wire format, identical for every bank:

            request : @TR:<bank>,<page_hex>
            reply   : @tr:<bank>,<page_hex>,<8 hex bytes>

        The 8-byte payload holds 4 ``u16`` slots for a counter bank or 8
        ``u8`` high bytes for an overflow bank. A machine without the
        bank answers the bare ``@tr:00`` J.O.E.'s matcher accepts as
        "not implemented", and a bank shorter than the client's page
        budget answers the same once its table runs out — the "bank ends
        here" case the client keeps partial results for.
        """
        bank, _, page_hex = cmd.partition(",")
        bank = bank.upper()
        entry = _COUNTER_BANK_TABLES.get(bank)
        if entry is None:
            # Unknown bank — the dongle echoes it back with a 00 tail.
            return f"@tr:{cmd[4:6]}00"
        attr, width, pad = entry
        table = getattr(self.config, attr)
        if table is None:
            return (
                self.config.overflow_bank_reply
                if bank == OVERFLOW_COUNTER_BANK
                else "@tr:00"
            )
        try:
            page = int(page_hex.strip(), 16)
        except ValueError:
            return "@tr:00"
        per_page = 8 // width
        start = page * per_page
        if page < 0 or start >= len(table):
            return "@tr:00"
        values = list(table[start : start + per_page])
        values += [pad] * (per_page - len(values))
        mask = (1 << (8 * width)) - 1
        payload = "".join(f"{v & mask:0{width * 2}X}" for v in values)
        return f"@tr:{bank[4:6].lower()},{page:02X},{payload}"

    # -- batch settings read / limit load ------------------------------
    def _handle_settings_bank(self, cmd: str) -> str:
        """Answer the XML's ``<BANK Name="Setting" Command="@TM:00,FC">``.

        The reply layout mirrors ``client._parse_settings_bank_reply``:
        the stored values of the bank's arguments concatenated in
        declaration order (self-delimited by the ItemSlider type tags)
        plus the usual ``ByteOperations.d`` checksum over
        ``"00,<values>"``. Nothing about it is hardware-verified — no
        J.O.E. code path issues this command — so the simulator also
        models the rejection token that makes the client fall back to
        per-setting reads.
        """
        tail = cmd[len("@TM:00,FC") :].strip().upper()
        expected_request_csum = _settings_checksum("00,FC")
        if tail and tail != expected_request_csum:
            return "@an:error"
        if self.config.settings_bank_requires_checksum and not tail:
            return self.config.settings_bank_reject_reply
        declared = self.config.settings_bank_arguments
        if not declared:
            return self.config.settings_bank_reject_reply
        values: list[str] = []
        for i in range(0, len(declared), 2):
            stored = self.config.settings.get(declared[i : i + 2].upper())
            if stored is None:
                # A bank argument this machine has no value for: the
                # whole batch read is refused rather than half-answered.
                return self.config.settings_bank_reject_reply
            values.append(stored.upper())
        body = "".join(values)
        csum = _settings_checksum(f"00,{body}")
        if self.config.settings_bank_corrupt_checksum:
            csum = _flip_checksum(csum)
        return f"@tm:00,{body}{csum}"

    def _handle_limit_load(self, cmd: str) -> str:
        """Answer ``@TM:60,<product code><csum>`` (``WifiCommandReadLimitLoad``).

        Reply shape from the APK's ``LimitLoadParser``:
        ``@tm:60,<code><5 min/max byte pairs><checksum>``.
        """
        body = cmd[len("@TM:60,") :].strip()
        if len(body) < 4:
            return "@an:error"
        code_hex, csum_recv = body[:2].upper(), body[2:].upper()
        if csum_recv != _settings_checksum(f"60,{code_hex}"):
            log.warning("simulator: bad limit-load checksum for %r", cmd)
            return "@an:error"
        try:
            code = int(code_hex, 16)
        except ValueError:
            return "@an:error"
        blob = self.config.limit_load.get(code)
        if blob is None:
            # "Machine does not support Product Programming".
            return "@tm:C1"
        echoed = code_hex
        if self.config.limit_load_echo_wrong_code:
            echoed = f"{(code + 1) & 0xFF:02X}"
        payload = f"{echoed}{blob.upper()}"
        csum = _settings_checksum(f"60,{payload}")
        if self.config.limit_load_corrupt_checksum:
            csum = _flip_checksum(csum)
        return f"@tm:60,{payload}{csum}"

    # -- programmable-recipe (PMode) ------------------------------------
    #
    # APK-derived, hardware-untested: no machine that exposes PMode was
    # available. Modelled after WifiCommandPModeProduct{Read,Write} and
    # WifiCommandPModeSlotProduct{Read,Write} plus their parsers. The
    # simulator serves both branches — a machine that exposes slots
    # (`pmode_products` set) and the EF1091-style machine that answers
    # the C1 / C2 rejection tokens for everything (`pmode_products`
    # left None, the default).

    def _handle_pmode(self, cmd: str) -> str | None:
        head, _, rest = cmd[len("@TM:") :].partition(",")
        # Reads carry just the product code / slot index (one byte);
        # anything longer is a write with a blob and a checksum.
        if len(rest) <= 2:
            return self._pmode_read(head, rest)
        if not self.config.pmode_writable:
            # Same guardrail DESTRUCTIVE_PREFIXES gives @TG: — a test
            # that means to exercise a write must ask for it.
            log.warning("simulator: refusing pmode write %r", cmd)
            return "@an:error"
        return self._pmode_write(head, rest)

    def _pmode_read(self, head: str, rest: str) -> str | None:
        if head == "41":
            products = self.config.pmode_products
            if products is None:
                return "@tm:C1"
            try:
                code = int(rest, 16)
            except ValueError:
                return "@tm:C1"
            blob = products.get(code)
            if blob is None:
                return "@tm:C1"
            return f"@tm:41,{blob}{_settings_checksum(f'41,{blob}')}"
        # head == "42"
        limit = self.config.pmode_reset_after_slot
        if limit is not None:
            self._pmode_reads += 1
            if self._pmode_reads > limit:
                # The real S8 EB resets the TCP session mid-table.
                return "@@CLOSE"
        try:
            slot = int(rest, 16)
        except ValueError:
            return "@tm:C2"
        product = self.config.pmode_slots.get(slot)
        if product is None:
            return "@tm:C2"
        payload = self.config.pmode_slot_blobs.get(slot, f"{product:02X}")
        body = f"42,{slot:02X}{payload}"
        return f"@tm:{body}{_settings_checksum(body)}"

    def _pmode_write(self, head: str, rest: str) -> str:
        body, csum = f"{head},{rest[:-2]}", rest[-2:].upper()
        if _settings_checksum(body) != csum:
            log.warning("simulator: bad pmode checksum for %r", body)
            return "@an:error"
        if self.config.pmode_reject_writes:
            return "@tm:00"
        products = self.config.pmode_products
        payload = rest[:-2].upper()
        if head == "41":
            if products is None:
                return "@tm:C1"
            products[int(payload[:2], 16)] = payload
            return "@tm:41"
        # head == "42": <slot><14-byte head><optional 6-byte tail>
        if products is None:
            return "@tm:C2"
        slot, blob = int(payload[:2], 16), payload[2:]
        self.config.pmode_slots[slot] = int(blob[:2], 16)
        self.config.pmode_slot_blobs[slot] = blob
        return f"@tm:42,{slot:02X}"

    # -- coffee timer --------------------------------------------------
    def _handle_coffee_timer(self, cmd: str) -> str | None:
        """Model ``@TM:3C`` (schedule) and ``@TV:84`` (wall clock).

        Both shapes are APK-derived and have never been seen on a real
        dongle, so the replies here are modelled, not observed: an
        accepted schedule echoes ``@tm:3c`` the way every other
        ``@TM:`` write echoes its argument, and the clock frame answers
        the literal ``@tv:84`` J.O.E.'s matcher waits for.
        """
        if cmd.startswith("@TM:3C,"):
            body = cmd[len("@TM:3C,") :]
            if len(body) < 3:
                return "@an:error"
            payload, csum = body[:-2], body[-2:]
            expected = _settings_checksum(f"3C,{payload}")
            if csum.upper() != expected:
                log.warning(
                    "simulator: bad coffee-timer checksum for %s (got %s, expected %s)",
                    cmd,
                    csum,
                    expected,
                )
                return "@an:error"
            if len(payload) != COFFEE_TIMER_BLOB_HEX_LEN + 4:
                # Blob + 16-bit delay is the only layout the machine takes.
                return "@tm:00"
            if self.config.coffee_timer_reject:
                return "@tm:00"
            self.config.coffee_timer_blob = payload[:COFFEE_TIMER_BLOB_HEX_LEN].upper()
            self.config.coffee_timer_delay = int(
                payload[COFFEE_TIMER_BLOB_HEX_LEN:], 16
            )
            return "@tm:3c"
        if cmd.startswith("@TV:84,"):
            try:
                text = bytes.fromhex(cmd[len("@TV:84,") :]).decode("ascii")
            except (ValueError, UnicodeDecodeError):
                return "@an:error"
            if self.config.coffee_timer_reject:
                return "@tv:00"
            self.config.coffee_timer_clock = text
            return "@tv:84"
        return None

    # -- firmware OTA / restart / milk cooler ---------------------------
    def _handle_firmware(self, cmd: str) -> str | None:
        """Model the dongle-maintenance family (opt-in, see the config).

        The ordering rules mirror what `CoffeeMachineAdapterWifi
        .sendFrogToBootloader` builds: bootloader first, then the `.dat`
        init packet, then the `.bin` windows, then the end marker. A
        payload that arrives out of order is refused, which is how the
        test-suite proves the sequencer sends things in order.
        """
        if cmd == "@HB":
            reply = self.config.bootloader_reply
            self.ota_bootloader = reply.strip().lower() == "@hb:ok"
            if self.ota_bootloader:
                self.ota_dat = None
                self.ota_image = bytearray()
                self.ota_chunks = 0
                self.ota_completed = False
            return reply
        if cmd.startswith("@HO:"):
            if not self.ota_bootloader:
                return "@ho:error"
            try:
                payload = bytes.fromhex(cmd[4:])
            except ValueError:
                return "@ho:error"
            if not payload:
                return "@ho:error"
            self.ota_dat = payload
            return self.config.ota_dat_reply
        if cmd.startswith("@HD:"):
            return self._handle_ota_chunk(cmd[4:])
        if cmd == "@HE":
            if not (self.ota_bootloader and self.ota_dat and self.ota_chunks):
                return "@he:error"
            reply = self.config.ota_end_reply
            if reply.strip().lower() == "@he:ok":
                self.ota_completed = True
                self.ota_bootloader = False
            return reply
        if cmd == "@HT:3":
            self.dongle_restarts += 1
            # A real dongle drops the session here; the simulator keeps it
            # so tests stay deterministic (the client tolerates both).
            self.ota_bootloader = False
            return "@ht"
        if cmd == "@HU":
            return _next_reply(self.config.milk_cooler_start_replies)
        return "@an:error"

    def _handle_ota_chunk(self, body: str) -> str:
        """Validate one `@HD:<offset:08X><len:04X><hex>` window."""
        if not (self.ota_bootloader and self.ota_dat is not None):
            return "@hd:error"
        if len(body) < 12:
            return "@hd:error"
        try:
            offset = int(body[:8], 16)
            length = int(body[8:12], 16)
            data = bytes.fromhex(body[12:])
        except ValueError:
            return "@hd:error"
        if length != len(data) or offset != len(self.ota_image):
            log.warning(
                "simulator: bad OTA chunk (offset %d, len %d, data %d, have %d)",
                offset,
                length,
                len(data),
                len(self.ota_image),
            )
            return "@hd:error"
        if self.config.ota_error_chunk == self.ota_chunks + 1:
            return "@hd:error"
        self.ota_image += data
        self.ota_chunks += 1
        # The success body is undocumented — J.O.E. only ever compares it
        # against the literal "error" — so echo the offset back.
        return f"@hd:{offset:08X}"

    # -- status emission -----------------------------------------------
    def _emit_status(self, conn: socket.socket) -> None:
        msg = f"@TF:{self.config.status_payload.hex().upper()}"
        self._send(conn, msg)

    def _send(self, conn: socket.socket, payload: str) -> None:
        log.debug("simulator -> %r", payload)
        body = (payload + "\r\n").encode("ascii")
        # The protocol framing terminates on the FIRST \r\n inside the
        # plaintext, so the reply itself must not embed a CRLF. Strip the
        # trailing CRLF we just added before encoding to avoid double-wrapping.
        protocol.send_frame(conn, payload.encode("ascii"))
        del body  # unused; keeping for traceability


# --------------------------------------------------------------------- #
# Test harness helpers
# --------------------------------------------------------------------- #


@contextlib.contextmanager
def run_in_thread(config: SimulatorConfig | None = None) -> Iterator[Simulator]:
    """Context manager: start a simulator, yield it, tear it down."""
    sim = Simulator(config)
    sim.start()
    try:
        yield sim
    finally:
        sim.stop()


def _cli() -> None:  # pragma: no cover - manual debugging utility
    import argparse

    ap = argparse.ArgumentParser(description="Standalone Jura simulator")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=51515)
    ap.add_argument("--pin", default="")
    ap.add_argument("--name", default="Sim")
    ap.add_argument(
        "--require-accept",
        action="store_true",
        help="simulate the on-machine 'Connect' prompt by delaying the @hp4",
    )
    ap.add_argument("--accept-delay", type=float, default=2.0)
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="%(message)s")
    cfg = SimulatorConfig(
        pin=args.pin,
        require_user_accept=args.require_accept,
        user_accept_delay=args.accept_delay,
        name=args.name,
    )
    with run_in_thread(cfg) as sim:
        print(f"simulator listening on {sim.address[0]}:{sim.address[1]}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":  # pragma: no cover
    _cli()
