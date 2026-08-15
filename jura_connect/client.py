"""TCP client for the Jura WiFi protocol (unset-PIN flow supported).

Layers:

* :class:`JuraConnection` -- raw framed transport (write/read encoded frames).
* :class:`JuraClient`     -- handshake (`@HP:`) + structured read operations.

Wire framing and crypto live in :mod:`jura_connect.protocol` / :mod:`jura_connect.crypto`
and are shared with the in-tree :mod:`jura_connect.simulator`.

Handshake (matches the J.O.E. Android app's ``WifiCommandConnectionSetup``)::

    -> @HP:<pin>,<conn_id_hex>,<auth_hash>\\r\\n
    <- @hp4                  CORRECT, no new hash
       @hp4:<hash>           CORRECT, persist ``<hash>`` for next time
       @hp5 / @hp5:00        WRONG_PIN  -- machine wants a PIN, none given
       @hp5:01               WRONG_HASH -- conn-id unknown / hash stale
       @hp5:02               ABORTED    -- machine refused

Initial pairing on a machine without a PIN configured:

1. The client opens a TCP session and sends ``@HP:,<conn_id_hex>,``
   (both ``pin`` and ``auth_hash`` empty).
2. The coffee machine pops up a **Connect** dialog on its own display.
3. The user accepts on the machine.
4. The machine replies with ``@hp4:<hash>`` carrying a 64-hex-char auth
   token, which the client surfaces via ``HandshakeResult.new_hash``.

The caller persists ``new_hash`` and passes it as ``auth_hash`` on
subsequent runs to skip the on-machine confirmation.
"""

from __future__ import annotations

import dataclasses
import datetime
import logging
import re
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence

from . import profile, protocol
from .process import (
    ProcessRun,
    ProcessRunner,
    ProcessStep,
    StepDecider,
    resolve_process,
    watch_states,
)
from .profile import PMODE_BLOB_BYTES, MachineProfile, ProductDef, SettingDef
from .progress import ProductProgress, is_progress_frame

log = logging.getLogger(__name__)

DEFAULT_PORT = 51515
DEFAULT_CONN_ID = "jura-connect"

# 60 seconds is what we observed empirically as a comfortable upper bound:
# the dongle keeps the dialog up roughly that long. The J.O.E. app uses 40 s
# (WifiCommand timeoutAfterSeconds=40L) -- we go a bit higher for humans.
DEFAULT_PAIR_TIMEOUT = 60.0


def _conn_id_hex(conn_id: str) -> str:
    """Hex-encode each character (matches ``ExtensionsKt.c`` in the APK)."""
    return "".join(f"{ord(c) & 0xFF:02X}" for c in conn_id)


class HandshakeError(RuntimeError):
    """Authentication / setup with the coffee machine failed."""


class PairingTimeout(HandshakeError):
    """The machine never sent ``@hp4``/``@hp5`` within the allotted window."""


@dataclasses.dataclass(slots=True)
class HandshakeResult:
    """Outcome of one ``@HP:`` round-trip.

    ``state`` is one of ``CORRECT``, ``WRONG_PIN``, ``WRONG_HASH``,
    ``ABORTED``, or ``REJECTED:<code>`` for unrecognised tails.
    """

    code: str
    state: str
    new_hash: str | None


_HP_RE = re.compile(r"^@hp([45])(?::(.*))?$")


def _capped_join(items: list[str], limit: int = 10) -> str:
    """Join ``items`` with commas, truncating to ``limit`` with an ellipsis.

    Product profiles carry 80+ names on some models; an error message
    that dumps all of them is unreadable, so cap the list.
    """
    if not items:
        return "(none)"
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f", … (+{len(items) - limit} more)"


def _is_brew_accept(reply: str) -> bool:
    """True when a ``@TP:`` reply means the machine accepted the brew.

    The machine returns a bare ``@tp`` on accept, but ``@tp:00`` when it
    rejects / silently ignores the blob (e.g. the old FF-padded layout,
    or a bare product code). ``@tp:00`` must NOT be treated as success —
    live-verified on the S8 EB (EF1091).
    """
    r = reply.strip().lower()
    return r.startswith("@tp") and not r.startswith("@tp:00")


def _classify(reply: str) -> HandshakeResult:
    m = _HP_RE.match(reply.strip())
    if not m:
        raise HandshakeError(f"unexpected handshake reply: {reply!r}")
    major, rest = m.group(1), m.group(2)
    if major == "4":
        return HandshakeResult(reply.strip(), "CORRECT", rest or None)
    code = rest or ""
    if code in ("", "00"):
        state = "WRONG_PIN"
    elif code == "01":
        state = "WRONG_HASH"
    elif code == "02":
        state = "ABORTED"
    else:
        state = f"REJECTED:{code}"
    return HandshakeResult(reply.strip(), state, None)


class JuraConnection:
    """Raw framed TCP connection. One ``send`` / ``recv_frame`` per message."""

    def __init__(
        self,
        address: str,
        port: int = DEFAULT_PORT,
        *,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
    ) -> None:
        self.address = address
        self.port = port
        self._sock: socket.socket | None = None
        self._reader: protocol.FrameReader | None = None
        self._lock = threading.Lock()
        self._read_timeout = read_timeout
        self._connect_timeout = connect_timeout

    def connect(self) -> None:
        if self._sock is not None:
            return
        s = socket.create_connection(
            (self.address, self.port), timeout=self._connect_timeout
        )
        s.settimeout(self._read_timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock = s
        self._reader = protocol.FrameReader(s)

    def close(self) -> None:
        s, self._sock = self._sock, None
        self._reader = None
        if s is None:
            return
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        s.close()

    def __enter__(self) -> JuraConnection:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def send(self, payload: bytes, *, key: int | None = None) -> None:
        if self._sock is None:
            raise OSError("not connected")
        with self._lock:
            protocol.send_frame(self._sock, payload, key=key)

    def send_str(self, payload: str, *, key: int | None = None) -> None:
        self.send(payload.encode("ascii"), key=key)

    def recv_frame(self, *, timeout: float | None = None) -> bytes:
        if self._reader is None:
            raise OSError("not connected")
        return self._reader.next_frame(timeout=timeout)

    def recv_str(self, *, timeout: float | None = None) -> str:
        return self.recv_frame(timeout=timeout).decode("ascii", errors="replace")


class JuraClient:
    """High-level WiFi client.

    Lifecycle::

        client = JuraClient("192.168.1.42", conn_id="my-host",
                            auth_hash="<persisted-or-empty>")
        result = client.connect()           # short timeout if hash is known
        # OR
        result = client.pair(on_user_prompt=print)  # long wait, user confirms

        client.read_maintenance_counter()   # structured query
        ...
        client.close()

    The handshake step blocks on the TCP receive until either ``@hp4`` /
    ``@hp5`` arrives or the requested timeout expires. Unsolicited
    ``@TF:`` status frames that show up *before* the handshake reply are
    captured into :attr:`status_history`.
    """

    def __init__(
        self,
        address: str,
        port: int = DEFAULT_PORT,
        *,
        pin: str = "",
        conn_id: str = DEFAULT_CONN_ID,
        auth_hash: str = "",
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        profile: MachineProfile | None = None,
    ) -> None:
        self.conn = JuraConnection(
            address,
            port,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )
        self.pin = pin
        self.conn_id = conn_id
        self.auth_hash = auth_hash
        self.handshake: HandshakeResult | None = None
        self.status_history: list[str] = []
        # Progress frames collected by the last brew(follow=True) call.
        self.last_progress: tuple[ProductProgress, ...] = ()
        # Optional MachineProfile (from jura_connect.profile). When set,
        # status bit names + product names come from the profile's
        # ALERTS / PRODUCTS sections rather than the EF536 baseline.
        self.profile = profile

    # -- lifecycle -----------------------------------------------------
    def connect(self, *, timeout: float = 15.0) -> HandshakeResult:
        """Open the TCP session and run ``@HP:`` with a short timeout.

        Use :meth:`pair` instead when you need the long, user-interactive
        window in which the machine shows its on-screen Connect prompt.
        """
        self.conn.connect()
        return self._do_handshake(timeout=timeout)

    def pair(
        self,
        *,
        timeout: float = DEFAULT_PAIR_TIMEOUT,
        on_user_prompt: Callable[[str], None] | None = None,
    ) -> HandshakeResult:
        """Run the initial pairing flow (no auth hash yet).

        Opens the connection, sends ``@HP:<pin>,<conn_id_hex>,`` (empty auth
        hash) and blocks for up to ``timeout`` seconds while the user accepts
        the "pair with this device?" prompt on the machine's display.
        Calls ``on_user_prompt`` once with a one-line instruction so the
        UI / CLI can tell the user to press OK on the coffee machine.

        For machines that have a setup PIN configured (e.g. Jura E6 / EF1030)
        the PIN **must** be set on the :class:`JuraClient` instance before
        calling this method — it is included in the ``@HP:`` request so the
        machine can verify the caller before showing the confirmation dialog.
        Machines without a PIN work the same way with ``pin=""`` (the default).

        Returns the same :class:`HandshakeResult` as :meth:`connect`. On
        ``CORRECT`` with a new hash, the new hash is captured in
        :attr:`auth_hash` and exposed via ``result.new_hash`` so callers
        can persist it.
        """
        self.auth_hash = ""
        self.conn.connect()
        if on_user_prompt is not None:
            on_user_prompt(
                "Coffee machine should be showing a 'Connect' prompt — "
                "press OK on the machine to accept this device "
                f"(waiting up to {timeout:.0f}s)."
            )
        return self._do_handshake(timeout=timeout)

    def close(self) -> None:
        """Hang up the way the J.O.E. app does: send an empty frame.

        The app's ``WifiCommandCloseConnection`` puts a frame with an
        empty payload on the wire and closes the socket. It does *not*
        send ``@HE`` — that is ``WifiCommandOTAEnd`` (it expects
        ``@he:ok`` and belongs to a firmware-update session), which
        earlier versions of this client used as a "polite close".

        Best-effort: a dongle that already went away must not turn
        ``close()`` into an exception.
        """
        try:
            self.send_command("")
        except Exception:  # noqa: BLE001
            pass
        self.conn.close()

    def __enter__(self) -> JuraClient:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- handshake -----------------------------------------------------
    def _do_handshake(self, *, timeout: float) -> HandshakeResult:
        cmd = f"@HP:{self.pin},{_conn_id_hex(self.conn_id)},{self.auth_hash}"
        self.conn.send_str(cmd)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PairingTimeout(
                    f"no @hp4/@hp5 reply within {timeout:.1f}s — "
                    "did the user accept on the machine?"
                )
            try:
                reply = self.conn.recv_str(timeout=remaining)
            except (TimeoutError, socket.timeout) as exc:
                raise PairingTimeout(
                    f"no @hp4/@hp5 reply within {timeout:.1f}s"
                ) from exc
            if reply.startswith(("@TF:", "@TV:")):
                self.status_history.append(reply)
                continue
            result = _classify(reply)
            if result.state == "CORRECT" and result.new_hash:
                self.auth_hash = result.new_hash
            self.handshake = result
            return result

    # -- request/response ---------------------------------------------
    def send_command(self, cmd: str) -> None:
        """Fire-and-forget command (no response wait)."""
        self.conn.send_str(cmd)

    def request(
        self,
        cmd: str,
        *,
        match: str | re.Pattern[str] | None = None,
        timeout: float = 6.0,
    ) -> str:
        """Send ``cmd`` and return the first matching reply.

        ``match`` may be a regex source or compiled pattern. When ``None``
        the first reply that isn't an unsolicited ``@TV:``/``@TF:`` status
        frame is returned. Status frames seen along the way are appended
        to :attr:`status_history`.
        """
        if isinstance(match, str):
            pattern: re.Pattern[str] | None = re.compile(match)
        else:
            pattern = match
        self.conn.send_str(cmd)
        return self._await_frame(pattern, timeout=timeout, what=f"reply to {cmd!r}")

    def _await_frame(
        self,
        pattern: re.Pattern[str] | None,
        *,
        timeout: float,
        what: str,
    ) -> str:
        """Read frames until one matches ``pattern`` (or the first non-status
        frame when ``pattern`` is ``None``).

        Sends nothing — :meth:`request` calls it after writing its
        command, :meth:`read_status` calls it to sit and wait for the
        dongle's next broadcast. ``what`` names the awaited thing in the
        :class:`TimeoutError` message.
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"no {what} within {timeout}s")
            try:
                reply = self.conn.recv_str(timeout=remaining)
            except (TimeoutError, socket.timeout) as exc:
                raise TimeoutError(f"no {what} within {timeout}s") from exc
            if reply.startswith(("@TF:", "@TV:")):
                self.status_history.append(reply)
                if pattern is None:
                    continue
                if not pattern.search(reply):
                    continue
                return reply
            if pattern is None:
                return reply
            if pattern.search(reply):
                return reply

    # -- raw helpers ---------------------------------------------------
    def iter_frames(self, *, until: float | None = None) -> Iterator[str]:
        """Yield every incoming frame as a decoded ASCII string.

        ``until`` is an optional absolute deadline (``time.monotonic()``).
        Useful for watching ``@TF:`` / ``@TV:`` status streams in tests
        and CLI ``--watch`` modes.
        """
        while True:
            if until is not None:
                remaining = until - time.monotonic()
                if remaining <= 0:
                    return
                try:
                    yield self.conn.recv_str(timeout=remaining)
                except (TimeoutError, socket.timeout):
                    return
            else:
                yield self.conn.recv_str()

    # -- progress stream -----------------------------------------------
    def iter_progress(
        self, *, timeout: float | None = None, until: float | None = None
    ) -> Iterator[ProductProgress]:
        """Yield decoded ``@TV:`` progress frames as the machine sends them.

        Built on :meth:`iter_frames`; everything that is not a decodable
        progress frame is skipped — ``@TF:`` status broadcasts, the
        ``@TB`` brew-start marker, and the ``@TV:81/82/84``
        language-download / clock-sync frames. ``@TF:`` frames still land
        in :attr:`status_history` so nothing is lost.

        ``timeout`` is a duration in seconds from now; ``until`` an
        absolute :func:`time.monotonic` deadline (``timeout`` wins when
        both are given). With neither, this blocks until the connection
        closes. The generator stops when the deadline passes — callers
        that want to stop on completion should ``break`` on
        :attr:`ProductProgress.is_complete`.
        """
        if timeout is not None:
            until = time.monotonic() + timeout
        for frame in self.iter_frames(until=until):
            if frame.startswith("@TF:"):
                self.status_history.append(frame)
                continue
            if not is_progress_frame(frame):
                continue
            yield ProductProgress.parse(frame, self.profile)

    def follow_progress(
        self,
        *,
        timeout: float = 120.0,
        on_progress: Callable[[ProductProgress], None] | None = None,
    ) -> list[ProductProgress]:
        """Collect progress frames until the machine says ``ENJOY``.

        Returns every frame seen, in order, stopping on the ``ENJOY``
        (``3E``) completion frame or when ``timeout`` seconds elapse —
        whichever comes first. ``on_progress`` is called with each frame
        as it arrives, for live UIs that don't want to wait for the
        list.
        """
        collected: list[ProductProgress] = []
        for update in self.iter_progress(timeout=timeout):
            collected.append(update)
            if on_progress is not None:
                on_progress(update)
            if update.is_complete:
                break
        return collected

    # -- maintenance processes -----------------------------------------
    def process_runner(self, name: str) -> ProcessRunner:
        """Bind a maintenance process to this session (sends nothing).

        ``name`` is a process name (``"cleaning"``, ``"descale"``,
        ``"filter_change"``, ``"cappu_clean"``, ``"cappu_rinse"``,
        ``"coffee_rinse"``); it is resolved against :attr:`profile` when
        one is loaded, so a machine that does not declare the process
        refuses instead of guessing. See
        :class:`jura_connect.process.ProcessRunner` for the step-by-step
        API — and note that every confirmation it sends advances a real
        cycle on real hardware.
        """
        return ProcessRunner(self, resolve_process(name, self.profile))

    def run_process(
        self,
        name: str,
        *,
        timeout: float = 900.0,
        step_timeout: float = 120.0,
        start_timeout: float = 6.0,
        auto_accept: bool = False,
        on_step: StepDecider | None = None,
    ) -> ProcessRun:
        """Start a maintenance process and follow it to the end.

        Thin wrapper over :meth:`ProcessRunner.run`. **Destructive**: it
        starts a real cycle (and, with ``auto_accept``, confirms every
        prompt unattended). The named-command layer gates it; library
        callers reaching for this are opting in.
        """
        return self.process_runner(name).run(
            timeout=timeout,
            step_timeout=step_timeout,
            start_timeout=start_timeout,
            auto_accept=auto_accept,
            on_step=on_step,
        )

    def watch_process(
        self,
        *,
        timeout: float = 60.0,
        on_step: Callable[[ProcessStep], None] | None = None,
    ) -> ProcessRun:
        """Listen to the machine's state stream without sending anything.

        Read-only counterpart of :meth:`run_process`: decodes the pushed
        ``@TV:`` frames of a cycle somebody started elsewhere (front
        panel, J.O.E. app) into named steps.
        """
        return watch_states(self, timeout=timeout, on_step=on_step)

    # -- structured reads ---------------------------------------------
    def read_maintenance_counter(
        self, *, timeout: float = 6.0
    ) -> "MaintenanceCounters":
        """Read the maintenance counter bank (``@TG:43``).

        The bank's field order is machine-specific, so the decode uses
        :attr:`profile` when one is loaded — without it the EF536 /
        EF1091 baseline order is assumed, which mislabels the 21
        profiles that declare a different one.
        """
        reply = self.request("@TG:43", match=r"^@tg:43", timeout=timeout)
        return MaintenanceCounters.parse(reply, profile=self.profile)

    def read_maintenance_percent(self, *, timeout: float = 6.0) -> "MaintenancePercent":
        """Read the maintenance percent bank (``@TG:C0``)."""
        reply = self.request("@TG:C0", match=r"^@tg:C0", timeout=timeout)
        return MaintenancePercent.parse(reply, profile=self.profile)

    def read_status(
        self, *, timeout: float = 6.0, nudge: bool = False
    ) -> "MachineStatus":
        """Wait for the machine's next ``@TF:`` status broadcast and parse it.

        There is no "read status" request in the protocol: the dongle
        pushes ``@TF:`` frames on its own and the J.O.E. app merely
        routes them (``TCPReceiveHandler``). So this method sends
        nothing and waits.

        ``nudge=True`` sends ``@HU?`` first. That command is the app's
        ``WifiCommandMilkCoolerUpdateStatus`` (answered with
        ``@hu:<3 hex>``, e.g. ``@hu:800``) — *not* a status query. It is
        kept only as an escape hatch for firmwares that want traffic on
        the socket before they resume broadcasting; the status still
        arrives as the next pushed ``@TF:`` frame either way.
        """
        if nudge:
            self.send_command("@HU?")
        reply = self._await_frame(
            re.compile(r"^@TF:"),
            timeout=timeout,
            what="pushed @TF: status frame",
        )
        return MachineStatus.parse(reply, profile=self.profile)

    def read_product_counters(
        self, *, timeout_per_page: float = 6.0
    ) -> "ProductCounters":
        """Read the per-product brew counter bank (``@TR:32``).

        The wire protocol paginates the response: the client sends
        ``@TR:32,<page>`` for each page ``00..0F`` (16 pages total) and
        reassembles the 8-byte payload of each page into a 64-slot
        table of ``u16`` counts. Slot 0 is the total number of brews;
        slots 1..63 are the per-product counts indexed by product code,
        with ``0xFFFF`` reserved for "this code is not configured on
        this machine". See :class:`ProductCounters` for the slot map.

        When the machine's profile declares an overflow bank
        (:data:`OVERFLOW_COUNTER_BANK`, ``@TR:33``) its per-slot high
        bytes are read as well and folded in, so counts past 65535
        survive. Machines that declare no such bank — every S8/Z10
        profile among them — issue one bank read as before.
        """
        spec = counter_bank_spec(PRODUCT_COUNTER_BANK)
        slots = self._read_counter_bank(
            spec.command,
            bytes_per_value=spec.bytes_per_value,
            timeout_per_page=timeout_per_page,
            pages=spec.pages,
        )
        if slots is None:
            raise ValueError("machine does not implement the @TR:32 counter bank")
        overflow = self._read_overflow_bank(spec, timeout_per_page=timeout_per_page)
        return ProductCounters.from_slots(
            slots, profile=self.profile, overflow=overflow
        )

    def read_counter_bank(
        self, bank: str, *, timeout_per_page: float = 6.0
    ) -> "CounterBank | None":
        """Read one counter bank other than ``@TR:32`` by wire command.

        ``bank`` is a base bank command from :data:`COUNTER_BANK_SPECS`:
        ``@TR:34`` (barista), ``@TR:52`` (special), ``@TR:42`` /
        ``@TR:44`` (the daily pair). Overflow banks are folded into their
        base bank and cannot be read on their own.

        Returns ``None`` — never an exception — when this machine has no
        such bank, which is the common case: either its profile does not
        declare it (then nothing is sent at all) or the dongle answers
        the bare ``@tr:00`` J.O.E.'s matcher treats as "not
        implemented". Use :meth:`read_product_counters` for ``@TR:32``,
        which every machine has.

        Without a profile there is no declaration to consult, so the
        bank is requested and the machine's own ``@tr:00`` decides.

        Only the special bank is exercised by the official app; the
        barista and daily banks are XML-derived and untested against
        hardware (docs/PROTOCOL.md §5.5).
        """
        spec = counter_bank_spec(bank)
        if spec.overflow_of is not None:
            raise ValueError(
                f"{spec.command} is the overflow bank of {spec.overflow_of}; "
                f"read {spec.overflow_of} instead — its high bytes are "
                "folded in automatically"
            )
        if self.profile is not None and not self.profile.declares_counter_bank(
            spec.command
        ):
            log.debug(
                "%s does not declare the %s bank; not reading it",
                self.profile.code,
                spec.command,
            )
            return None
        slots = self._read_counter_bank(
            spec.command,
            bytes_per_value=spec.bytes_per_value,
            timeout_per_page=timeout_per_page,
            pages=spec.pages,
        )
        if slots is None:
            return None
        overflow = self._read_overflow_bank(spec, timeout_per_page=timeout_per_page)
        return CounterBank.from_slots(
            spec.command, slots, profile=self.profile, overflow=overflow
        )

    def _read_overflow_bank(
        self, spec: "CounterBankSpec", *, timeout_per_page: float
    ) -> list[int] | None:
        """Read ``spec``'s overflow bank when the machine declares it.

        Any surprise on that read — silence, a reply shape we don't know
        — degrades to "no overflow data" rather than losing the base
        counts we already have.
        """
        if spec.overflow is None or self.profile is None:
            return None
        if not self.profile.declares_counter_bank(spec.overflow):
            return None
        over = counter_bank_spec(spec.overflow)
        try:
            return self._read_counter_bank(
                over.command,
                bytes_per_value=over.bytes_per_value,
                timeout_per_page=timeout_per_page,
                pages=over.pages,
            )
        except (TimeoutError, ValueError) as exc:
            log.warning(
                "%s declares %s but the read failed (%s); reporting base counts only",
                self.profile.code,
                over.command,
                exc,
            )
            return None

    def _read_counter_bank(
        self,
        bank: str,
        *,
        bytes_per_value: int,
        timeout_per_page: float,
        pages: int = 16,
    ) -> list[int] | None:
        """Read one paginated counter bank (``@TR:32``, ``@TR:33``, …).

        The dongle answers ``@tr:<bank>,<page>,<8 hex bytes>`` for pages
        ``00..0F``, or a bare ``@tr:00`` when it does not implement the
        bank at all — J.O.E. accepts the same two shapes. Returns the
        decoded values, or ``None`` when the very first page says the
        bank is not implemented. A ``@tr:00`` on a later page ends the
        bank early and returns what was read so far: J.O.E. sizes some
        banks differently (its special-counter read asks for 4 pages,
        the product counter for 16), so a shorter bank is a plausible
        firmware answer rather than an error.

        ``pages`` is the bank's page count from its
        :class:`CounterBankSpec`.
        """
        echo = bank.lower()
        values: list[int] = []
        for page in range(pages):
            reply = self.request(
                f"{bank},{page:02X}",
                match=rf"^({re.escape(echo)},{page:02X}|@tr:00)",
                timeout=timeout_per_page,
            )
            if reply.lower().startswith("@tr:00"):
                return values or None
            # "@tr:<bank>,<page>,<8 hex bytes>"
            try:
                _, _, body = reply.split(",", 2)
            except ValueError as exc:
                raise ValueError(
                    f"malformed {bank} reply for page {page:02X}: {reply!r}"
                ) from exc
            page_bytes = bytes.fromhex(body)
            for i in range(0, len(page_bytes), bytes_per_value):
                values.append(
                    int.from_bytes(page_bytes[i : i + bytes_per_value], "big")
                )
        return values

    def read_machine_info(self, *, timeout: float = 6.0) -> "MachineInfo":
        """Bundle of everything we can passively learn about the machine."""
        return MachineInfo(
            conn_id=self.conn_id,
            auth_hash=self.auth_hash,
            handshake_state=self.handshake.state if self.handshake else "UNKNOWN",
            status=self.read_status(timeout=timeout),
            maintenance_counters=self.read_maintenance_counter(timeout=timeout),
            maintenance_percent=self.read_maintenance_percent(timeout=timeout),
        )

    def read_pmode_slots(self, *, timeout: float = 6.0) -> "ProgramModeSlots":
        """Read the user-programmable recipe slots (``@TM:50`` + ``@TM:42``).

        Older machines expose a "Programmable Mode" where each slot
        holds a saved recipe (variant of a product). The wire protocol
        is two-step:

        * ``@TM:50`` returns the per-product-kind slot count (one byte
          per kind, summed for the total).
        * ``@TM:42,<slot_hex>`` returns the product code and parameters
          for one slot, or the magic ``C2`` prefix when the machine
          doesn't support the requested slot.

        On machines without pmode (e.g. the S8 EB / EF1091), the count
        may be non-zero but every per-slot read returns ``C2``; the
        resulting :class:`ProgramModeSlots` carries an empty
        ``slots`` tuple in that case.
        """
        # Matched loosely: the machine may answer the ``D0`` rejection
        # token instead of ``50,<counts>`` (``PModeNumSlotReadParser``),
        # and a strict ``^@tm:50`` matcher would time out on it.
        num_slots_reply = self.request("@TM:50", match=r"(?i)^@tm", timeout=timeout)
        num_slots = _parse_pmode_num_slots(num_slots_reply)
        entries: list[PModeSlot] = []
        unsupported: list[int] = []
        connection_dropped = False
        for slot in range(num_slots):
            if connection_dropped:
                unsupported.append(slot)
                continue
            cmd = f"@TM:42,{slot:02X}"
            try:
                reply = self.request(cmd, match=r"^@tm", timeout=timeout)
            except TimeoutError:
                # Some slots time out — record and keep iterating.
                unsupported.append(slot)
                continue
            except (ConnectionError, OSError):
                # The real S8 EB drops the TCP session after some
                # @TM:42 reads (observed on slot 0x80). Stop iterating
                # rather than spamming the dongle; mark every remaining
                # slot as unsupported so the caller sees what didn't
                # get answered.
                unsupported.append(slot)
                connection_dropped = True
                continue
            entry = _parse_pmode_slot(slot, reply)
            if entry is None:
                unsupported.append(slot)
            else:
                entries.append(entry)
        return ProgramModeSlots(
            num_slots=num_slots,
            slots=tuple(entries),
            unsupported=tuple(unsupported),
        )

    # -- PMode product / slot writes (APK-derived, hardware-untested) --
    #
    # Everything below mirrors the J.O.E. APK; no Jura machine that
    # actually exposes PMode was available while it was written, so
    # treat the wire formats as unverified. See docs/PROTOCOL.md §5.6.

    def read_pmode_product(
        self, product: "str | int", *, timeout: float = 6.0
    ) -> "PModeProduct | None":
        """Read one product's stored PMode settings (``@TM:41,<code>``).

        Mirrors ``WifiCommandPModeProductRead`` +
        ``PModeProductReadParser``:

        ```
        client → @TM:41,<product code hex>
        dongle → @tm:41,<F1..Fn hex><checksum>     (settings follow)
        dongle → @tm:C1                            (product programming
                                                    not supported)
        ```

        Returns ``None`` for the ``C1`` rejection token — the APK logs
        "Machine does not support Product Programming" and yields null
        there — and raises :class:`ValueError` when the checksum or the
        echoed product code doesn't match, so a corrupt reply can never
        pass for a stored recipe.
        """
        definition = self._pmode_product_def(product)
        code = definition.code if definition is not None else _pmode_code(product)
        reply = self.request(f"@TM:41,{code:02X}", match=r"(?i)^@tm", timeout=timeout)
        return _parse_pmode_product(code, reply, definition)

    def write_pmode_product(
        self,
        product: "str | int",
        overrides: "dict[str, int | str] | None" = None,
        *,
        timeout: float = 6.0,
    ) -> str:
        """Overwrite a product's stored PMode settings (``@TM:41``).

        **Destructive and APK-derived.** Mirrors
        ``WifiCommandPModeProductWrite``, whose body is
        ``"41," + AppProduct.d()`` followed by the same
        ``ByteOperations.d`` checksum the settings write uses::

            client → @TS:01
            client → @TM:41,<34 hex blob><checksum>
            dongle → @tm:41            (accepted)
            dongle → @tm:C1 / @tm:00   (not supported / rejected)
            client → @TS:00

        ``product`` is a profile product name, a 2-hex product code, or
        — the escape hatch, mirroring :meth:`~jura_connect.commands`'
        ``brew`` — a full 34-hex blob sent verbatim, which needs no
        profile. ``overrides`` are validated against the machine XML
        by :meth:`~jura_connect.profile.ProductDef.build_pmode_hex`
        before anything reaches the wire.

        Returns the dongle's reply. Raises :class:`ValueError` on the
        ``C1`` / ``00`` rejection tokens; ``@an:error`` is returned
        verbatim (matching :meth:`write_setting`).
        """
        blob = self._pmode_blob(product, overrides)
        return self._pmode_write(f"41,{blob}", timeout=timeout)

    def write_pmode_slot(
        self,
        slot: int,
        product: "str | int",
        overrides: "dict[str, int | str] | None" = None,
        *,
        timeout: float = 6.0,
    ) -> str:
        """Assign a product (with settings) to a PMode slot (``@TM:42``).

        **Destructive and APK-derived.** Mirrors
        ``CoffeeMachineAdapterBle2.sendPmodeProductCommandSlot``:

        * the body is ``"42," + <slot hex> + <first 14 bytes of the
          product blob> + <tail>``, plus the ``ByteOperations.d``
          checksum;
        * the tail comes from
          ``WifiCommandPModeSlotProductWrite.Companion.a``: six bytes
          ``00 <F17> 00 00 00 00`` when the product has a grinder-
          freeness parameter, six zero bytes when it does not but the
          machine declares ``IntakeF18``, and **nothing at all**
          otherwise (a 14-byte body);
        * the reply matcher is ``@tm:42,<slot>.*``, with ``@tm:C2``
          meaning "product code, slot, or function is not supported by
          machine".

        Note the F17 byte lands at blob index 15 here, not 16 as in
        :meth:`~jura_connect.profile.ProductDef.build_pmode_hex` — the
        APK splices ``getValue("F17")`` into the truncated head rather
        than sending the full 17-byte blob. That asymmetry is copied
        deliberately; it is what J.O.E. puts on the wire.
        """
        if not 0 <= slot <= 0xFF:
            raise ValueError(f"pmode slot {slot} outside 0..255")
        blob = self._pmode_blob(product, overrides)
        tail = self._pmode_tail(blob, self._pmode_product_def(product))
        body = f"42,{slot:02X}{blob[:_PMODE_SLOT_HEAD_HEX]}{tail}"
        return self._pmode_write(body, timeout=timeout)

    # -- PMode helpers -------------------------------------------------

    def _pmode_product_def(self, product: "str | int") -> "ProductDef | None":
        """Resolve ``product`` against the profile, or ``None`` when it
        is a verbatim blob / there is no profile to resolve against."""
        if isinstance(product, str) and _is_pmode_blob(product):
            return None
        if self.profile is None:
            if isinstance(product, int):
                return None
            raise ValueError(
                "pmode: product names and codes need a machine profile. "
                "Pair with --machine-type <EF_code>, or pass a full "
                f"{PMODE_BLOB_BYTES * 2}-hex blob as an escape hatch."
            )
        return self.resolve_product(product)

    def _pmode_blob(
        self, product: "str | int", overrides: "dict[str, int | str] | None"
    ) -> str:
        """Build (or accept verbatim) the 17-byte PMode product blob."""
        if isinstance(product, str) and _is_pmode_blob(product):
            if overrides:
                raise ValueError(
                    "pmode: parameter overrides cannot be combined with a "
                    "verbatim blob — bake the values into the blob instead."
                )
            return product.upper()
        definition = self._pmode_product_def(product)
        if definition is None:
            raise ValueError(
                "pmode: a machine profile is required to build the blob for "
                f"{product!r}; pass a full {PMODE_BLOB_BYTES * 2}-hex blob "
                "instead."
            )
        if not definition.product_settings:
            raise ValueError(
                f'pmode: {definition.name!r} is marked ProductSettings="false" '
                "in this machine's XML — it is not programmable."
            )
        return definition.build_pmode_hex(overrides)

    def _pmode_tail(self, blob: str, definition: "ProductDef | None") -> str:
        """The six-byte tail (or nothing) the slot write appends.

        ``WifiCommandPModeSlotProductWrite.Companion.a`` branches on
        ``AppProduct.e()`` — "does this product *declare* an F17
        parameter" — not on the value. With a verbatim blob there is no
        product definition to ask, so a non-zero byte 16 stands in
        (grinder-freeness catalogues start at ``01``).
        """
        freeness = blob[_PMODE_FREENESS_OFFSET * 2 :][:2]
        has_f17 = (
            freeness != "00"
            if definition is None
            else definition.param(_KIND_GRINDER_FREENESS) is not None
        )
        if has_f17:
            return f"00{freeness}00000000"
        if self.profile is not None and self.profile.intake_f18:
            return "000000000000"
        return ""

    def _pmode_write(self, body: str, *, timeout: float) -> str:
        """Send one checksummed PMode write inside the @TS lock wrapper."""
        cmd = f"@TM:{body}{_settings_checksum(body)}"
        self.lock_screen()
        try:
            reply = self.request(cmd, match=r"(?i)^@(tm|an)", timeout=timeout)
        finally:
            try:
                self.unlock_screen()
            except Exception:  # noqa: BLE001
                # Best-effort unlock; a failure here must not mask the
                # original write error.
                pass
        if reply.lower().startswith("@an:error"):
            return reply
        token = ""
        if reply.lower().startswith("@tm:"):
            token = reply[len("@tm:") :].split(",", 1)[0].strip().upper()
        if token in _PMODE_NOT_SUPPORTED:
            raise ValueError(
                f"pmode write {body.split(',', 1)[0]}: machine answered "
                f"{reply!r} — {_PMODE_NOT_SUPPORTED[token]}. Nothing was "
                "stored."
            )
        return reply

    def read_setting(self, p_argument: str, *, timeout: float = 3.0) -> str:
        """Read one machine setting via ``@TM:<p_argument>``.

        ``p_argument`` is the ``P_Argument`` attribute from the XML
        ``<MACHINESETTINGS>`` block (e.g. ``"02"`` for hardness).

        Returns the raw hex value with the trailing two-char checksum
        stripped. Reply shape on the wire is
        ``@tm:<arg>,<value><checksum>`` — same checksum algorithm as
        the write side (``ByteOperations.d`` over ``"<arg>,<value>"``);
        we verify it before returning. For most settings the value is
        one byte (2 hex chars); for ItemSlider settings it can be 4
        or 6 chars (the AutoOFF table's ``"22021C"`` for 9h).

        Raises :class:`ValueError` when the checksum doesn't match —
        the value would otherwise alias as a too-large integer
        (hardness=13 came back as 3581 in v0.9.0 because the
        checksum byte was lumped in).
        """
        arg = p_argument.upper()
        cmd = f"@TM:{arg}"
        # (?i) — the dongle may echo the argument in either case
        # (observed lowercase for "0a" / "0A" alike), so match
        # case-insensitively on the reply.
        reply = self.request(cmd, match=rf"(?i)^@tm:{arg}", timeout=timeout)
        prefix = f"@tm:{arg.lower()}"
        body = reply[len(prefix) :] if reply.lower().startswith(prefix) else reply
        body = body.lstrip(",").strip()
        if len(body) < 4:
            # Shorter than 2 (value) + 2 (csum). Some firmwares answer
            # plain "@tm:<arg>" when the setting is unknown — surface
            # that as-is rather than synthesising a value.
            return body
        value, csum = body[:-2], body[-2:]
        expected = _settings_checksum(f"{arg},{value}")
        if csum.upper() != expected:
            raise ValueError(
                f"setting read for arg={arg}: checksum mismatch "
                f"(got {csum!r}, expected {expected!r} over "
                f"{arg!r},{value!r}); reply was {reply!r}"
            )
        return value

    def write_setting(
        self,
        p_argument: str,
        value_hex: str,
        *,
        timeout: float = 3.0,
        verify: bool = True,
    ) -> str:
        """Write one setting via ``@TM:<arg>,<value><checksum>``.

        Wire flow on the real dongle (verified against TT237W /
        Kaffeebert and matching the J.O.E. APK's PriorityChannel
        dispatch for ``CommandPriority.PMODE``):

            client → @TS:01                  (lock keypad)
            client ← @ts
            client → @TM:<arg>,<val><csum>   (actual write)
            client ← @tm:<arg>  / @an:error
            client → @TS:00                  (release keypad)
            client ← @ts

        Skipping the lock/unlock wrapper is the bug v0.9.0 - v0.9.1
        shipped: the dongle ACKs the bare ``@TM:`` write with
        ``@tm:<arg>`` so the call looks successful, but the machine
        silently ignores the new value until a future power cycle.
        The APK ALWAYS wraps PMODE-priority commands; we now do the
        same.

        The checksum follows the J.O.E. APK's ``ByteOperations.d``:
        sum every ASCII byte of ``"<arg>,<value>"``, cast
        ``-1 - sum`` to a signed byte, format as two upper-case hex
        chars and append.

        When :attr:`profile` is set and carries a
        :class:`~jura_connect.profile.SettingDef` for ``p_argument``,
        ``value_hex`` is run through
        :meth:`~jura_connect.profile.SettingDef.normalise_value`
        first. That accepts an ITEM name (``"30min"``), a raw catalogue
        hex value (``"211E"``), or — for step sliders — a decimal
        integer in range; any other input raises :class:`ValueError`
        before the dongle ever sees it. This guards against writing
        e.g. ``auto_off = "30"`` (which would mean raw byte ``0x30 =
        48 dec`` rather than the ``30min`` ItemSlider entry ``"211E"``).
        When no profile is loaded, the value is passed through
        unchanged.

        When ``verify`` is true (default), reads the setting back
        AFTER the unlock and raises :class:`ValueError` if the
        stored value doesn't match — guards against a firmware that
        accepts the wrapped write but still silently drops it.
        Disable via ``verify=False`` if the read-back path is broken
        for a particular setting.
        """
        arg = p_argument.upper()
        value = value_hex.upper()
        if self.profile is not None:
            definition = self.profile.setting_by_arg(arg)
            if definition is not None:
                # Raises ValueError on invalid input. Also turns
                # ITEM-name input like "30min" into the wire-format
                # hex "211E" so library callers can pass either form.
                value = definition.validate_wire_hex(value_hex)
        checksum = _settings_checksum(f"{arg},{value}")
        cmd = f"@TM:{arg},{value}{checksum}"

        # Wrap in @TS:01 / @TS:00. The unlock runs in `finally` so a
        # mid-write exception can't leave the keypad locked.
        self.lock_screen()
        try:
            reply = self.request(cmd, match=r"^@(tm|an)", timeout=timeout)
        finally:
            try:
                self.unlock_screen()
            except Exception:  # noqa: BLE001
                # Best-effort unlock; failure here mustn't mask the
                # original write error.
                pass

        if reply.lower().startswith("@an:error"):
            return reply
        # `@tm:00` from a non-00 write means the dongle rejected the
        # request (this happens when the cleartext body is missing the
        # trailing CRLF that protocol.wrap now appends). Surface it as
        # a hard error so callers don't silently get a stale value.
        reply_arg = ""
        if reply.lower().startswith("@tm:"):
            reply_arg = reply[len("@tm:") :].split(",", 1)[0].strip().upper()
        if arg != "00" and reply_arg == "00":
            raise ValueError(
                f"setting write for arg={arg}: dongle replied "
                f"{reply!r} (rejection — likely missing CRLF in body, "
                f"see protocol.wrap)."
            )
        if verify:
            try:
                stored = self.read_setting(arg, timeout=timeout)
            except (TimeoutError, ValueError):
                # Read-back failed; surface the original reply rather
                # than masking it.
                return reply
            stored_u = stored.upper()
            # ItemSlider values for AutoOFF (P_Argument=13) use a
            # 1-byte type-tag prefix (`21` = follow with 1-byte value,
            # `22` = follow with 2-byte value). The dongle stores the
            # raw value bytes and on read returns either the stripped
            # form (`211E` written -> `1E` stored) or the full form
            # (`220168` -> `220168`) depending on the firmware code
            # path. Accept either: equality OR the stored form being a
            # trailing slice of the written value.
            if stored_u != value and not value.endswith(stored_u):
                raise ValueError(
                    f"setting write for arg={arg}: dongle ACK'd "
                    f"{reply!r} but read-back is {stored!r} (we sent "
                    f"{value!r})."
                )
        return reply

    def lock_screen(self) -> str:
        """Lock the machine's front panel (``@TS:01``)."""
        return self.request("@TS:01", match=r"^@ts")

    def unlock_screen(self) -> str:
        """Unlock the machine's front panel (``@TS:00``)."""
        return self.request("@TS:00", match=r"^@ts")

    # -- name-based settings API --------------------------------------
    def _require_setting(self, name: str) -> SettingDef:
        if self.profile is None:
            raise RuntimeError(
                "no MachineProfile loaded — pass profile=load_profile('EFxxxx') "
                "to JuraClient() to use the name-based settings API."
            )
        catalogue = self.profile.setting_by_name
        if name in catalogue:
            return catalogue[name]
        known = ", ".join(sorted(catalogue)) or "(none)"
        raise ValueError(
            f"setting {name!r} is not in the {self.profile.code} catalogue. "
            f"Known: {known}"
        )

    def list_settings(self) -> tuple[SettingDef, ...]:
        """Return every :class:`SettingDef` from the loaded profile.

        Useful for enumerating writable settings and their allowed
        ITEM values from a script or REPL. Raises :class:`RuntimeError`
        when no profile is loaded.
        """
        if self.profile is None:
            raise RuntimeError("no MachineProfile loaded on this client")
        return self.profile.settings

    def get_setting(self, name: str, *, timeout: float = 3.0) -> SettingValue:
        """Read a setting by snake_case name (``"auto_off"``,
        ``"hardness"``, ``"language"``, …).

        Returns a :class:`SettingValue` carrying both the raw wire-format
        hex and the resolved ITEM name (when the hex matches a
        catalogue entry, including AutoOFF's type-tag-stripped form).
        Requires :attr:`profile` to be set. Raises :class:`ValueError`
        if the setting name is unknown.
        """
        definition = self._require_setting(name)
        raw = self.read_setting(definition.p_argument, timeout=timeout)
        item = definition.item_from_hex(raw)
        return SettingValue(
            name=definition.name,
            raw=raw.upper(),
            item=item.name if item is not None else None,
            definition=definition,
        )

    def set_setting(
        self,
        name: str,
        value: str,
        *,
        timeout: float = 3.0,
        verify: bool = True,
    ) -> str:
        """Write a setting by snake_case name.

        ``value`` may be:

        * an ITEM name from the catalogue (``"30min"``, ``"english"``,
          ``"on"``)
        * the wire-format hex (``"211E"`` for ``auto_off=30min``)
        * for step sliders, the hex form of an in-range integer
          (``"0D"`` = 13 °dH for hardness)

        Anything else raises :class:`ValueError` before the request
        hits the wire. Requires :attr:`profile` to be loaded.
        """
        definition = self._require_setting(name)
        return self.write_setting(
            definition.p_argument, value, timeout=timeout, verify=verify
        )

    # -- batch settings read (@TM:00,FC) ---------------------------------
    def read_settings_bank(
        self, *, timeout: float = 3.0, checksum: bool = False
    ) -> dict[str, str]:
        """Read several settings in one round trip via the XML's
        settings bank (``<BANK Name="Setting" Command="@TM:00,FC"
        CommandArgument="02080913"/>``).

        Returns ``{P_Argument: value_hex}`` in the bank's declared order
        (``{"02": "10", "08": "00", "09": "02", "13": "211E"}`` on the
        S8 EB), i.e. the same values four separate
        :meth:`read_setting` calls would return.

        **APK-derived request, guessed reply layout, untested on
        hardware.** J.O.E. 4.6.10 parses ``CommandArgument`` out of the
        XML and then throws it away (``Bank``'s constructor drops it),
        and its WiFi settings path is ``WifiCommandReadPModeComposite``
        — one ``@TM:<arg>`` per setting. So nothing in the app tells us
        what the machine answers here. What we send is the XML's
        ``Command`` verbatim, like every other ``<BANK Command="…">``;
        what we expect back is modelled on the single-setting read:

            client → @TM:00,FC
            dongle → @tm:00,<v1><v2>…<checksum>
            dongle → @tm:00                  (rejection — no bank)

        with the values concatenated in ``CommandArgument`` order and
        self-delimited by the ItemSlider type tags documented in
        §5.7 (``21`` = one value byte follows, ``22`` = two, anything
        else = a bare one-byte value), and ``<checksum>`` the usual
        ``ByteOperations.d`` over ``"00,<values>"``.

        Pass ``checksum=True`` to append the ``ByteOperations.d``
        checksum to the *request* as well (``@TM:00,FCEA``) — the other
        plausible request form, since ``@TM:60,…`` and every settings
        write carry one while ``@TM:41/42,…`` reads do not. Which form
        (if either) a real machine accepts is unknown.

        Raises :class:`ValueError` when the machine rejects the command
        or the reply does not parse; :meth:`read_all_settings` catches
        that and falls back to per-setting reads.
        """
        if self.profile is None:
            raise RuntimeError(
                "no MachineProfile loaded — pass profile=load_profile('EFxxxx') "
                "to JuraClient() to use the batch settings read."
            )
        bank = self.profile.settings_bank
        if bank is None:
            raise ValueError(
                f"{self.profile.code}: the machine XML declares no "
                "<MACHINESETTINGS><BANK Name='Setting'> — there is no batch "
                "settings read on this machine family."
            )
        cmd = bank.command
        if checksum:
            body = cmd[4:] if cmd.upper().startswith("@TM:") else cmd
            cmd = f"{cmd}{_settings_checksum(body)}"
        reply = self.request(cmd, match=r"(?i)^@(tm|an)", timeout=timeout)
        return _parse_settings_bank_reply(reply, bank.command, bank.arguments)

    def read_all_settings(
        self, *, timeout: float = 3.0, batch: bool = True
    ) -> SettingsSnapshot:
        """Read every setting in the machine's catalogue.

        Uses the batch read (:meth:`read_settings_bank`) for the
        arguments the XML's settings bank covers and one
        :meth:`read_setting` per remaining catalogue entry. When the
        batch read is unavailable, rejected, or answers something we
        cannot parse — the expected case, since its reply layout is a
        guess — every setting is read individually instead and the
        failure is recorded in :attr:`SettingsSnapshot.batch_error`.
        The returned values are identical either way.

        Set ``batch=False`` to skip the batch attempt entirely.
        """
        if self.profile is None:
            raise RuntimeError(
                "no MachineProfile loaded — pass profile=load_profile('EFxxxx') "
                "to JuraClient() to read the settings catalogue."
            )
        profile = self.profile
        batch_values: dict[str, str] = {}
        batch_error: str | None = None
        if batch and profile.settings_bank is not None:
            try:
                batch_values = self.read_settings_bank(timeout=timeout)
            except (ValueError, TimeoutError) as exc:
                batch_error = str(exc)

        readings: list[SettingReading] = []
        covered: set[str] = set()
        for definition in profile.settings:
            arg = definition.p_argument.upper()
            covered.add(arg)
            if arg in batch_values:
                raw, source = batch_values[arg].upper(), "batch"
            else:
                raw, source = self.read_setting(arg, timeout=timeout).upper(), "single"
            item = definition.item_from_hex(raw)
            readings.append(
                SettingReading(
                    p_argument=arg,
                    name=definition.name,
                    raw=raw,
                    item=item.name if item is not None else None,
                    definition=definition,
                    source=source,
                )
            )
        # Bank arguments the catalogue does not declare still carry real
        # values (16 of the 89 profiles name settings their own
        # <MACHINESETTINGS> block omits); surface them unnamed rather
        # than dropping machine data on the floor.
        for arg, raw in batch_values.items():
            if arg in covered:
                continue
            readings.append(
                SettingReading(
                    p_argument=arg,
                    name=None,
                    raw=raw.upper(),
                    item=None,
                    definition=None,
                    source="batch",
                )
            )
        return SettingsSnapshot(
            readings=tuple(readings),
            batch_used=bool(batch_values),
            batch_error=batch_error,
        )

    # -- limit load (@TM:60) ---------------------------------------------
    def read_limit_load(
        self, product: str | int, *, timeout: float = 3.0
    ) -> ProductLimits:
        """Read the machine's *live* limits for one product (``@TM:60``).

        J.O.E.'s ``WifiCommandReadLimitLoad`` sends
        ``@TM:60,<product code><checksum>`` and bounds the product
        sliders with the answer instead of with the static XML ranges —
        the machine narrows them according to its current state (filter,
        milk system, cup size, …).

        Returns a :class:`ProductLimits` whose ranges are already scaled
        into XML units (ml for water/bypass, seconds for the milk
        parameters), so they can be compared directly against the values
        :meth:`brew` accepts.

        Wire format and decode are APK-derived (``LimitLoadParser``) but
        **untested on hardware**. Raises :class:`ValueError` when the
        machine answers the ``C1`` "product programming not supported"
        token or the reply fails its checksum / product-code check.
        """
        definition = self.resolve_product(product)
        payload = f"60,{definition.code:02X}"
        cmd = f"@TM:{payload}{_settings_checksum(payload)}"
        reply = self.request(cmd, match=r"(?i)^@(tm|an)", timeout=timeout)
        return _parse_limit_load(reply, definition)

    # -- brewing ---------------------------------------------------------
    def resolve_product(
        self, product: str | int, *, substring: bool = False
    ) -> ProductDef:
        """Resolve a product by code, snake_case name, or 2-hex code.

        Accepts an int product code (``0x0D``), a 2-char hex code
        (``"0D"``), or a snake_case name from the profile
        (``"espresso"``). Resolution order for a string:

        1. an exact 2-hex product code (``"0D"``) — checked *before*
           names so a code is never mistaken for a name prefix;
        2. an exact snake_case name;
        3. a name *prefix* (``"hotwater"`` → ``hotwater_portion_normal``)
           when unambiguous.

        Set ``substring=True`` to also match anywhere in the name
        (opt-in only — the default prefix match keeps ``"esp"`` from
        silently resolving to a milk drink that merely contains it).
        Requires :attr:`profile`.
        """
        if self.profile is None:
            raise RuntimeError(
                "no MachineProfile loaded — pass profile=load_profile('EFxxxx') "
                "to JuraClient() to brew by product name."
            )
        catalogue = self.profile.product_by_code
        if isinstance(product, int):
            if product in catalogue:
                return catalogue[product]
            raise ValueError(
                f"product code 0x{product:02X} is not in the "
                f"{self.profile.code} catalogue."
            )
        text = product.strip()
        # 2-char hex product code first ("0D") — before any name match.
        if re.fullmatch(r"[0-9A-Fa-f]{2}", text):
            code = int(text, 16)
            if code in catalogue:
                return catalogue[code]
        target = text.lower()
        by_name = {p.name: p for p in self.profile.products}
        if target in by_name:
            return by_name[target]
        # Name prefix match (or substring when explicitly opted in).
        if substring:
            matches = [p for p in self.profile.products if target in p.name]
        else:
            matches = [p for p in self.profile.products if p.name.startswith(target)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            names = ", ".join(p.name for p in matches)
            raise ValueError(
                f"product {product!r} is ambiguous on {self.profile.code}; "
                f"matches {names}"
            )
        known = _capped_join(sorted(by_name))
        raise ValueError(
            f"product {product!r} not known on profile {self.profile.code}. "
            f"Known: {known}"
        )

    def brew(
        self,
        product: str | int,
        *,
        ml: int | None = None,
        strength: int | None = None,
        temperature: int | str | None = None,
        milk: int | None = None,
        milk_foam: int | None = None,
        milk_break: int | None = None,
        bypass: int | None = None,
        preselections: Sequence[str] = (),
        preselect_mask: int | None = None,
        substring: bool = False,
        retry: bool = False,
        timeout: float = 6.0,
        follow: bool = False,
        follow_timeout: float = 120.0,
        on_progress: Callable[[ProductProgress], None] | None = None,
    ) -> str:
        """Start brewing a product (``@TP:<recipe blob>``).

        **Destructive**: the machine immediately heats up, grinds, and
        dispenses at the spout. Make sure a suitable cup is in place;
        there is no remote abort.

        ``product`` is resolved via :meth:`resolve_product` (pass
        ``substring=True`` to widen name matching). Recipe parameters
        use XML units — ``ml`` for water, brew ``strength`` level,
        ``temperature`` as ITEM name (``"low"`` / ``"normal"`` /
        ``"high"``) or value, ``milk_foam`` / ``milk_break`` in seconds,
        ``bypass`` in ml. Anything left ``None`` falls back to the XML
        default for this product. Values are validated against the
        machine XML before going on the wire.

        **Not live-verified — may misbrew, verify on your hardware:**
        ``bypass``, ``milk_foam`` and ``milk_break`` are encoded from
        the XML (ml ÷5 ticks, seconds as-is) but not confirmed on a
        physical machine. Water and temperature are live-verified.

        The wire format is a 16-byte blob (verified live on an E8 (EB)
        / EF538): byte 0 is the product code; each XML parameter lands
        on byte ``F-1``. A bare product code — what the Bluetooth-era
        docs suggest — is ACK'd with ``@tp`` but silently ignored by
        TT237W-family WiFi firmware, and an unset water byte means 255
        ticks ≈ 1.3 l, so always send the full validated blob.

        ``preselections`` names the extra-shot / double / powder /
        cold-brew / light-brew / sweet-foam toggles to apply, validated
        against what the product's ``<PRESELECTION>`` element declares
        and against the machine's legal ``<COMBINATION>`` rows. On an
        old-T-protocol machine (the S8 EB among them) a ``double``
        **selects a different product** — the recipe is then built from
        that double product, whose parameters may differ. See
        :meth:`~jura_connect.profile.MachineProfile.plan_preselections`
        for what each machine generation can express;
        ``preselect_mask`` forces the mask byte of an ``IntakeF18``
        machine verbatim. **Preselection encoding is APK-derived and has
        never been seen on a wire — it may misbrew** (PROTOCOL.md
        §5.13).

        ``retry=True`` sends the blob a second time if the first reply
        is not an ``@tp`` accept: a machine in ``energy_safe`` wakes on
        the first ``@TP:`` but may ignore it (see PROTOCOL.md §5.9).

        Returns the dongle's reply (``"@tp"`` on accept). The machine
        then emits ``@TB`` (brew start) and ``@TV:`` progress frames,
        observable via :meth:`iter_frames` / :meth:`iter_progress`.

        ``follow=True`` (off by default, so the call stays a single
        round-trip unless asked) blocks after an accepted blob and
        collects the progress stream via :meth:`follow_progress` until
        the ``ENJOY`` frame or ``follow_timeout`` seconds. The frames
        land in :attr:`last_progress`; ``on_progress`` sees each one as
        it arrives. A rejected blob (``@tp:00``) is never followed —
        the machine sends nothing to follow.
        """
        definition = self.resolve_product(product, substring=substring)
        prof = self.profile
        plan: profile.PreselectionPlan | None = None
        if (preselections or preselect_mask is not None) and prof is not None:
            # resolve_product already refused a missing profile.
            plan = prof.plan_preselections(
                definition, preselections, mask=preselect_mask
            )
            definition = plan.product
        overrides: dict[str, int | str] = {}
        for kind, value in (
            (profile.KIND_WATER_AMOUNT, ml),
            (profile.KIND_COFFEE_STRENGTH, strength),
            (profile.KIND_TEMPERATURE, temperature),
            (profile.KIND_MILK_AMOUNT, milk),
            (profile.KIND_MILK_FOAM_AMOUNT, milk_foam),
            (profile.KIND_MILK_BREAK, milk_break),
            (profile.KIND_BYPASS, bypass),
        ):
            if value is not None:
                overrides[kind] = value
        recipe = (
            definition.build_recipe_hex(overrides)
            if plan is None
            else plan.build_recipe_hex(overrides)
        )
        reply = self.request(f"@TP:{recipe}", timeout=timeout)
        if retry and not _is_brew_accept(reply):
            # Energy-safe wake-up: the first @TP: only woke the machine;
            # resend now that it is awake.
            reply = self.request(f"@TP:{recipe}", timeout=timeout)
        self.last_progress = ()
        if follow and _is_brew_accept(reply):
            self.last_progress = tuple(
                self.follow_progress(timeout=follow_timeout, on_progress=on_progress)
            )
        return reply

    @staticmethod
    def random_conn_id() -> str:
        return f"jura-connect-{uuid.uuid4().hex[:8]}"

    # -- coffee timer ----------------------------------------------------
    #
    # Two commands, both lifted from the J.O.E. APK
    # (``WifiCommandStartCoffeeTimer`` / ``WifiSendTimeForCoffeeTimer``,
    # cross-checked against ``CoffeeMachineAdapterBle2``'s
    # ``addCoffeeTimerCommand`` / ``sendTimeForCoffeeTimer``, which kept
    # their method names through obfuscation). **APK-derived, untested
    # on hardware** — see docs/PROTOCOL.md §5.12.

    def send_coffee_timer_time(
        self,
        when: str | datetime.time | datetime.datetime,
        *,
        timeout: float = 3.0,
    ) -> str:
        """Tell the machine the wall-clock time of a coffee timer (``@TV:84``).

        ``when`` is a ``"HH:MM"`` string, a :class:`datetime.time`, or a
        :class:`datetime.datetime` (only the time-of-day is used). It is
        normalised to ``"%02d:%02d"`` and hex-encoded character by
        character — the same ``ExtensionsKt.c`` encoding the handshake
        uses for the connection id — so ``07:30`` goes out as
        ``@TV:84,30373A3330``.

        J.O.E. sends this *after* :meth:`schedule_brew`, carrying the
        wall-clock time the drink should be ready at (the countdown
        itself is the ``@TM:3C`` delay field). Whether the machine
        treats it as a clock sync or purely as a display string is
        **not established** — see docs/PROTOCOL.md §5.12.

        Returns the dongle's reply; ``"@tv:84"`` is the acknowledgement
        J.O.E.'s matcher accepts.
        """
        payload = encode_coffee_timer_clock(when)
        return self.request(f"@TV:84,{payload}", match=r"^@(tv:84|an)", timeout=timeout)

    def schedule_brew(
        self,
        product: str | int | None = None,
        *,
        recipe: str | None = None,
        at: str | datetime.time | datetime.datetime | None = None,
        delay: int | None = None,
        now: datetime.datetime | None = None,
        ml: int | None = None,
        strength: int | None = None,
        temperature: int | str | None = None,
        milk: int | None = None,
        milk_foam: int | None = None,
        milk_break: int | None = None,
        bypass: int | None = None,
        overrides: dict[str, int | str] | None = None,
        substring: bool = False,
        sync_time: bool = True,
        timeout: float = 6.0,
    ) -> CoffeeTimerSchedule:
        """Schedule a brew for later (``@TM:3C`` + ``@TV:84``).

        **Destructive**: the machine pours the drink at the scheduled
        moment with nobody in front of it. Leave a cup under the spout,
        or come back to coffee on the drip tray.

        Pass either ``product`` (resolved through :meth:`resolve_product`,
        with the same recipe overrides :meth:`brew` accepts) or a
        verbatim 32-hex ``recipe`` blob as an escape hatch. The blob is
        built by :meth:`~jura_connect.profile.ProductDef.build_recipe_hex`
        — byte for byte the same payload ``@TP:`` takes — then
        right-padded with ``"00"`` to 40 hex chars and followed by a
        16-bit big-endian delay in seconds and the usual ``@TM:``
        checksum.

        Timing: pass either ``at`` (a ``"HH:MM"`` wall-clock target,
        rolled to tomorrow when it has already passed today) or
        ``delay`` (seconds from now). Either way the value is floored
        to a whole minute — J.O.E. only ever sends multiples of 60 —
        and must land in the
        :data:`COFFEE_TIMER_MIN_DELAY_SECONDS` …
        :data:`COFFEE_TIMER_MAX_DELAY_SECONDS` window the app enforces
        (1 minute … 16 hours). ``now`` overrides the reference clock,
        which makes the derivation testable.

        Recipe values may also be passed as an ``overrides`` mapping of
        ``KIND_*`` to value, the form
        :meth:`~jura_connect.profile.ProductDef.build_recipe_hex` takes;
        the named keywords win when both name the same parameter.

        Products the machine XML marks ``Coffeetimer="false"`` are
        refused client-side before anything reaches the wire.

        With ``sync_time`` (the default) the wall-clock frame follows an
        accepted schedule, mirroring J.O.E.'s order (``@TM:3C`` first,
        then ``@TV:84``). It is skipped when the machine refused the
        schedule, so a firmware without a coffee timer doesn't leave the
        caller waiting on a reply that never comes.
        """
        if (product is None) == (recipe is None):
            raise ValueError(
                "schedule_brew: pass exactly one of product=<name/code> or "
                "recipe=<32-hex blob>"
            )
        reference = (now or datetime.datetime.now()).replace(second=0, microsecond=0)
        ready_at, delay_seconds = _coffee_timer_timing(at, delay, reference)

        name: str | None = None
        code: int | None = None
        if product is None:
            # ``recipe`` is the only other option the check above allows;
            # an empty string is rejected by the validator.
            recipe_hex = _validated_recipe_hex(recipe or "")
        else:
            definition = self.resolve_product(product, substring=substring)
            if not definition.coffee_timer:
                raise ValueError(
                    f"{definition.name}: this machine's profile "
                    f"({self.profile.code if self.profile else '?'}) marks the "
                    f"product as ineligible for the coffee timer "
                    f'(XML Coffeetimer="false").'
                )
            recipe_overrides: dict[str, int | str] = dict(overrides or {})
            for kind, value in (
                (profile.KIND_WATER_AMOUNT, ml),
                (profile.KIND_COFFEE_STRENGTH, strength),
                (profile.KIND_TEMPERATURE, temperature),
                (profile.KIND_MILK_AMOUNT, milk),
                (profile.KIND_MILK_FOAM_AMOUNT, milk_foam),
                (profile.KIND_MILK_BREAK, milk_break),
                (profile.KIND_BYPASS, bypass),
            ):
                if value is not None:
                    recipe_overrides[kind] = value
            recipe_hex = definition.build_recipe_hex(recipe_overrides)
            name, code = definition.name, definition.code

        command = build_coffee_timer_command(recipe_hex, delay_seconds)
        reply = self.request(command, match=r"(?i)^@(tm|an)", timeout=timeout)
        accepted = _is_coffee_timer_accept(reply)

        time_command: str | None = None
        time_reply: str | None = None
        if sync_time and accepted:
            time_command = f"@TV:84,{encode_coffee_timer_clock(ready_at)}"
            time_reply = self.send_coffee_timer_time(ready_at, timeout=timeout)

        body = command[len("@TM:3C,") : -2]
        return CoffeeTimerSchedule(
            product=name,
            product_code=code,
            recipe_hex=recipe_hex,
            blob_hex=body[:COFFEE_TIMER_BLOB_HEX_LEN],
            delay_seconds=delay_seconds,
            ready_at=ready_at,
            command=command,
            reply=reply.strip(),
            time_command=time_command,
            time_reply=time_reply.strip() if time_reply is not None else None,
            accepted=accepted,
        )


@dataclasses.dataclass(slots=True, frozen=True)
class SettingValue:
    """Result of :meth:`JuraClient.get_setting`.

    ``raw`` is the wire-format hex (``"1E"`` for AutoOFF=30min on the
    dongle's read path), ``item`` is the catalogue ITEM name when the
    value resolves (``"30min"``) and ``None`` when the hex isn't in
    the catalogue. ``definition`` carries the full :class:`SettingDef`
    so callers can inspect allowed values, kind, range, etc.
    """

    name: str
    raw: str
    item: str | None
    definition: SettingDef

    def __str__(self) -> str:  # pragma: no cover - human formatting
        if self.item is not None:
            return f"{self.name} = {self.item} (0x{self.raw})"
        return f"{self.name} = 0x{self.raw}"


# --------------------------------------------------------------------- #
# Structured read results
# --------------------------------------------------------------------- #


def _hex_body(reply: str, expected_prefix: str) -> bytes:
    body = reply.strip()
    if not body.lower().startswith(expected_prefix.lower()):
        raise ValueError(f"{expected_prefix!r} reply expected, got {reply!r}")
    hex_part = body[len(expected_prefix) :]
    # Pad with trailing 0 if odd length to ensure valid hex pairs
    if len(hex_part) % 2 != 0:
        hex_part += "0"
    return bytes.fromhex(hex_part)


def _settings_checksum(payload: str) -> str:
    """Compute the @TM:<arg>,<val> trailing checksum.

    Ported from ``ByteOperations.d`` in the J.O.E. APK::

        sum = sum(c for c in payload)
        return f"{(-1 - sum) & 0xFF:02X}"

    where ``c`` is the codepoint of each character. Empirically the
    dongle requires every settings write to carry this trailing byte;
    omitting it gets you ``@an:error``.
    """
    total = sum(ord(c) for c in payload)
    return f"{(-1 - total) & 0xFF:02X}"


#: Field order of the ``@TG:43`` bank on the EF536 / EF1091 baseline.
#: Used when no :class:`MachineProfile` is available; the profile's own
#: ``maintenance_counter_fields`` wins whenever there is one, because
#: the order is per-machine (docs/PROTOCOL.md §5.3).
DEFAULT_MAINTENANCE_COUNTER_FIELDS: tuple[str, ...] = (
    "cleaning",
    "filter_change",
    "descale",
    "cappu_rinse",
    "coffee_rinse",
    "cappu_clean",
)

#: Same for the ``@TG:C0`` percent bank. Uniform across every bundled
#: profile except EF567_C, which omits ``filter_change``.
DEFAULT_MAINTENANCE_PERCENT_FIELDS: tuple[str, ...] = (
    "cleaning",
    "filter_change",
    "descale",
)

#: Human labels for the pretty-printed ``format()`` output where they
#: differ from the field name.
_MAINTENANCE_LABELS = {"filter_change": "filter"}


def _maintenance_fields(
    profile: MachineProfile | None, attribute: str, fallback: tuple[str, ...]
) -> tuple[str, ...]:
    """Field order for one maintenance bank.

    Prefers the machine XML's declaration and falls back to the
    hard-coded baseline when no profile is loaded (or when a profile
    somehow declares no such bank).
    """
    declared = getattr(profile, attribute, ()) if profile is not None else ()
    return tuple(declared) or fallback


def _decode_maintenance(
    values: list[int], fields: tuple[str, ...], bank: str, reply: str
) -> dict[str, int]:
    """Zip decoded wire values onto the bank's declared field names.

    A machine that returns fewer values than its XML declares is
    reported for what it sent rather than padded with garbage — the
    remaining names simply stay absent. This is also the shape a
    four-counter machine takes when it is read without a profile.
    """
    if not values:
        raise ValueError(f"{bank} payload too short (0 values): {reply!r}")
    if len(values) < len(fields):
        log.warning(
            "%s returned %d value(s) but %d field(s) are declared; "
            "decoding the ones that arrived (pass a MachineProfile if the "
            "machine's field order differs from the baseline)",
            bank,
            len(values),
            len(fields),
        )
    return dict(zip(fields, values, strict=False))


@dataclasses.dataclass(slots=True, frozen=True)
class MaintenanceCounters:
    """Decoded ``@TG:43`` payload — each counter a big-endian u16.

    Which counters the payload carries, and in which order, is declared
    per machine by the XML's ``<BANK Command="@TG:43">`` ``<TEXTITEM
    Type=…>`` children; :meth:`parse` takes them from a
    :class:`~jura_connect.profile.MachineProfile` when one is available
    and falls back to :data:`DEFAULT_MAINTENANCE_COUNTER_FIELDS`
    otherwise. ``counters`` holds the decoded name/value pairs in wire
    order; the named properties return ``None`` for counters this
    machine does not report.
    """

    counters: tuple[tuple[str, int], ...]
    raw: bytes

    @classmethod
    def parse(
        cls, reply: str, profile: MachineProfile | None = None
    ) -> MaintenanceCounters:
        data = _hex_body(reply, "@tg:43")
        fields = _maintenance_fields(
            profile, "maintenance_counter_fields", DEFAULT_MAINTENANCE_COUNTER_FIELDS
        )
        values = [
            int.from_bytes(data[i : i + 2], "big")
            for i in range(0, len(data) - len(data) % 2, 2)
        ]
        decoded = _decode_maintenance(values, fields, "@tg:43", reply)
        return cls(counters=tuple(decoded.items()), raw=data)

    def get(self, name: str) -> int | None:
        """Counter by field name, or ``None`` when not reported."""
        for field, value in self.counters:
            if field == name:
                return value
        return None

    @property
    def cleaning(self) -> int | None:
        return self.get("cleaning")

    @property
    def filter_change(self) -> int | None:
        return self.get("filter_change")

    @property
    def descale(self) -> int | None:
        return self.get("descale")

    @property
    def cappu_rinse(self) -> int | None:
        return self.get("cappu_rinse")

    @property
    def coffee_rinse(self) -> int | None:
        return self.get("coffee_rinse")

    @property
    def cappu_clean(self) -> int | None:
        return self.get("cappu_clean")

    def format(self) -> str:
        return " ".join(
            f"{_MAINTENANCE_LABELS.get(name, name)}={value}"
            for name, value in self.counters
        )

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = dict(self.counters)
        out["raw_hex"] = self.raw.hex().upper()
        return out


@dataclasses.dataclass(slots=True, frozen=True)
class MaintenancePercent:
    """Decoded ``@TG:C0`` payload (one byte per maintenance type, 0..100, or 0xFF if absent).

    Like :class:`MaintenanceCounters` the fields are XML-declared per
    machine (``<BANK Command="@TG:C0">``); every bundled profile but
    EF567_C, which has no filter, uses the baseline order.
    """

    percent: tuple[tuple[str, int], ...]
    raw: bytes

    @classmethod
    def parse(
        cls, reply: str, profile: MachineProfile | None = None
    ) -> MaintenancePercent:
        data = _hex_body(reply, "@tg:C0")
        fields = _maintenance_fields(
            profile, "maintenance_percent_fields", DEFAULT_MAINTENANCE_PERCENT_FIELDS
        )
        decoded = _decode_maintenance(list(data), fields, "@tg:C0", reply)
        return cls(percent=tuple(decoded.items()), raw=data)

    def get(self, name: str) -> int | None:
        """Percentage by field name, or ``None`` when not reported."""
        for field, value in self.percent:
            if field == name:
                return value
        return None

    @property
    def cleaning(self) -> int | None:
        return self.get("cleaning")

    @property
    def filter_change(self) -> int | None:
        return self.get("filter_change")

    @property
    def descale(self) -> int | None:
        return self.get("descale")

    def format(self) -> str:
        return " ".join(
            f"{_MAINTENANCE_LABELS.get(name, name)}={value}"
            for name, value in self.percent
        )

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = dict(self.percent)
        out["raw_hex"] = self.raw.hex().upper()
        return out


# Bit-to-alert mapping for the S8 / EF536 (see assets/documents/xml/EF536/1.0.xml).
# Bit index is global: byte_index*8 + bit_within_byte.
#
# Each entry is (name, severity). The XML carries a Type attribute that
# distinguishes blocking errors from informational / in-progress states:
#
#   * "error" -> XML Type="block": the machine is in a state that stops it
#     from operating until the user clears the condition (e.g. fill water,
#     insert tray).
#   * "info"  -> XML Type="info" or missing Type: an informational bit
#     that may or may not block specific products (e.g. "no beans" with
#     Blocked="C" blocks coffee but isn't an error from the user's
#     perspective — the bin just needs refilling).
#   * "process" -> XML Type="ip": an in-process / reminder bit, typically
#     a "schedule maintenance" prompt (descale / cleaning / filter / cappu
#     rinse) that the user is supposed to action eventually.
_STATUS_BITS: dict[int, tuple[str, str]] = {
    0: ("insert_tray", "error"),
    1: ("fill_water", "error"),
    2: ("empty_grounds", "error"),
    3: ("empty_tray", "error"),
    4: ("insert_coffee_bin", "error"),
    5: ("outlet_missing", "error"),
    6: ("rear_cover_missing", "error"),
    7: ("milk_alert", "info"),
    8: ("fill_system", "error"),
    9: ("system_filling", "info"),
    10: ("no_beans", "info"),
    11: ("welcome", "info"),
    12: ("heating_up", "info"),
    13: ("coffee_ready", "info"),
    14: ("no_milk_sensor", "info"),
    15: ("milk_sensor_error", "info"),
    16: ("milk_sensor_no_signal", "info"),
    17: ("please_wait", "error"),
    18: ("coffee_rinsing", "info"),
    19: ("ventilation_closed", "info"),
    20: ("close_powder_cover", "error"),
    21: ("fill_powder", "error"),
    22: ("system_emptying", "info"),
    23: ("not_enough_powder", "info"),
    24: ("remove_water_tank", "info"),
    25: ("press_rinse", "info"),
    26: ("goodbye", "info"),
    27: ("periphery_alert", "info"),
    28: ("powder_product", "info"),
    29: ("program_mode_status", "error"),
    30: ("error_status", "error"),
    31: ("enjoy_product", "info"),
    32: ("filter_alert", "process"),
    33: ("descale_alert", "process"),
    34: ("cleaning_alert", "process"),
    35: ("cappu_rinse_alert", "process"),
    36: ("energy_safe", "info"),
    37: ("active_rf_filter", "info"),
    38: ("remote_screen", "info"),
}


@dataclasses.dataclass(slots=True, frozen=True)
class MachineStatus:
    """Decoded ``@TF:<hex>`` status frame.

    The status frame is a bitfield. The codebook above tags every known
    bit with a severity (``error`` / ``info`` / ``process``) lifted from
    the machine XML's ALERT.Type attribute. ``errors`` are the bits the
    user actually needs to action right now; ``info`` covers normal
    state transitions and low-supply reminders (e.g. "no beans" when the
    bean container is low — informational, not an error); ``process``
    holds the periodic maintenance prompts (descale / cleaning / filter /
    cappu rinse) which the machine surfaces *before* they block brewing.

    ``active_alerts`` is kept as the union of all active named bits for
    backwards compatibility — it's what older callers and the legacy
    ``status`` CLI output have always returned. Prefer ``errors`` to
    decide whether the machine is genuinely stuck.

    With a profile the frame also answers "can I brew right now?": every
    active alert contributes the product kinds it blocks
    (:attr:`blocked_kinds`, and :attr:`blocked_products` for the
    machine's own product names), and every active alert that declares a
    maintenance ``Process`` contributes the process that clears it
    (:attr:`alert_processes`). Those three fields stay empty without a
    profile — the hard-coded fallback codebook carries no such metadata.
    See docs/PROTOCOL.md §5.11.
    """

    raw: bytes
    active_alerts: tuple[str, ...]
    errors: tuple[str, ...]
    info: tuple[str, ...]
    process: tuple[str, ...]
    # Product kinds ("C", "M", "CM", "T", "TM", "P") no product of which
    # can be started while these alerts are active.
    blocked_kinds: tuple[str, ...] = ()
    # Names of the active alerts that block anything at all.
    blocking_alerts: tuple[str, ...] = ()
    # (alert name, maintenance process that clears it) for every active
    # alert whose XML declares a Process — e.g.
    # ("cleaning_alert", "cleaning"). Feed the process name to
    # ``jura_connect.process.resolve_process``.
    alert_processes: tuple[tuple[str, str], ...] = ()
    # Profile product names currently blocked, derived from the profile's
    # <PRODUCT P_Kind=…> against ``blocked_kinds``.
    blocked_products: tuple[str, ...] = ()

    def can_brew_kind(self, kind: str) -> bool:
        """Whether a product of kind ``kind`` can be started right now.

        ``kind`` is a P_Kind token ("C", "M", "CM", "T", "TM", "P").
        Always True without a profile — the fallback codebook does not
        know what any alert blocks, and claiming otherwise would be a
        guess.
        """
        return kind.strip().upper() not in self.blocked_kinds

    def can_brew(self, product: str) -> bool:
        """Whether the named profile product can be started right now."""
        return product.strip().lower() not in self.blocked_products

    @classmethod
    def parse(cls, reply: str, profile: MachineProfile | None = None) -> MachineStatus:
        """Parse an ``@TF:`` reply.

        ``profile`` is an optional :class:`jura_connect.profile.MachineProfile`;
        when supplied, its per-machine bit-to-name + severity map is
        used in preference to the hard-coded fallback. Pass it to make
        the parser EF1091-aware (or any other variant) instead of the
        EF536 baseline.
        """
        data = _hex_body(reply, "@TF:")
        active: list[str] = []
        errors: list[str] = []
        info: list[str] = []
        process: list[str] = []
        blocked_kinds: list[str] = []
        blocking: list[str] = []
        alert_processes: list[tuple[str, str]] = []
        bits: dict[int, tuple[str, str]]
        alerts = profile.alert_by_bit if profile is not None else {}
        if alerts:
            bits = {bit: (a.name, a.severity) for bit, a in alerts.items()}
        else:
            bits = _STATUS_BITS
        for bit_index, (name, severity) in bits.items():
            # MSB-first within each byte, per the J.O.E. APK's
            # `Status.a()`: `(1 << (7 - (i%8))) & bArr[i/8]`.
            byte_i, bit_in_byte = divmod(bit_index, 8)
            if byte_i >= len(data) or not (data[byte_i] >> (7 - bit_in_byte)) & 1:
                continue
            active.append(name)
            if severity == "error":
                errors.append(name)
            elif severity == "process":
                process.append(name)
            else:
                info.append(name)
            definition = alerts.get(bit_index)
            if definition is None:
                continue
            if definition.blocked_kinds:
                blocking.append(name)
                blocked_kinds.extend(
                    k for k in definition.blocked_kinds if k not in blocked_kinds
                )
            if definition.process is not None:
                alert_processes.append((name, definition.process))
        blocked_products: list[str] = []
        if profile is not None and blocked_kinds:
            blocked_products = [
                p.name
                for p in profile.products
                if p.kind and p.kind in blocked_kinds and p.name not in blocked_products
            ]
        return cls(
            raw=data,
            active_alerts=tuple(active),
            errors=tuple(errors),
            info=tuple(info),
            process=tuple(process),
            blocked_kinds=tuple(blocked_kinds),
            blocking_alerts=tuple(blocking),
            alert_processes=tuple(alert_processes),
            blocked_products=tuple(blocked_products),
        )

    def format(self) -> str:
        def _fmt(group: tuple[str, ...]) -> str:
            return ", ".join(group) if group else "(none)"

        lines = [
            f"bits={self.raw.hex().upper()}",
            f"  errors  : {_fmt(self.errors)}",
            f"  info    : {_fmt(self.info)}",
            f"  process : {_fmt(self.process)}",
        ]
        if self.blocked_kinds:
            lines.append(f"  blocked : {_fmt(self.blocked_kinds)}")
        if self.alert_processes:
            fixes = ", ".join(
                f"{alert} -> {proc}" for alert, proc in self.alert_processes
            )
            lines.append(f"  clear by: {fixes}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "bits_hex": self.raw.hex().upper(),
            "active_alerts": list(self.active_alerts),
            "errors": list(self.errors),
            "info": list(self.info),
            "process": list(self.process),
            "blocked_kinds": list(self.blocked_kinds),
            "blocking_alerts": list(self.blocking_alerts),
            "alert_processes": dict(self.alert_processes),
            "blocked_products": list(self.blocked_products),
        }


@dataclasses.dataclass(slots=True, frozen=True)
class MachineInfo:
    """Aggregated read-only snapshot returned by :meth:`JuraClient.read_machine_info`."""

    conn_id: str
    auth_hash: str
    handshake_state: str
    status: MachineStatus
    maintenance_counters: MaintenanceCounters
    maintenance_percent: MaintenancePercent

    def format(self) -> str:
        def _fmt(group: tuple[str, ...]) -> str:
            return ", ".join(group) if group else "(none)"

        hash_preview = (self.auth_hash[:16] + "...") if self.auth_hash else "(none)"
        return (
            "== machine info ==\n"
            f"  conn-id        : {self.conn_id}\n"
            f"  handshake state: {self.handshake_state}\n"
            f"  auth-hash      : {hash_preview}\n"
            f"  status bits    : {self.status.raw.hex().upper()}\n"
            f"  errors         : {_fmt(self.status.errors)}\n"
            f"  info flags     : {_fmt(self.status.info)}\n"
            f"  process flags  : {_fmt(self.status.process)}\n"
            f"  maintenance    : {self.maintenance_counters.format()}\n"
            f"  maintenance %  : {self.maintenance_percent.format()}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "conn_id": self.conn_id,
            "auth_hash": self.auth_hash,
            "handshake_state": self.handshake_state,
            "status": self.status.to_dict(),
            "maintenance_counters": self.maintenance_counters.to_dict(),
            "maintenance_percent": self.maintenance_percent.to_dict(),
        }


# Product code -> human-readable name. Derived from the per-machine
# XML maps under apk/assets/documents/xml/ -- codes are stable across
# machine variants, so a single table covers every TT237W family
# firmware (S8, ENA8, Z8 etc.). 0xFFFF in the wire response means the
# code is not configured on this machine.
PRODUCT_NAMES: dict[int, str] = {
    0x01: "ristretto",
    0x02: "espresso",
    0x03: "coffee",
    0x04: "cappuccino",
    0x05: "milk_coffee",
    0x06: "espresso_macchiato",
    0x07: "latte_macchiato",
    0x08: "milk_foam",
    0x0A: "milk_portion",
    0x0D: "hotwater_portion",
    0x0F: "powder_product",
    0x11: "two_ristretti",
    0x12: "two_espressi",
    0x13: "two_coffees",
    0x28: "americano",
    0x29: "lungo",
    0x2D: "hotwater_green_tea",
    0x2E: "flat_white",
    0x30: "espresso_doppio",
}

#: Machine types whose ``@TR:32`` table counts a product somewhere other
#: than at its own product code, keyed by EF code: product code -> slot.
#:
#: This mirrors the only per-machine quirk J.O.E. carries. Its
#: ``CoffeeMachineGenerator`` builds the remap as
#: ``str.equals("EF545") ? {"31": "12", "36": "13"} : emptyMap`` and
#: ``ProductCounterStatisticsParser`` reads each catalogue product from
#: ``remap.getOrDefault(code, code)``. Every other machine — and every
#: other product on the Z10 — is counted at its own code. See
#: docs/PROTOCOL.md §5.5.
COUNTER_SLOT_OVERRIDES: dict[str, dict[int, int]] = {
    # Z10 (EF545): the two plain doubles are counted one nibble above
    # their singles. Observed on a real Z10 (NAA, article 15361): slot
    # 0x13 held 141 brews and matched the machine's own J.O.E. CSV
    # export ("2 x Coffee,141") while code 0x36 read 0xFFFF.
    "EF545": {0x31: 0x12, 0x36: 0x13},
}


# Wire-level sentinel for "this product code is not configured on the
# current machine" inside an @TR:32 page.
PRODUCT_COUNT_UNUSED = 0xFFFF

#: Bank command carrying the high byte of each product counter. A
#: machine declares it in its XML (:attr:`MachineProfile.counter_banks`);
#: without it a per-product count wraps at 65535.
OVERFLOW_COUNTER_BANK = "@TR:33"

#: The lifetime product counter and the other banks a machine's XML may
#: declare next to it. Names mirror the ``<BANK Name=…>`` attributes.
PRODUCT_COUNTER_BANK = "@TR:32"
BARISTA_COUNTER_BANK = "@TR:34"
SPECIAL_COUNTER_BANK = "@TR:52"
#: Counters since the last ``@TF:05`` reset, declared under
#: ``<DAILYCOUNTER>``. J.O.E. never reads these — the XML comments them
#: "Not available in JOE" — so they are XML-derived and untested against
#: hardware. See docs/PROTOCOL.md §5.5.
DAILY_PRODUCT_COUNTER_BANK = "@TR:42"
DAILY_BARISTA_COUNTER_BANK = "@TR:44"

#: Command that zeroes every ``<DAILYCOUNTER>`` bank. All 37 profiles
#: declaring a daily section spell it ``@TF:05``; it is irreversible and
#: therefore gated as a destructive command.
DAILY_COUNTER_RESET = "@TF:05"

# Overflow bytes that carry no high word. J.O.E. skips both: 0x00 is
# "no overflow yet", 0xFF the same not-configured sentinel @TR:32 uses.
OVERFLOW_COUNT_UNUSED = frozenset({0x00, 0xFF})


@dataclasses.dataclass(slots=True, frozen=True)
class CounterBankSpec:
    """How one ``@TR:<bank>`` counter bank is read off the wire.

    ``pages`` and ``bytes_per_value`` are per bank, not per family:
    J.O.E.'s WiFi composite asks for 16 pages of the product counter but
    only 4 of the special counter, and every overflow bank packs one
    byte per slot where its base bank packs two. See docs/PROTOCOL.md
    §5.5 for the provenance of each row.
    """

    command: str
    name: str  # snake_case identifier, e.g. "special_counter"
    label: str  # human-readable label for format()
    pages: int
    bytes_per_value: int
    #: Bank holding the high byte of every slot in this one, if any.
    overflow: str | None = None
    #: Set on overflow banks: the base bank they belong to. Overflow
    #: banks are never read on their own — they are folded into the base.
    overflow_of: str | None = None
    #: True when slot N counts the product whose code is N (the ``@TR:32``
    #: layout). False for the special counter, whose slots are fixed
    #: functions rather than catalogue products.
    product_indexed: bool = True
    #: True for the ``<DAILYCOUNTER>`` banks, which ``@TF:05`` zeroes.
    daily: bool = False


#: Every counter bank the 89 bundled profiles declare, keyed by command.
#:
#: Page counts: ``@TR:32``/``@TR:33`` and ``@TR:52``/``@TR:53`` are
#: J.O.E.'s (``WifiCommandProductCounterStatistics`` walks
#: ``IntRange(0, 15)``, ``WifiCommandSpecialCounterStatistics``
#: ``IntRange(0, 3)``). The barista and daily banks appear in no APK
#: code path at all; they get the product counter's 16 pages because
#: they index the same 64-slot product-code space, and a machine that
#: serves fewer answers ``@tr:00`` early, which the reader honours.
COUNTER_BANK_SPECS: dict[str, CounterBankSpec] = {
    "@TR:32": CounterBankSpec(
        command="@TR:32",
        name="product_counter",
        label="product counter",
        pages=16,
        bytes_per_value=2,
        overflow="@TR:33",
    ),
    "@TR:33": CounterBankSpec(
        command="@TR:33",
        name="product_counter_overflow",
        label="product counter overflow",
        pages=16,
        bytes_per_value=1,
        overflow_of="@TR:32",
    ),
    "@TR:34": CounterBankSpec(
        command="@TR:34",
        name="barista_counter",
        label="barista counter",
        pages=16,
        bytes_per_value=2,
        overflow="@TR:35",
    ),
    "@TR:35": CounterBankSpec(
        command="@TR:35",
        name="barista_counter_overflow",
        label="barista counter overflow",
        pages=16,
        bytes_per_value=1,
        overflow_of="@TR:34",
    ),
    "@TR:42": CounterBankSpec(
        command="@TR:42",
        name="daily_product_counter",
        label="daily product counter",
        pages=16,
        bytes_per_value=2,
        overflow="@TR:43",
        daily=True,
    ),
    "@TR:43": CounterBankSpec(
        command="@TR:43",
        name="daily_product_counter_overflow",
        label="daily product counter overflow",
        pages=16,
        bytes_per_value=1,
        overflow_of="@TR:42",
        daily=True,
    ),
    "@TR:44": CounterBankSpec(
        command="@TR:44",
        name="daily_barista_counter",
        label="daily barista counter",
        pages=16,
        bytes_per_value=2,
        overflow="@TR:45",
        daily=True,
    ),
    "@TR:45": CounterBankSpec(
        command="@TR:45",
        name="daily_barista_counter_overflow",
        label="daily barista counter overflow",
        pages=16,
        bytes_per_value=1,
        overflow_of="@TR:44",
        daily=True,
    ),
    "@TR:52": CounterBankSpec(
        command="@TR:52",
        name="special_counter",
        label="special counter",
        pages=4,
        bytes_per_value=2,
        overflow="@TR:53",
        product_indexed=False,
    ),
    "@TR:53": CounterBankSpec(
        command="@TR:53",
        name="special_counter_overflow",
        label="special counter overflow",
        pages=4,
        bytes_per_value=1,
        overflow_of="@TR:52",
        product_indexed=False,
    ),
}

#: Slot map of the special counter bank (``@TR:52``), lifted from
#: J.O.E.'s ``SpecialCounterStatisticsParser.parse()``. Its slots are
#: fixed functions, not catalogue product codes, and three of the five
#: values are sums over neighbouring slots:
#:
#:     coldBrew   = h(4) + h(5) + h(6)
#:     lightBrew  = h(12) + h(13) + h(14)
#:     sweetFoam  = h(3)
#:     strongCold = h(9)
#:
#: (``hotBrew`` reads slot 0 in the app — the same slot as the total —
#: which looks like a copy/paste bug in J.O.E. and is not reproduced.)
SPECIAL_COUNTER_SLOTS: dict[str, tuple[int, ...]] = {
    "sweet_foam": (3,),
    "cold_brew": (4, 5, 6),
    "strong_cold_brew": (9,),
    "light_brew": (12, 13, 14),
}


def _fold_overflow(slots: list[int], overflow: list[int] | None) -> list[int]:
    """Fold an overflow bank's high bytes into its base bank's values.

    J.O.E. computes ``value + (high << 16)`` per slot
    (``StatisticStateEmit``), skipping the two neutral high bytes and
    leaving slots the base table marks unused alone. Returns ``slots``
    unchanged when there is no overflow data.
    """
    if not overflow:
        return slots
    merged = list(slots)
    for index, high in enumerate(overflow[: len(merged)]):
        if high in OVERFLOW_COUNT_UNUSED:
            continue
        if merged[index] == PRODUCT_COUNT_UNUSED:
            continue
        merged[index] += high << 16
    return merged


def _product_slot_names(
    slots: list[int], profile: MachineProfile | None
) -> dict[int, str]:
    """Slot index -> product name for a product-code-indexed bank.

    Profile catalogue names win over the package-wide
    :data:`PRODUCT_NAMES` fallback, and :data:`COUNTER_SLOT_OVERRIDES`
    moves a product to the slot its machine really counts it at.
    """
    if profile is None or not getattr(profile, "product_by_code", None):
        return dict(PRODUCT_NAMES)
    overrides = COUNTER_SLOT_OVERRIDES.get(getattr(profile, "code", ""), {})
    code_to_name: dict[int, str] = {}
    for code, product in profile.product_by_code.items():
        slot = overrides.get(code, code)
        if slot != code and (slot >= len(slots) or slots[slot] == PRODUCT_COUNT_UNUSED):
            # The override target carries nothing on this firmware; fall
            # back to the product's own code so a machine that does
            # count there is still named.
            slot = code
        code_to_name[slot] = product.name
    return code_to_name


def _slots_by_code(slots: list[int]) -> dict[str, int]:
    """Hex slot index -> count for every configured slot but the total."""
    return {
        f"{index:02X}": value
        for index, value in enumerate(slots)
        if index and value != PRODUCT_COUNT_UNUSED
    }


def _slots_by_name(slots: list[int], names: dict[int, str]) -> dict[str, int]:
    """Named view of ``slots`` for a slot -> name map."""
    by_name: dict[str, int] = {}
    for index in range(1, len(slots)):
        value = slots[index]
        if value == PRODUCT_COUNT_UNUSED:
            continue
        name = names.get(index)
        if name is not None:
            by_name[name] = value
    return by_name


def _special_slots_by_name(slots: list[int]) -> dict[str, int]:
    """Named view of the special counter bank (``@TR:52``).

    Each name sums the slots J.O.E.'s ``SpecialCounterStatisticsParser``
    sums for it (see :data:`SPECIAL_COUNTER_SLOTS`); unconfigured slots
    count as zero, exactly like the app's ``h()`` helper, and a name
    whose slots are *all* unconfigured is dropped rather than reported
    as 0.
    """
    by_name: dict[str, int] = {}
    for name, indices in SPECIAL_COUNTER_SLOTS.items():
        present = [
            slots[i]
            for i in indices
            if i < len(slots) and slots[i] != PRODUCT_COUNT_UNUSED
        ]
        if present:
            by_name[name] = sum(present)
    return by_name


def _format_counter_slots(
    header: str, by_name: dict[str, int], by_code: dict[str, int]
) -> str:
    """Shared pretty-printer for a decoded counter bank."""
    lines = [header]
    for name, count in by_name.items():
        lines.append(f"  {name:20s}: {count}")
    # An "unnamed" slot is one the active slot->name map didn't cover at
    # parse time — i.e. by_code has an entry but by_name doesn't. We
    # re-derive it here so both the fallback and the profile-aware case
    # are covered without ever double-listing a slot.
    named_counts = list(by_name.values())
    unnamed: dict[str, int] = {}
    for code_hex, count in by_code.items():
        try:
            named_counts.remove(count)
        except ValueError:
            unnamed[code_hex] = count
    if unnamed:
        lines.append(
            "  (unnamed slots): "
            + ", ".join(f"0x{code}={count}" for code, count in unnamed.items())
        )
    return "\n".join(lines)


@dataclasses.dataclass(slots=True, frozen=True)
class ProductCounters:
    """Decoded ``@TR:32`` paginated payload — per-product brew counters.

    The dongle returns 16 pages of 4 ``u16`` slots each (64 slots total),
    indexed by product code:

    * Slot 0 carries the total number of brews ever performed.
    * Slots 1..63 each carry the count for the product whose code matches
      the slot index, or ``0xFFFF`` if that code is not configured on
      the machine.

    The product code -> name mapping in :data:`PRODUCT_NAMES` is shared
    across the TT237W family; unknown codes are surfaced under
    ``by_code`` only.
    """

    total: int
    by_name: dict[str, int]
    by_code: dict[str, int]
    raw_slots: tuple[int, ...]

    @classmethod
    def from_slots(
        cls,
        slots: list[int],
        profile: MachineProfile | None = None,
        overflow: list[int] | None = None,
    ) -> ProductCounters:
        """Decode a 64-slot @TR:32 table.

        ``profile`` is an optional :class:`jura_connect.profile.MachineProfile`
        whose per-product name map is preferred over the package-wide
        :data:`PRODUCT_NAMES` fallback. Unknown codes still surface
        through ``by_code``.

        ``overflow`` is the per-slot high byte from the machine's
        ``@TR:33`` bank, if it has one. A slot's count is then
        ``value + (high << 16)``, which is how a machine reports past
        65535. Overflow bytes of ``0x00``/``0xFF`` carry no high word,
        and a slot the base table marks unused stays unused.
        """
        if len(slots) < 1:
            raise ValueError("product counter table is empty")
        slots = _fold_overflow(slots, overflow)
        total = slots[0]
        by_code = _slots_by_code(slots)
        by_name = _slots_by_name(slots, _product_slot_names(slots, profile))
        return cls(
            total=total,
            by_name=by_name,
            by_code=by_code,
            raw_slots=tuple(slots),
        )

    def format(self) -> str:
        return _format_counter_slots(
            f"total brews : {self.total}", self.by_name, self.by_code
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "by_name": dict(self.by_name),
            "by_code": dict(self.by_code),
        }


@dataclasses.dataclass(slots=True, frozen=True)
class CounterBank:
    """Decoded payload of any counter bank other than ``@TR:32``.

    ``@TR:32`` keeps its own :class:`ProductCounters` type because
    consumers (Home Assistant among them) depend on its shape. Every
    other bank — special, barista, daily product, daily barista — shares
    this one, which carries the bank command so a caller can tell them
    apart in a single collection.

    Slot 0 is the bank's own total. The remaining slots are indexed by
    product code for the product-indexed banks (see
    :class:`CounterBankSpec`), so profile catalogue names apply; the
    special bank's slots are fixed functions instead and are named from
    :data:`SPECIAL_COUNTER_SLOTS`. Slots no name covers always survive
    in ``by_code``.
    """

    bank: str
    name: str
    total: int
    by_name: dict[str, int]
    by_code: dict[str, int]
    raw_slots: tuple[int, ...]

    @classmethod
    def from_slots(
        cls,
        bank: str,
        slots: list[int],
        profile: MachineProfile | None = None,
        overflow: list[int] | None = None,
    ) -> CounterBank:
        """Decode one bank's slot table, folding in ``overflow`` if read."""
        spec = counter_bank_spec(bank)
        if spec.overflow_of is not None:
            raise ValueError(
                f"{spec.command} is the overflow bank of {spec.overflow_of}; "
                "decode it through its base bank"
            )
        if len(slots) < 1:
            raise ValueError(f"{spec.command} counter table is empty")
        slots = _fold_overflow(slots, overflow)
        if spec.product_indexed:
            by_name = _slots_by_name(slots, _product_slot_names(slots, profile))
        else:
            by_name = _special_slots_by_name(slots)
        return cls(
            bank=spec.command,
            name=spec.name,
            total=slots[0],
            by_name=by_name,
            by_code=_slots_by_code(slots),
            raw_slots=tuple(slots),
        )

    def format(self) -> str:
        spec = counter_bank_spec(self.bank)
        return _format_counter_slots(
            f"{spec.label} ({self.bank}) total: {self.total}",
            self.by_name,
            self.by_code,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "bank": self.bank,
            "name": self.name,
            "total": self.total,
            "by_name": dict(self.by_name),
            "by_code": dict(self.by_code),
        }


def counter_bank_spec(bank: str) -> CounterBankSpec:
    """Look up one :class:`CounterBankSpec` by wire command."""
    try:
        return COUNTER_BANK_SPECS[bank.strip().upper()]
    except KeyError as exc:
        known = ", ".join(sorted(COUNTER_BANK_SPECS))
        raise ValueError(f"unknown counter bank {bank!r}. Known: {known}") from exc


# --------------------------------------------------------------------- #
# Programmable mode slots (@TM:50 + @TM:42,<slot>)
# --------------------------------------------------------------------- #
#
# Older Jura machines expose a "Programmable Mode" where each slot
# holds a saved recipe (a variant of a base product code, e.g. "my
# strong espresso"). On newer machines like the S8 EB (EF1091), the
# XML has no ``PROGRAMMODE`` section: ``@TM:50`` returns a non-zero
# slot count but every ``@TM:42,<slot>`` answer is ``@tm:C2``
# (= "slot/product/function not supported by machine"). The
# :class:`ProgramModeSlots` dataclass surfaces both states cleanly so
# callers can tell the difference between "no pmode on this firmware"
# and "pmode present but slot N is empty".


#: Rejection tokens the PMode commands answer with instead of data.
#: Straight out of the APK's parsers: ``C1`` =
#: ``PModeProductReadParser`` "Machine does not support Product
#: Programming", ``C2`` = ``PModeSlotProductReadParser`` "Product code,
#: slot, or function is not supported by machine", ``D0`` =
#: ``PModeNumSlotReadParser``'s no-slots answer. ``00`` is the dongle's
#: generic "write rejected" echo — the same one a settings write with a
#: missing CRLF gets. None of these is a success.
_PMODE_NOT_SUPPORTED: dict[str, str] = {
    "C1": "product programming is not supported by this machine",
    "C2": "the product code, slot, or function is not supported by this machine",
    "D0": "the machine reports no programmable-recipe slots",
    "00": "the write was rejected",
}

#: Number of hex chars of the product blob the ``@TM:42`` slot write
#: keeps: ``AppProduct.d().substring(0, 28)`` = the first 14 bytes.
_PMODE_SLOT_HEAD_HEX = 28

#: Blob byte holding grinder freeness (``Argument="F17"`` → byte 16).
_PMODE_FREENESS_OFFSET = PMODE_BLOB_BYTES - 1

#: :attr:`~jura_connect.profile.ProductParam.kind` of the F17 parameter
#: (the XML element is ``<GRINDER_FREENESS Argument="F17" …>``).
_KIND_GRINDER_FREENESS = "grinder_freeness"


def _is_pmode_blob(value: str) -> bool:
    """True for a verbatim 17-byte PMode blob (the escape hatch)."""
    return len(value) == PMODE_BLOB_BYTES * 2 and _HEX_ONLY.fullmatch(value) is not None


_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+")


def _pmode_code(product: str | int) -> int:
    """Product code from an int, a 2-hex string, or a verbatim blob.

    Used when there is no profile to resolve a name against; byte 0 of
    a blob *is* the product code (``AppProduct.d()`` writes it last).
    """
    if isinstance(product, int):
        return product
    if _is_pmode_blob(product):
        product = product[:2]
    try:
        return int(product, 16)
    except ValueError as exc:
        raise ValueError(
            f"pmode: {product!r} is not a 2-hex product code and no machine "
            "profile is loaded to resolve it by name."
        ) from exc


@dataclasses.dataclass(slots=True, frozen=True)
class PModeProduct:
    """One product's stored PMode settings, from ``@TM:41,<code>``.

    ``arguments`` is the APK's view of the payload: byte *i* becomes
    ``F<i+1>``, so ``F1`` is the product code, ``F4`` the water amount
    and ``F17`` the grinder freeness. ``blob`` is the same payload as
    one hex string, directly comparable with
    :meth:`~jura_connect.profile.ProductDef.build_pmode_hex`.
    """

    product_code: int
    blob: str
    arguments: dict[str, str]
    name: str | None = None  # profile product name, when one is loaded

    def format(self) -> str:
        label = self.name or f"0x{self.product_code:02X}"
        lines = [f"pmode settings for {label}:", f"  blob: {self.blob}"]
        for key, value in self.arguments.items():
            if key == "F1":
                continue
            lines.append(f"  {key}: {value}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "product_code": f"{self.product_code:02X}",
            "name": self.name,
            "blob": self.blob,
            "arguments": dict(self.arguments),
        }


def _pmode_arguments(payload: str) -> dict[str, str]:
    """Split a PMode payload into the APK's ``F<n>`` argument map."""
    return {
        f"F{i + 1}": payload[i * 2 : i * 2 + 2].upper()
        for i in range(len(payload) // 2)
    }


def _pmode_strip_checksum(head: str, body: str) -> str | None:
    """Drop ``body``'s trailing checksum byte if it verifies.

    ``head`` is the command echo the checksum covers together with the
    payload (``"41"`` or ``"42"``); the APK checksums
    ``"<head>,<payload>"``. Returns ``None`` when the checksum does not
    match, so callers can refuse the reply rather than decode noise.
    """
    if len(body) < 4 or len(body) % 2:
        return None
    payload, csum = body[:-2], body[-2:]
    if _settings_checksum(f"{head},{payload}") != csum.upper():
        return None
    return payload.upper()


def _parse_pmode_product(
    code: int, reply: str, definition: ProductDef | None
) -> PModeProduct | None:
    """Parse the reply to ``@TM:41,<code>`` (``PModeProductReadParser``)."""
    text = reply.strip()
    if text.lower().startswith("@tm:"):
        text = text[4:]
    head = text[:2].upper()
    if head in _PMODE_NOT_SUPPORTED:
        return None
    if head != "41":
        return None
    payload = _pmode_strip_checksum("41", text[2:].lstrip(","))
    if payload is None:
        raise ValueError(
            f"pmode product read for 0x{code:02X}: checksum mismatch in {reply!r}"
        )
    arguments = _pmode_arguments(payload)
    if arguments.get("F1") != f"{code:02X}":
        raise ValueError(
            f"pmode product read for 0x{code:02X}: reply carries product "
            f"code {arguments.get('F1')!r}; refusing to attribute another "
            f"product's recipe to it (reply was {reply!r})"
        )
    return PModeProduct(
        product_code=code,
        blob=payload,
        arguments=arguments,
        name=None if definition is None else definition.name,
    )


@dataclasses.dataclass(slots=True, frozen=True)
class PModeSlot:
    """One configured slot from ``@TM:42,<slot>``."""

    index: int
    product_code: int  # base product code (e.g. 0x02 for Espresso)
    raw_payload: str  # the hex tail after the slot index in the reply


@dataclasses.dataclass(slots=True, frozen=True)
class ProgramModeSlots:
    """Decoded ``@TM:50`` count + per-slot ``@TM:42`` results."""

    num_slots: int
    slots: tuple[PModeSlot, ...]
    unsupported: tuple[int, ...]  # slot indices that returned C2 / timed out

    def format(self) -> str:
        if not self.num_slots:
            return "pmode: this machine reports no slots"
        if not self.slots:
            return (
                f"pmode: {self.num_slots} slot(s) reported by @TM:50, "
                "but every slot returned C2 (= 'not supported by machine'). "
                "This firmware does not expose pmode entries over WiFi."
            )
        lines = [f"pmode: {self.num_slots} slots, {len(self.slots)} configured"]
        for s in self.slots:
            lines.append(
                f"  slot {s.index:02d}: product=0x{s.product_code:02X}  raw={s.raw_payload}"
            )
        if self.unsupported:
            lines.append(
                "  unsupported slots: "
                + ", ".join(f"{i:02d}" for i in self.unsupported)
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "num_slots": self.num_slots,
            "slots": [
                {
                    "index": s.index,
                    "product_code": f"{s.product_code:02X}",
                    "raw_payload": s.raw_payload,
                }
                for s in self.slots
            ],
            "unsupported": list(self.unsupported),
        }


def _parse_pmode_num_slots(reply: str) -> int:
    """Parse the reply to ``@TM:50``.

    Wire format (lifted from the APK's ``PModeNumSlotReadParser``):

        @tm:50,<N hex bytes><1-byte checksum>

    The body bytes are summed (each byte parsed as hex) and the total
    is the number of pmode slots. The trailing byte is a checksum that
    we don't currently verify (the APK does but the algorithm is opaque
    and not needed for correctness — wrong counts surface as
    unsupported-slot replies below).

    ``@tm:D0`` is the parser's "no slots" rejection token and decodes
    to zero, as does any other head we don't recognise.
    """
    text = reply.strip()
    if text.lower().startswith("@tm:"):
        text = text[4:]
    if "," in text:
        head, payload = text.split(",", 1)
    else:
        head, payload = text[:2], text[2:]
    if head.lower() != "50":
        return 0
    if len(payload) < 4:
        return 0
    # Drop the trailing checksum byte (last 2 hex chars).
    body = payload[:-2]
    if len(body) % 2:
        return 0
    total = 0
    for i in range(0, len(body), 2):
        try:
            total += int(body[i : i + 2], 16)
        except ValueError:
            return 0
    return total


def _parse_pmode_slot(slot: int, reply: str) -> PModeSlot | None:
    """Parse the reply to ``@TM:42,<slot>``.

    Wire format (success path, per ``PModeSlotProductReadParser``):
    ``@tm:42,<slot_hex><product_code_hex><arguments><checksum>``. We
    strip ``@tm:``, the ``42`` prefix and the echoed slot byte; the
    remainder is the product code followed by the ``F2..Fn`` argument
    bytes. The trailing checksum byte covers ``"42,<slot><payload>"``
    and is dropped from :attr:`PModeSlot.raw_payload` once verified.

    Returns ``None`` when the machine answered with a rejection token
    (``C2`` — "product code, slot, or function is not supported by
    machine" in the APK — or one of its siblings), and when the reply
    is otherwise malformed. A reply whose checksum does not verify
    keeps its trailing bytes rather than being silently truncated;
    :attr:`ProgramModeSlots` callers see the raw hex either way.
    """
    text = reply.strip()
    if text.lower().startswith("@tm:"):
        text = text[4:]
    if not text:
        return None
    head = text[:2].upper()
    if head in _PMODE_NOT_SUPPORTED:
        return None
    if head != "42":
        return None
    # Drop the "42" prefix and any leading comma.
    body = text[2:].lstrip(",")
    # Body starts with the slot byte (echoed back). Strip it, but keep
    # it for the checksum, which the APK computes over "42,<body>".
    if len(body) < 4:
        return None
    verified = _pmode_strip_checksum("42", body)
    payload = (verified or body)[2:].lstrip(",")
    if len(payload) < 2:
        return None
    try:
        product_code = int(payload[:2], 16)
    except ValueError:
        return None
    if verified is None:
        log.warning(
            "pmode slot %02X: checksum mismatch in %r; payload kept verbatim",
            slot,
            reply,
        )
    return PModeSlot(index=slot, product_code=product_code, raw_payload=payload)


# --------------------------------------------------------------------- #
# Batch settings read (@TM:00,FC — the XML's <BANK Name="Setting">)
# --------------------------------------------------------------------- #
#
# Every newer machine XML declares
#
#     <BANK Name="Setting" Command="@TM:00,FC" CommandArgument="02080913"/>
#
# under <MACHINESETTINGS> — one round trip for the four settings 02
# (hardness), 08 (units), 09 (language) and 13 (auto-off) instead of
# four separate @TM:<arg> reads. J.O.E. 4.6.10 parses the declaration
# (XMLParser.e()) and then discards CommandArgument in Bank's
# constructor; its WiFi settings path is WifiCommandReadPModeComposite,
# i.e. one WifiCommandReadPMode per SettingElement. So the app never
# issues this command and tells us nothing about the reply.
#
# What is implemented here: the XML's Command sent verbatim, and a
# deliberately strict parser modelled on the single-setting read
# (`@tm:<addr>,<values><checksum>`). Anything unexpected raises, and
# JuraClient.read_all_settings falls back to per-setting reads — so a
# wrong guess costs a round trip, not a wrong value.


@dataclasses.dataclass(slots=True, frozen=True)
class SettingReading:
    """One setting's value inside a :class:`SettingsSnapshot`.

    ``name``/``definition`` are ``None`` for a bank argument that the
    machine's own ``<MACHINESETTINGS>`` catalogue does not declare.
    ``source`` is ``"batch"`` when the value came from the settings
    bank and ``"single"`` when it came from its own ``@TM:<arg>`` read.
    """

    p_argument: str
    name: str | None
    raw: str
    item: str | None
    definition: SettingDef | None
    source: str

    def to_dict(self) -> dict[str, object]:
        return {
            "p_argument": self.p_argument,
            "name": self.name,
            "raw": self.raw,
            "item": self.item,
            "source": self.source,
        }


@dataclasses.dataclass(slots=True, frozen=True)
class SettingsSnapshot:
    """Result of :meth:`JuraClient.read_all_settings`.

    ``batch_used`` says whether the ``@TM:00,FC`` bank answered; when it
    did not, ``batch_error`` carries the reason and every reading came
    from an individual ``@TM:<arg>`` request.
    """

    readings: tuple[SettingReading, ...]
    batch_used: bool
    batch_error: str | None = None

    def reading(self, name: str) -> SettingReading | None:
        """Look up one reading by its snake_case setting name."""
        for r in self.readings:
            if r.name == name:
                return r
        return None

    def format(self) -> str:
        how = "batch @TM:00,FC" if self.batch_used else "per-setting @TM:<arg>"
        lines = [f"settings ({len(self.readings)} read via {how}):"]
        for r in self.readings:
            label = r.name or f"(arg {r.p_argument})"
            value = f"{r.item} (0x{r.raw})" if r.item else f"0x{r.raw}"
            lines.append(f"  {label:<28} {value}")
        if self.batch_error:
            lines.append(f"  batch read unavailable: {self.batch_error}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "batch_used": self.batch_used,
            "batch_error": self.batch_error,
            "readings": [r.to_dict() for r in self.readings],
        }


def _split_tagged_values(body: str) -> list[str]:
    """Split a concatenation of settings values into individual values.

    Uses the ItemSlider type tags documented in ``docs/PROTOCOL.md``
    §5.7: ``21`` prefixes a one-byte value, ``22`` a two-byte value,
    and anything else *is* a bare one-byte value. That makes the run
    self-delimiting, which is the only way a concatenated reply can be
    decoded at all — AutoOFF alone is 1, 2 or 3 bytes wide depending on
    the chosen item.
    """
    values: list[str] = []
    i = 0
    while i < len(body):
        tag = body[i : i + 2].upper()
        width = {"21": 4, "22": 6}.get(tag, 2)
        chunk = body[i : i + width]
        if len(chunk) != width:
            raise ValueError(
                f"settings bank: value at offset {i} is truncated ({chunk!r})"
            )
        try:
            int(chunk, 16)
        except ValueError as exc:
            raise ValueError(
                f"settings bank: value at offset {i} is not hex ({chunk!r})"
            ) from exc
        values.append(chunk.upper())
        i += width
    return values


def _parse_settings_bank_reply(
    reply: str, command: str, arguments: tuple[str, ...]
) -> dict[str, str]:
    """Decode the reply to the XML's settings-bank command.

    ``command`` is the declaration (``"@TM:00,FC"``); its address
    (``"00"``) is what the dongle echoes. Layout is a guess — see the
    section comment above — so every deviation raises
    :class:`ValueError` instead of being papered over.
    """
    address = command[4:].split(",", 1)[0].strip().upper() if len(command) > 4 else ""
    text = reply.strip()
    low = text.lower()
    if low.startswith("@an:"):
        raise ValueError(
            f"settings bank {command!r}: machine rejected the batch read ({reply!r})"
        )
    if not low.startswith("@tm:"):
        raise ValueError(f"settings bank {command!r}: unexpected reply {reply!r}")
    head, sep, rest = text[4:].partition(",")
    if head.strip().upper() != address:
        raise ValueError(
            f"settings bank {command!r}: reply echoes address "
            f"{head.strip()!r}, expected {address!r} ({reply!r})"
        )
    rest = rest.strip()
    if not sep or not rest:
        # Bare "@tm:00" — the same short rejection token a settings
        # write gets when the dongle refuses the frame.
        raise ValueError(
            f"settings bank {command!r}: machine rejected the batch read "
            f"({reply!r}) — this firmware has no batch settings read"
        )
    if len(rest) < 4:
        raise ValueError(f"settings bank {command!r}: reply too short ({reply!r})")
    body, csum = rest[:-2], rest[-2:]
    expected = _settings_checksum(f"{address},{body}")
    if csum.upper() != expected:
        raise ValueError(
            f"settings bank {command!r}: checksum mismatch (got {csum!r}, "
            f"expected {expected!r} over {address!r},{body!r}); reply was {reply!r}"
        )
    values = _split_tagged_values(body)
    if len(values) != len(arguments):
        raise ValueError(
            f"settings bank {command!r}: reply carries {len(values)} value(s) "
            f"but the XML declares {len(arguments)} argument(s) "
            f"({', '.join(arguments)}); reply was {reply!r}"
        )
    return dict(zip(arguments, values, strict=True))


# --------------------------------------------------------------------- #
# Limit load (@TM:60,<product code><checksum>)
# --------------------------------------------------------------------- #
#
# Decode ported from the APK's LimitLoadParser. The reply body is a
# product code followed by exactly five min/max byte pairs, always in
# this argument order regardless of what the product declares:
LIMIT_LOAD_ARGUMENTS: tuple[int, ...] = (4, 5, 6, 10, 11)
#
# A pair whose min or max is 0xFF means "not applicable to this
# product"; the app drops those, and so do we. Each surviving pair is
# scaled by the argument's XML ``Step`` (5 for water/bypass, giving
# millilitres; 1 for the milk parameters, giving seconds).
_LIMIT_LOAD_BODY_HEX = 2 + len(LIMIT_LOAD_ARGUMENTS) * 4  # code + 5 pairs


@dataclasses.dataclass(slots=True, frozen=True)
class ProductLimit:
    """One parameter's live range from a ``@TM:60`` reply."""

    kind: str  # profile KIND_* identifier, e.g. "water_amount"
    argument: int  # F-number (4, 5, 6, 10, 11)
    minimum: int  # in XML units (ml / seconds), already scaled
    maximum: int
    step: int  # the scale factor that was applied

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "argument": self.argument,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "step": self.step,
        }


@dataclasses.dataclass(slots=True, frozen=True)
class ProductLimits:
    """Result of :meth:`JuraClient.read_limit_load`."""

    product_code: int
    product_name: str
    limits: tuple[ProductLimit, ...]
    raw: str

    def limit(self, kind: str) -> ProductLimit | None:
        for entry in self.limits:
            if entry.kind == kind:
                return entry
        return None

    def allows(self, kind: str, value: int) -> bool:
        """Whether ``value`` (in XML units) is inside the machine's live
        range for ``kind``. Parameters the machine did not report are
        unconstrained and return ``True``."""
        entry = self.limit(kind)
        if entry is None:
            return True
        return entry.minimum <= value <= entry.maximum

    def format(self) -> str:
        lines = [
            f"limits for {self.product_name} (0x{self.product_code:02X}), "
            f"as reported by the machine:"
        ]
        if not self.limits:
            lines.append("  (no adjustable parameter reported)")
        for entry in self.limits:
            lines.append(
                f"  {entry.kind:<20} {entry.minimum}..{entry.maximum} "
                f"(step {entry.step})"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "product_code": f"{self.product_code:02X}",
            "product_name": self.product_name,
            "limits": [entry.to_dict() for entry in self.limits],
            "raw": self.raw,
        }


def _parse_limit_load(reply: str, definition: ProductDef) -> ProductLimits:
    """Decode a ``@tm:60,…`` reply against the product's XML parameters.

    Mirrors ``LimitLoadParser.e()``: verify the ``ByteOperations.d``
    checksum over ``"60,<body>"``, check the echoed product code, then
    read five min/max pairs for F4, F5, F6, F10 and F11, dropping the
    ones flagged ``FF`` and the ones this product does not declare.
    """
    text = reply.strip()
    low = text.lower()
    if low.startswith("@an:"):
        raise ValueError(f"@TM:60 for {definition.name}: machine refused ({reply!r})")
    if not low.startswith("@tm:"):
        raise ValueError(f"@TM:60 for {definition.name}: unexpected reply {reply!r}")
    rest = text[4:]
    head = rest[:2].upper()
    if head == "C1":
        # LimitLoadParser logs "Machine does not support Product
        # Programming" and gives up on this token.
        raise ValueError(
            f"@TM:60 for {definition.name}: machine answered C1 — this "
            "firmware does not support product programming / limit load"
        )
    if head != "60":
        raise ValueError(
            f"@TM:60 for {definition.name}: reply echoes {head!r}, "
            f"expected '60' ({reply!r})"
        )
    body_all = rest[2:].lstrip(",").strip()
    if len(body_all) < _LIMIT_LOAD_BODY_HEX + 2:
        raise ValueError(
            f"@TM:60 for {definition.name}: reply body too short "
            f"({len(body_all)} hex chars, need {_LIMIT_LOAD_BODY_HEX + 2}): {reply!r}"
        )
    body, csum = body_all[:-2], body_all[-2:]
    expected = _settings_checksum(f"60,{body}")
    if csum.upper() != expected:
        raise ValueError(
            f"@TM:60 for {definition.name}: checksum mismatch (got {csum!r}, "
            f"expected {expected!r} over '60,{body}'); reply was {reply!r}"
        )
    try:
        echoed = int(body[:2], 16)
    except ValueError as exc:
        raise ValueError(
            f"@TM:60 for {definition.name}: product code {body[:2]!r} is not hex"
        ) from exc
    if echoed != definition.code:
        raise ValueError(
            f"@TM:60 for {definition.name}: reply carries product code "
            f"0x{echoed:02X}, expected 0x{definition.code:02X}"
        )
    pairs = body[2:_LIMIT_LOAD_BODY_HEX]
    limits: list[ProductLimit] = []
    for index, f_number in enumerate(LIMIT_LOAD_ARGUMENTS):
        chunk = pairs[index * 4 : index * 4 + 4]
        lo_hex, hi_hex = chunk[:2].upper(), chunk[2:].upper()
        if lo_hex == "FF" or hi_hex == "FF":
            continue  # not applicable to this product
        param = next((p for p in definition.params if p.argument == f_number), None)
        if param is None:
            continue  # reported but not declared by this product's XML
        try:
            lo, hi = int(lo_hex, 16), int(hi_hex, 16)
        except ValueError as exc:
            raise ValueError(
                f"@TM:60 for {definition.name}: F{f_number} range {chunk!r} is not hex"
            ) from exc
        step = param.step or 1
        limits.append(
            ProductLimit(
                kind=param.kind,
                argument=f_number,
                minimum=lo * step,
                maximum=hi * step,
                step=step,
            )
        )
    return ProductLimits(
        product_code=definition.code,
        product_name=definition.name,
        limits=tuple(limits),
        raw=body_all.upper(),
    )


# --------------------------------------------------------------------- #
# Coffee timer (@TM:3C schedule + @TV:84 wall clock)
# --------------------------------------------------------------------- #
#
# APK-derived, **not** hardware-verified. Sources:
#
#   WifiCommandStartCoffeeTimer:
#       strO = "3C," + take(40, appProduct.c(data) + repeat("00", 20))
#                    + ExtensionsKt.e(seconds)
#       cmd  = "@TM:" + strO + ByteOperations.d(strO)      matcher "@tm:.*"
#   WifiSendTimeForCoffeeTimer:
#       cmd  = "@TV:84," + ExtensionsKt.c(time)            matcher "@tv:84"
#
# with ExtensionsKt.e(i) = "%04X" % (i & 0xFFFF) and ExtensionsKt.c(s)
# = the per-character "%02X" hex encoding also used for the handshake's
# connection id. ``appProduct.c(data)`` is the very same builder
# ``@TP:`` uses, i.e. ProductDef.build_recipe_hex(). The Bluetooth
# adapter's addCoffeeTimerCommand / sendTimeForCoffeeTimer build byte
# for byte the same strings. See docs/PROTOCOL.md §5.12.

#: ``@TM:`` argument that carries a coffee-timer schedule.
COFFEE_TIMER_ARG = "3C"

#: The recipe blob is right-padded with ``"00"`` to this many hex
#: characters (20 bytes) before the delay field — the APK appends 20
#: ``"00"`` pairs and then takes the first 40 characters.
COFFEE_TIMER_BLOB_HEX_LEN = 40

#: Delay bounds J.O.E.'s coffee-timer screen enforces before it will
#: send anything: at least one minute out, at most 16 hours. The wire
#: field is 16 bits, so 16 h (57600 s) fits with room to spare.
COFFEE_TIMER_MIN_DELAY_SECONDS = 60
COFFEE_TIMER_MAX_DELAY_SECONDS = 16 * 3600

#: J.O.E. only ever puts whole minutes on the wire: its delay is
#: ``(millis_until_target // 60000) * 60``.
COFFEE_TIMER_DELAY_GRANULARITY = 60

_CLOCK_RE = re.compile(r"^(\d{1,2}):(\d{2})$")


def _normalise_clock(value: str | datetime.time | datetime.datetime) -> str:
    """Return ``"HH:MM"`` for a string / time / datetime.

    Mirrors the APK's ``String.format("%02d:%02d", HOUR_OF_DAY, MINUTE)``.
    """
    if isinstance(value, datetime.datetime | datetime.time):
        return f"{value.hour:02d}:{value.minute:02d}"
    m = _CLOCK_RE.match(value.strip())
    if m is None:
        raise ValueError(f"coffee timer clock: expected 'HH:MM', got {value!r}")
    hour, minute = int(m.group(1)), int(m.group(2))
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ValueError(f"coffee timer clock: {value!r} is not a valid time of day")
    return f"{hour:02d}:{minute:02d}"


def encode_coffee_timer_clock(value: str | datetime.time | datetime.datetime) -> str:
    """Hex-encode a wall-clock time for ``@TV:84``.

    ``"07:30"`` becomes ``"30373A3330"`` — one ``%02X`` per ASCII
    character, the ``ExtensionsKt.c`` encoding.
    """
    return _conn_id_hex(_normalise_clock(value))


def _validated_recipe_hex(recipe: str) -> str:
    """Sanity-check a verbatim recipe blob before it goes on the wire."""
    text = recipe.strip().upper()
    if not re.fullmatch(r"(?:[0-9A-F]{2})+", text):
        raise ValueError(
            f"coffee timer: recipe blob must be an even number of hex "
            f"characters, got {recipe!r}"
        )
    if len(text) > COFFEE_TIMER_BLOB_HEX_LEN:
        raise ValueError(
            f"coffee timer: recipe blob is {len(text)} hex chars but the "
            f"command only carries {COFFEE_TIMER_BLOB_HEX_LEN}"
        )
    return text


def build_coffee_timer_command(recipe_hex: str, delay_seconds: int) -> str:
    """Build the ``@TM:3C`` frame for one scheduled brew.

    ``recipe_hex`` is the ``@TP:`` recipe blob (32 hex chars from
    :meth:`~jura_connect.profile.ProductDef.build_recipe_hex`); it is
    right-padded with ``"00"`` to :data:`COFFEE_TIMER_BLOB_HEX_LEN` and
    truncated there, exactly like the APK's
    ``take(40, blob + repeat("00", 20))``.

    ``delay_seconds`` is how far in the future the brew should start.
    It must be a whole minute inside the
    :data:`COFFEE_TIMER_MIN_DELAY_SECONDS` …
    :data:`COFFEE_TIMER_MAX_DELAY_SECONDS` window; the value goes on
    the wire as four upper-case hex chars (16-bit big-endian).

    The trailing byte is the same ``ByteOperations.d`` checksum every
    other ``@TM:`` write carries, computed over ``"3C,<blob><delay>"``.
    """
    _check_coffee_timer_delay(delay_seconds)
    if delay_seconds % COFFEE_TIMER_DELAY_GRANULARITY:
        raise ValueError(
            f"coffee timer: delay {delay_seconds}s is not a whole minute; "
            f"the app only ever sends multiples of "
            f"{COFFEE_TIMER_DELAY_GRANULARITY}s"
        )
    padded = (recipe_hex.strip().upper() + "00" * 20)[:COFFEE_TIMER_BLOB_HEX_LEN]
    body = f"{padded}{delay_seconds & 0xFFFF:04X}"
    checksum = _settings_checksum(f"{COFFEE_TIMER_ARG},{body}")
    return f"@TM:{COFFEE_TIMER_ARG},{body}{checksum}"


def _check_coffee_timer_delay(delay_seconds: int) -> None:
    if (
        not COFFEE_TIMER_MIN_DELAY_SECONDS
        <= delay_seconds
        <= COFFEE_TIMER_MAX_DELAY_SECONDS
    ):
        raise ValueError(
            f"coffee timer: delay {delay_seconds}s is outside the "
            f"{COFFEE_TIMER_MIN_DELAY_SECONDS}..{COFFEE_TIMER_MAX_DELAY_SECONDS}s "
            f"window J.O.E. allows (1 minute .. 16 hours)"
        )


def _is_coffee_timer_accept(reply: str) -> bool:
    """True when an ``@TM:3C`` reply means the schedule was stored.

    J.O.E.'s matcher is the permissive ``@tm:.*``, so the short
    rejection tokens the ``@TM:`` family uses elsewhere — ``@tm:00``
    ("rejected") and ``@tm:C2`` ("not supported by machine") — arrive
    through the same door and must not be read as success.
    """
    r = reply.strip().lower()
    if not r.startswith("@tm:"):
        return False
    return not r.startswith(("@tm:00", "@tm:c2"))


def _coffee_timer_timing(
    at: str | datetime.time | datetime.datetime | None,
    delay: int | None,
    reference: datetime.datetime,
) -> tuple[str, int]:
    """Resolve ``at``/``delay`` into ``(ready_at "HH:MM", delay seconds)``.

    Exactly one of the two must be given. A wall-clock target that has
    already passed today rolls over to tomorrow, matching J.O.E.'s
    ``if (target.before(now)) target.add(DAY_OF_MONTH, 1)``. Both paths
    floor to a whole minute so the wire value stays a multiple of 60.
    """
    if (at is None) == (delay is None):
        raise ValueError(
            "coffee timer: pass exactly one of at=<HH:MM> or delay=<seconds>"
        )
    if at is not None:
        hour, minute = (int(part) for part in _normalise_clock(at).split(":"))
        target = reference.replace(hour=hour, minute=minute)
        if target < reference:
            target += datetime.timedelta(days=1)
        seconds = int((target - reference).total_seconds())
    else:
        seconds = int(delay or 0)
    seconds -= seconds % COFFEE_TIMER_DELAY_GRANULARITY
    _check_coffee_timer_delay(seconds)
    ready = reference + datetime.timedelta(seconds=seconds)
    return _normalise_clock(ready), seconds


@dataclasses.dataclass(slots=True, frozen=True)
class CoffeeTimerSchedule:
    """Outcome of one :meth:`JuraClient.schedule_brew` call.

    ``accepted`` is the honest answer to "did the machine take it?" —
    the ``@tm:00`` / ``@tm:C2`` rejection tokens come back through the
    same permissive matcher a success does. ``time_command`` is
    ``None`` when the wall-clock frame was skipped (schedule refused,
    or ``sync_time=False``).
    """

    product: str | None  # None for a verbatim recipe blob
    product_code: int | None
    recipe_hex: str  # the 32-hex @TP: blob this was built from
    blob_hex: str  # the same blob padded to 40 hex chars, as sent
    delay_seconds: int
    ready_at: str  # "HH:MM" the drink should be ready at
    command: str  # the @TM:3C frame, verbatim
    reply: str
    time_command: str | None  # the @TV:84 frame, verbatim
    time_reply: str | None
    accepted: bool

    def format(self) -> str:
        who = self.product or f"recipe {self.recipe_hex}"
        if self.product_code is not None:
            who += f" (0x{self.product_code:02X})"
        minutes, seconds = divmod(self.delay_seconds, 60)
        verdict = "scheduled" if self.accepted else "REFUSED by machine"
        lines = [
            f"coffee timer: {who} — {verdict}",
            f"  ready at   : {self.ready_at} (in {minutes}m{seconds:02d}s)",
            f"  schedule   : {self.command} -> {self.reply}",
        ]
        if self.time_command is not None:
            lines.append(f"  wall clock : {self.time_command} -> {self.time_reply}")
        else:
            lines.append("  wall clock : (not sent)")
        if not self.accepted:
            lines.append(
                "  note       : the machine answered a rejection token; no "
                "brew is scheduled."
            )
        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        return {
            "product": self.product,
            "product_code": (
                None if self.product_code is None else f"{self.product_code:02X}"
            ),
            "recipe_hex": self.recipe_hex,
            "blob_hex": self.blob_hex,
            "delay_seconds": self.delay_seconds,
            "ready_at": self.ready_at,
            "command": self.command,
            "reply": self.reply,
            "time_command": self.time_command,
            "time_reply": self.time_reply,
            "accepted": self.accepted,
        }
