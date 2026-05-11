"""Auto-discovery of Jura coffee machines on the local network.

Mirrors the Android app's ``UDPManagerBroadcast`` / ``WifiFrog`` flow:
broadcast a fixed 16-byte scan packet to UDP port 51515 and parse each
reply as an extended status frame.

The reply layout (offsets in bytes) is derived from
``WifiFrog.H(byte[])``::

      0..2   total length (big endian)
      2..4   control word (low 12 bits == 1523, bit 15 must be set)
      4..20  firmware/version string, ASCII, space-padded   -> Machine.fw
     20..52  user-assigned machine name, ASCII              -> Machine.name
     52..68  hardware identifier, ASCII                     -> Machine.hw_id
     68..78  10 bytes of binary status (article#, machine#, serial,
                  production date, UCHI production date)
     78..81  3 bytes
     81..83  2 bytes
     83..90  7 bytes (unused)
     90..108 18 bytes (unused)
    108..109 1 byte  -> Machine.extra
        109  status bits: bit0=valid, bit4=ready, bit7=available
    110..L   raw status payload
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import datetime
import ipaddress
import socket
import struct
import time
from collections.abc import Iterable, Iterator

# UDP / TCP port used by the Jura WiFi dongle.
JURA_PORT = 51515

# The 16-byte broadcast scan probe. Verbatim from UDPCommandScan.
SCAN_PROBE = bytes.fromhex("0010A5F3000000000000000000000000")


def _decode_ascii(blob: bytes) -> str:
    return blob.decode("latin-1", errors="replace").strip().rstrip("\x00").strip()


def _ymd(raw: int) -> datetime.date | None:
    year = ((raw & 0xFE00) >> 9) + 1990
    month = (raw & 0x01E0) >> 5
    day = raw & 0x1F
    if month == 0 or day == 0:
        return None
    try:
        return datetime.date(year, month, day)
    except ValueError:
        return None


@dataclasses.dataclass(frozen=True, slots=True)
class Machine:
    """A discovered coffee machine.

    Attributes mirror the fields parsed out of the broadcast response.
    """

    address: str
    name: str
    fw: str
    hw_id: str
    article_number: int
    machine_number: int
    serial_number: int
    production_date: datetime.date | None
    uchi_production_date: datetime.date | None
    status_flags: int
    status_hex: str
    raw: bytes

    @property
    def ready(self) -> bool:
        # bit4 of byte 109 -> in WifiFrog.H this drives Frog.F (available?)
        return bool((self.status_flags >> 4) & 1)

    @property
    def busy(self) -> bool:
        # bit0 == 0 means "active product" (this.S in WifiFrog)
        return (self.status_flags & 1) == 0

    @property
    def standby(self) -> bool:
        # bit7 == 1 means powered down. APK sets R = !standby.
        return bool((self.status_flags >> 7) & 1)

    def __str__(self) -> str:  # pragma: no cover - human formatting
        return (
            f"{self.name!r} @ {self.address}  fw={self.fw}  hw={self.hw_id}  "
            f"article={self.article_number}  machine={self.machine_number}  "
            f"serial={self.serial_number}  prod={self.production_date}  "
            f"flags=0x{self.status_flags:02X}"
        )


def parse_reply(data: bytes, address: str) -> Machine:
    """Parse a single broadcast reply. Raises ``ValueError`` if malformed."""
    if len(data) < 110:
        raise ValueError(f"reply too short: {len(data)} bytes")

    # WifiFrog.H uses BigInteger over bytes 0..2 -> declared total length.
    total_len = int.from_bytes(data[0:2], "big", signed=False)

    control_bytes = data[2:4]
    control = int.from_bytes(control_bytes, "big", signed=False)
    if (control & 0x0FFF) != 1523:
        raise ValueError(f"not a Jura frame: control=0x{control:04X}")

    # Mirror WifiFrog.G(idx, bArr): pick bit ``length % 8`` of byte
    # ``length // 8`` where ``length = bytes*8 - idx - 1``. For the
    # 2-byte control word that means G(14)/G(15) read bits 1/0 of the
    # **high** byte respectively.
    def _g(buf: bytes, idx: int) -> int:
        length = len(buf) * 8 - idx - 1
        return (buf[length // 8] >> (length % 8)) & 1

    if _g(control_bytes, 14) != 0:
        raise ValueError("control bit-14 must be cleared")
    if _g(control_bytes, 15) != 1:
        raise ValueError("control bit-15 must be set")

    fw = _decode_ascii(data[4:20])
    name = _decode_ascii(data[20:52])
    hw_id = _decode_ascii(data[52:68])

    nums = data[68:78]

    def u16(off: int) -> int:
        # ByteOperations.f(b2,b8) -> ((b2<<8)|(b8&0xFF))&0xFFFF -> big-endian
        return (nums[off] << 8 | nums[off + 1]) & 0xFFFF

    article_number = u16(0)
    machine_number = u16(2)
    serial_number = u16(4)
    production_date = _ymd(u16(6))
    uchi_production_date = _ymd(u16(8))

    flags = data[109]

    # The remaining tail of length (total_len - 110) carries the live status
    # bytes that the app re-emits as "@TV:" or "@TF:" frames.
    end = min(total_len, len(data))
    status_payload = data[110:end]
    status_hex = status_payload.hex().upper()

    return Machine(
        address=address,
        name=name,
        fw=fw,
        hw_id=hw_id,
        article_number=article_number,
        machine_number=machine_number,
        serial_number=serial_number,
        production_date=production_date,
        uchi_production_date=uchi_production_date,
        status_flags=flags,
        status_hex=status_hex,
        raw=bytes(data[:end]),
    )


def _broadcast_addresses() -> list[str]:
    """Best-effort enumeration of broadcast targets.

    Always includes the global broadcast ``255.255.255.255``. When ``socket``
    can introspect local interfaces, the per-interface broadcasts are added
    too — this is what the Android app does when picking inet addresses.
    """
    targets: list[str] = ["255.255.255.255"]
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None):
            family, _, _, _, sockaddr = info
            if family != socket.AF_INET:
                continue
            ip = sockaddr[0]
            # AF_INET narrows sockaddr to (host: str, port: int) at
            # runtime, but the stdlib's stub leaves it as the union
            # `str | int`. Make it explicit so the type-checker can
            # narrow without `cast()`.
            if not isinstance(ip, str) or ip.startswith("127."):
                continue
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            bcast = str(net.broadcast_address)
            if bcast not in targets:
                targets.append(bcast)
    except Exception:  # noqa: BLE001 - best-effort enumeration
        pass
    return targets


def discover(
    timeout: float = 3.0,
    *,
    repeats: int = 3,
    interval: float = 1.0,
    bind_port: int = JURA_PORT,
    targets: Iterable[str] | None = None,
) -> Iterator[Machine]:
    """Broadcast the scan probe and yield each discovered machine once.

    The Android app uses a sustained 1 s broadcast loop on port 51515. We
    bind the same port so machines that reply via broadcast (not unicast)
    are also caught.
    """
    if targets is None:
        targets = _broadcast_addresses()
    targets = list(targets)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    sock.bind(("", bind_port))
    sock.settimeout(0.2)

    deadline = time.monotonic() + timeout
    next_send = 0.0
    sends_left = repeats
    seen: set[str] = set()
    try:
        while time.monotonic() < deadline:
            now = time.monotonic()
            if sends_left > 0 and now >= next_send:
                for target in targets:
                    try:
                        sock.sendto(SCAN_PROBE, (target, JURA_PORT))
                    except OSError:
                        continue
                sends_left -= 1
                next_send = now + interval
            try:
                data, addr = sock.recvfrom(2048)
            except TimeoutError:
                continue
            # Ignore our own probe echoed back by the kernel.
            if data == SCAN_PROBE:
                continue
            try:
                machine = parse_reply(data, addr[0])
            except ValueError:
                continue
            if machine.address in seen:
                continue
            seen.add(machine.address)
            yield machine
    finally:
        sock.close()


def probe(address: str, timeout: float = 2.0) -> Machine | None:
    """Send a unicast scan probe to a single known IP and parse its reply.

    Newer Jura firmwares (e.g. TT237W) appear to only reply to *broadcast*
    scan probes, not unicast — when that's the case the function returns
    ``None`` even though the machine is reachable. Use :func:`tcp_probe`
    as a fallback to verify reachability over the TCP control port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.bind(("", JURA_PORT))
        except OSError:
            sock.bind(("", 0))
        sock.sendto(SCAN_PROBE, (address, JURA_PORT))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, peer = sock.recvfrom(2048)
            except TimeoutError:
                return None
            if peer[0] != address or data == SCAN_PROBE:
                continue
            try:
                return parse_reply(data, peer[0])
            except ValueError:
                continue
        return None
    finally:
        sock.close()


def tcp_probe(address: str, port: int = JURA_PORT, timeout: float = 2.0) -> bool:
    """Return ``True`` if a TCP handshake to the Jura control port succeeds.

    Useful when the dongle does not reply to UDP scans (e.g. TT237W firmware)
    but accepts TCP connections. A successful return does *not* prove that
    the listener is a Jura machine — pair it with the encrypted ``@HP``
    handshake in :mod:`jura_connect.client` to confirm.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect((address, port))
        except (OSError, TimeoutError):
            return False
        return True
    finally:
        sock.close()


def _local_ipv4_networks() -> list[ipaddress.IPv4Network]:
    """Enumerate IPv4 /24 networks reachable from this host.

    Best-effort, in order of preference:

    1. Parse ``/proc/net/fib_trie`` (Linux) — catches every interface even
       when ``getaddrinfo(gethostname())`` only returns the VPN tunnel IP.
    2. Fall back to ``socket.getaddrinfo(gethostname())``.
    """
    nets: list[ipaddress.IPv4Network] = []

    try:
        import re

        with open("/proc/net/fib_trie", encoding="ascii") as fh:
            text = fh.read()
        # Lines that mark a /24-or-narrower local-host route. We collect
        # the immediately preceding network address line, which sits two
        # lines above ``32 host LOCAL``.
        host_re = re.compile(r"^\s+\|--\s+(\d+\.\d+\.\d+\.\d+)\s*$", re.MULTILINE)
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if "32 host LOCAL" not in line:
                continue
            # Walk back to find the matching IP line.
            for j in range(i - 1, max(-1, i - 6), -1):
                m = host_re.match(lines[j])
                if m:
                    ip = m.group(1)
                    if ip.startswith("127."):
                        break
                    if ip.endswith(".255") or ip.endswith(".0"):
                        break
                    net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                    # Skip point-to-point /32 tunnels (heuristic: no peers
                    # in the same /24). We still include them — the scan
                    # is cheap.
                    if net not in nets:
                        nets.append(net)
                    break
    except (FileNotFoundError, OSError):
        pass

    if not nets:
        try:
            host = socket.gethostname()
            for info in socket.getaddrinfo(host, None):
                family, _, _, _, sockaddr = info
                if family != socket.AF_INET:
                    continue
                ip = sockaddr[0]
                if not isinstance(ip, str) or ip.startswith("127."):
                    continue
                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                if net not in nets:
                    nets.append(net)
        except Exception:  # noqa: BLE001
            pass

    return nets


def scan_tcp(
    networks: Iterable[ipaddress.IPv4Network] | None = None,
    *,
    port: int = JURA_PORT,
    timeout: float = 0.4,
    workers: int = 64,
) -> list[str]:
    """Scan one or more local /24 networks for hosts that accept TCP on ``port``.

    Returns a list of IPv4 addresses (as strings) that completed a TCP
    handshake. Use as a fallback when UDP discovery does not return — the
    dongle still answers TCP. Pair with :func:`jura_connect.client.JuraClient`
    to confirm a hit is actually a coffee machine.
    """
    nets = list(networks) if networks is not None else _local_ipv4_networks()
    targets: list[str] = []
    for net in nets:
        for host in net.hosts():
            targets.append(str(host))

    hits: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(tcp_probe, ip, port, timeout): ip for ip in targets}
        for fut in concurrent.futures.as_completed(futs):
            ip = futs[fut]
            try:
                if fut.result():
                    hits.append(ip)
            except Exception:  # noqa: BLE001
                continue
    hits.sort(key=lambda s: tuple(int(x) for x in s.split(".")))
    return hits


# Status probe (unicast) command. Mirrors UDPCommandStatus.
def status_probe_packet(address: str) -> bytes:
    """Build the UDP status request packet for a known IP."""
    octets = socket.inet_aton(address)
    return bytes.fromhex("0010A5F3") + octets + bytes(8)


# Silence unused import warning when struct isn't needed at runtime.
_ = struct
