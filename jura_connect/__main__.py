"""Command-line interface for ``jura_connect``.

Subcommands::

    discover         broadcast for machines on the LAN (TCP fallback)
    probe <ip>       send a unicast UDP scan probe to a known IP
    pair <ip>        run the unset-PIN pairing flow and persist the hash
    command <name>   run a named read command against a paired machine
    creds            inspect or remove stored credentials

Named commands (use ``command --list`` to see them, or
``jura_connect.commands.list_commands()`` from Python) are defined in
:mod:`jura_connect.commands`. Destructive process commands are
intentionally absent — for those use ``command raw '@…'`` with
explicit intent.

The pairing hash is written to ``$XDG_DATA_HOME/jura-connect/credentials.json``
(see :mod:`jura_connect.credentials`). Pass ``--store`` to override.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from .client import (
    DEFAULT_CONN_ID,
    DEFAULT_PAIR_TIMEOUT,
    HandshakeError,
    JuraClient,
)
from .commands import CommandError, DestructiveCommandError, list_commands, run_named
from .credentials import CredentialStore, MachineCredentials, default_path
from .discovery import JURA_PORT, discover, probe, scan_tcp
from .profile import (
    MachineProfile,
    known_machine_names,
    list_profile_codes,
    load_profile,
    lookup_by_article_number,
    search_by_friendly_name,
)


def _resolve_machine(args: argparse.Namespace) -> MachineCredentials | None:
    """Look up stored credentials for ``--name`` if any."""
    if not getattr(args, "name", None):
        return None
    store = CredentialStore(getattr(args, "store", None))
    return store.get(args.name)


def _split_host_port(addr: str, *, default_port: int = JURA_PORT) -> tuple[str, int]:
    """Split ``host[:port]`` into ``(host, port)``; only used by the CLI."""
    if ":" in addr:
        host, _, port = addr.rpartition(":")
        try:
            return host, int(port)
        except ValueError as exc:
            raise SystemExit(
                f"bad address: {addr!r} (expected host or host:port)"
            ) from exc
    return addr, default_port


# --------------------------------------------------------------------- #
# discover / probe
# --------------------------------------------------------------------- #


def cmd_discover(args: argparse.Namespace) -> int:
    print(f"broadcasting on UDP/{JURA_PORT} for {args.timeout:.1f}s ...")
    any_found = False
    for m in discover(timeout=args.timeout, repeats=args.repeats):
        any_found = True
        print(m)
        if args.verbose:
            print(f"  status_hex={m.status_hex}")
            print(f"  raw[0:32]={m.raw[:32].hex()}")
    if any_found:
        return 0
    if args.tcp_fallback:
        print(f"no UDP replies; sweeping TCP/{JURA_PORT} on local networks ...")
        hits = scan_tcp(timeout=args.tcp_timeout)
        if not hits:
            print("no hosts accepted TCP either", file=sys.stderr)
            return 1
        for ip in hits:
            print(f"tcp/{JURA_PORT} open -> {ip}  (try: jura-connect pair {ip})")
        return 0
    print("no machines responded", file=sys.stderr)
    return 1


def cmd_probe(args: argparse.Namespace) -> int:
    m = probe(args.address, timeout=args.timeout)
    if m is None:
        print(f"no UDP reply from {args.address}", file=sys.stderr)
        return 1
    print(m)
    return 0


# --------------------------------------------------------------------- #
# pair
# --------------------------------------------------------------------- #


def _resolve_machine_type(explicit: str | None, address: str) -> tuple[str | None, str]:
    """Pick the EF code for a freshly paired machine.

    Returns ``(code, source)`` where ``source`` describes how the code
    was chosen ("explicit", "discovery", "unknown"). The explicit flag
    wins; otherwise we attempt a UDP probe of the address and look the
    article number up in JOE_MACHINES.TXT. TT237W firmware doesn't
    reply to unicast UDP, so on the S8 EB ``--machine-type`` is the
    practical path.
    """
    if explicit:
        return explicit, "explicit"
    host, _, _ = address.partition(":")
    try:
        m = probe(host, timeout=2.0)
    except Exception:  # noqa: BLE001
        m = None
    if m is None:
        return None, "unknown"
    entry = lookup_by_article_number(m.article_number)
    if entry is None:
        return None, "unknown"
    return entry.ef_code, "discovery"


def cmd_pair(args: argparse.Namespace) -> int:
    store = CredentialStore(args.store)
    conn_id = args.conn_id or JuraClient.random_conn_id()
    client = JuraClient(args.address, conn_id=conn_id, auth_hash="")
    print(f"connecting to {args.address}:{JURA_PORT} as conn-id {conn_id!r}")
    print("look at the coffee machine -- a 'Connect' prompt should appear.")
    try:
        result = client.pair(
            timeout=args.timeout,
            on_user_prompt=lambda msg: print(f"  -> {msg}"),
        )
    except HandshakeError as exc:
        print(f"pair failed: {exc}", file=sys.stderr)
        client.close()
        return 2
    print(f"handshake -> {result.state}  ({result.code})")
    if result.state != "CORRECT":
        client.close()
        return 2
    if not result.new_hash:
        print(
            "machine accepted us without issuing a new hash -- nothing to save.",
            file=sys.stderr,
        )
        client.close()
        return 0
    machine_type, source = _resolve_machine_type(args.machine_type, args.address)
    if machine_type:
        try:
            load_profile(machine_type)
        except KeyError:
            print(
                f"warning: machine type {machine_type!r} not in the bundled "
                "registry; storing it anyway. Use `jura-connect machine-types` "
                "to see known codes.",
                file=sys.stderr,
            )
        print(f"machine type   : {machine_type}  ({source})")
    else:
        print(
            "machine type   : (unknown — TT237W firmware doesn't answer UDP "
            "discovery; set it with `jura-connect set-machine-type --name "
            f"{args.name} <EF_code>` after pairing)",
            file=sys.stderr,
        )
    creds = MachineCredentials(
        name=args.name,
        address=args.address,
        conn_id=conn_id,
        auth_hash=result.new_hash,
        machine_type=machine_type,
    )
    store.put(creds)
    print(f"saved credentials for {args.name!r} -> {store.path}")
    client.close()
    return 0


# --------------------------------------------------------------------- #
# command (run named read commands against an already-paired machine)
# --------------------------------------------------------------------- #


def _print_command_list() -> None:
    specs = list_commands()
    width = max(len(s.usage()) for s in specs)
    safe = [s for s in specs if not s.destructive]
    destructive = [s for s in specs if s.destructive]
    print("available commands:")
    print("  read-only:")
    for s in safe:
        print(f"    {s.usage().ljust(width)}  {s.description}")
    if destructive:
        print()
        print(
            "  destructive (require --allow-destructive-commands; "
            "see 'jura-connect command --help'):"
        )
        for s in destructive:
            print(f"    {s.usage().ljust(width)}  {s.description}")


def cmd_command(args: argparse.Namespace) -> int:
    if args.list:
        _print_command_list()
        return 0
    if not args.command:
        print(
            "command name required (use --list to see all)",
            file=sys.stderr,
        )
        return 2

    # In --json mode, stdout is reserved for the JSON response. Every
    # other piece of human-readable progress (handshake banner, watch
    # announcement, watched frames) is routed to stderr so the result
    # on stdout is parseable verbatim.
    info_stream = sys.stderr if args.json else sys.stdout

    creds = _resolve_machine(args)
    address = args.address or (creds.address if creds else None)
    conn_id = args.conn_id or (creds.conn_id if creds else DEFAULT_CONN_ID)
    auth_hash = args.auth_hash or (creds.auth_hash if creds else "")
    if not address:
        print("no address: pass --address or --name", file=sys.stderr)
        return 2
    if not auth_hash:
        print(
            "no auth-hash: run 'jura-connect pair' first or pass --auth-hash",
            file=sys.stderr,
        )
        return 2

    host, port = _split_host_port(address)
    machine_type = args.machine_type or (creds.machine_type if creds else None)
    profile: MachineProfile | None = None
    if machine_type:
        try:
            profile = load_profile(machine_type)
        except KeyError:
            print(
                f"warning: machine type {machine_type!r} not in registry; "
                "falling back to the EF536 baseline.",
                file=sys.stderr,
            )
    client = JuraClient(
        host,
        port=port,
        conn_id=conn_id,
        auth_hash=auth_hash,
        profile=profile,
    )
    try:
        handshake = client.connect(timeout=args.handshake_timeout)
    except HandshakeError as exc:
        print(f"connect failed: {exc}", file=sys.stderr)
        client.close()
        return 2
    print(f"handshake -> {handshake.state}  ({handshake.code})", file=info_stream)
    if handshake.state != "CORRECT":
        client.close()
        return 2

    try:
        try:
            result = run_named(
                client,
                args.command,
                args.args,
                timeout=args.cmd_timeout,
                allow_destructive=args.allow_destructive_commands,
            )
        except DestructiveCommandError as exc:
            # Print the gated-command explanation verbatim. It already
            # tells the user what the command does and how to override.
            print(f"refused: {exc}", file=sys.stderr)
            return 2
        except CommandError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except TimeoutError as exc:
            print(f"timeout: {exc}", file=sys.stderr)
            return 2
        if args.json:
            json.dump(result.to_dict(), sys.stdout, indent=2, sort_keys=False)
            sys.stdout.write("\n")
        else:
            print(result.format())
        if args.watch:
            print(f"watching status for {args.watch:.1f}s ...", file=info_stream)
            until = time.monotonic() + args.watch
            for frame in client.iter_frames(until=until):
                print(f"<-- {frame!r}", file=info_stream)
    finally:
        client.close()
    return 0


# --------------------------------------------------------------------- #
# creds
# --------------------------------------------------------------------- #


def cmd_creds(args: argparse.Namespace) -> int:
    store = CredentialStore(args.store)
    if args.delete:
        if store.remove(args.delete):
            print(f"removed {args.delete!r} from {store.path}")
            return 0
        print(f"{args.delete!r} not found in {store.path}", file=sys.stderr)
        return 1
    rows = store.entries()
    if not rows:
        print(f"(no credentials in {store.path})")
        return 0
    if args.json:
        print(json.dumps([r.to_dict() | {"name": r.name} for r in rows], indent=2))
        return 0
    print(f"# {store.path}")
    for r in rows:
        mtype = r.machine_type or "(unset)"
        print(
            f"{r.name:20s}  {r.address:15s}  conn-id={r.conn_id}  "
            f"hash={r.auth_hash[:16]}...  type={mtype}  paired_at={r.paired_at}"
        )
    return 0


# --------------------------------------------------------------------- #
# set-machine-type
# --------------------------------------------------------------------- #


def cmd_set_machine_type(args: argparse.Namespace) -> int:
    store = CredentialStore(args.store)
    try:
        load_profile(args.machine_type)
    except KeyError:
        print(
            f"unknown machine type {args.machine_type!r}. Use "
            "`jura-connect machine-types` to see known codes.",
            file=sys.stderr,
        )
        return 2
    if not store.set_machine_type(args.name, args.machine_type):
        print(
            f"{args.name!r} not found in {store.path}",
            file=sys.stderr,
        )
        return 1
    print(f"set {args.name!r} machine type to {args.machine_type} -> {store.path}")
    return 0


# --------------------------------------------------------------------- #
# machine-types — list known EF codes / friendly names
# --------------------------------------------------------------------- #


def cmd_machine_types(args: argparse.Namespace) -> int:
    if args.filter:
        rows = search_by_friendly_name(args.filter)
        if not rows:
            print(
                f"no machines match {args.filter!r}",
                file=sys.stderr,
            )
            return 1
        if args.json:
            print(
                json.dumps(
                    [
                        {
                            "article_number": r.article_number,
                            "friendly_name": r.friendly_name,
                            "ef_code": r.ef_code,
                            "type_id": r.type_id,
                        }
                        for r in rows
                    ],
                    indent=2,
                )
            )
            return 0
        print(f"# matches for {args.filter!r}:")
        for r in rows:
            print(f"  {r.article_number:>6d}  {r.friendly_name:30s}  {r.ef_code}")
        return 0

    names = known_machine_names()
    bundled = set(list_profile_codes())
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "friendly_name": fn,
                        "ef_code": ef,
                        "bundled_profile": ef in bundled,
                    }
                    for fn, ef in names
                ],
                indent=2,
            )
        )
        return 0
    print(
        f"# {len(names)} known machines ({len(bundled)} with bundled XML "
        "profiles). Use --filter to narrow."
    )
    for friendly, ef in names:
        marker = " " if ef in bundled else "?"
        print(f"  {marker}  {friendly:30s}  {ef}")
    print(
        "\n? = no bundled XML profile (status / product names will fall back "
        "to the EF536 baseline)."
    )
    return 0


# --------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jura-connect")
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    p.add_argument(
        "--store",
        default=str(default_path()),
        help="credentials JSON file (default: %(default)s)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="broadcast for machines on the LAN")
    d.add_argument("-v", "--verbose", action="store_true")
    d.add_argument("--timeout", type=float, default=5.0)
    d.add_argument("--repeats", type=int, default=4)
    d.add_argument(
        "--tcp-fallback",
        action="store_true",
        default=True,
        help="when UDP yields nothing, scan TCP/51515 on local /24s",
    )
    d.add_argument(
        "--no-tcp-fallback",
        action="store_false",
        dest="tcp_fallback",
        help="disable the TCP fallback sweep",
    )
    d.add_argument("--tcp-timeout", type=float, default=0.4)
    d.set_defaults(func=cmd_discover)

    pr = sub.add_parser("probe", help="unicast UDP scan probe to a known IP")
    pr.add_argument("address")
    pr.add_argument("--timeout", type=float, default=2.0)
    pr.set_defaults(func=cmd_probe)

    pa = sub.add_parser(
        "pair",
        help="run the unset-PIN pair flow; user accepts on the machine",
    )
    pa.add_argument("address")
    pa.add_argument(
        "--name",
        required=True,
        help="local nickname to store credentials under (e.g. 'Kaffeebert')",
    )
    pa.add_argument(
        "--conn-id",
        help="connection identifier the dongle will remember (auto-generated by default)",
    )
    pa.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_PAIR_TIMEOUT,
        help="max time to wait for user to press OK on the machine",
    )
    pa.add_argument(
        "--machine-type",
        help=(
            "EF code of the machine variant (e.g. 'EF1091' for the S8 EB). "
            "Without this flag the pair flow attempts UDP discovery to "
            "auto-detect, which only works on older firmwares — set it "
            "explicitly on TT237W. See `jura-connect machine-types`."
        ),
    )
    pa.set_defaults(func=cmd_pair)

    cm = sub.add_parser(
        "command",
        help="run a named read command (info, counters, status, ...)",
    )
    cm.add_argument("command", nargs="?", help="command name; --list shows the catalog")
    cm.add_argument("args", nargs="*", help="positional arguments for the command")
    cm.add_argument(
        "--list",
        action="store_true",
        help="list available commands with their arguments and exit",
    )
    cm.add_argument(
        "--name",
        help="nickname to look up in the credential store",
    )
    cm.add_argument(
        "--address",
        "-a",
        help="machine IP (overrides --name lookup)",
    )
    cm.add_argument("--conn-id")
    cm.add_argument("--auth-hash")
    cm.add_argument(
        "--machine-type",
        help=(
            "EF code overriding the stored credential's machine_type "
            "(see `jura-connect machine-types`)"
        ),
    )
    cm.add_argument("--handshake-timeout", type=float, default=15.0)
    cm.add_argument("--cmd-timeout", type=float, default=6.0)
    cm.add_argument(
        "--watch",
        type=float,
        default=0.0,
        help="after the command, listen N seconds for unsolicited frames",
    )
    cm.add_argument(
        "--json",
        action="store_true",
        help=(
            "emit the command result as JSON on stdout. All progress, "
            "handshake banner, watched frames, and error messages go to "
            "stderr so stdout is parseable verbatim."
        ),
    )
    cm.add_argument(
        "--allow-destructive-commands",
        action="store_true",
        help=(
            "explicitly permit destructive commands "
            "(clean / decalc / set-pin / set-ssid / reset-counters / …). "
            "Without this flag any destructive command is refused with a "
            "warning. These can consume supplies, lock you out of the "
            "machine, or render the dongle unreachable; use only when you "
            "really mean it."
        ),
    )
    cm.set_defaults(func=cmd_command)

    cr = sub.add_parser("creds", help="inspect or delete stored credentials")
    cr.add_argument("--json", action="store_true")
    cr.add_argument("--delete", metavar="NAME", help="remove the entry for NAME")
    cr.set_defaults(func=cmd_creds)

    smt = sub.add_parser(
        "set-machine-type",
        help="retro-fit a machine_type onto an existing paired machine",
    )
    smt.add_argument("--name", required=True, help="nickname in the credential store")
    smt.add_argument(
        "machine_type",
        help="EF code, e.g. EF1091 (S8 EB). See `machine-types`.",
    )
    smt.set_defaults(func=cmd_set_machine_type)

    mt = sub.add_parser(
        "machine-types",
        help="list known Jura machines and their EF codes",
    )
    mt.add_argument(
        "--filter",
        help="case-insensitive substring filter on the friendly name (e.g. 'S8')",
    )
    mt.add_argument("--json", action="store_true")
    mt.set_defaults(func=cmd_machine_types)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
