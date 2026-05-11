"""Command-line interface for ``jura_wifi``.

Subcommands::

    discover         broadcast for machines on the LAN (TCP fallback)
    probe <ip>       send a unicast UDP scan probe to a known IP
    pair <ip>        run the unset-PIN pairing flow and persist the hash
    connect <ip>     re-attach with a stored hash, run read commands
    creds            inspect or remove stored credentials

The pairing hash is written to ``$XDG_DATA_HOME/jura-connect/credentials.json``
(see :mod:`jura_wifi.credentials`). Pass ``--store`` to override.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from .client import (
    DEFAULT_CONN_ID,
    DEFAULT_PAIR_TIMEOUT,
    HandshakeError,
    JuraClient,
    MachineInfo,
)
from .credentials import CredentialStore, MachineCredentials, default_path
from .discovery import JURA_PORT, discover, probe, scan_tcp


def _resolve_machine(args: argparse.Namespace) -> MachineCredentials | None:
    """Look up stored credentials for ``--name`` if any."""
    if not getattr(args, "name", None):
        return None
    store = CredentialStore(getattr(args, "store", None))
    return store.get(args.name)


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
            print(f"tcp/{JURA_PORT} open -> {ip}  (try: jura_wifi pair {ip})")
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
    creds = MachineCredentials(
        name=args.name,
        address=args.address,
        conn_id=conn_id,
        auth_hash=result.new_hash,
    )
    store.put(creds)
    print(f"saved credentials for {args.name!r} -> {store.path}")
    client.close()
    return 0


# --------------------------------------------------------------------- #
# connect (run reads against an already-paired machine)
# --------------------------------------------------------------------- #


def cmd_connect(args: argparse.Namespace) -> int:
    creds = _resolve_machine(args)
    address = args.address or (creds.address if creds else None)
    conn_id = args.conn_id or (creds.conn_id if creds else DEFAULT_CONN_ID)
    auth_hash = args.auth_hash or (creds.auth_hash if creds else "")
    if not address:
        print("no address: pass <address> or set up --name first", file=sys.stderr)
        return 2
    if not auth_hash:
        print(
            "no auth-hash: run `jura_wifi pair` first or pass --auth-hash",
            file=sys.stderr,
        )
        return 2

    client = JuraClient(address, conn_id=conn_id, auth_hash=auth_hash)
    try:
        result = client.connect(timeout=args.handshake_timeout)
    except HandshakeError as exc:
        print(f"connect failed: {exc}", file=sys.stderr)
        client.close()
        return 2
    print(f"handshake -> {result.state}  ({result.code})")
    if result.state != "CORRECT":
        client.close()
        return 2

    try:
        if args.read_info:
            info = client.read_machine_info(timeout=args.cmd_timeout)
            _print_info(info)
        for raw in args.read or []:
            print(f"--> {raw}")
            try:
                reply = client.request(raw, timeout=args.cmd_timeout)
            except TimeoutError as exc:
                print(f"  timeout: {exc}", file=sys.stderr)
                continue
            print(f"<-- {reply!r}")
        if args.watch:
            print(f"watching status for {args.watch:.1f}s ...")
            until = time.monotonic() + args.watch
            for frame in client.iter_frames(until=until):
                print(f"<-- {frame!r}")
    finally:
        client.close()
    return 0


def _print_info(info: MachineInfo) -> None:
    print("== machine info ==")
    print(f"  conn-id        : {info.conn_id}")
    print(f"  handshake state: {info.handshake_state}")
    print(f"  auth-hash      : {info.auth_hash[:16]}...")
    s = info.status
    alerts = ", ".join(s.active_alerts) or "(none)"
    print(f"  status bits    : {s.raw.hex().upper()}")
    print(f"  active alerts  : {alerts}")
    mc = info.maintenance_counters
    print(
        f"  maintenance    : cleaning={mc.cleaning} filter={mc.filter_change} "
        f"decalc={mc.decalc} cappu_rinse={mc.cappu_rinse} "
        f"coffee_rinse={mc.coffee_rinse} cappu_clean={mc.cappu_clean}"
    )
    mp = info.maintenance_percent
    print(
        f"  maintenance %  : cleaning={mp.cleaning} filter={mp.filter_change} "
        f"decalc={mp.decalc}"
    )


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
    rows = store.list()
    if not rows:
        print(f"(no credentials in {store.path})")
        return 0
    if args.json:
        print(json.dumps([r.to_dict() | {"name": r.name} for r in rows], indent=2))
        return 0
    print(f"# {store.path}")
    for r in rows:
        print(
            f"{r.name:20s}  {r.address:15s}  conn-id={r.conn_id}  "
            f"hash={r.auth_hash[:16]}...  paired_at={r.paired_at}"
        )
    return 0


# --------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="jura_wifi")
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
        "--tcp-fallback", action="store_true", default=True,
        help="when UDP yields nothing, scan TCP/51515 on local /24s",
    )
    d.add_argument(
        "--no-tcp-fallback", action="store_false", dest="tcp_fallback",
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
        "--name", required=True,
        help="local nickname to store credentials under (e.g. 'Kaffeebert')",
    )
    pa.add_argument(
        "--conn-id",
        help="connection identifier the dongle will remember (auto-generated by default)",
    )
    pa.add_argument(
        "--timeout", type=float, default=DEFAULT_PAIR_TIMEOUT,
        help="max time to wait for user to press OK on the machine",
    )
    pa.set_defaults(func=cmd_pair)

    c = sub.add_parser(
        "connect", help="re-attach using a stored hash; run read commands"
    )
    c.add_argument("address", nargs="?")
    c.add_argument(
        "--name",
        help="nickname to look up in the credential store",
    )
    c.add_argument("--conn-id")
    c.add_argument("--auth-hash")
    c.add_argument("--handshake-timeout", type=float, default=15.0)
    c.add_argument(
        "--read-info", action="store_true",
        help="fetch status, maintenance counters and maintenance percent",
    )
    c.add_argument(
        "--read", action="append",
        help="extra read command to send (repeat). e.g. --read '@TG:43'",
    )
    c.add_argument("--cmd-timeout", type=float, default=6.0)
    c.add_argument(
        "--watch", type=float, default=0.0,
        help="after reads, listen for N seconds of unsolicited frames",
    )
    c.set_defaults(func=cmd_connect)

    cr = sub.add_parser("creds", help="inspect or delete stored credentials")
    cr.add_argument("--json", action="store_true")
    cr.add_argument(
        "--delete", metavar="NAME", help="remove the entry for NAME"
    )
    cr.set_defaults(func=cmd_creds)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
