"""Tests for the JSON credential store and the pair-then-connect flow."""

from __future__ import annotations

import json
import stat

from jura_connect.client import JuraClient
from jura_connect.credentials import CredentialStore, MachineCredentials


def test_store_round_trip(tmp_path) -> None:
    store = CredentialStore(tmp_path / "creds.json")
    creds = MachineCredentials(
        name="Kaffeebert",
        address="192.168.1.42",
        conn_id="device-A",
        auth_hash="A" * 64,
    )
    store.put(creds)
    got = store.get("Kaffeebert")
    assert got is not None
    assert got.address == "192.168.1.42"
    assert got.conn_id == "device-A"
    assert got.auth_hash == "A" * 64
    assert got.paired_at  # filled in automatically

    # File is valid JSON with the documented shape.
    data = json.loads((tmp_path / "creds.json").read_text())
    assert data["version"] == 1
    assert "Kaffeebert" in data["machines"]


def test_store_lists_and_removes(tmp_path) -> None:
    store = CredentialStore(tmp_path / "creds.json")
    store.put(MachineCredentials("a", "10.0.0.1", "cid", "hashA"))
    store.put(MachineCredentials("b", "10.0.0.2", "cid", "hashB"))
    names = [c.name for c in store.list()]
    assert names == ["a", "b"]
    assert store.remove("a") is True
    assert store.remove("a") is False
    assert [c.name for c in store.list()] == ["b"]


def test_store_creates_parent_dirs(tmp_path) -> None:
    nested = tmp_path / "nested" / "dir" / "creds.json"
    store = CredentialStore(nested)
    store.put(MachineCredentials("x", "1.1.1.1", "c", "h"))
    assert nested.exists()


def test_store_file_is_user_readable_only(tmp_path) -> None:
    """The auth hash grants control of the machine; protect the file."""
    p = tmp_path / "creds.json"
    store = CredentialStore(p)
    store.put(MachineCredentials("x", "1.1.1.1", "c", "h"))
    mode = stat.S_IMODE(p.stat().st_mode)
    # rwx-bits for group/other must be off.
    assert mode & 0o077 == 0


def test_pair_then_persist_then_reconnect(sim, tmp_path) -> None:
    """Full workflow: pair via simulator -> save -> reconnect from disk."""
    host, port = sim.address
    store = CredentialStore(tmp_path / "creds.json")

    # Pair
    c = JuraClient(host, port=port, conn_id="user-host", auth_hash="")
    r = c.pair(timeout=2.0)
    c.close()
    assert r.state == "CORRECT"
    assert r.new_hash

    store.put(
        MachineCredentials(
            name="SimMachine",
            address=f"{host}:{port}",
            conn_id="user-host",
            auth_hash=r.new_hash,
        )
    )

    # Reconnect from disk
    loaded = store.get("SimMachine")
    assert loaded is not None
    c2 = JuraClient(host, port=port, conn_id=loaded.conn_id, auth_hash=loaded.auth_hash)
    r2 = c2.connect(timeout=2.0)
    c2.close()
    assert r2.state == "CORRECT"
    assert r2.code == "@hp4"
