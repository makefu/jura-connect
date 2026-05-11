"""CLI behaviour tests around the new ``command`` subcommand.

The CLI is invoked by calling :func:`jura_wifi.__main__.main` directly
with an argv list and capturing stdout via the ``capsys`` fixture, which
keeps the tests fast and avoids spawning subprocesses.
"""

from __future__ import annotations

import json

import pytest

from jura_wifi.__main__ import main


def test_command_list_prints_known_names(capsys) -> None:
    rc = main(["--store", "/dev/null", "command", "--list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "info" in out
    assert "counters" in out
    assert "mem-read <addr>" in out


def test_command_without_name_errors(capsys) -> None:
    rc = main(["--store", "/dev/null", "command"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "command name required" in err


def test_command_runs_info_through_simulator(sim, tmp_path, capsys) -> None:
    host, port = sim.address
    store_path = tmp_path / "creds.json"

    # Pair via the CLI's library so we have a stored credential keyed by name.
    from jura_wifi.client import JuraClient
    from jura_wifi.credentials import CredentialStore, MachineCredentials

    c = JuraClient(host, port=port, conn_id="cli-tests", auth_hash="")
    r = c.pair(timeout=2.0)
    c.close()
    assert r.new_hash
    CredentialStore(store_path).put(
        MachineCredentials(
            name="Sim",
            address=f"{host}:{port}",
            conn_id="cli-tests",
            auth_hash=r.new_hash,
        )
    )

    # Now exercise the CLI against the running simulator. Note: --address
    # overrides the name lookup so we can target the simulator's port.
    rc = main([
        "--store", str(store_path),
        "command",
        "--name", "Sim",
        "--address", f"{host}:{port}",
        "--auth-hash", r.new_hash,
        "--conn-id", "cli-tests",
        "--handshake-timeout", "3",
        "--cmd-timeout", "3",
        "info",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "machine info" in out
    assert "active alerts" in out
    assert "no_beans" in out


def test_command_missing_credentials_errors(capsys, tmp_path) -> None:
    rc = main([
        "--store", str(tmp_path / "empty.json"),
        "command",
        "info",
        "--name", "DoesNotExist",
    ])
    assert rc == 2
    err = capsys.readouterr().err
    assert "no address" in err or "no auth-hash" in err


def test_version_flag(capsys) -> None:
    from jura_wifi import __version__

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert __version__ in (captured.out + captured.err)


def test_creds_json_output(capsys, tmp_path) -> None:
    from jura_wifi.credentials import CredentialStore, MachineCredentials

    p = tmp_path / "creds.json"
    CredentialStore(p).put(
        MachineCredentials("a", "1.2.3.4", "cid", "h" * 64)
    )
    rc = main(["--store", str(p), "creds", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["name"] == "a"
    assert payload[0]["address"] == "1.2.3.4"
