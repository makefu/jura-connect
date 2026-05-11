"""Handshake state transitions: CORRECT / WRONG_PIN / WRONG_HASH / ABORTED.

These talk to the in-tree simulator over a real loopback TCP socket; no
mocks. The simulator and client share the same crypto module, so a
mis-encoded byte on either side would surface as a test failure.
"""

from __future__ import annotations

import pytest

from jura_connect.client import HandshakeError, JuraClient


def test_pair_succeeds_with_empty_hash_and_yields_a_hash(sim) -> None:
    host, port = sim.address
    client = JuraClient(host, port=port, conn_id="device-A", auth_hash="")
    result = client.pair(timeout=2.0)
    assert result.state == "CORRECT"
    assert result.new_hash is not None
    assert len(result.new_hash) == 64
    client.close()
    # Simulator recorded the @HP we sent.
    assert any(b"@HP:" in c for c in sim.sent_commands)


def test_subsequent_connect_with_stored_hash_returns_plain_hp4(sim) -> None:
    host, port = sim.address
    a = JuraClient(host, port=port, conn_id="device-B", auth_hash="")
    r1 = a.pair(timeout=2.0)
    a.close()
    assert r1.state == "CORRECT"
    assert r1.new_hash

    b = JuraClient(host, port=port, conn_id="device-B", auth_hash=r1.new_hash)
    r2 = b.connect(timeout=2.0)
    assert r2.state == "CORRECT"
    assert r2.code == "@hp4"
    assert r2.new_hash is None  # no fresh hash on a known device
    b.close()


def test_wrong_hash_for_known_conn_id(sim) -> None:
    host, port = sim.address
    a = JuraClient(host, port=port, conn_id="device-C", auth_hash="")
    a.pair(timeout=2.0)
    a.close()

    b = JuraClient(host, port=port, conn_id="device-C", auth_hash="DEADBEEF" * 8)
    r = b.connect(timeout=2.0)
    assert r.state == "WRONG_HASH"
    b.close()


def test_aborted_when_empty_hash_after_existing_pairing(sim) -> None:
    host, port = sim.address
    a = JuraClient(host, port=port, conn_id="device-D", auth_hash="")
    a.pair(timeout=2.0)
    a.close()

    # Same conn_id with an empty hash now -> ABORTED (matches Kaffeebert).
    b = JuraClient(host, port=port, conn_id="device-D", auth_hash="")
    # Use connect() (not pair()) so we don't reset the conn-id slot.
    r = b.connect(timeout=2.0)
    assert r.state == "ABORTED"
    b.close()


def test_wrong_pin(sim_factory) -> None:
    sim = sim_factory(pin="1234")
    host, port = sim.address
    client = JuraClient(host, port=port, conn_id="device-E", pin="0000")
    r = client.connect(timeout=2.0)
    assert r.state == "WRONG_PIN"
    client.close()


def test_pair_invokes_user_prompt_callback(sim_factory) -> None:
    sim = sim_factory(require_user_accept=True, user_accept_delay=0.1)
    host, port = sim.address
    prompts: list[str] = []
    client = JuraClient(host, port=port, conn_id="device-F")
    r = client.pair(timeout=3.0, on_user_prompt=prompts.append)
    assert prompts and "press OK" in prompts[0]
    assert r.state == "CORRECT"
    assert r.new_hash
    client.close()


def test_handshake_error_on_garbage_reply() -> None:
    # We need a server that returns something other than @hp4/@hp5 to
    # exercise the unexpected-reply path -- bypass the simulator and
    # write a tiny one-shot socket server inline.
    import socket
    import threading

    from jura_connect import protocol

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def handle():
        c, _ = server.accept()
        reader = protocol.FrameReader(c)
        reader.next_frame(timeout=2.0)
        # Send a syntactically valid frame whose body is nonsense.
        protocol.send_frame(c, b"@@@nope@@@")
        c.close()

    t = threading.Thread(target=handle, daemon=True)
    t.start()
    try:
        client = JuraClient("127.0.0.1", port=port, conn_id="device-G")
        with pytest.raises(HandshakeError):
            client.connect(timeout=2.0)
        client.close()
    finally:
        server.close()
        t.join(timeout=2.0)
