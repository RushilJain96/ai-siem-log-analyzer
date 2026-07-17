"""Unit tests for api/realtime.py (the WebSocket ConnectionManager).

The async methods are driven via asyncio.run() inside sync tests, so no
pytest-asyncio/anyio plugin config is needed and CI stays simple. A
FakeWS stands in for a real Starlette WebSocket — the manager only needs
accept() and send_json(). The true end-to-end (real uvicorn, real
browser client) is verified manually; these lock the manager's logic:
registration, disconnect, fan-out, and dead-client eviction.
"""
import asyncio

from api.realtime import ConnectionManager


class FakeWS:
    """Minimal async stand-in for a Starlette WebSocket."""

    def __init__(self, fail_on_send: bool = False) -> None:
        self.sent: list = []
        self.accepted = False
        self.fail_on_send = fail_on_send

    async def accept(self) -> None:
        self.accepted = True

    async def send_json(self, data) -> None:
        if self.fail_on_send:
            raise RuntimeError("client is gone")
        self.sent.append(data)


def test_connect_accepts_and_registers():
    mgr = ConnectionManager()
    ws = FakeWS()
    asyncio.run(mgr.connect(ws))
    assert ws.accepted is True
    assert mgr.connection_count == 1


def test_disconnect_removes_client():
    mgr = ConnectionManager()
    ws = FakeWS()
    asyncio.run(mgr.connect(ws))
    mgr.disconnect(ws)
    assert mgr.connection_count == 0


def test_disconnect_is_idempotent():
    """Disconnecting a client that isn't registered shouldn't raise."""
    mgr = ConnectionManager()
    mgr.disconnect(FakeWS())  # never connected
    assert mgr.connection_count == 0


def test_broadcast_reaches_every_client():
    mgr = ConnectionManager()
    a, b = FakeWS(), FakeWS()
    asyncio.run(mgr.connect(a))
    asyncio.run(mgr.connect(b))

    asyncio.run(mgr.broadcast({"type": "log", "data": {"id": 1}}))

    assert a.sent == [{"type": "log", "data": {"id": 1}}]
    assert b.sent == [{"type": "log", "data": {"id": 1}}]


def test_broadcast_evicts_a_dead_client_but_still_delivers_to_others():
    """A client whose send raises must be dropped without blocking or
    breaking delivery to the healthy clients."""
    mgr = ConnectionManager()
    good = FakeWS()
    dead = FakeWS(fail_on_send=True)
    asyncio.run(mgr.connect(good))
    asyncio.run(mgr.connect(dead))

    asyncio.run(mgr.broadcast({"x": 1}))

    assert good.sent == [{"x": 1}]        # healthy client still got it
    assert mgr.connection_count == 1      # dead client evicted
    assert dead not in mgr._connections


def test_broadcast_threadsafe_noops_without_a_bound_loop():
    """Called from a sync context with no event loop bound (e.g. a unit
    test, or ingest before startup): must not raise."""
    mgr = ConnectionManager()
    asyncio.run(mgr.connect(FakeWS()))
    mgr.broadcast_threadsafe({"x": 1})  # no loop bound -> silent no-op


def test_broadcast_threadsafe_noops_with_no_clients():
    mgr = ConnectionManager()
    mgr.bind_loop(asyncio.new_event_loop())
    mgr.broadcast_threadsafe({"x": 1})  # no clients -> silent no-op


def test_ingest_broadcasts_log_to_connected_dashboard(client):
    """The real Day 9 end-to-end path, exercised through the full app.

    A browser opens /ws, a log is POSTed to /logs/ingest, and the
    browser must receive that log as a {"type": "log"} frame. No trained
    model is needed: we broadcast EVERY log (scored or not), so this
    proves the sync-ingest -> event-loop -> WebSocket bridge end to end,
    not just the manager's units above.

    Runs against the app singleton's real ConnectionManager, whose loop
    was bound by the lifespan when the TestClient context started — the
    same wiring production uses.
    """
    with client.websocket_connect("/ws") as ws:
        resp = client.post(
            "/logs/ingest",
            json={
                "event_time": "2026-01-01T00:00:00",
                "source_ip": "203.0.113.9",
                "event_type": "portscan",
            },
        )
        assert resp.status_code == 201

        message = ws.receive_json()
        assert message["type"] == "log"
        assert message["data"]["id"] == resp.json()["id"]
        assert message["data"]["source_ip"] == "203.0.113.9"
        # top_features always rides along (empty when the log was unscored).
        assert "top_features" in message["data"]
