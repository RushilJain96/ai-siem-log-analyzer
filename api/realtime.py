"""Real-time WebSocket broadcasting for the live dashboard (Day 9).

Owns the set of connected dashboard WebSocket clients and the machinery
to push messages to all of them.

The tricky part this module exists to solve: POST /logs/ingest is a SYNC
route, which Starlette runs in a worker thread (correct — we use sync
SQLAlchemy, which would block the event loop if the route were async).
But WebSocket connections live ON the event loop. You cannot `await`
a broadcast from a sync route running in a thread.

The bridge (broadcast_threadsafe): capture the running event loop once
at startup (bind_loop, called from the lifespan), then use
asyncio.run_coroutine_threadsafe to schedule the async broadcast onto
that loop from the sync/thread side. Fire-and-forget — ingest must not
block on delivering to dashboards.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class _WebSocketLike(Protocol):
    """The slice of WebSocket this module uses — lets tests substitute a
    plain async fake without a real connection."""

    async def accept(self) -> None: ...
    async def send_json(self, data: Any) -> None: ...


class ConnectionManager:
    """Tracks connected dashboard clients and broadcasts to all of them."""

    def __init__(self) -> None:
        self._connections: set[_WebSocketLike] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Record the app's event loop so sync routes can schedule
        broadcasts onto it. Called once from the startup lifespan."""
        self._loop = loop

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: _WebSocketLike) -> None:
        await websocket.accept()
        self._connections.add(websocket)
        logger.info("Dashboard client connected", extra={"clients": len(self._connections)})

    def disconnect(self, websocket: _WebSocketLike) -> None:
        self._connections.discard(websocket)
        logger.info("Dashboard client disconnected", extra={"clients": len(self._connections)})

    async def broadcast(self, message: dict) -> None:
        """Send `message` to every connected client. A client whose send
        raises (already gone, network drop) is dropped — a dead client
        must never block or break delivery to the others. Iterates a
        snapshot so disconnects during the loop don't mutate the set
        mid-iteration."""
        dead: list[_WebSocketLike] = []
        for ws in list(self._connections):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)

    def broadcast_threadsafe(self, message: dict) -> None:
        """Schedule broadcast() onto the app's event loop from a SYNC
        context (the ingest route's worker thread). Fire-and-forget:
        we don't wait on the returned Future, so ingest returns to the
        client without blocking on dashboard delivery.

        No-ops safely when there's no bound loop or no clients — so
        ingest works identically whether or not a dashboard is watching,
        and unit tests that never start a loop don't error.
        """
        if self._loop is None or not self._connections:
            return
        asyncio.run_coroutine_threadsafe(self.broadcast(message), self._loop)


# Module-level singleton — one manager for the whole app, imported by the
# ingest route (to broadcast) and the WS route (to register clients).
manager = ConnectionManager()
