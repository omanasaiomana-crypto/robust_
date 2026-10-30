"""Server-Sent Events (SSE) broadcaster for IdentityShield v3.

Follows context.md Section 17 & PRD §19:
- Broadcaster with per-client asyncio queues (bounded at 1,000, drop oldest on full)
- Heartbeat comment (': heartbeat\\n\\n') every 15 seconds
- Supported event types: 'trace', 'risk', 'case', 'action', 'metrics'
- GET /api/v3/stream returns text/event-stream (EventSource compatible)
- Thread-safe event distribution from background workers and topic bus
"""
import asyncio
import json
import logging
import threading
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

log = logging.getLogger("identityshield.sse")

CLIENT_QUEUE_MAX = 1000
HEARTBEAT_INTERVAL = 15.0


class SSEBroadcaster:
    """Thread-safe multi-client event broadcaster for Server-Sent Events."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._clients: set[asyncio.Queue[str]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register active asyncio event loop for threadsafe dispatch."""
        with self._lock:
            self._loop = loop

    def subscribe(self) -> asyncio.Queue[str]:
        """Create and register a bounded asyncio queue for a new client."""
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=CLIENT_QUEUE_MAX)
        with self._lock:
            self._clients.add(q)
            log.debug("SSE client connected; total clients: %d", len(self._clients))
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        """Unregister a client queue on disconnect."""
        with self._lock:
            self._clients.discard(q)
            log.debug("SSE client disconnected; remaining clients: %d", len(self._clients))

    def publish(self, event_type: str, data: Any) -> None:
        """Format and dispatch an event payload to all connected clients."""
        try:
            if isinstance(data, (dict, list)):
                payload_str = json.dumps(data, sort_keys=True)
            elif hasattr(data, "model_dump_json"):
                payload_str = data.model_dump_json()
            elif hasattr(data, "to_dict"):
                payload_str = json.dumps(data.to_dict(), sort_keys=True)
            else:
                payload_str = json.dumps(data)
        except Exception as exc:  # noqa: BLE001
            log.debug("Failed to serialize SSE payload: %s", exc)
            payload_str = json.dumps({"raw": str(data)})

        # Standard SSE wire format
        msg = f"event: {event_type}\ndata: {payload_str}\n\n"

        with self._lock:
            targets = list(self._clients)
            loop = self._loop

        for q in targets:
            try:
                if loop and loop.is_running():
                    loop.call_soon_threadsafe(self._push_to_queue, q, msg)
                else:
                    self._push_to_queue(q, msg)
            except Exception as exc:  # noqa: BLE001
                log.debug("Error delivering SSE message: %s", exc)

    @staticmethod
    def _push_to_queue(q: asyncio.Queue[str], msg: str) -> None:
        """Push message to queue, dropping oldest message if full."""
        if q.full():
            try:
                q.get_nowait()
            except asyncio.QueueEmpty:
                pass
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass

    async def event_generator(self, q: asyncio.Queue[str]) -> AsyncGenerator[str, None]:
        """Yield events as they arrive, emitting heartbeat comment every 15s."""
        try:
            # Send initial connected event
            yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=HEARTBEAT_INTERVAL)
                    yield msg
                except TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            self.unsubscribe(q)


# Global singleton instance
broadcaster = SSEBroadcaster()


router = APIRouter()


@router.get("/stream")
async def sse_stream() -> StreamingResponse:
    """Server-Sent Events text/event-stream endpoint."""
    loop = asyncio.get_running_loop()
    broadcaster.set_loop(loop)
    client_queue = broadcaster.subscribe()
    return StreamingResponse(
        broadcaster.event_generator(client_queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
