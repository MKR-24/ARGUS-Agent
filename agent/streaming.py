"""
Streaming progress events for SSE.
Each agent node puts a progress event into the queue.
The FastAPI SSE endpoint reads from it and streams to the client.
"""

import asyncio
from typing import AsyncGenerator
import json


class InvestigationStream:
    """One stream per investigation run."""

    def __init__(self):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._done = False

    async def emit(self, event: str, data: dict):
        await self._queue.put({"event": event, "data": data})

    async def done(self):
        self._done = True
        await self._queue.put(None)

    async def events(self) -> AsyncGenerator[str, None]:
        while True:
            item = await self._queue.get()
            if item is None:
                break
            yield f"event: {item['event']}\ndata: {json.dumps(item['data'])}\n\n"


# Global registry: alert_id → InvestigationStream
_streams: dict[str, InvestigationStream] = {}


def create_stream(alert_id: str) -> InvestigationStream:
    stream = InvestigationStream()
    _streams[alert_id] = stream
    return stream


def get_stream(alert_id: str) -> InvestigationStream | None:
    return _streams.get(alert_id)


def remove_stream(alert_id: str):
    _streams.pop(alert_id, None)
