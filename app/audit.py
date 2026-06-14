from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class AuditEvent:
    event_type: str          # wrap | verify | chat
    success: bool
    ip: str
    duration_ms: float
    details: dict            # event-specific metadata — no raw content, no context values
    user_id: Optional[str] = None   # populated by SSO later
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: str = field(default_factory=lambda: str(uuid4()))


class AuditLogger:
    def __init__(self) -> None:
        self._sinks: list = []

    def add_sink(self, sink) -> None:
        self._sinks.append(sink)

    async def log(self, event: AuditEvent) -> None:
        if not self._sinks:
            return
        results = await asyncio.gather(
            *[s.emit(event) for s in self._sinks],
            return_exceptions=True,
        )
        for sink, result in zip(self._sinks, results):
            if isinstance(result, Exception):
                logger.error("Audit sink %s failed: %s", type(sink).__name__, result)

    async def startup(self) -> None:
        for sink in self._sinks:
            await sink.startup()

    async def shutdown(self) -> None:
        for sink in self._sinks:
            await sink.shutdown()


audit = AuditLogger()
