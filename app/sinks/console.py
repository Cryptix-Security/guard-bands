import json
import logging

from app.audit import AuditEvent
from app.sinks.base import AuditSink

logger = logging.getLogger("guard_bands.audit")


class ConsoleSink(AuditSink):
    """Always-on sink — emits structured JSON to stdout via the logging subsystem."""

    async def emit(self, event: AuditEvent) -> None:
        record = {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "success": event.success,
            "ip": event.ip,
            "user_id": event.user_id,
            "duration_ms": round(event.duration_ms, 2),
            **event.details,
        }
        if event.success:
            logger.info(json.dumps(record))
        else:
            logger.warning(json.dumps(record))
