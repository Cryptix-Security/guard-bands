import json
import sys

from app.audit import AuditEvent
from app.sinks.base import AuditSink


class ConsoleSink(AuditSink):
    """Always-on sink — writes one JSON object per audit event to stdout.

    Avoids the Python logging subsystem so events always appear regardless of
    the host logging configuration (uvicorn, gunicorn, etc.).  Pipe stdout to
    your log aggregator or redirect to a file as needed.
    """

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
        print(json.dumps(record), file=sys.stdout, flush=True)
