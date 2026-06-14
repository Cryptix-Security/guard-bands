import json
import logging

import asyncpg

from app.audit import AuditEvent
from app.sinks.base import AuditSink

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id          UUID PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type  TEXT NOT NULL,
    success     BOOLEAN NOT NULL,
    ip          TEXT,
    user_id     TEXT,
    duration_ms REAL,
    details     JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_ts        ON audit_events (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_type      ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_failures  ON audit_events (timestamp DESC) WHERE NOT success;
"""

_INSERT = """
INSERT INTO audit_events (id, timestamp, event_type, success, ip, user_id, duration_ms, details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
"""


class PostgresSink(AuditSink):
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def startup(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=5)
        async with self._pool.acquire() as conn:
            await conn.execute(_SCHEMA)
        logger.info("PostgreSQL audit sink ready")

    async def shutdown(self) -> None:
        if self._pool:
            await self._pool.close()

    async def emit(self, event: AuditEvent) -> None:
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                _INSERT,
                event.id,
                event.timestamp,
                event.event_type,
                event.success,
                event.ip,
                event.user_id,
                event.duration_ms,
                json.dumps(event.details),
            )
