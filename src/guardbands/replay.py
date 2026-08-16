"""Replay-protection primitives for Guard Band verification.

The core package intentionally has no application settings or process-global
ledger. Applications construct a ledger and inject it at their enforcement
boundary.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Protocol

from .crypto import GuardBandContext, GuardBandResult, _canonical_json_v1


def _canonical_replay_value(value: object) -> str:
    """Preserve pre-v2 ledger keys across a rolling protocol upgrade."""
    return _canonical_json_v1(value)


class ReplayLedger(Protocol):
    """Storage contract for atomically consuming a verified nonce."""

    def consume(
        self,
        context: GuardBandContext,
        key_id: str,
        nonce: str,
        now: float | None = None,
    ) -> bool: ...


class NonceReplayLedger:
    """In-memory nonce ledger for tests and single-process applications."""

    def __init__(self, ttl_seconds: int) -> None:
        self.ttl_seconds = ttl_seconds
        self._seen: dict[tuple[str, str, str], float] = {}

    def consume(
        self,
        context: GuardBandContext,
        key_id: str,
        nonce: str,
        now: float | None = None,
    ) -> bool:
        current_time = time.time() if now is None else now
        self._prune(current_time)

        ledger_key = (_canonical_replay_value(context), key_id, nonce)
        if ledger_key in self._seen:
            return False

        self._seen[ledger_key] = current_time + self.ttl_seconds
        return True

    def _prune(self, now: float) -> None:
        expired = [key for key, expires_at in self._seen.items() if expires_at <= now]
        for key in expired:
            del self._seen[key]


class SQLiteReplayLedger:
    """SQLite-backed replay ledger for durable single-node applications."""

    def __init__(self, path: str, ttl_seconds: int) -> None:
        self.path = Path(path)
        self.ttl_seconds = ttl_seconds
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def consume(
        self,
        context: GuardBandContext,
        key_id: str,
        nonce: str,
        now: float | None = None,
    ) -> bool:
        current_time = time.time() if now is None else now
        ledger_key = self._ledger_key(context, key_id, nonce)
        expires_at = current_time + self.ttl_seconds

        with self._connect() as conn:
            conn.execute("DELETE FROM replay_nonces WHERE expires_at <= ?", (current_time,))
            try:
                conn.execute(
                    """
                    INSERT INTO replay_nonces (ledger_key, context_value, key_id, nonce, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        ledger_key,
                        _canonical_replay_value(context),
                        key_id,
                        nonce,
                        expires_at,
                    ),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS replay_nonces (
                    ledger_key TEXT PRIMARY KEY,
                    context_value TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_replay_nonces_expires_at "
                "ON replay_nonces (expires_at)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def _ledger_key(self, context: GuardBandContext, key_id: str, nonce: str) -> str:
        return _canonical_replay_value({"context": context, "key_id": key_id, "nonce": nonce})


def apply_replay_protection(
    result: GuardBandResult,
    context: GuardBandContext,
    ledger: ReplayLedger | None,
) -> GuardBandResult:
    """Consume a verified nonce, returning a fail-closed result on replay."""
    if not result.get("valid") or ledger is None:
        return result

    if not ledger.consume(context, result["key_id"], result["nonce"]):
        return {
            "valid": False,
            "error": "Replay detected for nonce in this context",
            "nonce": result.get("nonce"),
            "key_id": result.get("key_id"),
        }

    return result
