import time
import sqlite3
from pathlib import Path

from app.config import settings
from app.crypto import canonical_context


class NonceReplayLedger:
    """In-memory nonce ledger for POC single-use replay protection."""

    def __init__(self, ttl_seconds: int) -> None:
        self.ttl_seconds = ttl_seconds
        self._seen: dict[tuple[str, str, str], float] = {}

    def consume(self, context: dict, key_id: str, nonce: str, now: float | None = None) -> bool:
        current_time = time.time() if now is None else now
        self._prune(current_time)

        ledger_key = (canonical_context(context), key_id, nonce)
        if ledger_key in self._seen:
            return False

        self._seen[ledger_key] = current_time + self.ttl_seconds
        return True

    def _prune(self, now: float) -> None:
        expired = [key for key, expires_at in self._seen.items() if expires_at <= now]
        for key in expired:
            del self._seen[key]


class SQLiteReplayLedger:
    """SQLite-backed replay ledger for durable single-node deployments."""

    def __init__(self, path: str, ttl_seconds: int) -> None:
        self.path = Path(path)
        self.ttl_seconds = ttl_seconds
        if self.path.parent:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def consume(self, context: dict, key_id: str, nonce: str, now: float | None = None) -> bool:
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
                        canonical_context(context),
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

    def _ledger_key(self, context: dict, key_id: str, nonce: str) -> str:
        return canonical_context({
            "context": context,
            "key_id": key_id,
            "nonce": nonce,
        })


def create_replay_ledger():
    if not settings.REPLAY_PROTECTION_ENABLED:
        return None
    if settings.REPLAY_LEDGER_BACKEND == "memory":
        return NonceReplayLedger(settings.REPLAY_WINDOW_SECONDS)
    if settings.REPLAY_LEDGER_BACKEND == "sqlite":
        return SQLiteReplayLedger(
            path=settings.REPLAY_LEDGER_PATH,
            ttl_seconds=settings.REPLAY_WINDOW_SECONDS,
        )
    raise ValueError(f"Unsupported replay ledger backend: {settings.REPLAY_LEDGER_BACKEND}")


replay_ledger = create_replay_ledger()


def apply_replay_protection(result: dict, context: dict) -> dict:
    if not result.get("valid") or replay_ledger is None:
        return result

    if not replay_ledger.consume(context, result["key_id"], result["nonce"]):
        return {
            "valid": False,
            "error": "Replay detected for nonce in this context",
            "nonce": result.get("nonce"),
            "key_id": result.get("key_id"),
        }

    return result
