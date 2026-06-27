import time

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


replay_ledger = (
    NonceReplayLedger(settings.REPLAY_WINDOW_SECONDS)
    if settings.REPLAY_PROTECTION_ENABLED
    else None
)


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

