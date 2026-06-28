import os
import sys
import json

from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Core
    SECRET_KEY: bytes
    KEY_ID: str
    GUARD_BAND_KEYS: dict[str, bytes]
    ANTHROPIC_API_KEY: str
    DEBUG: bool
    GUARD_BAND_TTL_SECONDS: int
    ALLOWED_ORIGINS: list[str]
    REPLAY_PROTECTION_ENABLED: bool
    REPLAY_LEDGER_BACKEND: str
    REPLAY_LEDGER_PATH: str
    REPLAY_WINDOW_SECONDS: int

    # Audit — PostgreSQL
    LOG_POSTGRES_DSN: str

    # Audit — Splunk HEC
    LOG_SPLUNK_HEC_URL: str
    LOG_SPLUNK_HEC_TOKEN: str
    LOG_SPLUNK_INDEX: str
    LOG_SPLUNK_SOURCE: str
    LOG_SPLUNK_SSL_VERIFY: bool

    def __init__(self) -> None:
        raw_key = os.getenv("SECRET_KEY", "")
        if not raw_key:
            sys.exit("FATAL: SECRET_KEY environment variable is not set. "
                     "Generate one with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"")
        self.SECRET_KEY = raw_key.encode("utf-8")
        self.KEY_ID = os.getenv("KEY_ID", "key001")
        self.GUARD_BAND_KEYS = self._load_guard_band_keys(raw_key)

        self.ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
        self.DEBUG = os.getenv("DEBUG", "false").lower() == "true"
        # Lifetime stamped into each wrapped band (authenticated iat/exp). Bands
        # verify as expired past this window, independent of the replay ledger.
        self.GUARD_BAND_TTL_SECONDS = int(os.getenv("GUARD_BAND_TTL_SECONDS", "900"))
        self.REPLAY_PROTECTION_ENABLED = os.getenv("REPLAY_PROTECTION_ENABLED", "false").lower() == "true"
        self.REPLAY_LEDGER_BACKEND = os.getenv("REPLAY_LEDGER_BACKEND", "memory")
        self.REPLAY_LEDGER_PATH = os.getenv("REPLAY_LEDGER_PATH", "data/replay-ledger.sqlite3")
        self.REPLAY_WINDOW_SECONDS = int(os.getenv("REPLAY_WINDOW_SECONDS", "900"))

        origins_raw = os.getenv("ALLOWED_ORIGINS", "")
        self.ALLOWED_ORIGINS = [o.strip() for o in origins_raw.split(",") if o.strip()]

        # Logging sinks (optional — omit to disable)
        self.LOG_POSTGRES_DSN = os.getenv("LOG_POSTGRES_DSN", "")

        self.LOG_SPLUNK_HEC_URL = os.getenv("LOG_SPLUNK_HEC_URL", "")
        self.LOG_SPLUNK_HEC_TOKEN = os.getenv("LOG_SPLUNK_HEC_TOKEN", "")
        self.LOG_SPLUNK_INDEX = os.getenv("LOG_SPLUNK_INDEX", "guard_bands")
        self.LOG_SPLUNK_SOURCE = os.getenv("LOG_SPLUNK_SOURCE", "guard-bands-api")
        self.LOG_SPLUNK_SSL_VERIFY = os.getenv("LOG_SPLUNK_SSL_VERIFY", "true").lower() == "true"

        self.LLM_MODEL = os.getenv("LLM_MODEL", "claude-3-5-haiku-20241022")

        # SSO — set by oauth2-proxy headers; disabled by default for local dev
        # oauth2-proxy --pass-user-headers=true sets X-Forwarded-User / X-Forwarded-Email
        # (--set-xauthrequest is for nginx auth_request mode only — response headers, not upstream)
        self.SSO_ENABLED = os.getenv("SSO_ENABLED", "false").lower() == "true"
        self.SSO_HEADER_USER = os.getenv("SSO_HEADER_USER", "X-Forwarded-User")
        self.SSO_HEADER_EMAIL = os.getenv("SSO_HEADER_EMAIL", "X-Forwarded-Email")

    def _load_guard_band_keys(self, fallback_key: str) -> dict[str, bytes]:
        raw_keys = os.getenv("GUARD_BAND_KEYS", "")
        if not raw_keys:
            return {self.KEY_ID: fallback_key.encode("utf-8")}

        try:
            parsed = json.loads(raw_keys)
        except json.JSONDecodeError as e:
            sys.exit(f"FATAL: GUARD_BAND_KEYS must be a JSON object: {e}")

        if not isinstance(parsed, dict) or not parsed:
            sys.exit("FATAL: GUARD_BAND_KEYS must be a non-empty JSON object")

        keys: dict[str, bytes] = {}
        for key_id, key_value in parsed.items():
            if not isinstance(key_id, str) or not isinstance(key_value, str):
                sys.exit("FATAL: GUARD_BAND_KEYS must map string key ids to string secrets")
            keys[key_id] = key_value.encode("utf-8")
        return keys


settings = Settings()
