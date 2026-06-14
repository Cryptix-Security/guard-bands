import os
import sys

from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Core
    SECRET_KEY: bytes
    ANTHROPIC_API_KEY: str
    DEBUG: bool
    ALLOWED_ORIGINS: list[str]

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

        self.ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
        self.DEBUG = os.getenv("DEBUG", "false").lower() == "true"

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


settings = Settings()
