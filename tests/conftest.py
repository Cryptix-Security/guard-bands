import os

os.environ.setdefault("SECRET_KEY", "pytest-secret-key")
os.environ.setdefault("ANTHROPIC_API_KEY", "pytest-anthropic-key")
os.environ.setdefault("SSO_ENABLED", "false")

