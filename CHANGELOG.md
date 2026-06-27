# Changelog

## v0.2.0-poc - 2026-06-27

- Added SQLite-backed persistent replay ledger configuration for single-node pilots.
- Added authorization helper examples for role, tenant, user, and policy-path checks.
- Added a reference support-ticket FastAPI app and `make reference-demo`.
- Added production deployment, authorization, and reference-app documentation.
- Added FastAPI Guard Band verification middleware for protected request-body routes.
- Added an API-key-free FastAPI demo runnable with `make demo`.
- Added parser and verification micro-benchmarks runnable with `make bench`.
- Added architecture/threat-model documentation and operational limits guidance.
- Expanded integration documentation around FastAPI instead of proxy-based integrations.
- Added tests for FastAPI middleware enforcement and unsupported sensitive tool calls.

## v0.1.0-poc

- Converted security checks from a manual script into a pytest suite.
- Added GitHub Actions CI for Python 3.11 and 3.12.
- Pinned Python dependency versions in `requirements.txt`.
- Added canonical JSON serialization for Guard Band MAC payloads.
- Included nonce values in authenticated MAC input.
- Added app-side enforcement that guard-banded chat content must be verified before final model responses are accepted.
- Added API curl examples, key-management expectations, and replay-protection examples.
- Updated vulnerable dependency pins for `cryptography`, `python-dotenv`, `requests`, and `pytest`.
- Added Dependabot configuration for future pip and GitHub Actions maintenance updates.
