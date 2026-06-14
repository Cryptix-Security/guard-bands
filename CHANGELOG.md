# Changelog

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
