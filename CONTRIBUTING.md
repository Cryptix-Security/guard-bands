# Contributing

Contributions are welcome, especially threat-model feedback, bypass attempts, tests, docs, and integrations.

## Development

Use Python 3.12 for local development. CI currently tests Python 3.11 and 3.12.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest
```

## Pull Requests

- Keep changes focused.
- Add tests for security-relevant behavior.
- Update docs when changing protocol, context, replay, key, or deployment behavior.
- Do not commit real secrets, tokens, `.env` files, or private infrastructure details.

## Security Changes

Changes touching cryptography, parsing, replay protection, key handling, authentication, audit logging, CI, or dependency pins should receive extra review.

