# Guard Bands

[![CI](https://github.com/Cryptix-Security/guard-bands/actions/workflows/ci.yml/badge.svg)](https://github.com/Cryptix-Security/guard-bands/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Cryptix-Security/guard-bands/actions/workflows/codeql.yml/badge.svg)](https://github.com/Cryptix-Security/guard-bands/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

**A small Python library for cryptographically separating untrusted LLM
content from trusted instructions and tool execution.**

Guard Bands wraps untrusted text in authenticated markers. Verification proves
that the content and its context, issuer, key id, protocol version, and lifetime
have not changed since a trusted signer created the band.

This repository contains only the reusable boundary library and its optional
FastAPI middleware. The API service, dual-channel demonstration, SSO, audit
sinks, LLM integrations, and deployment assets live in
[`Cryptix-Security/guard-bands-reference`](https://github.com/Cryptix-Security/guard-bands-reference).

## Install

```bash
python -m pip install guard-bands
```

For the FastAPI integration:

```bash
python -m pip install 'guard-bands[fastapi]'
```

Until version `0.8.0` is published, install directly from the repository:

```bash
python -m pip install 'guard-bands[fastapi] @ git+https://github.com/Cryptix-Security/guard-bands.git'
```

## Wrap and verify

```python
from guardbands import GuardBandCrypto

crypto = GuardBandCrypto(b"replace-with-a-secret-from-your-key-manager")
context = {
    "tenant_id": "tenant-a",
    "request_id": "req-001",
    "policy_path": "support.summarize",
}

wrapped = crypto.wrap_content(
    "Untrusted document text",
    context,
    issuer="document-ingress",
)
result = crypto.extract_and_verify(wrapped, context)

if not result["valid"]:
    raise ValueError(result["error"])

content = result["content"]
```

HMAC-SHA256 is supported for single-service deployments. Ed25519 private and
public keys provide signing/verification role separation for split-trust
deployments.

## FastAPI middleware

```python
from fastapi import FastAPI, Request

from guardbands import GuardBandCrypto
from guardbands.integrations.fastapi import (
    GuardBandVerificationMiddleware,
    guard_band_verification,
)

app = FastAPI()
crypto = GuardBandCrypto(b"replace-with-a-secret-from-your-key-manager")

app.add_middleware(
    GuardBandVerificationMiddleware,
    crypto=crypto,
    required_paths={"/tool-input"},
)


@app.post("/tool-input")
async def tool_input(payload: dict, request: Request):
    verification = guard_band_verification(request)
    return {"verified_content": verification["content"]}
```

The middleware verifies the configured JSON body field before the handler
runs, rejects malformed or oversized bodies, and stores the verification
result on `request.state`. Replay protection is opt-in and explicitly injected
with the `replay_ledger` argument.

## Security boundary

Guard Bands proves integrity, provenance, freshness, and context binding. It
does **not** prove that signed content is true, benign, authorized, or safe for
a model to follow. Treat verified content as data, not authority, and retain
normal authorization, least-privilege tools, output validation, monitoring,
and human approval where appropriate.

See:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/CONTEXT_SERIALIZATION.md`](docs/CONTEXT_SERIALIZATION.md)
- [`docs/KEY_MANAGEMENT.md`](docs/KEY_MANAGEMENT.md)
- [`docs/REPLAY_PROTECTION.md`](docs/REPLAY_PROTECTION.md)
- [`docs/LIMITS.md`](docs/LIMITS.md)

## Development

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest
```

The test suite includes HMAC and Ed25519 behavior, context and metadata
tampering, key rotation, expiry, replay ledgers, strict parser fuzzing, and
FastAPI enforcement.

## Status

Guard Bands remains an experimental security mechanism. Protocol or API
changes may occur before `1.0.0`; wire-format changes are called out explicitly
in the changelog.
