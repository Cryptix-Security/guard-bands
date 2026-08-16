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
FastAPI and MCP integrations. The API service, dual-channel demonstration, SSO,
audit sinks, LLM integrations, and deployment assets live in
[`Cryptix-Security/guard-bands-reference`](https://github.com/Cryptix-Security/guard-bands-reference).

## How it works

```text
untrusted source                 trusted application boundary
      |                                      |
      v                                      v
trusted signer -- signed inert data --> verifier -- policy --> model / tool
      ^                                      |
      |                                      v
 signing key                         authorization still required
```

The signer authenticates the exact content, its lifetime, provenance, and the
application context in which it may be used. The verifier reconstructs that
context from trusted application state and fails closed if any authenticated
value has changed. Verification establishes a data boundary; it does not grant
authority or replace normal authorization.

For the design rationale, security claims, threat model, and research status,
read [`docs/RESEARCH.md`](docs/RESEARCH.md). For a concise implementation view,
see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
The normative wire format and cross-language fixtures are in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) and [`conformance/`](conformance/).

## Install

The package is not yet published to PyPI. Install a tagged GitHub release:

```bash
python -m pip install 'guard-bands @ git+https://github.com/Cryptix-Security/guard-bands.git@v0.11.0'
```

For the FastAPI integration:

```bash
python -m pip install 'guard-bands[fastapi] @ git+https://github.com/Cryptix-Security/guard-bands.git@v0.11.0'
```

For the MCP integration:

```bash
python -m pip install 'guard-bands[mcp] @ git+https://github.com/Cryptix-Security/guard-bands.git@v0.11.0'
```

For both optional integrations:

```bash
python -m pip install 'guard-bands[fastapi,mcp] @ git+https://github.com/Cryptix-Security/guard-bands.git@v0.11.0'
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

## MCP tools

The optional MCP 2.x integration signs complete tool arguments and results in
MCP `_meta`, verifies guarded inputs before the tool handler runs, and wraps
textual outputs in visible inert markers before they return to the model.

```python
from mcp import Client
from mcp.server.mcpserver import MCPServer

from guardbands import GuardBandCrypto
from guardbands.integrations.mcp import (
    GuardBandMCPClient,
    GuardBandMCPServerExtension,
    MCPToolPolicy,
    guard_bands_client_capability,
)

crypto = GuardBandCrypto(b"replace-with-a-secret-from-your-key-manager")
policy = MCPToolPolicy(guard_inputs=True, guard_outputs=True)
extension = GuardBandMCPServerExtension(
    crypto,
    audience="support-tools",
    policies={"search_tickets": policy},
)
mcp = MCPServer("support-tools", extensions=[extension])


@mcp.tool()
def search_tickets(query: str) -> dict[str, list[str]]:
    return {"matches": [query]}


async def call_tool():
    async with Client(
        mcp,
        extensions=[guard_bands_client_capability()],
    ) as raw_client:
        client = GuardBandMCPClient(
            raw_client,
            crypto,
            audience="support-tools",
            policies={"search_tickets": policy},
        )
        return await client.call_tool("search_tickets", {"query": "refund"})
```

For production, use separate Ed25519 signing keys in each direction and derive
server verification context from authenticated application state. See
[`docs/MCP.md`](docs/MCP.md) for policies, context binding, limits, and the
current `tools/call` scope.

## Security boundary

Guard Bands proves integrity, provenance, freshness, and context binding. It
does **not** prove that signed content is true, benign, authorized, or safe for
a model to follow. Treat verified content as data, not authority, and retain
normal authorization, least-privilege tools, output validation, monitoring,
and human approval where appropriate.

See:

- [`docs/RESEARCH.md`](docs/RESEARCH.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/CONTEXT_SERIALIZATION.md`](docs/CONTEXT_SERIALIZATION.md)
- [`docs/KEY_MANAGEMENT.md`](docs/KEY_MANAGEMENT.md)
- [`docs/REMOTE_SIGNING.md`](docs/REMOTE_SIGNING.md)
- [`docs/EXTERNAL_REVIEW.md`](docs/EXTERNAL_REVIEW.md)
- [`docs/REPLAY_PROTECTION.md`](docs/REPLAY_PROTECTION.md)
- [`docs/LIMITS.md`](docs/LIMITS.md)
- [`docs/MCP.md`](docs/MCP.md)

## Development

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy
```

The test suite includes HMAC and Ed25519 behavior, context and metadata
tampering, key rotation, expiry, replay ledgers, strict parser fuzzing, and
FastAPI enforcement. Strict mypy coverage currently applies to the core crypto
and replay modules; the configured baseline will expand to the optional
integrations incrementally.

## Status

Guard Bands remains an experimental security mechanism. Protocol or API
changes may occur before `1.0.0`; wire-format changes are called out explicitly
in the changelog. A stable release is blocked on the independent review gate in
[`docs/EXTERNAL_REVIEW.md`](docs/EXTERNAL_REVIEW.md).
