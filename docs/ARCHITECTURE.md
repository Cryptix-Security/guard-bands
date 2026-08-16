# Architecture and Threat Model

Guard Bands separates untrusted content from trusted instructions by giving the application a cryptographic boundary it can verify before sensitive behavior is allowed.

This document is the concise implementation-oriented architecture. See
[`RESEARCH.md`](RESEARCH.md) for the longer design rationale, security claims,
assumptions, and research status.

## Repository Boundary

This repository is the canonical implementation and specification home for the
Guard Bands mechanism:

- signing and verification primitives
- canonical serialization and marker parsing
- replay primitives
- FastAPI middleware
- MCP `tools/call` integration

The separate
[`guard-bands-reference`](https://github.com/Cryptix-Security/guard-bands-reference)
repository consumes this library as a versioned dependency. It owns deployment
examples, LLM workflows, SSO, audit sinks, dual-channel services, and other
operational demonstrations. Core library code is not copied into that
repository.

## Trust Boundaries

| Boundary | Trusted side | Untrusted side |
|---|---|---|
| Wrapping | application signer and key resolver | uploaded files, retrieved documents, tickets, web pages, emails |
| Verification | application verifier and expected context | model-generated tool inputs and user-controlled prompt text |
| Tool execution | application policy and authorization checks | any text inside model context, including verified document text |
| MCP tool calls | configured client/server keys and authenticated application context | model-selected arguments and tool-produced content |
| Audit | server-side event logger | user, model, and document content |

The model is not the root of trust. It can request verification, but the application chooses the verification context and decides whether a tool path is allowed.

## Signing Flow

1. Application receives untrusted content.
2. Application builds the expected context, such as request id, tenant id, user id, model, and policy path.
3. `GuardBandCrypto.wrap_content` generates a nonce, stamps issued/expiry timestamps and the minting issuer, and signs the canonical payload.
4. The wrapped block is passed downstream as inert data.

The marker format is versioned, and every field is authenticated by the MAC:

```text
⟪INERT:START:v:2:r:b64url(nonce):iat:issued_at:exp:expires_at⟫
[untrusted content]
⟪INERT:END:mac:b64(mac):kid:keyid:iss:b64url(issuer)⟫
```

## Verification Flow

1. Application detects a complete Guard Band block.
2. Application verifies marker structure, protocol version, nonce, key id, issuer, MAC, lifetime (expiry), and context.
3. Optional replay protection checks the nonce against the canonical context.
4. Application treats verified content as data, not authority.
5. Sensitive tool calls still require normal authorization and policy checks.

Verification fails closed. If a block is malformed, tampered with, signed by an unknown key, bound to the wrong context, expired, or replayed inside the same context, the application rejects it.

Protocol v2 uses RFC 8785 canonical JSON for cross-language signatures. The
Python implementation also verifies legacy v1 artifacts. The normative format
and migration sequence are in [`PROTOCOL.md`](PROTOCOL.md), with executable
fixtures in [`../conformance/`](../conformance/).

## FastAPI Integration

The optional `guardbands.integrations.fastapi.GuardBandVerificationMiddleware`
protects routes that should only accept verified Guard Band request bodies.

```python
from fastapi import FastAPI, Request

from guardbands import GuardBandCrypto
from guardbands.integrations.fastapi import (
    GuardBandVerificationMiddleware,
    guard_band_verification,
)

app = FastAPI()
crypto = GuardBandCrypto(b"dev-secret")

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

This middleware is useful when a route should never process unverified tool input. It verifies before the route handler runs and attaches the verification result to `request.state.guard_band_verification`.

## MCP Integration

The optional `guardbands.integrations.mcp` adapter protects MCP `tools/call`
without depending on the underlying stdio or Streamable HTTP transport.

1. The guarded client signs the complete canonical tool-arguments object in a
   detached envelope carried under `com.guardbands/guard-band` in MCP `_meta`.
2. The server extension reconstructs the expected context and verifies the
   envelope before invoking the tool handler.
3. The extension wraps each text result block in visible Guard Band markers,
   signs the complete `CallToolResult`, and attaches a detached result envelope.
4. The guarded client verifies the result envelope and every visible text band
   before returning the result to the host.

The authenticated MCP context binds the direction, configured audience, tool
name, logical call id, application context, and a digest of the exact input.
It deliberately excludes the transport's JSON-RPC request id because MCP
multi-round-trip retries assign a new id.

## Threats Addressed

- forged Guard Band markers
- modified wrapped content
- unknown signing keys
- context replay across users, tenants, requests, or policy paths
- incomplete or malformed markers
- model attempts to skip verification
- model attempts to call unsupported tools from guarded content

## Out of Scope

Guard Bands do not prove content is true, safe, benign, or authorized. Verified content can still contain malicious claims, social engineering, or unsafe business requests. Production systems still need least-privilege tools, authorization checks, human approval for high-risk actions, output validation, monitoring, and incident response.

## Production Notes

- Keep signing keys outside source control.
- Use an external key manager or secret manager for production keys.
- Use a shared nonce ledger for multi-process replay protection.
- Bind context to tenant, user, request, policy path, and downstream tool path.
- Terminate TLS at a production-grade proxy or platform edge.
- Keep audit logs immutable enough for investigation and retention needs.
