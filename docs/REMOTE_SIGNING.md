# Remote Signing and Async Key Resolution

Status: proposed for post-`0.10`; no runtime API in this document is available
yet.

Guard Bands currently resolves an in-process HMAC secret or Ed25519 key through
the synchronous `KeyResolver` protocol. That boundary is intentionally small,
but it cannot represent a key that never leaves a KMS, Vault transit engine, or
HSM, and a synchronous network lookup would block FastAPI and MCP event loops.

This document fixes the intended boundary before implementation. It does not
change protocol v2 or the bytes that are signed.

## Decision

Add a separate, explicitly asynchronous crypto path. Do not make the existing
methods sometimes return values and sometimes return awaitables, and do not use
coroutine inspection to guess how a resolver behaves.

- `GuardBandCrypto` and `KeyResolver` remain synchronous and source compatible.
- `AsyncGuardBandCrypto` exposes async counterparts to wrapping, detached
  signing, and verification.
- An async resolver returns an opaque key handle. The handle identifies the
  cryptographic primitive and an immutable key version, and performs the
  remote operation itself.
- The core library, not the remote provider, constructs the canonical protocol
  payload. Providers receive the exact bytes to sign or verify.
- Provider-specific SDKs and credentials stay in optional adapter packages or
  application code, not in the dependency-light core.

An explicit async API makes blocking behavior visible to callers, keeps type
checking useful, and gives MCP/FastAPI integrations a single predictable
execution model.

## Proposed interfaces

Names may be refined during implementation, but the separation of
responsibilities is normative for the design:

```python
from typing import Literal, Protocol

KeyPrimitive = Literal["HMAC-SHA256", "Ed25519"]


class AsyncSigningKey(Protocol):
    key_id: str
    primitive: KeyPrimitive

    async def sign(self, message: bytes) -> bytes: ...


class AsyncVerificationKey(Protocol):
    key_id: str
    primitive: KeyPrimitive

    async def verify(self, message: bytes, signature: bytes) -> bool: ...


class AsyncKeyResolver(Protocol):
    async def get_signing_key(
        self, key_id: str | None = None
    ) -> AsyncSigningKey: ...

    async def get_verification_key(
        self, key_id: str
    ) -> AsyncVerificationKey | None: ...
```

The resolver may accept a configured alias when selecting a signing key, but
the returned handle's `key_id` must name the exact immutable key version used
for the operation. That exact id is authenticated into `kid`. An alias that can
move during rotation must never appear in a completed Guard Band.

The handle reports a primitive such as `Ed25519`; the core maps that primitive
and protocol version to the authenticated `GBv2-Ed25519` or
`GBv2-HMAC-SHA256` algorithm tag. Cloud-provider algorithm names do not enter
the wire format.

## Signing flow

1. Validate content, context, issuer, TTL, and requested key id locally.
2. Resolve one immutable async signing-key handle.
3. Generate the nonce and timestamps once.
4. Derive the protocol algorithm tag from the handle's trusted primitive.
5. Construct the canonical MAC payload in the core library.
6. Ask the handle to sign those exact bytes.
7. Validate the returned signature encoding and length before emitting an
   inline band or detached envelope.

The library must never retry the whole flow because that would silently mint a
new nonce. A provider adapter may perform bounded retries of the same immutable
key operation and the same message bytes when its service documents that as
safe.

## Verification flow

1. Parse and validate the untrusted envelope or marker before any remote call.
2. Resolve the exact `kid` to a trusted verification handle.
3. Derive the expected protocol algorithm from the handle and reject an
   algorithm mismatch.
4. Reconstruct the canonical payload locally.
5. Ask the handle to verify the decoded signature.
6. Enforce expiry and replay policy exactly as the synchronous path does.

For Ed25519, deployments should normally distribute and cache the public key
and verify locally. Remote verification is still part of the abstraction for
non-exportable HMAC keys and policy-constrained HSMs. Remote verification must
not be mistaken for authorization.

## Wire compatibility

Remote signing is an execution change, not a protocol change. A remote provider
must produce the same raw 32-byte HMAC-SHA256 or 64-byte Ed25519 signature over
the same protocol v2 payload as the local implementation. Existing Python and
TypeScript verifiers must accept the result without knowing which provider was
used.

A service that only offers a different primitive, pre-hashed signing mode, or
signature encoding is not compatible through an adapter alone. Supporting it
requires a new authenticated algorithm identifier, conformance vectors, and
the normal protocol review process. Providers must not silently translate to a
different algorithm.

## Failure behavior

The async API should expose a small typed error hierarchy so integrations can
distinguish:

- unknown or disabled key;
- permission or authentication failure;
- unsupported primitive or algorithm mismatch;
- timeout, cancellation, throttling, or transient provider failure; and
- malformed provider response.

All failures are fail-closed. There is no automatic fallback to an in-process
secret, another key id, unsigned output, or a stale signing handle. MCP tool
execution must not begin after input-verification failure, and a tool result
must not be returned under a required guarded-output policy after signing
failure.

Cancellation should propagate to the provider call. Adapters should use
bounded timeouts, concurrency limits, and narrowly scoped retry policies.

## Rotation and caching

- Signing aliases resolve to immutable versions before the message is built.
- Verification lookup uses the immutable `kid` carried in the artifact.
- Retired verification keys remain available for at least the maximum artifact
  TTL and replay window.
- Public Ed25519 keys may be cached with a bounded TTL. Cache entries are keyed
  by immutable `kid`, not alias.
- Signing handles and non-exportable HMAC verification handles must follow the
  provider's revocation semantics. Negative lookup caches, if any, should be
  brief so rotation does not create an avoidable outage.

## Integration behavior

The MCP client and server extension are already asynchronous. Their async
variants should await Guard Band operations at the existing pre-execution and
post-result boundaries. They must preserve the current complete-result and
multi-round-trip behavior documented in [`MCP.md`](MCP.md).

FastAPI should get a separate async middleware/configuration path rather than
running remote operations in a thread pool. Existing synchronous middleware
behavior stays available for local verification.

## Provider adapter requirements

An adapter must:

- validate configured provider identifiers separately from public `kid`;
- pin the exact key version used for signing;
- authenticate the provider endpoint and verify TLS;
- pass the exact message bytes without provider-side canonicalization;
- normalize only the provider's signature encoding, never its algorithm;
- validate response key version, primitive, and signature length;
- avoid logging keys, payloads, signatures, content, or full contexts; and
- emit safe telemetry such as operation, provider, immutable key id, primitive,
  latency, retry count, payload length or digest, and outcome.

Credentials, endpoints, retry policy, and tenant-to-key authorization are
deployment configuration. Callers must derive tenant and policy context from
authenticated state; an untrusted MCP argument must never select an arbitrary
provider key.

## Delivery sequence

1. Add the async protocols, typed failures, and fake deterministic provider.
2. Add `AsyncGuardBandCrypto` with byte-for-byte parity against every local v2
   conformance vector.
3. Add timeout, cancellation, rotation-race, response-validation, and
   concurrency tests.
4. Add async MCP client/server integration tests that prove handlers do not run
   on verification failure and results do not escape on signing failure.
5. Add an async FastAPI path with the same body and replay limits as the current
   middleware.
6. Build one provider adapter outside the core as a proving implementation.
7. Obtain independent review of the interface, failure modes, and provider
   adapter before declaring the API stable.

## Acceptance criteria

- Local and remote implementations reproduce identical protocol v2 artifacts
  for deterministic HMAC and Ed25519 inputs.
- Existing synchronous APIs and v1 verification remain unchanged.
- No private key bytes cross the async-provider boundary for non-exportable
  keys.
- Alias rotation cannot cause the signed `kid` to disagree with the key that
  performed the operation.
- Timeouts, cancellation, throttling, unknown keys, algorithm mismatch, and
  malformed signatures are all tested and fail closed.
- MCP and FastAPI event loops perform no blocking provider I/O.
- The external review records findings and their disposition before `1.0.0`.

## Non-goals

- adding new cryptographic algorithms in this change;
- treating KMS authorization as application authorization;
- hiding network latency behind the synchronous API;
- embedding any cloud SDK in the base installation; or
- promising exactly-once calls to an external signing service.
