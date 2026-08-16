# External Review Gate for v1.0.0

Status: awaiting an independent reviewer.

Guard Bands must not be released as `1.0.0` until a human reviewer who did not
author the implementation has examined the protocol and its Python/TypeScript
implementations, recorded findings, and verified the disposition of release-
blocking findings.

This is a review brief, not a claim that an audit has happened.

## Frozen review targets

The initial review baseline is:

| Component | Repository | Commit |
|---|---|---|
| Python core, protocol, FastAPI, MCP, and remote-signing design | `Cryptix-Security/guard-bands` | `a4295eb6121117143ed457b4ac4d62fccb46e282` |
| TypeScript core and MCP implementation | `Cryptix-Security/guard-bands-ts` | `c63b037760b2cc70a0185261398c20a23dea0c54` |

Documentation-only review-gate changes made after the Python baseline do not
alter the protocol target. Any code or conformance-vector change made in
response to review creates a new target commit that must be recorded in the
tracking issue and rechecked to the extent requested by the reviewer.

## Security claims to examine

Given an uncompromised supported key and application-derived expected context,
the implementation should reject:

- content, context, protocol-version, algorithm, issuer, key-id, timestamp, or
  signature modification;
- malformed, incomplete, nested, or ambiguous inline markers;
- replay across contexts when context values differ, and same-context replay
  when an injected replay ledger is enabled;
- detached JSON value substitution;
- MCP argument or result modification, cross-call substitution, audience/tool
  substitution, and visible text-band modification; and
- use of an Ed25519 public key to mint an artifact.

Protocol v2 artifacts produced by Python and TypeScript should be byte-for-byte
interoperable for the committed conformance vectors.

Guard Bands does not claim that authenticated content is true, benign,
authorized, confidential, or safe to execute. It does not replace application
authorization, least privilege, output validation, or human approval.

## Priority review questions

1. Does RFC 8785 canonicalization agree across runtimes for every supported JSON
   value, including Unicode ordering, numeric edge cases, and invalid inputs?
2. Is algorithm and protocol-version domain separation complete, with no
   downgrade or cross-algorithm acceptance path?
3. Can the inline extractor/parser disagree with verification in a way that
   enables truncation, marker smuggling, or a different application view of the
   signed content?
4. Are signature parsing, base64 handling, key typing, key-id selection,
   timestamp checks, and constant-time HMAC comparison fail-closed?
5. Are detached JSON envelopes bound to their value kind and complete expected
   context?
6. Does the MCP normalization cover every supported content block without
   losing a security-relevant field? Can unsigned metadata influence a security
   decision or model-visible output?
7. Can mismatched client/server policies, multi-round-trip results, Tasks,
   transport framing, or payload limits bypass required verification?
8. Does replay behavior survive upgrades and distributed deployment without
   overstating its guarantees?
9. Does the proposed remote-signing interface prevent alias-rotation races,
   algorithm translation, blocking event-loop I/O, unsafe fallback, or key
   material exposure?
10. Are documented security claims narrower than or equal to what the code
    actually enforces?

## Suggested attack cases

- duplicate, reordered, missing, unknown, oversized, and non-UTF-8 marker
  fields;
- fake end markers followed by a valid end marker, nested starts, and marker
  prefixes embedded in content;
- invalid/lone Unicode surrogates, non-finite numbers, negative zero, large
  integers, exponent boundaries, cyclic values, and non-plain objects;
- version/algorithm/key substitution and Ed25519/HMAC confusion;
- expired, zero-TTL, far-future, negative, non-integer, and overflowing
  timestamps;
- unknown or rotated key ids and public-key-only sign attempts;
- context changes at each nested field and replay-ledger races;
- MCP call-id, audience, direction, tool, input digest, application context,
  content-index, structured-content, error flag, and content-block tampering;
- oversized payloads before and after visible text wrapping; and
- remote-provider timeouts, cancellation, throttling, malformed signatures,
  stale aliases, and response-key mismatch.

## Reproducing the baseline

Python:

```bash
git clone https://github.com/Cryptix-Security/guard-bands.git
cd guard-bands
git checkout a4295eb6121117143ed457b4ac4d62fccb46e282
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy
```

TypeScript:

```bash
git clone https://github.com/Cryptix-Security/guard-bands-ts.git
cd guard-bands-ts
git checkout c63b037760b2cc70a0185261398c20a23dea0c54
pnpm install --frozen-lockfile
pnpm check
pnpm build
pnpm pack --pack-destination /tmp
```

The normative protocol is in [`PROTOCOL.md`](PROTOCOL.md). Deterministic
fixtures are in [`../conformance/vectors.json`](../conformance/vectors.json),
and the TypeScript repository vendors the same file. MCP scope and lifecycle
limits are in [`MCP.md`](MCP.md). The proposed remote boundary is in
[`REMOTE_SIGNING.md`](REMOTE_SIGNING.md).

## Required review record

The reviewer should provide a public report or a public summary plus privately
reported vulnerability details. The record must include:

- reviewer name or organization and independence from implementation;
- review dates and exact commit hashes;
- reviewed areas and methods;
- findings with severity, rationale, and reproduction guidance;
- limitations and areas not reviewed; and
- a follow-up statement for fixes the reviewer rechecked.

Suspected exploitable vulnerabilities should follow [`../SECURITY.md`](../SECURITY.md)
rather than being published before a fix is available.

## Release gate

`1.0.0` remains blocked until:

- an independent review record exists;
- every critical or high finding is fixed and rechecked;
- every medium finding is fixed or has an explicit, documented risk decision;
- conformance vectors and both implementations agree after fixes;
- Python and TypeScript CI and code-scanning checks pass; and
- the changelog names externally visible corrections made during review.

Low/informational findings may be scheduled after `1.0.0` only when they do not
contradict a security claim or create an interoperability ambiguity.
