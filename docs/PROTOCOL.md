# Guard Bands Wire Protocol

This document is the normative interoperability description for Guard Bands
protocol v2. The executable compatibility contract is
[`../conformance/vectors.json`](../conformance/vectors.json).

## Versions and canonicalization

New signatures use protocol version `"2"`. V2 canonicalizes every signed JSON
object with the JSON Canonicalization Scheme (JCS) from
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html), then signs the UTF-8
bytes. Inputs must be in the I-JSON domain: finite IEEE-754 numbers, valid
Unicode without lone surrogates, and no duplicate object names.

Protocol v1 used Python's `json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False, allow_nan=False)` output. Python continues to verify v1
artifacts for migration, but v1 is not a portable cross-language signing
target. Its algorithm tags are `GBv1-HMAC-SHA256` and `GBv1-Ed25519`.

V2 algorithm tags are `GBv2-HMAC-SHA256` and `GBv2-Ed25519`. The tag is inside
the signed payload and is derived from the resolved key type; verifiers do not
trust an unauthenticated algorithm choice.

## Authenticated payload

The signature input for an inline text band is the JCS serialization of:

```json
{
  "alg": "GBv2-HMAC-SHA256",
  "content": "<exact text>",
  "context": {},
  "exp": 1700000900,
  "iat": 1700000000,
  "iss": "<issuer>",
  "kid": "<key id>",
  "nonce": "<nonce>",
  "v": "2"
}
```

For a detached JSON value, canonicalize the value first and place that JSON
string in `content`; also add `"kind":"json"` to the payload. This domain
separates detached JSON signatures from inline text signatures.

HMAC signatures are HMAC-SHA256 bytes. Ed25519 signatures follow RFC 8032.
Marker and envelope signatures use standard padded Base64. The marker issuer
uses unpadded Base64url of its UTF-8 bytes.

## Inline text format

```text
⟪INERT:START:v:2:r:<nonce>:iat:<unix-seconds>:exp:<unix-seconds>⟫
<exact content>
⟪INERT:END:mac:<base64-signature>:kid:<key-id>:iss:<base64url-issuer>⟫
```

The content is every character between the newline after the start marker and
the newline before the end marker. Content containing the reserved prefixes
`⟪INERT:START` or `⟪INERT:END` cannot be signed. Marker parameter names must
appear exactly once; unknown or missing parameters are invalid.

## Detached JSON envelope

The value remains outside the envelope so structured protocols can preserve
their schemas:

```json
{
  "version": "2",
  "nonce": "<nonce>",
  "issued_at": 1700000000,
  "expires_at": 1700000900,
  "key_id": "<key id>",
  "issuer": "<issuer>",
  "algorithm": "GBv2-Ed25519",
  "signature": "<base64-signature>"
}
```

These eight fields are exact: additional or missing fields are invalid.

## Verification and lifetime

A verifier validates syntax and field types, resolves the key by `kid`, derives
the expected algorithm from the key and version, reconstructs the exact signed
payload, and verifies the signature before trusting timestamps. An artifact is
valid at `exp` and expired when the verifier's integer Unix time is greater
than `exp`. Replay protection is a separate, optional atomic nonce-consumption
step after successful verification.

## V1-to-v2 rollout

For multi-instance or split signer/verifier deployments:

1. upgrade every verifier to a version that accepts both v1 and v2;
2. during that rollout, construct signers with `signing_version="1"`;
3. after all old verifiers are gone, remove the override so signers emit v2;
4. retain v1 verification for at least the maximum artifact lifetime and any
   archival-verification requirement.

Do not let a v2 signer send artifacts to a v1-only verifier. A single-process
deployment can upgrade atomically.
