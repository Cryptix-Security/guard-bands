"""Print the deterministic Guard Bands conformance vectors as JSON.

The keys in this script are public test fixtures. They must never be used for
real signing.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardbands.crypto import (
    CURRENT_PROTOCOL_VERSION,
    STRUCTURED_VALUE_KIND,
    GuardBandCrypto,
    StaticKeyResolver,
    _canonical_json_for_version,
    _encode_issuer,
    canonical_json,
    canonical_mac_payload,
    key_algorithm,
)

HMAC_KEY = bytes(range(32))
ED25519_SEED = bytes(range(32))
NONCE = "AAAAAAAAAAAAAAAA"
ISSUED_AT = 1_700_000_000
EXPIRES_AT = 1_700_000_900
ISSUER = "conformance.example"
MCP_CALL_ID = "BBBBBBBBBBBBBBBB"


class FixedNonceCrypto(GuardBandCrypto):
    def generate_nonce(self) -> str:
        return NONCE


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _signer(key: bytes | Ed25519PrivateKey, key_id: str) -> FixedNonceCrypto:
    return FixedNonceCrypto(key_resolver=StaticKeyResolver({key_id: key}, key_id))


def _payload(
    content: str,
    context: dict[str, Any],
    key: bytes | Ed25519PrivateKey,
    key_id: str,
    version: str,
    *,
    kind: str = "text",
) -> str:
    return canonical_mac_payload(
        content,
        context,
        NONCE,
        version=version,
        key_id=key_id,
        issuer=ISSUER,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        alg=key_algorithm(key, version=version),
        kind=kind,
    ).decode("utf-8")


def _inline_vector(
    vector_id: str,
    key: bytes | Ed25519PrivateKey,
    key_id: str,
    version: str,
    content: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    signer = _signer(key, key_id)
    signature = signer.generate_mac(
        content,
        context,
        NONCE,
        key,
        version=version,
        key_id=key_id,
        issuer=ISSUER,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
    )
    wrapped = (
        f"⟪INERT:START:v:{version}:r:{NONCE}:iat:{ISSUED_AT}:exp:{EXPIRES_AT}⟫\n"
        f"{content}\n"
        f"⟪INERT:END:mac:{signature}:kid:{key_id}:iss:{_encode_issuer(ISSUER)}⟫"
    )
    return {
        "id": vector_id,
        "mode": "inline",
        "version": version,
        "key_id": key_id,
        "issuer": ISSUER,
        "nonce": NONCE,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "content": content,
        "context": context,
        "canonical_payload": _payload(content, context, key, key_id, version),
        "signature_base64": signature,
        "artifact": wrapped,
    }


def _detached_vector(
    vector_id: str,
    key: bytes | Ed25519PrivateKey,
    key_id: str,
    version: str,
    value: Any,
    context: dict[str, Any],
) -> dict[str, Any]:
    signer = _signer(key, key_id)
    value_json = _canonical_json_for_version(value, version)
    signature = signer.generate_mac(
        value_json,
        context,
        NONCE,
        key,
        version=version,
        key_id=key_id,
        issuer=ISSUER,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        kind=STRUCTURED_VALUE_KIND,
    )
    envelope = {
        "version": version,
        "nonce": NONCE,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "key_id": key_id,
        "issuer": ISSUER,
        "algorithm": key_algorithm(key, version=version),
        "signature": signature,
    }
    return {
        "id": vector_id,
        "mode": "detached-json",
        "version": version,
        "key_id": key_id,
        "issuer": ISSUER,
        "nonce": NONCE,
        "issued_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "value": value,
        "context": context,
        "canonical_value": value_json,
        "canonical_payload": _payload(
            value_json,
            context,
            key,
            key_id,
            version,
            kind=STRUCTURED_VALUE_KIND,
        ),
        "signature_base64": signature,
        "artifact": envelope,
    }


def _mcp_context(
    *,
    direction: str,
    arguments: dict[str, Any],
    content_index: int | None = None,
) -> dict[str, Any]:
    context: dict[str, Any] = {
        "application": {"tenant": "a"},
        "audience": "conformance-host",
        "call_id": MCP_CALL_ID,
        "direction": direction,
        "input_sha256": hashlib.sha256(canonical_json(arguments).encode()).hexdigest(),
        "integration": "mcp",
        "method": "tools/call",
        "tool": "echo",
    }
    if content_index is not None:
        context["content_index"] = content_index
    return context


def _mcp_vector() -> dict[str, Any]:
    arguments = {"text": "untrusted document"}
    signer = _signer(HMAC_KEY, "test-hmac-01")
    input_envelope = signer.sign_value(
        arguments,
        _mcp_context(direction="input", arguments=arguments),
        issuer="conformance-client",
        now=ISSUED_AT,
    )
    wrapped_text = signer.wrap_content(
        "untrusted document",
        _mcp_context(direction="output-text", arguments=arguments, content_index=0),
        issuer="conformance-server",
        now=ISSUED_AT,
    )
    result_payload = {
        "content": [
            {
                "type": "text",
                "text": wrapped_text,
                "annotations": None,
                "_meta": None,
            }
        ],
        "is_error": False,
        "structured_content": {"echo": "untrusted document"},
    }
    output_envelope = signer.sign_value(
        result_payload,
        _mcp_context(direction="output", arguments=arguments),
        issuer="conformance-server",
        now=ISSUED_AT,
    )
    return {
        "id": "mcp-v2-hmac-tools-call",
        "envelope_version": 1,
        "audience": "conformance-host",
        "tool": "echo",
        "call_id": MCP_CALL_ID,
        "arguments": arguments,
        "application_context": {"tenant": "a"},
        "input_envelope": input_envelope,
        "result_payload": result_payload,
        "output_envelope": output_envelope,
    }


def build_vectors() -> dict[str, Any]:
    private = Ed25519PrivateKey.from_private_bytes(ED25519_SEED)
    public = private.public_key().public_bytes_raw()
    portable_context = {
        "direction": "input",
        "request_id": "req-conformance-001",
        "tenant": "café-😀",
    }
    structured_value = {
        "large": 1e20,
        "negative_zero": -0.0,
        "nested": {"😀": 1.0, "דּ": 2},
        "small": 1e-7,
    }

    signatures = [
        _inline_vector(
            "v2-hmac-inline",
            HMAC_KEY,
            "test-hmac-01",
            CURRENT_PROTOCOL_VERSION,
            "Untrusted café content\nSecond line",
            portable_context,
        ),
        _detached_vector(
            "v2-hmac-detached",
            HMAC_KEY,
            "test-hmac-01",
            CURRENT_PROTOCOL_VERSION,
            structured_value,
            portable_context,
        ),
        _inline_vector(
            "v2-ed25519-inline",
            private,
            "test-ed25519-01",
            CURRENT_PROTOCOL_VERSION,
            'Tool output: {"ok":true}',
            portable_context,
        ),
        _detached_vector(
            "v2-ed25519-detached",
            private,
            "test-ed25519-01",
            CURRENT_PROTOCOL_VERSION,
            structured_value,
            portable_context,
        ),
        _inline_vector(
            "v1-hmac-inline-legacy",
            HMAC_KEY,
            "test-hmac-01",
            "1",
            "Legacy ASCII content",
            {"request_id": "legacy-001"},
        ),
        _detached_vector(
            "v1-ed25519-detached-legacy",
            private,
            "test-ed25519-01",
            "1",
            {"count": 1, "ok": True},
            {"request_id": "legacy-001"},
        ),
    ]

    tampered_inline = signatures[0]["artifact"].replace("café", "cafe", 1)
    tampered_envelope = dict(signatures[1]["artifact"])
    tampered_envelope["issuer"] = "attacker.example"

    return {
        "schema": "guard-bands-conformance-v1",
        "protocol": {
            "current": CURRENT_PROTOCOL_VERSION,
            "verification": ["1", CURRENT_PROTOCOL_VERSION],
            "v2_canonicalization": "RFC 8785 (JCS)",
        },
        "warning": "All keys are public test fixtures. Never use them in production.",
        "test_keys": {
            "test-hmac-01": {
                "type": "HMAC-SHA256",
                "secret_hex": HMAC_KEY.hex(),
            },
            "test-ed25519-01": {
                "type": "Ed25519",
                "private_seed_hex": ED25519_SEED.hex(),
                "public_key_base64url": _b64url(public),
            },
        },
        "canonicalization": [
            {
                "id": "object-order",
                "input_json": '{"z":0,"a":{"b":2,"a":1}}',
                "canonical_json": canonical_json({"z": 0, "a": {"b": 2, "a": 1}}),
            },
            {
                "id": "ecmascript-numbers",
                "input_json": "[1.0,-0.0,1e-7,1e20,333333333.33333329]",
                "canonical_json": canonical_json([1.0, -0.0, 1e-7, 1e20, 333333333.33333329]),
            },
            {
                "id": "utf16-property-order",
                "input_json": '{"דּ":2,"😀":1,"€":3,"\\r":4,"1":5,"\u0080":6,"ö":7}',
                "canonical_json": canonical_json(
                    {"דּ": 2, "😀": 1, "€": 3, "\r": 4, "1": 5, "\u0080": 6, "ö": 7}
                ),
            },
            {
                "id": "string-escaping",
                "input_json": '{"value":"€$\\u000f\\nA\\"\\\\/"}',
                "canonical_json": canonical_json({"value": '€$\u000f\nA"\\/'}),
            },
        ],
        "signatures": signatures,
        "mcp": [_mcp_vector()],
        "negative_cases": [
            {
                "id": "inline-content-tampering",
                "key_id": "test-hmac-01",
                "mode": "inline",
                "context": portable_context,
                "artifact": tampered_inline,
                "valid": False,
            },
            {
                "id": "detached-metadata-tampering",
                "key_id": "test-hmac-01",
                "mode": "detached-json",
                "value": structured_value,
                "context": portable_context,
                "artifact": tampered_envelope,
                "valid": False,
            },
        ],
    }


if __name__ == "__main__":
    print(json.dumps(build_vectors(), ensure_ascii=False, indent=2))
