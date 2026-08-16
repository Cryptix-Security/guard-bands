import base64

import pytest

from guardbands import (
    ED25519_ALG,
    MAC_ALG,
    GuardBandCrypto,
    StaticKeyResolver,
    canonical_json,
)
from guardbands.crypto import (
    generate_ed25519_keypair,
    load_ed25519_private_key,
    load_ed25519_public_key,
)


def test_detached_value_round_trip_is_key_order_independent():
    crypto = GuardBandCrypto(b"structured-secret")
    context = {"tool": "search", "direction": "input"}
    value = {"query": "otters", "filters": {"year": 2026, "safe": True}}

    envelope = crypto.sign_value(value, context, issuer="trusted-host", now=1_000)
    reordered = {"filters": {"safe": True, "year": 2026}, "query": "otters"}
    result = crypto.verify_value(reordered, envelope, context, now=1_001)

    assert result["valid"] is True
    assert result["value"] == reordered
    assert result["algorithm"] == MAC_ALG


def test_detached_value_rejects_value_context_and_metadata_tampering():
    crypto = GuardBandCrypto(b"structured-secret")
    context = {"tool": "payments.create", "direction": "input"}
    envelope = crypto.sign_value({"amount": 10}, context, now=1_000)

    assert not crypto.verify_value({"amount": 11}, envelope, context, now=1_001)["valid"]
    assert not crypto.verify_value(
        {"amount": 10}, envelope, {**context, "tool": "payments.delete"}, now=1_001
    )["valid"]

    changed = {**envelope, "issuer": "attacker"}
    assert not crypto.verify_value({"amount": 10}, changed, context, now=1_001)["valid"]


def test_detached_value_rejects_expired_unknown_and_extra_fields():
    crypto = GuardBandCrypto(b"structured-secret")
    envelope = crypto.sign_value([], {}, ttl_seconds=10, now=1_000)

    assert crypto.verify_value([], envelope, {}, now=1_010)["valid"] is True
    assert crypto.verify_value([], envelope, {}, now=1_011)["error"] == "Guard band expired"
    assert crypto.verify_value([], {**envelope, "extra": True}, {}, now=1_001)["error"] == (
        "Invalid detached envelope fields"
    )
    assert (
        crypto.verify_value([], {**envelope, "key_id": "missing"}, {}, now=1_001)["error"]
        == "Unknown key id: missing"
    )


def test_detached_value_rejects_algorithm_confusion():
    crypto = GuardBandCrypto(b"structured-secret")
    envelope = crypto.sign_value({"ok": True}, {}, now=1_000)

    changed = {**envelope, "algorithm": ED25519_ALG}
    assert crypto.verify_value({"ok": True}, changed, {}, now=1_001)["error"] == (
        "Signature algorithm mismatch"
    )


def test_detached_value_supports_ed25519_verify_only_keys():
    private_encoded, public_encoded = generate_ed25519_keypair()
    private = load_ed25519_private_key(private_encoded)
    public = load_ed25519_public_key(public_encoded)
    signer = GuardBandCrypto(key_resolver=StaticKeyResolver({"server": private}, "server"))
    verifier = GuardBandCrypto(key_resolver=StaticKeyResolver({"server": public}, "server"))

    envelope = signer.sign_value({"content": ["safe"]}, {}, now=1_000)
    result = verifier.verify_value({"content": ["safe"]}, envelope, {}, now=1_001)

    assert result["valid"] is True
    assert result["algorithm"] == ED25519_ALG
    with pytest.raises(ValueError, match="verification-only"):
        verifier.sign_value({"content": ["forged"]}, {}, now=1_000)


def test_detached_value_is_domain_separated_from_inline_text():
    crypto = GuardBandCrypto(b"structured-secret")
    crypto.generate_nonce = lambda: "fixedNonceValue123"
    context = {"tool": "echo"}
    wrapped = crypto.wrap_content(canonical_json("hello"), context, now=1_000)
    start, _, end = wrapped.split("\n")
    start_fields = start.removeprefix("⟪INERT:START:").removesuffix("⟫").split(":")
    end_fields = end.removeprefix("⟪INERT:END:").removesuffix("⟫").split(":")
    start_meta = dict(zip(start_fields[::2], start_fields[1::2], strict=True))
    end_meta = dict(zip(end_fields[::2], end_fields[1::2], strict=True))
    issuer = base64.urlsafe_b64decode(end_meta["iss"] + "==").decode()
    transplanted = {
        "version": start_meta["v"],
        "nonce": start_meta["r"],
        "issued_at": int(start_meta["iat"]),
        "expires_at": int(start_meta["exp"]),
        "key_id": end_meta["kid"],
        "issuer": issuer,
        "algorithm": MAC_ALG,
        "signature": end_meta["mac"],
    }

    assert crypto.verify_value("hello", transplanted, context, now=1_001)["error"] == (
        "Signature verification failed"
    )


def test_detached_value_rejects_non_json_values():
    crypto = GuardBandCrypto(b"structured-secret")

    with pytest.raises((TypeError, ValueError)):
        crypto.sign_value({"bad": object()}, {})
    with pytest.raises(ValueError, match="Out of range float"):
        crypto.sign_value({"bad": float("nan")}, {})
