import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from guardbands import GuardBandCrypto, StaticKeyResolver, canonical_json
from scripts.generate_conformance import FixedNonceCrypto, _mcp_context, build_vectors

ROOT = Path(__file__).parents[1]
VECTORS_PATH = ROOT / "conformance" / "vectors.json"


def load_vectors() -> dict[str, Any]:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def make_keys(vectors: dict[str, Any]) -> tuple[bytes, Ed25519PrivateKey]:
    fixtures = vectors["test_keys"]
    hmac_key = bytes.fromhex(fixtures["test-hmac-01"]["secret_hex"])
    ed25519_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(fixtures["test-ed25519-01"]["private_seed_hex"])
    )
    return hmac_key, ed25519_key


def test_committed_vectors_match_generator():
    assert load_vectors() == build_vectors()


def test_rfc8785_canonicalization_vectors():
    for vector in load_vectors()["canonicalization"]:
        value = json.loads(vector["input_json"])
        assert canonical_json(value) == vector["canonical_json"], vector["id"]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -(2**53), 2**53])
def test_v2_rejects_values_outside_the_jcs_domain(value: float | int):
    with pytest.raises(ValueError):
        canonical_json(value)


def test_signature_vectors_verify_and_v2_artifacts_reproduce():
    vectors = load_vectors()
    hmac_key, ed25519_private = make_keys(vectors)
    resolver = StaticKeyResolver(
        {
            "test-hmac-01": hmac_key,
            "test-ed25519-01": ed25519_private.public_key(),
        },
        "test-hmac-01",
    )
    verifier = GuardBandCrypto(key_resolver=resolver)

    for vector in vectors["signatures"]:
        if vector["mode"] == "inline":
            result = verifier.extract_and_verify(
                vector["artifact"], vector["context"], now=vector["issued_at"]
            )
        else:
            result = verifier.verify_value(
                vector["value"],
                vector["artifact"],
                vector["context"],
                now=vector["issued_at"],
            )
        assert result["valid"] is True, vector["id"]

        if vector["version"] != "2":
            continue

        signing_key = hmac_key if vector["key_id"] == "test-hmac-01" else ed25519_private
        signer = FixedNonceCrypto(
            key_resolver=StaticKeyResolver({vector["key_id"]: signing_key}, vector["key_id"])
        )
        ttl = vector["expires_at"] - vector["issued_at"]
        if vector["mode"] == "inline":
            reproduced = signer.wrap_content(
                vector["content"],
                vector["context"],
                issuer=vector["issuer"],
                ttl_seconds=ttl,
                now=vector["issued_at"],
            )
        else:
            reproduced = signer.sign_value(
                vector["value"],
                vector["context"],
                issuer=vector["issuer"],
                ttl_seconds=ttl,
                now=vector["issued_at"],
            )
        assert reproduced == vector["artifact"], vector["id"]


def test_negative_conformance_vectors_are_rejected():
    vectors = load_vectors()
    hmac_key, _ = make_keys(vectors)
    verifier = GuardBandCrypto(
        key_resolver=StaticKeyResolver({"test-hmac-01": hmac_key}, "test-hmac-01")
    )

    for vector in vectors["negative_cases"]:
        if vector["mode"] == "inline":
            result = verifier.extract_and_verify(
                vector["artifact"], vector["context"], now=1_700_000_000
            )
        else:
            result = verifier.verify_value(
                vector["value"],
                vector["artifact"],
                vector["context"],
                now=1_700_000_000,
            )
        assert result["valid"] is vector["valid"], vector["id"]


def test_mcp_conformance_vector_verifies_complete_exchange():
    vectors = load_vectors()
    hmac_key, _ = make_keys(vectors)
    crypto = GuardBandCrypto(
        key_resolver=StaticKeyResolver({"test-hmac-01": hmac_key}, "test-hmac-01")
    )
    vector = vectors["mcp"][0]
    arguments = vector["arguments"]

    input_result = crypto.verify_value(
        arguments,
        vector["input_envelope"],
        _mcp_context(direction="input", arguments=arguments),
        now=1_700_000_000,
    )
    output_result = crypto.verify_value(
        vector["result_payload"],
        vector["output_envelope"],
        _mcp_context(direction="output", arguments=arguments),
        now=1_700_000_000,
    )
    text_result = crypto.extract_and_verify(
        vector["result_payload"]["content"][0]["text"],
        _mcp_context(direction="output-text", arguments=arguments, content_index=0),
        now=1_700_000_000,
    )

    assert input_result["valid"] is True
    assert output_result["valid"] is True
    assert text_result["valid"] is True
