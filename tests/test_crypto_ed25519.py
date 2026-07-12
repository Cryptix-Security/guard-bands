import pytest

from app.crypto import (
    ED25519_ALG,
    MAC_ALG,
    GuardBandCrypto,
    StaticKeyResolver,
    generate_ed25519_keypair,
    key_algorithm,
    load_ed25519_private_key,
    load_ed25519_public_key,
)


def make_keypair():
    private_b64, public_b64 = generate_ed25519_keypair()
    return load_ed25519_private_key(private_b64), load_ed25519_public_key(public_b64)


def test_keypair_round_trips_through_encoding():
    private_b64, public_b64 = generate_ed25519_keypair()
    private = load_ed25519_private_key(private_b64)
    public = load_ed25519_public_key(public_b64)
    assert private.public_key().public_bytes_raw() == public.public_bytes_raw()


def test_key_algorithm_dispatch():
    private, public = make_keypair()
    assert key_algorithm(b"secret") == MAC_ALG
    assert key_algorithm(private) == ED25519_ALG
    assert key_algorithm(public) == ED25519_ALG
    with pytest.raises(TypeError):
        key_algorithm("not-a-key")


def test_ed25519_wrap_and_verify_round_trip():
    private, _ = make_keypair()
    crypto = GuardBandCrypto(key_resolver=StaticKeyResolver({"signer": private}, "signer"))
    context = {"request_id": "req-001", "user": "alice"}

    wrapped = crypto.wrap_content("Document body", context, issuer="signer")
    result = crypto.extract_and_verify(wrapped, context)

    assert result["valid"] is True
    assert result["content"] == "Document body"
    assert result["key_id"] == "signer"
    assert result["issuer"] == "signer"


def test_public_key_verifies_but_cannot_sign():
    private, public = make_keypair()
    signer = GuardBandCrypto(key_resolver=StaticKeyResolver({"signer": private}, "signer"))
    verifier = GuardBandCrypto(key_resolver=StaticKeyResolver({"signer": public}, "signer"))
    context = {"request_id": "req-001"}

    wrapped = signer.wrap_content("Document body", context)

    # Verification-only role: the public-key holder validates the band...
    assert verifier.extract_and_verify(wrapped, context)["valid"] is True

    # ...but is cryptographically unable to mint one.
    with pytest.raises(ValueError, match="verification-only"):
        verifier.wrap_content("forged content", context)


def test_ed25519_tampered_content_is_rejected():
    private, public = make_keypair()
    signer = GuardBandCrypto(key_resolver=StaticKeyResolver({"signer": private}, "signer"))
    verifier = GuardBandCrypto(key_resolver=StaticKeyResolver({"signer": public}, "signer"))
    context = {"request_id": "req-001"}

    wrapped = signer.wrap_content("Refund account 4471.", context)
    tampered = wrapped.replace("4471", "9999")

    result = verifier.extract_and_verify(tampered, context)
    assert result["valid"] is False
    assert result["error"] == "MAC verification failed"


def test_ed25519_context_binding_is_enforced():
    private, _ = make_keypair()
    crypto = GuardBandCrypto(key_resolver=StaticKeyResolver({"signer": private}, "signer"))
    wrapped = crypto.wrap_content("Document body", {"tenant": "a"})

    result = crypto.extract_and_verify(wrapped, {"tenant": "b"})
    assert result["valid"] is False
    assert result["error"] == "MAC verification failed"


def test_ed25519_signature_under_wrong_public_key_is_rejected():
    private, _ = make_keypair()
    _, other_public = make_keypair()
    signer = GuardBandCrypto(key_resolver=StaticKeyResolver({"signer": private}, "signer"))
    wrong_verifier = GuardBandCrypto(
        key_resolver=StaticKeyResolver({"signer": other_public}, "signer")
    )
    context = {"request_id": "req-001"}

    wrapped = signer.wrap_content("Document body", context)
    result = wrong_verifier.extract_and_verify(wrapped, context)
    assert result["valid"] is False
    assert result["error"] == "MAC verification failed"


def test_cross_algorithm_confusion_fails_closed():
    # An HMAC band whose kid resolves to an Ed25519 key (or vice versa) must
    # never verify: the signature length gate and the authenticated alg tag
    # both reject it.
    private, public = make_keypair()
    hmac_signer = GuardBandCrypto(
        key_resolver=StaticKeyResolver({"shared-id": b"hmac-secret"}, "shared-id")
    )
    ed_signer = GuardBandCrypto(
        key_resolver=StaticKeyResolver({"shared-id": private}, "shared-id")
    )
    context = {"request_id": "req-001"}

    hmac_band = hmac_signer.wrap_content("Document body", context)
    ed_band = ed_signer.wrap_content("Document body", context)

    ed_verifier = GuardBandCrypto(
        key_resolver=StaticKeyResolver({"shared-id": public}, "shared-id")
    )
    assert ed_verifier.extract_and_verify(hmac_band, context)["valid"] is False
    assert hmac_signer.extract_and_verify(ed_band, context)["valid"] is False


def test_resolver_rejects_unsupported_key_types():
    with pytest.raises(TypeError):
        StaticKeyResolver({"key001": "string-not-bytes"}, "key001")


def test_hmac_bands_still_work_unchanged():
    crypto = GuardBandCrypto(b"hmac-secret")
    context = {"request_id": "req-001"}
    wrapped = crypto.wrap_content("Document body", context)
    result = crypto.extract_and_verify(wrapped, context)
    assert result["valid"] is True
    assert result["content"] == "Document body"
