import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Protocol, cast

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CURRENT_PROTOCOL_VERSION = "2"
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"1", CURRENT_PROTOCOL_VERSION})
# Compatibility alias retained for callers that used the original singular
# constant to discover the version emitted by the signer.
SUPPORTED_PROTOCOL_VERSION = CURRENT_PROTOCOL_VERSION
STRUCTURED_VALUE_KIND = "json"
# Domain-separation / algorithm tags bound into every signature. The tag is
# derived from the resolved key's type and authenticated inside the payload,
# so a band signed under one algorithm can never verify under another
# (no downgrade or cross-algorithm confusion).
LEGACY_MAC_ALG = "GBv1-HMAC-SHA256"
LEGACY_ED25519_ALG = "GBv1-Ed25519"
MAC_ALG = "GBv2-HMAC-SHA256"
ED25519_ALG = "GBv2-Ed25519"
_ALGORITHMS = {
    "1": {"hmac": LEGACY_MAC_ALG, "ed25519": LEGACY_ED25519_ALG},
    "2": {"hmac": MAC_ALG, "ed25519": ED25519_ALG},
}
_SIGNATURE_LENGTHS = {
    LEGACY_MAC_ALG: 32,
    LEGACY_ED25519_ALG: 64,
    MAC_ALG: 32,
    ED25519_ALG: 64,
}

# Keys accepted by the resolver: raw bytes select HMAC-SHA256 (symmetric —
# whoever can verify can also sign); Ed25519 keys select asymmetric signing,
# where a public key is verification-only and cannot forge bands. That split
# is what gives the two-channel architecture true cryptographic role
# separation demonstrated by the guard-bands-reference deployment.
GuardBandKey = bytes | Ed25519PrivateKey | Ed25519PublicKey
GuardBandContext = dict[str, Any]
GuardBandResult = dict[str, Any]


class KeyResolver(Protocol):
    """Application-supplied key lookup boundary."""

    def get_signing_key(self, key_id: str | None = None) -> tuple[str, GuardBandKey]: ...

    def get_verification_key(self, key_id: str) -> GuardBandKey | None: ...


DEFAULT_TTL_SECONDS = 900
DEFAULT_ISSUER = "anonymous"

KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
ISSUER_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,344}$")  # base64url(no pad) of <=256 bytes
INT_PATTERN = re.compile(r"^[0-9]{1,19}$")
START_PREFIX = "⟪INERT:START:"
END_PREFIX = "⟪INERT:END:"
RESERVED_START_MARKER = "⟪INERT:START"
RESERVED_END_MARKER = "⟪INERT:END"


def canonical_json(value: Any) -> str:
    """Return RFC 8785 canonical JSON used by Guard Band protocol v2."""
    return rfc8785.dumps(value).decode("utf-8")


def _canonical_json_v1(value: Any) -> str:
    """Return the legacy Python canonical JSON used by protocol v1."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _canonical_json_for_version(value: Any, version: str) -> str:
    if version == "1":
        return _canonical_json_v1(value)
    if version == "2":
        return canonical_json(value)
    raise ValueError(f"Unsupported guard band version: {version}")


def canonical_context(context: GuardBandContext | None) -> str:
    """Return the canonical context string used for signing and verification."""
    return canonical_json(context or {})


def key_algorithm(key: GuardBandKey, *, version: str = CURRENT_PROTOCOL_VERSION) -> str:
    """Return the authenticated algorithm tag selected by a key's type."""
    try:
        algorithms = _ALGORITHMS[version]
    except KeyError as exc:
        raise ValueError(f"Unsupported guard band version: {version}") from exc
    if isinstance(key, (Ed25519PrivateKey, Ed25519PublicKey)):
        return algorithms["ed25519"]
    if isinstance(key, (bytes, bytearray)):
        return algorithms["hmac"]
    raise TypeError(f"Unsupported key type: {type(key).__name__}")


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


def generate_ed25519_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair as (private_b64url, public_b64url).

    The private key belongs only on signing services (e.g. the data plane);
    the public key is safe to distribute to verifiers, which cannot use it
    to forge bands.
    """
    private = Ed25519PrivateKey.generate()
    return (
        _b64url_no_pad(private.private_bytes_raw()),
        _b64url_no_pad(private.public_key().public_bytes_raw()),
    )


def load_ed25519_private_key(encoded: str) -> Ed25519PrivateKey:
    """Load a base64url-encoded raw Ed25519 private key."""
    return Ed25519PrivateKey.from_private_bytes(_b64url_decode(encoded.strip()))


def load_ed25519_public_key(encoded: str) -> Ed25519PublicKey:
    """Load a base64url-encoded raw Ed25519 public key."""
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(encoded.strip()))


def canonical_mac_payload(
    content: str,
    context: GuardBandContext | None,
    nonce: str,
    *,
    version: str,
    key_id: str,
    issuer: str,
    issued_at: int,
    expires_at: int,
    alg: str | None = None,
    kind: str = "text",
) -> bytes:
    """Serialize the exact payload authenticated by the Guard Band signature.

    Every field that travels in the marker — algorithm tag, protocol version,
    key id, issuer, and the issued/expiry timestamps — is bound here so none of
    them can be tampered with or downgraded without invalidating the signature.
    """
    payload = {
        "alg": alg or _ALGORITHMS.get(version, {}).get("hmac", MAC_ALG),
        "content": content,
        "context": context or {},
        "exp": expires_at,
        "iat": issued_at,
        "iss": issuer,
        "kid": key_id,
        "nonce": nonce,
        "v": version,
    }
    # Preserve the v1 text payload byte-for-byte while giving detached JSON
    # values an authenticated domain tag. A signature minted for one form can
    # therefore never be transplanted into the other.
    if kind != "text":
        payload["kind"] = kind
    return _canonical_json_for_version(payload, version).encode("utf-8")


def _encode_issuer(issuer: str) -> str:
    return base64.urlsafe_b64encode(issuer.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_issuer(encoded: str) -> str | None:
    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
    except Exception:
        return None


def extract_guard_band_blocks(text: str) -> list[str]:
    """Find syntactically valid Guard Band candidates in a larger prompt.

    Extraction does not establish authenticity. Every returned block still
    requires ``extract_and_verify`` with application-derived context.
    """
    blocks: list[str] = []
    search_from = 0
    while True:
        start_index = text.find(START_PREFIX, search_from)
        if start_index == -1:
            return blocks

        start_close = text.find("⟫\n", start_index + len(START_PREFIX))
        if start_close == -1:
            search_from = start_index + len(START_PREFIX)
            continue

        nested_start = text.find(
            START_PREFIX,
            start_index + len(START_PREFIX),
            start_close,
        )
        if nested_start != -1:
            search_from = nested_start
            continue

        end_index = text.find(f"\n{END_PREFIX}", start_close + 2)
        if end_index == -1:
            search_from = start_index + len(START_PREFIX)
            continue

        end_close = text.find("⟫", end_index + len(END_PREFIX) + 1)
        if end_close == -1:
            search_from = start_index + len(START_PREFIX)
            continue

        # A forged outer start must not swallow a genuine inner band. Valid
        # signer output can never contain a reserved start marker, so the
        # innermost candidate is the only one worth parsing.
        nested_start = text.find(START_PREFIX, start_close + 2, end_index)
        if nested_start != -1:
            search_from = nested_start
            continue

        candidate = text[start_index : end_close + 1]
        _, syntax_error = _parse_guard_band(candidate, validate_signature=True)
        if syntax_error is None:
            blocks.append(candidate)
            search_from = end_close + 1
        else:
            # Resume after the start token rather than after the candidate end
            # so a later genuine start cannot be skipped by hostile framing.
            search_from = start_index + len(START_PREFIX)


def _parse_guard_band_block(wrapped: str) -> tuple[str, str, str, str | None]:
    if not wrapped.startswith(START_PREFIX):
        return "", "", "", "Missing start marker"

    start_close = wrapped.find("⟫\n", len(START_PREFIX))
    if start_close == -1:
        return "", "", "", "Malformed guard band block"

    content_start = start_close + 2
    end_index = wrapped.rfind(f"\n{END_PREFIX}", content_start)
    if end_index == -1:
        return "", "", "", "Missing end marker"

    end_close = wrapped.find("⟫", end_index + len(END_PREFIX) + 1)
    if end_close != len(wrapped) - 1:
        return "", "", "", "Malformed guard band block"

    start_params = wrapped[len(START_PREFIX) : start_close]
    content = wrapped[content_start:end_index]
    end_params = wrapped[end_index + 1 + len(END_PREFIX) : end_close]
    return start_params, content, end_params, None


def _decode_base64_field(value: str, expected_bytes: int, field_name: str) -> str | None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        return f"Invalid {field_name} encoding"
    if len(decoded) != expected_bytes:
        return f"Invalid {field_name} length"
    return None


def _parse_params(raw_params: str, expected_keys: set[str]) -> tuple[dict[str, str], str | None]:
    parts = raw_params.split(":")
    if len(parts) % 2 != 0:
        return {}, "Malformed marker parameters"

    params: dict[str, str] = {}
    for index in range(0, len(parts), 2):
        key = parts[index]
        value = parts[index + 1]
        if not key or not value:
            return {}, "Malformed marker parameters"
        if key in params:
            return {}, f"Duplicate marker parameter: {key}"
        if key not in expected_keys:
            return {}, f"Unsupported marker parameter: {key}"
        params[key] = value

    missing = expected_keys - set(params)
    if missing:
        return {}, f"Missing marker parameter: {sorted(missing)[0]}"

    return params, None


def _parse_guard_band(
    wrapped: str,
    *,
    validate_signature: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    """Parse and validate marker grammar without establishing authenticity."""
    start_params, content, end_params, parse_error = _parse_guard_band_block(wrapped)
    if parse_error:
        return None, parse_error

    if RESERVED_START_MARKER in content or RESERVED_END_MARKER in content:
        return None, "Nested guard band markers are not allowed"

    start_dict, start_error = _parse_params(start_params, {"v", "r", "iat", "exp"})
    if start_error:
        return None, start_error

    end_dict, end_error = _parse_params(end_params, {"mac", "kid", "iss"})
    if end_error:
        return None, end_error

    version = start_dict["v"]
    if version not in SUPPORTED_PROTOCOL_VERSIONS:
        return None, f"Unsupported guard band version: {version}"

    nonce = start_dict["r"]
    if not NONCE_PATTERN.fullmatch(nonce):
        return None, "Invalid nonce format"

    if not INT_PATTERN.fullmatch(start_dict["iat"]) or not INT_PATTERN.fullmatch(start_dict["exp"]):
        return None, "Invalid timestamp format"
    issued_at = int(start_dict["iat"])
    expires_at = int(start_dict["exp"])
    if expires_at < issued_at:
        return None, "Invalid timestamp range"

    key_id = end_dict["kid"]
    if not KEY_ID_PATTERN.fullmatch(key_id):
        return None, "Invalid key id format"

    encoded_issuer = end_dict["iss"]
    if not ISSUER_PATTERN.fullmatch(encoded_issuer):
        return None, "Invalid issuer format"
    issuer = _decode_issuer(encoded_issuer)
    if issuer is None:
        return None, "Invalid issuer encoding"

    provided_mac = end_dict["mac"]
    if validate_signature:
        try:
            decoded_mac = base64.b64decode(provided_mac, validate=True)
        except Exception:
            return None, "Invalid MAC encoding"
        if len(decoded_mac) not in _SIGNATURE_LENGTHS.values():
            return None, "Invalid MAC length"

    return {
        "content": content,
        "version": version,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "key_id": key_id,
        "issuer": issuer,
        "provided_mac": provided_mac,
    }, None


class StaticKeyResolver:
    """Small key resolver for POC deployments and tests.

    Keys may be raw bytes (HMAC-SHA256), Ed25519 private keys (sign and
    verify), or Ed25519 public keys (verify-only). A resolver holding only a
    public key can verify bands but is cryptographically unable to mint them.
    """

    def __init__(self, keys: dict[str, GuardBandKey], signing_key_id: str = "key001") -> None:
        if not keys:
            raise ValueError("At least one signing key is required")
        if signing_key_id not in keys:
            raise ValueError("Signing key id must exist in key map")
        for key_id, key in keys.items():
            if not KEY_ID_PATTERN.fullmatch(key_id):
                raise ValueError(f"Invalid key id: {key_id}")
            key_algorithm(key)  # raises TypeError on unsupported key types
        self._keys = keys
        self.signing_key_id = signing_key_id

    def get_signing_key(self, key_id: str | None = None) -> tuple[str, GuardBandKey]:
        selected_key_id = key_id or self.signing_key_id
        if not KEY_ID_PATTERN.fullmatch(selected_key_id):
            raise ValueError("Invalid signing key id format")
        key = self._keys.get(selected_key_id)
        if key is None:
            raise ValueError(f"Unknown signing key id: {selected_key_id}")
        if isinstance(key, Ed25519PublicKey):
            raise ValueError(f"Key id {selected_key_id} is verification-only and cannot sign")
        return selected_key_id, key

    def get_verification_key(self, key_id: str) -> GuardBandKey | None:
        return self._keys.get(key_id)


class GuardBandCrypto:
    def __init__(
        self,
        secret_key: bytes | None = None,
        key_resolver: KeyResolver | None = None,
        default_key_id: str = "key001",
        signing_version: str = CURRENT_PROTOCOL_VERSION,
    ):
        if signing_version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise ValueError(f"Unsupported signing version: {signing_version}")
        if key_resolver is None:
            if secret_key is None:
                raise ValueError("secret_key or key_resolver is required")
            key_resolver = StaticKeyResolver({default_key_id: secret_key}, default_key_id)
        self.key_resolver = key_resolver
        self.signing_version = signing_version

    def generate_nonce(self) -> str:
        """Generate a random nonce"""
        return secrets.token_urlsafe(16)

    def hash_content(self, content: str) -> str:
        """SHA-256 digest of content.

        Informational only — the MAC is the integrity guarantee. Exposed for
        callers that want a stable content fingerprint (e.g. audit logs).
        """
        h = hashlib.sha256(content.encode("utf-8")).digest()
        return base64.b64encode(h).decode("utf-8")

    def generate_mac(
        self,
        content: str,
        context: GuardBandContext,
        nonce: str,
        secret_key: GuardBandKey,
        *,
        version: str,
        key_id: str,
        issuer: str,
        issued_at: int,
        expires_at: int,
        kind: str = "text",
    ) -> str:
        """Sign content + context + all authenticated metadata.

        The algorithm follows the key type: bytes → HMAC-SHA256, Ed25519
        private key → Ed25519 signature. A verification-only public key
        cannot sign and raises.
        """
        alg = key_algorithm(secret_key, version=version)
        message = canonical_mac_payload(
            content,
            context,
            nonce,
            version=version,
            key_id=key_id,
            issuer=issuer,
            issued_at=issued_at,
            expires_at=expires_at,
            alg=alg,
            kind=kind,
        )
        if isinstance(secret_key, Ed25519PublicKey):
            raise ValueError("Ed25519 public key is verification-only and cannot sign")
        if isinstance(secret_key, Ed25519PrivateKey):
            signature = secret_key.sign(message)
        else:
            signature = hmac.new(secret_key, message, hashlib.sha256).digest()
        return base64.b64encode(signature).decode("utf-8")

    def verify_mac(
        self,
        content: str,
        context: GuardBandContext,
        nonce: str,
        provided_mac: str,
        secret_key: GuardBandKey,
        *,
        version: str,
        key_id: str,
        issuer: str,
        issued_at: int,
        expires_at: int,
        kind: str = "text",
    ) -> bool:
        """Verify the signature over the recomputed authenticated payload."""
        alg = key_algorithm(secret_key, version=version)
        if isinstance(secret_key, (Ed25519PrivateKey, Ed25519PublicKey)):
            message = canonical_mac_payload(
                content,
                context,
                nonce,
                version=version,
                key_id=key_id,
                issuer=issuer,
                issued_at=issued_at,
                expires_at=expires_at,
                alg=alg,
                kind=kind,
            )
            public_key = (
                secret_key.public_key() if isinstance(secret_key, Ed25519PrivateKey) else secret_key
            )
            try:
                public_key.verify(base64.b64decode(provided_mac), message)
                return True
            except (InvalidSignature, ValueError):
                return False

        expected_mac = self.generate_mac(
            content,
            context,
            nonce,
            secret_key,
            version=version,
            key_id=key_id,
            issuer=issuer,
            issued_at=issued_at,
            expires_at=expires_at,
            kind=kind,
        )
        return hmac.compare_digest(expected_mac, provided_mac)

    def sign_value(
        self,
        value: Any,
        context: GuardBandContext,
        key_id: str | None = None,
        issuer: str | None = None,
        ttl_seconds: int | None = None,
        now: float | None = None,
    ) -> GuardBandResult:
        """Sign a JSON-compatible value and return a detached envelope.

        Detached envelopes are intended for structured protocols such as MCP,
        where changing the application's JSON value would violate its schema.
        The value itself is not included in the envelope.
        """
        value_json = _canonical_json_for_version(value, self.signing_version)
        issuer = issuer or DEFAULT_ISSUER
        if len(issuer.encode("utf-8")) > 256:
            raise ValueError("Issuer must be at most 256 bytes")

        ttl = DEFAULT_TTL_SECONDS if ttl_seconds is None else ttl_seconds
        if ttl < 0:
            raise ValueError("ttl_seconds must not be negative")

        nonce = self.generate_nonce()
        signing_key_id, signing_key = self.key_resolver.get_signing_key(key_id)
        issued_at = int(time.time() if now is None else now)
        expires_at = issued_at + ttl
        algorithm = key_algorithm(signing_key, version=self.signing_version)
        signature = self.generate_mac(
            value_json,
            context,
            nonce,
            signing_key,
            version=self.signing_version,
            key_id=signing_key_id,
            issuer=issuer,
            issued_at=issued_at,
            expires_at=expires_at,
            kind=STRUCTURED_VALUE_KIND,
        )
        return {
            "version": self.signing_version,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "key_id": signing_key_id,
            "issuer": issuer,
            "algorithm": algorithm,
            "signature": signature,
        }

    def verify_value(
        self,
        value: Any,
        envelope: GuardBandResult,
        context: GuardBandContext,
        now: float | None = None,
    ) -> GuardBandResult:
        """Verify a detached envelope for a JSON-compatible value."""
        try:
            expected_fields = {
                "version",
                "nonce",
                "issued_at",
                "expires_at",
                "key_id",
                "issuer",
                "algorithm",
                "signature",
            }
            if not isinstance(envelope, dict) or set(envelope) != expected_fields:
                return {"valid": False, "error": "Invalid detached envelope fields"}

            version = envelope["version"]
            nonce = envelope["nonce"]
            issued_at = envelope["issued_at"]
            expires_at = envelope["expires_at"]
            key_id = envelope["key_id"]
            issuer = envelope["issuer"]
            algorithm = envelope["algorithm"]
            signature = envelope["signature"]

            if not isinstance(version, str) or version not in SUPPORTED_PROTOCOL_VERSIONS:
                return {"valid": False, "error": f"Unsupported guard band version: {version}"}
            if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
                return {"valid": False, "error": "Invalid nonce format"}
            if type(issued_at) is not int or type(expires_at) is not int:
                return {"valid": False, "error": "Invalid timestamp format"}
            if issued_at < 0 or expires_at < issued_at:
                return {"valid": False, "error": "Invalid timestamp range"}
            if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
                return {"valid": False, "error": "Invalid key id format"}
            if not isinstance(issuer, str) or len(issuer.encode("utf-8")) > 256:
                return {"valid": False, "error": "Invalid issuer format"}
            if not isinstance(signature, str):
                return {"valid": False, "error": "Invalid signature format"}

            verification_key = self.key_resolver.get_verification_key(key_id)
            if verification_key is None:
                return {"valid": False, "error": f"Unknown key id: {key_id}"}
            expected_algorithm = key_algorithm(verification_key, version=version)
            if algorithm != expected_algorithm:
                return {"valid": False, "error": "Signature algorithm mismatch"}
            signature_error = _decode_base64_field(
                signature, _SIGNATURE_LENGTHS[expected_algorithm], "signature"
            )
            if signature_error:
                return {"valid": False, "error": signature_error}

            value_json = _canonical_json_for_version(value, version)
            if not self.verify_mac(
                value_json,
                context,
                nonce,
                signature,
                verification_key,
                version=version,
                key_id=key_id,
                issuer=issuer,
                issued_at=issued_at,
                expires_at=expires_at,
                kind=STRUCTURED_VALUE_KIND,
            ):
                return {"valid": False, "error": "Signature verification failed"}

            current_time = int(time.time() if now is None else now)
            if current_time > expires_at:
                return {
                    "valid": False,
                    "error": "Guard band expired",
                    "nonce": nonce,
                    "key_id": key_id,
                }

            return {
                "valid": True,
                "value": value,
                "nonce": nonce,
                "key_id": key_id,
                "version": version,
                "issuer": issuer,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "algorithm": algorithm,
            }
        except (TypeError, ValueError, RecursionError) as exc:
            return {"valid": False, "error": f"Value verification error: {exc}"}

    def wrap_with_metadata(
        self,
        content: str,
        context: GuardBandContext,
        key_id: str | None = None,
        issuer: str | None = None,
        ttl_seconds: int | None = None,
        now: float | None = None,
    ) -> GuardBandResult:
        """Wrap content and return the band plus its authenticated metadata."""
        if RESERVED_START_MARKER in content or RESERVED_END_MARKER in content:
            raise ValueError("Content contains reserved Guard Band markers")

        issuer = issuer or DEFAULT_ISSUER
        if len(issuer.encode("utf-8")) > 256:
            raise ValueError("Issuer must be at most 256 bytes")

        ttl = DEFAULT_TTL_SECONDS if ttl_seconds is None else ttl_seconds
        if ttl < 0:
            raise ValueError("ttl_seconds must not be negative")

        nonce = self.generate_nonce()
        signing_key_id, signing_key = self.key_resolver.get_signing_key(key_id)
        issued_at = int(time.time() if now is None else now)
        expires_at = issued_at + ttl

        mac = self.generate_mac(
            content,
            context,
            nonce,
            signing_key,
            version=self.signing_version,
            key_id=signing_key_id,
            issuer=issuer,
            issued_at=issued_at,
            expires_at=expires_at,
        )

        wrapped = (
            f"⟪INERT:START:v:{self.signing_version}"
            f":r:{nonce}:iat:{issued_at}:exp:{expires_at}⟫\n"
            f"{content}\n"
            f"⟪INERT:END:mac:{mac}:kid:{signing_key_id}:iss:{_encode_issuer(issuer)}⟫"
        )
        return {
            "wrapped": wrapped,
            "nonce": nonce,
            "key_id": signing_key_id,
            "issuer": issuer,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    def wrap_content(
        self,
        content: str,
        context: GuardBandContext,
        key_id: str | None = None,
        issuer: str | None = None,
        ttl_seconds: int | None = None,
        now: float | None = None,
    ) -> str:
        """Wrap content with guard bands and return the band string."""
        metadata = self.wrap_with_metadata(
            content,
            context,
            key_id=key_id,
            issuer=issuer,
            ttl_seconds=ttl_seconds,
            now=now,
        )
        return cast(str, metadata["wrapped"])

    def extract_and_verify(
        self,
        wrapped: str,
        context: GuardBandContext,
        now: float | None = None,
    ) -> GuardBandResult:
        """Extract content and verify guard bands"""
        try:
            if "⟪INERT:START" not in wrapped:
                return {"valid": False, "error": "Missing start marker"}

            if "⟪INERT:END" not in wrapped:
                return {"valid": False, "error": "Missing end marker"}

            parsed, parse_error = _parse_guard_band(wrapped)
            if parse_error:
                return {"valid": False, "error": parse_error}
            assert parsed is not None

            content = parsed["content"]
            version = parsed["version"]
            nonce = parsed["nonce"]
            issued_at = parsed["issued_at"]
            expires_at = parsed["expires_at"]
            key_id = parsed["key_id"]
            issuer = parsed["issuer"]
            provided_mac = parsed["provided_mac"]

            verification_key = self.key_resolver.get_verification_key(key_id)
            if verification_key is None:
                return {"valid": False, "error": f"Unknown key id: {key_id}"}

            expected_length = _SIGNATURE_LENGTHS[key_algorithm(verification_key, version=version)]
            mac_error = _decode_base64_field(provided_mac, expected_length, "MAC")
            if mac_error:
                return {"valid": False, "error": mac_error}

            # Verify the signature — the sole integrity and authenticity check.
            # It binds content, context, nonce, version, key id, issuer,
            # lifetime, and the algorithm tag (derived from the key type, so
            # cross-algorithm confusion fails closed).
            if not self.verify_mac(
                content,
                context,
                nonce,
                provided_mac,
                verification_key,
                version=version,
                key_id=key_id,
                issuer=issuer,
                issued_at=issued_at,
                expires_at=expires_at,
            ):
                return {"valid": False, "error": "MAC verification failed"}

            # Freshness is enforced only after the MAC proves iat/exp authentic,
            # so a tampered expiry cannot extend a band's lifetime (fail closed).
            current_time = int(time.time() if now is None else now)
            if current_time > expires_at:
                return {
                    "valid": False,
                    "error": "Guard band expired",
                    "nonce": nonce,
                    "key_id": key_id,
                }

            return {
                "valid": True,
                "content": content,
                "nonce": nonce,
                "key_id": key_id,
                "version": version,
                "issuer": issuer,
                "issued_at": issued_at,
                "expires_at": expires_at,
            }

        except Exception as e:
            return {"valid": False, "error": f"Parse error: {str(e)}"}
