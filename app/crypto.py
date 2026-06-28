import hmac
import hashlib
import secrets
import base64
import json
import re
import time
from typing import Any


SUPPORTED_PROTOCOL_VERSION = "1"
# Domain-separation / algorithm tag bound into every MAC. Bump this (and add a
# new branch in extract_and_verify) before introducing a second MAC algorithm
# so an attacker cannot downgrade an authenticated band to a weaker scheme.
MAC_ALG = "GBv1-HMAC-SHA256"
DEFAULT_TTL_SECONDS = 900
DEFAULT_ISSUER = "anonymous"

KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
ISSUER_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,344}$")  # base64url(no pad) of <=256 bytes
INT_PATTERN = re.compile(r"^[0-9]{1,19}$")
START_PREFIX = "⟪INERT:START:"
END_PREFIX = "⟪INERT:END:"


def canonical_json(value: Any) -> str:
    """Return stable JSON for authenticated Guard Band metadata."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_context(context: dict | None) -> str:
    """Return the canonical context string used for signing and verification."""
    return canonical_json(context or {})


def canonical_mac_payload(
    content: str,
    context: dict | None,
    nonce: str,
    *,
    version: str,
    key_id: str,
    issuer: str,
    issued_at: int,
    expires_at: int,
) -> bytes:
    """Serialize the exact payload authenticated by the Guard Band MAC.

    Every field that travels in the marker — algorithm tag, protocol version,
    key id, issuer, and the issued/expiry timestamps — is bound here so none of
    them can be tampered with or downgraded without invalidating the MAC.
    """
    return canonical_json({
        "alg": MAC_ALG,
        "content": content,
        "context": context or {},
        "exp": expires_at,
        "iat": issued_at,
        "iss": issuer,
        "kid": key_id,
        "nonce": nonce,
        "v": version,
    }).encode("utf-8")


def _encode_issuer(issuer: str) -> str:
    return base64.urlsafe_b64encode(issuer.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_issuer(encoded: str) -> str | None:
    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
    except Exception:
        return None


def extract_guard_band_blocks(text: str) -> list[str]:
    """Find complete Guard Band blocks embedded in a larger prompt."""
    blocks = []
    search_from = 0
    while True:
        start_index = text.find(START_PREFIX, search_from)
        if start_index == -1:
            return blocks

        start_close = text.find("⟫\n", start_index + len(START_PREFIX))
        if start_close == -1:
            search_from = start_index + len(START_PREFIX)
            continue

        nested_start = text.find(START_PREFIX, start_index + len(START_PREFIX), start_close)
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

        blocks.append(text[start_index:end_close + 1])
        search_from = end_close + 1


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

    start_params = wrapped[len(START_PREFIX):start_close]
    content = wrapped[content_start:end_index]
    end_params = wrapped[end_index + 1 + len(END_PREFIX):end_close]
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


class StaticKeyResolver:
    """Small key resolver for POC deployments and tests."""

    def __init__(self, keys: dict[str, bytes], signing_key_id: str = "key001") -> None:
        if not keys:
            raise ValueError("At least one signing key is required")
        if signing_key_id not in keys:
            raise ValueError("Signing key id must exist in key map")
        for key_id in keys:
            if not KEY_ID_PATTERN.fullmatch(key_id):
                raise ValueError(f"Invalid key id: {key_id}")
        self._keys = keys
        self.signing_key_id = signing_key_id

    def get_signing_key(self, key_id: str | None = None) -> tuple[str, bytes]:
        selected_key_id = key_id or self.signing_key_id
        if not KEY_ID_PATTERN.fullmatch(selected_key_id):
            raise ValueError("Invalid signing key id format")
        key = self._keys.get(selected_key_id)
        if key is None:
            raise ValueError(f"Unknown signing key id: {selected_key_id}")
        return selected_key_id, key

    def get_verification_key(self, key_id: str) -> bytes | None:
        return self._keys.get(key_id)


class GuardBandCrypto:
    def __init__(
        self,
        secret_key: bytes | None = None,
        key_resolver: StaticKeyResolver | None = None,
        default_key_id: str = "key001",
    ):
        if key_resolver is None:
            if secret_key is None:
                raise ValueError("secret_key or key_resolver is required")
            key_resolver = StaticKeyResolver({default_key_id: secret_key}, default_key_id)
        self.key_resolver = key_resolver

    def generate_nonce(self) -> str:
        """Generate a random nonce"""
        return secrets.token_urlsafe(16)

    def hash_content(self, content: str) -> str:
        """SHA-256 digest of content.

        Informational only — the MAC is the integrity guarantee. Exposed for
        callers that want a stable content fingerprint (e.g. audit logs).
        """
        h = hashlib.sha256(content.encode('utf-8')).digest()
        return base64.b64encode(h).decode('utf-8')

    def generate_mac(
        self,
        content: str,
        context: dict,
        nonce: str,
        secret_key: bytes,
        *,
        version: str,
        key_id: str,
        issuer: str,
        issued_at: int,
        expires_at: int,
    ) -> str:
        """Generate HMAC over content + context + all authenticated metadata."""
        message = canonical_mac_payload(
            content, context, nonce,
            version=version, key_id=key_id, issuer=issuer,
            issued_at=issued_at, expires_at=expires_at,
        )
        h = hmac.new(secret_key, message, hashlib.sha256)
        return base64.b64encode(h.digest()).decode('utf-8')

    def verify_mac(
        self,
        content: str,
        context: dict,
        nonce: str,
        provided_mac: str,
        secret_key: bytes,
        *,
        version: str,
        key_id: str,
        issuer: str,
        issued_at: int,
        expires_at: int,
    ) -> bool:
        """Verify HMAC matches the recomputed authenticated payload."""
        expected_mac = self.generate_mac(
            content, context, nonce, secret_key,
            version=version, key_id=key_id, issuer=issuer,
            issued_at=issued_at, expires_at=expires_at,
        )
        return hmac.compare_digest(expected_mac, provided_mac)

    def wrap_with_metadata(
        self,
        content: str,
        context: dict,
        key_id: str | None = None,
        issuer: str | None = None,
        ttl_seconds: int | None = None,
        now: float | None = None,
    ) -> dict:
        """Wrap content and return the band plus its authenticated metadata."""
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
            content, context, nonce, signing_key,
            version=SUPPORTED_PROTOCOL_VERSION, key_id=signing_key_id,
            issuer=issuer, issued_at=issued_at, expires_at=expires_at,
        )

        wrapped = (
            f"⟪INERT:START:v:{SUPPORTED_PROTOCOL_VERSION}"
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
        context: dict,
        key_id: str | None = None,
        issuer: str | None = None,
        ttl_seconds: int | None = None,
        now: float | None = None,
    ) -> str:
        """Wrap content with guard bands and return the band string."""
        return self.wrap_with_metadata(
            content, context, key_id=key_id, issuer=issuer,
            ttl_seconds=ttl_seconds, now=now,
        )["wrapped"]

    def extract_and_verify(self, wrapped: str, context: dict, now: float | None = None) -> dict:
        """Extract content and verify guard bands"""
        try:
            if "⟪INERT:START" not in wrapped:
                return {"valid": False, "error": "Missing start marker"}

            if "⟪INERT:END" not in wrapped:
                return {"valid": False, "error": "Missing end marker"}

            start_params, content, end_params, parse_error = _parse_guard_band_block(wrapped)
            if parse_error:
                return {"valid": False, "error": parse_error}

            if "⟪INERT:START" in content or "⟪INERT:END" in content:
                return {"valid": False, "error": "Nested guard band markers are not allowed"}

            start_dict, start_error = _parse_params(start_params, {"v", "r", "iat", "exp"})
            if start_error:
                return {"valid": False, "error": start_error}

            end_dict, end_error = _parse_params(end_params, {"mac", "kid", "iss"})
            if end_error:
                return {"valid": False, "error": end_error}

            version = start_dict["v"]
            if version != SUPPORTED_PROTOCOL_VERSION:
                return {"valid": False, "error": f"Unsupported guard band version: {version}"}

            nonce = start_dict["r"]
            if not NONCE_PATTERN.fullmatch(nonce):
                return {"valid": False, "error": "Invalid nonce format"}

            if not INT_PATTERN.fullmatch(start_dict["iat"]) or not INT_PATTERN.fullmatch(start_dict["exp"]):
                return {"valid": False, "error": "Invalid timestamp format"}
            issued_at = int(start_dict["iat"])
            expires_at = int(start_dict["exp"])
            if expires_at < issued_at:
                return {"valid": False, "error": "Invalid timestamp range"}

            key_id = end_dict["kid"]
            if not KEY_ID_PATTERN.fullmatch(key_id):
                return {"valid": False, "error": "Invalid key id format"}

            encoded_issuer = end_dict["iss"]
            if not ISSUER_PATTERN.fullmatch(encoded_issuer):
                return {"valid": False, "error": "Invalid issuer format"}
            issuer = _decode_issuer(encoded_issuer)
            if issuer is None:
                return {"valid": False, "error": "Invalid issuer encoding"}

            verification_key = self.key_resolver.get_verification_key(key_id)
            if verification_key is None:
                return {"valid": False, "error": f"Unknown key id: {key_id}"}

            provided_mac = end_dict["mac"]
            mac_error = _decode_base64_field(provided_mac, 32, "MAC")
            if mac_error:
                return {"valid": False, "error": mac_error}

            # Verify MAC — the sole integrity and authenticity check. It binds
            # content, context, nonce, version, key id, issuer, and lifetime.
            if not self.verify_mac(
                content, context, nonce, provided_mac, verification_key,
                version=version, key_id=key_id, issuer=issuer,
                issued_at=issued_at, expires_at=expires_at,
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
