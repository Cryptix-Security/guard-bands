import hmac
import hashlib
import secrets
import base64
import json
import re
from typing import Any


SUPPORTED_PROTOCOL_VERSION = "1"
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
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


def canonical_mac_payload(content: str, context: dict | None, nonce: str) -> bytes:
    """Serialize the exact payload authenticated by the Guard Band MAC."""
    return canonical_json({
        "content": content,
        "context": context or {},
        "nonce": nonce,
    }).encode("utf-8")


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
        """SHA-256 hash of content"""
        h = hashlib.sha256(content.encode('utf-8')).digest()
        return base64.b64encode(h).decode('utf-8')
    
    def generate_mac(self, content: str, context: dict, nonce: str, secret_key: bytes) -> str:
        """Generate HMAC for content + context + nonce."""
        message = canonical_mac_payload(content, context, nonce)

        h = hmac.new(secret_key, message, hashlib.sha256)
        return base64.b64encode(h.digest()).decode('utf-8')
    
    def verify_mac(self, content: str, context: dict, nonce: str, provided_mac: str, secret_key: bytes) -> bool:
        """Verify HMAC matches"""
        expected_mac = self.generate_mac(content, context, nonce, secret_key)
        return hmac.compare_digest(expected_mac, provided_mac)
    
    def wrap_content(self, content: str, context: dict, key_id: str | None = None) -> str:
        """Wrap content with guard bands"""
        nonce = self.generate_nonce()
        content_hash = self.hash_content(content)
        signing_key_id, signing_key = self.key_resolver.get_signing_key(key_id)
        mac = self.generate_mac(content, context, nonce, signing_key)
        
        wrapped = (
            f"⟪INERT:START:v:{SUPPORTED_PROTOCOL_VERSION}:r:{nonce}:h:{content_hash}⟫\n"
            f"{content}\n"
            f"⟪INERT:END:mac:{mac}:kid:{signing_key_id}⟫"
        )
        return wrapped
    
    def extract_and_verify(self, wrapped: str, context: dict) -> dict:
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

            start_dict, start_error = _parse_params(start_params, {"v", "r", "h"})
            if start_error:
                return {"valid": False, "error": start_error}

            end_dict, end_error = _parse_params(end_params, {"mac", "kid"})
            if end_error:
                return {"valid": False, "error": end_error}

            version = start_dict["v"]
            if version != SUPPORTED_PROTOCOL_VERSION:
                return {"valid": False, "error": f"Unsupported guard band version: {version}"}

            nonce = start_dict["r"]
            if not NONCE_PATTERN.fullmatch(nonce):
                return {"valid": False, "error": "Invalid nonce format"}

            key_id = end_dict["kid"]
            if not KEY_ID_PATTERN.fullmatch(key_id):
                return {"valid": False, "error": "Invalid key id format"}

            verification_key = self.key_resolver.get_verification_key(key_id)
            if verification_key is None:
                return {"valid": False, "error": f"Unknown key id: {key_id}"}

            provided_hash = start_dict["h"]
            hash_error = _decode_base64_field(provided_hash, 32, "content hash")
            if hash_error:
                return {"valid": False, "error": hash_error}

            provided_mac = end_dict["mac"]
            mac_error = _decode_base64_field(provided_mac, 32, "MAC")
            if mac_error:
                return {"valid": False, "error": mac_error}

            # Verify hash
            expected_hash = self.hash_content(content)
            if not hmac.compare_digest(expected_hash, provided_hash):
                return {
                    "valid": False, 
                    "error": f"Content hash mismatch (expected: {expected_hash[:20]}..., got: {provided_hash[:20]}...)"
                }
            
            # Verify MAC
            if not self.verify_mac(content, context, nonce, provided_mac, verification_key):
                return {"valid": False, "error": "MAC verification failed"}
            
            return {
                "valid": True,
                "content": content,
                "nonce": nonce,
                "key_id": key_id,
                "version": version,
            }
            
        except Exception as e:
            return {"valid": False, "error": f"Parse error: {str(e)}"}
