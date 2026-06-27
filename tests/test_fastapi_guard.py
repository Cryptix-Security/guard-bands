from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.crypto import GuardBandCrypto
from integrations.fastapi_guard import (
    GuardBandVerificationMiddleware,
    guard_band_verification,
)


def make_app(crypto: GuardBandCrypto, max_body_bytes: int = 50_000) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        GuardBandVerificationMiddleware,
        crypto=crypto,
        required_paths={"/protected"},
        max_body_bytes=max_body_bytes,
    )

    @app.post("/protected")
    async def protected(payload: dict, request: Request):
        verification = guard_band_verification(request)
        return {
            "content": verification["content"],
            "payload_keys": sorted(payload.keys()),
            "verified": verification["valid"],
        }

    @app.post("/open")
    async def open_route(payload: dict):
        return {"payload_keys": sorted(payload.keys())}

    return app


def test_fastapi_guard_middleware_verifies_before_route_handler():
    crypto = GuardBandCrypto(b"test-secret")
    app = make_app(crypto)
    context = {"request_id": "req-001", "user": "alice"}
    wrapped = crypto.wrap_content("Sensitive tool input", context)

    with TestClient(app) as client:
        response = client.post(
            "/protected",
            json={"wrapped_content": wrapped, "context": context, "other": "value"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "content": "Sensitive tool input",
        "payload_keys": ["context", "other", "wrapped_content"],
        "verified": True,
    }


def test_fastapi_guard_middleware_rejects_context_replay():
    crypto = GuardBandCrypto(b"test-secret")
    app = make_app(crypto)
    wrapped = crypto.wrap_content("Tenant A document", {"tenant": "a"})

    with TestClient(app) as client:
        response = client.post(
            "/protected",
            json={"wrapped_content": wrapped, "context": {"tenant": "b"}},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Guard Band verification failed: MAC verification failed"


def test_fastapi_guard_middleware_only_applies_to_required_paths():
    crypto = GuardBandCrypto(b"test-secret")
    app = make_app(crypto)

    with TestClient(app) as client:
        response = client.post("/open", json={"message": "no guard band required"})

    assert response.status_code == 200
    assert response.json() == {"payload_keys": ["message"]}


def test_fastapi_guard_middleware_rejects_oversized_body():
    crypto = GuardBandCrypto(b"test-secret")
    app = make_app(crypto, max_body_bytes=20)

    with TestClient(app) as client:
        response = client.post(
            "/protected",
            json={"wrapped_content": "too large for this route", "context": {}},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Request body exceeds 20 bytes"
