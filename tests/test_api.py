from fastapi.testclient import TestClient

from app.main import app


def test_wrap_and_verify_api_round_trip():
    with TestClient(app) as client:
        context = {"request_id": "req-001", "user": "alice"}
        wrap_response = client.post(
            "/wrap",
            json={"content": "API document", "context": context},
        )
        assert wrap_response.status_code == 200

        wrapped = wrap_response.json()["wrapped_content"]
        verify_response = client.post(
            "/verify",
            json={"wrapped_content": wrapped, "context": context},
        )

    assert verify_response.status_code == 200
    assert verify_response.json()["valid"] is True
    assert verify_response.json()["content"] == "API document"


def test_verify_api_rejects_replayed_context():
    with TestClient(app) as client:
        wrap_response = client.post(
            "/wrap",
            json={
                "content": "Tenant A document",
                "context": {"tenant": "a", "request_id": "req-001"},
            },
        )
        wrapped = wrap_response.json()["wrapped_content"]

        verify_response = client.post(
            "/verify",
            json={
                "wrapped_content": wrapped,
                "context": {"tenant": "b", "request_id": "req-001"},
            },
        )

    assert verify_response.status_code == 200
    assert verify_response.json()["valid"] is False
    assert verify_response.json()["error"] == "MAC verification failed"


def test_wrap_api_rejects_unknown_key_id():
    with TestClient(app) as client:
        response = client.post(
            "/wrap",
            json={
                "content": "API document",
                "context": {"request_id": "req-001"},
                "key_id": "missing-key",
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown signing key id: missing-key"


def test_chat_estimate_cost_api_returns_preflight_estimate():
    with TestClient(app) as client:
        response = client.post(
            "/chat/estimate-cost",
            json={
                "message": "Summarize this document",
                "context": {"request_id": "req-001"},
                "max_output_tokens": 100,
            },
        )

    assert response.status_code == 200
    estimate = response.json()
    assert estimate["model"]
    assert estimate["method"] == "approx_chars_per_token"
    assert estimate["input_tokens_estimate"] > 0
    assert estimate["output_tokens_budget"] == 100
    assert estimate["estimated_total_cost_usd"] >= 0
    assert estimate["threshold_usd"] == 1.0
