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

