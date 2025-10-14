import requests
import json

BASE_URL = "http://localhost:8000"

# Test wrapping
print("=== WRAPPING ===")
wrap_response = requests.post(f"{BASE_URL}/wrap", json={
    "content": "Test content",
    "context": {"request_id": "req-001", "user": "alice"}
})

print("Wrap response:")
print(json.dumps(wrap_response.json(), indent=2))
print()

wrapped = wrap_response.json()["wrapped_content"]
print("Wrapped content:")
print(wrapped)
print()

# Test verification with SAME context
print("=== VERIFYING (same context) ===")
verify_response = requests.post(f"{BASE_URL}/verify", json={
    "wrapped_content": wrapped,
    "context": {"request_id": "req-001", "user": "alice"}
})

print("Verify response:")
print(json.dumps(verify_response.json(), indent=2))
