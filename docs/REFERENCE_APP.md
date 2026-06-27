# Reference Support App

`reference_app/support_app.py` is a small FastAPI workflow showing how Guard Bands can fit into a real application.

It models a support-ticket flow:

1. A ticket enters the system as untrusted content.
2. The app wraps the ticket with Guard Bands and a `support.read_only` policy path.
3. A read-only summary action verifies and authorizes successfully.
4. A refund action is rejected because the content was not signed for `support.refund`.
5. Tampered content is rejected before authorization.

Run the command-line demo:

```bash
make reference-demo
```

Run the app directly:

```bash
export REFERENCE_APP_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
uvicorn reference_app.support_app:app --reload --port 8001
```

Example wrap call:

```bash
curl -X POST http://localhost:8001/tickets/wrap \
  -H "Content-Type: application/json" \
  -d '{
    "ticket_id": "ticket-001",
    "content": "Customer asks for an order status update.",
    "principal": {
      "user_id": "alice",
      "tenant_id": "tenant-a",
      "roles": ["support_agent"]
    }
  }'
```

The returned `wrapped_content` and `context` can then be submitted to `/tool-action`.

This app is deliberately small. It is meant to show the enforcement sequence, not to provide production user management, persistence, or a real CRM integration.
