# Authorization Example

Guard Bands answers one question:

> Was this content wrapped by a trusted signer, unchanged, and used in the expected context?

Authorization answers a different question:

> Is this caller allowed to perform this action on this resource?

Real deployments need both.

## Policy Path Binding

Bind wrapped content to the narrowest policy path that may consume it:

```json
{
  "request_id": "ticket-001",
  "tenant_id": "tenant-a",
  "user": "alice",
  "policy_path": "support.read_only",
  "resource_type": "support_ticket"
}
```

The same wrapped content should not verify for `support.refund`, `crm.update_customer`, or any other more privileged path because the policy path is part of the signed context.

## Example Check

`app/authorization.py` includes a small role and policy-path example:

```python
from app.authorization import Principal, authorize_action

principal = Principal(
    user_id="alice",
    tenant_id="tenant-a",
    roles=frozenset({"support_agent"}),
)

decision = authorize_action(
    principal=principal,
    action="summarize_ticket",
    context={
        "tenant_id": "tenant-a",
        "user": "alice",
        "policy_path": "support.read_only",
    },
)

if not decision.allowed:
    deny(decision.reason)
```

## Tool Execution Pattern

Before a sensitive tool runs:

1. Verify Guard Bands.
2. Build the authenticated principal from your IdP/session.
3. Authorize the requested action against the signed context.
4. Run the tool only if both verification and authorization pass.
5. Audit the decision.

```python
verification = crypto.extract_and_verify(wrapped_content, context)
if not verification["valid"]:
    deny(verification["error"])

decision = authorize_action(principal, "refund_customer", context)
if not decision.allowed:
    deny(decision.reason)

run_refund_tool()
```

## Reference App

The reference app in `reference_app/support_app.py` demonstrates:

- wrapping a support ticket as untrusted content
- allowing `summarize_ticket` from a `support.read_only` context
- rejecting `refund_customer` when the content is only signed for read-only use
- rejecting tampered ticket content before authorization

Run it without an external service:

```bash
make reference-demo
```
