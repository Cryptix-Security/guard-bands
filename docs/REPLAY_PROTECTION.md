# Replay-Protection Examples

Guard Bands prevents replay across different authenticated contexts. A payload wrapped for one tenant, request, user, or policy path fails verification when used under another context.

Replay within the exact same context is an application policy decision. For production systems, pair Guard Bands with a nonce ledger, expiration window, or both.

## Context-Bound Replay Protection

Wrap with a narrow context:

```json
{
  "request_id": "req-001",
  "tenant_id": "tenant-a",
  "user": "alice",
  "policy_path": "support.summarize"
}
```

Verification fails if an attacker reuses the payload under:

```json
{
  "request_id": "req-001",
  "tenant_id": "tenant-b",
  "user": "alice",
  "policy_path": "support.summarize"
}
```

or:

```json
{
  "request_id": "req-001",
  "tenant_id": "tenant-a",
  "user": "alice",
  "policy_path": "support.issue_refund"
}
```

## Nonce Ledger Pattern

For single-use payloads, store verified nonces and reject reuse:

```python
result = crypto.extract_and_verify(wrapped, context)
if not result["valid"]:
    deny(result["error"])

nonce_key = (context["tenant_id"], result["key_id"], result["nonce"])
if nonce_ledger.exists(nonce_key):
    deny("replayed nonce")

nonce_ledger.insert(nonce_key, ttl_seconds=900)
allow(result["content"])
```

Use an atomic insert or uniqueness constraint so two concurrent requests cannot both consume the same nonce.

## Expiration-Bucket Pattern

For workflows that tolerate short reuse, include a bounded time bucket in context:

```json
{
  "request_id": "req-001",
  "tenant_id": "tenant-a",
  "user": "alice",
  "policy_path": "support.summarize",
  "expires_at": "2026-06-14T22:00:00Z"
}
```

Verification should check both the MAC and the expiration timestamp. The timestamp must be part of the signed context so attackers cannot extend the lifetime.

## Tool-Path Binding

Bind wrapped content to the narrowest tool or policy path that may consume it:

```json
{
  "request_id": "req-001",
  "tenant_id": "tenant-a",
  "user": "alice",
  "policy_path": "crm.read_only_summary"
}
```

The same payload should not verify for:

```json
{
  "request_id": "req-001",
  "tenant_id": "tenant-a",
  "user": "alice",
  "policy_path": "crm.update_customer_record"
}
```

