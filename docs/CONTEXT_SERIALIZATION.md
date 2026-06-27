# Canonical Context Serialization

Guard Bands signs a canonical JSON payload:

```json
{
  "content": "<exact wrapped content body>",
  "context": { "...": "..." },
  "nonce": "<guard-band nonce>"
}
```

The canonical serializer uses:

- UTF-8 encoded JSON
- sorted object keys
- compact separators with no insignificant spaces
- unescaped non-ASCII characters
- no NaN or Infinity values

This makes context key order irrelevant:

```json
{"request_id":"req-001","user":"alice"}
```

and:

```json
{"user":"alice","request_id":"req-001"}
```

produce the same authenticated context.

## Context Design

Context should include the values that make a wrapped payload valid for exactly the intended use:

- `request_id` or workflow execution id
- `tenant_id` or account boundary
- authenticated user or service principal
- policy path or tool path
- model/workflow version when relevant
- timestamp or expiration bucket when using time-bounded replay protection

Do not include unstable values that legitimately change between wrap and verify unless they are intentionally part of the security decision.

## Compatibility Note

Changing canonicalization changes MAC input. If this POC is extended into a deployed system, treat serialization rules as versioned protocol behavior and include the serializer version in signed metadata before supporting multiple formats.

The current marker format includes protocol version `v:1`:

```text
⟪INERT:START:v:1:r:nonce:h:hash⟫
content
⟪INERT:END:mac:signature:kid:key001⟫
```
