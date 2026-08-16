# MCP Integration

Guard Bands integrates with MCP 2.x at the `tools/call` boundary. The adapter
is optional:

```bash
python -m pip install 'guard-bands[mcp]'
```

## What Is Protected

For each configured tool, `MCPToolPolicy` independently enables:

- `guard_inputs`: the client signs the complete arguments object and the server
  verifies it before the tool handler runs.
- `guard_outputs`: the server signs the complete final `CallToolResult` and the
  client verifies it before returning it to the host.
- `wrap_text_outputs`: text content blocks also receive visible inline Guard
  Band markers so the model sees the data/instruction boundary. This defaults
  on when outputs are guarded.

Tools not listed in the policy mapping pass through unchanged. A `"*"` policy
can provide an explicit default.

## Wire Metadata

Detached envelopes use the reverse-DNS MCP extension identifier:

```json
{
  "_meta": {
    "com.guardbands/guard-band": {
      "version": 1,
      "call_id": "cryptographically-random-logical-call-id",
      "input": {
        "version": "1",
        "nonce": "...",
        "issued_at": 1786838400,
        "expires_at": 1786839300,
        "key_id": "client-2026-08",
        "issuer": "trusted-mcp-host",
        "algorithm": "GBv1-Ed25519",
        "signature": "..."
      }
    }
  }
}
```

The result uses the same outer structure with an `output` envelope. Protocol
bookkeeping metadata such as MCP server identity is not part of the signature;
the signed payload is the content blocks, structured content, and error flag.

## Context Binding

The adapter authenticates:

- integration and method (`mcp`, `tools/call`)
- direction (`input`, `output`, or an indexed visible text output)
- configured server audience
- tool name
- logical call id
- SHA-256 digest of the exact canonical arguments
- application context

The client supplies application context with `guard_context`. The server must
reconstruct the expected value with `context_resolver`, preferably from an
authenticated principal, tenant, and authorization policy:

```python
def server_context(tool_name, arguments, request_context):
    principal = authenticated_principal(request_context)
    return {
        "tenant_id": principal.tenant_id,
        "user_id": principal.user_id,
        "policy_path": f"tools.{tool_name}",
    }
```

Do not derive authorization identity from self-reported MCP `clientInfo` or
`serverInfo`. Guard Bands also do not replace normal tool authorization. A
client-side `authorizer` callback can veto a call before the client signs it,
but the server must still perform its own authorization.

## Key Separation

HMAC works for a single trusted process. For split deployments, use two
Ed25519 key pairs:

- the trusted host signs inputs; the MCP server holds its public key
- the MCP server signs outputs; the host holds its public key

This prevents either verifier from forging traffic in the opposite direction.

## MCP Lifecycle

The server extension signs final `CallToolResult` values. MCP
`input_required` responses pass through so the official client can perform a
multi-round-trip retry; the eventual final result is signed. The logical Guard
Band call id remains stable even though MCP assigns a new JSON-RPC request id
to each retry.

### Streaming, Progress, and Deferred Results

MCP's **Streamable HTTP** name describes its transport framing: a response may
use an SSE stream to carry protocol messages. It does not define incremental or
partial `CallToolResult` content. The Guard Bands adapter is transport-neutral
and signs the one complete tool result defined by `tools/call`.

MCP **progress notifications** contain a progress token, numeric progress, and
optional total and human-readable status message. They are notifications, not
partial tool results, and this adapter does not sign them. Applications must
not promote a progress message into trusted model content; if an application
does pass one to a model, it needs a separate application-level data boundary.

The **Tasks extension** can return a task handle and expose a deferred final
result through separate task methods. Task handles, task polling, and task
results are outside the current adapter. Do not combine guarded-output policies
with task-returning tools until explicit Tasks support exists.

See the current MCP specifications for
[`tools/call`](https://modelcontextprotocol.io/specification/2026-07-28/server/tools),
[progress](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/progress),
[transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports),
and the [Tasks extension](https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks).

The first release intentionally covers `tools/call` only. Resources, prompts,
notifications, vendor-defined partial-content messages, and task-extension
methods are not Guard Band boundaries. Do not apply the generic nonce replay
ledgers directly to MCP inputs: a valid multi-round-trip flow can legitimately
reuse the signed arguments. Use application idempotency keys for side-effecting
tools until a retry-aware MCP replay ledger is provided.

## Limits and Failure Behavior

- Canonical arguments and results are limited to 1 MB by default.
- Non-JSON values, NaN, infinity, expired envelopes, unknown keys, altered
  context, and malformed metadata fail closed.
- Tool output containing reserved Guard Band markers is rejected before it can
  create a nested or ambiguous visible band.
- Guarded inputs missing valid metadata never reach the tool handler.
- Signed content can still be malicious or false. Verification proves
  provenance, integrity, freshness, and context—not safety or authority.
