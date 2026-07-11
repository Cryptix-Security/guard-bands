# Two-Channel Architecture (Data Plane / Control Plane)

Classic boundary failures were fixed by moving control out of band: telephony
signaling left the voice channel, prepared statements separated SQL code from
data. The original idea behind Guard Bands was the same move for LLM
applications — untrusted data and trusted commands on **two separate API
channels, different ports even**.

The hard constraint: today's model APIs converge everything into one token
stream at the final model hop, and no provider exposes a typed data channel
the model is architecturally unable to interpret as instructions. That single
hop cannot be split from outside.

Everything up to that hop can be. This reference architecture implements the
two-channel design around the model and uses the Guard Band signature as the
enforcement mechanism at the one point where the channels must join.

## Topology

```text
untrusted content                     trusted operators / instructions
      |                                          |
      v                                          v
+------------------+                  +----------------------+
|   DATA PLANE     |                  |    CONTROL PLANE     |
|   port 8001      |                  |    port 8002         |
|                  |                  |                      |
| /ingest only     |                  | /execute             |
| no tools         |                  | tool registry        |
| no instructions  |                  | authorization        |
| no model access  |                  | verification gate    |
+------------------+                  +----------------------+
      |                                          |
      |  signed inert blocks                     |
      |  (kid + issuer + channel                 |
      |   authenticated by the MAC)              |
      +--------------------+---------------------+
                           v
                 one cryptographic join point:
                 instructions + verified inert data -> model / tools
```

Run the planes as separate processes (separate ports, hosts, or network
segments):

```bash
uvicorn dual_channel.data_plane:app --port 8001
uvicorn dual_channel.control_plane:app --port 8002
```

Or run the demo, which drives both services end to end without an LLM key:

```bash
make dual-channel-demo
```

## Enforced invariants

1. **The data plane cannot execute.** It exposes a single `/ingest` endpoint
   and returns signed inert blocks. There is no tool registry, no instruction
   surface, and no model access to compromise. It also rejects content
   containing guard band markers, closing marker smuggling at the entry.
2. **Provenance is cryptographic, not asserted.** Every block the data plane
   emits is signed with the data-plane key id and issuer and bound to
   `channel: data` in the authenticated context. All three are covered by the
   MAC (v0.3.0+), so they cannot be forged, stripped, or rebound.
3. **The control plane admits data only from the data plane.** Raw text,
   tampered blocks, bands minted by another issuer, bands bound to another
   channel, or cross-tenant blocks are all rejected fail-closed before any
   tool logic runs.
4. **Instructions never come from content.** Action selection happens
   exclusively in the control plane's authenticated request. Document text is
   summarized or attached — it is never parsed for commands, so an injected
   "call issue_refund" selects nothing, and the same escalation attempted
   through the real channel still faces role authorization.

## What this does and does not prove

It proves the two-channel design is deployable today at the application
layer: an attacker who fully controls the data channel can neither execute
anything there nor smuggle authority into the control channel, because the
join point requires the data plane's signature and takes instructions from
nowhere else.

It does not split the final model hop. When the control plane ultimately
sends instructions plus verified data to a model, they share one token
stream, and a verified-but-malicious document can still attempt semantic
manipulation there (see the threat model). Pairing this architecture with a
quarantined-model pattern (dual-LLM / CaMeL-style, where untrusted content is
processed by a model with no tool access) is the natural next step, with the
Guard Band signature acting as the capability token between the two models.

## Files

| File | Purpose |
|---|---|
| `dual_channel/data_plane.py` | Intake-only service: wrap and sign, nothing else |
| `dual_channel/control_plane.py` | Instructions, verification gate, tool authorization |
| `scripts/dual_channel_demo.py` | End-to-end demo of both services and all rejections |
| `tests/test_dual_channel.py` | Invariant coverage, including forged issuer and wrong-channel bindings |
