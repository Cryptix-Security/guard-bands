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
segments). Each plane requires its half of an Ed25519 keypair and fails
closed without it:

```bash
eval "$(make dual-channel-keys | sed 's/^/export /')"
DUAL_CHANNEL_SIGNING_KEY=$DUAL_CHANNEL_SIGNING_KEY uvicorn dual_channel.data_plane:app --port 8001
DUAL_CHANNEL_VERIFY_KEY=$DUAL_CHANNEL_VERIFY_KEY uvicorn dual_channel.control_plane:app --port 8002
```

Or run the demo, which drives both services end to end without an LLM key:

```bash
make dual-channel-demo
```

## Deploying with Docker Compose

`deploy/docker-compose.dual-channel.yml` runs the planes as two containers on
separate ports **and separate networks that never touch each other** — the
client/orchestrator shuttles signed blocks between them, and the signature is
the only bridge of trust:

```bash
make dual-channel-keys > .env.dual-channel   # one-time Ed25519 keypair
docker compose -f deploy/docker-compose.dual-channel.yml \
  --env-file .env.dual-channel up --build
```

The data-plane container receives only `DUAL_CHANNEL_SIGNING_KEY` (the
private key); the control-plane container receives only
`DUAL_CHANNEL_VERIFY_KEY` (the public key). Compose refuses to start if
either is missing, and the services themselves fail closed at startup — there
is no development fallback key that could accidentally reach production. Keys
resolve through the pluggable secret provider, so `SECRETS_BACKEND=aws|vault`
works here too (see [`docs/SECRETS.md`](SECRETS.md)).

## Key separation: isolation vs. cryptographic roles

Process and network isolation alone do not separate cryptographic roles. With
a shared HMAC secret, whoever can *verify* a band can also *forge* one — a
compromised verifier becomes a signer.

The planes therefore use **Ed25519**: the data plane signs with the private
key, and the control plane holds only the public key, which is
cryptographically unable to mint bands (the resolver rejects signing with a
verification-only key, and the demo shows the attempt failing). A fully
compromised control plane still cannot fabricate data-plane provenance.

The core library supports both modes — raw-bytes keys select HMAC-SHA256,
Ed25519 keys select asymmetric signing — with the algorithm tag bound into
the authenticated payload so bands can never be confused across algorithms.
Single-service deployments where signer and verifier are the same process can
keep HMAC; split-trust topologies like this one should use Ed25519.

## Enforced invariants

1. **The data plane cannot execute.** It exposes a single `/ingest` endpoint
   and returns signed inert blocks. There is no tool registry, no instruction
   surface, and no model access to compromise. It also rejects content
   containing guard band markers, closing marker smuggling at the entry.
2. **Provenance is cryptographic, not asserted.** Every block the data plane
   emits is signed with the data-plane key id and issuer and bound to
   `channel: data` in the authenticated context. All three are covered by the
   Ed25519 signature, so they cannot be forged, stripped, or rebound.
3. **The control plane admits data only from the data plane.** Raw text,
   tampered blocks, bands minted by another issuer, bands bound to another
   channel, or cross-tenant blocks are all rejected fail-closed before any
   tool logic runs.
4. **Instructions never come from content.** Action selection happens
   exclusively in the control plane's authenticated request. Document text is
   summarized or attached — it is never parsed for commands, so an injected
   "call issue_refund" selects nothing, and the same escalation attempted
   through the real channel still faces role authorization.
5. **The verifier cannot become a forger.** The control plane holds only the
   public key, so even its full compromise cannot mint data-plane provenance —
   and neither plane will start without real key material (no dev defaults).

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
| `dual_channel/data_plane.py` | Intake-only service: signs with the Ed25519 private key, nothing else |
| `dual_channel/control_plane.py` | Instructions, verification gate (public key only), tool authorization |
| `deploy/docker-compose.dual-channel.yml` | Two containers, separate ports and disjoint networks, split key delivery |
| `scripts/dual_channel_demo.py` | End-to-end demo of both services, all rejections, and the failed forgery |
| `tests/test_dual_channel.py` | Invariant coverage: forged issuer, wrong channel, fail-closed startup, cannot-sign |
