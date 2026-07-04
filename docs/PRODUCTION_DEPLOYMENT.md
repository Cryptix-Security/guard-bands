# Production Deployment Guide

This project is still a POC, but a small-company pilot should have a safer shape than the local development stack.

## Recommended Pilot Topology

```text
internet or internal users
  -> TLS reverse proxy / platform ingress
  -> SSO or API gateway
  -> Guard Bands FastAPI service
  -> audit sinks, replay ledger, LLM provider, internal tools
```

Do not expose the FastAPI service directly. Put TLS, authentication, request limits, and logging at the edge.

## Running the Hardened Stack

A production-shape Compose overlay is provided. It adds a Caddy TLS front door,
removes direct port exposure, runs Keycloak in production mode, and applies
restart policies and CPU/memory limits:

```bash
cp .env.production.example .env.production   # fill in real secrets
docker compose -f docker-compose.yml -f deploy/docker-compose.prod.yml \
  --env-file .env.production up -d --build
```

By default Caddy serves a self-signed cert so the hardened stack runs locally;
point `deploy/Caddyfile` at a real domain for automatic Let's Encrypt certs.
The image runs as a non-root user with a `/health` healthcheck.

## Secrets

Secret-bearing settings resolve through a pluggable provider. Set
`SECRETS_BACKEND=env|aws|vault` — see [`docs/SECRETS.md`](SECRETS.md). `env` is
the default and works with orchestrator-injected secrets (Vault Agent, ECS task
secrets, Kubernetes External Secrets); `aws` and `vault` fetch by name.

## Minimum Production Settings

Set these explicitly:

```bash
SECRETS_BACKEND=env   # or aws | vault
SECRET_KEY=<generated high-entropy secret>
KEY_ID=key-2026-06
GUARD_BAND_KEYS={"key-2026-06":"active-secret","key-2026-05":"previous-secret"}
DEBUG=false
ALLOWED_ORIGINS=https://your-app.example.com
SSO_ENABLED=true

COST_GUARD_ENABLED=true
COST_GUARD_THRESHOLD_USD=1.00
COST_GUARD_INPUT_USD_PER_MTOK=1.00
COST_GUARD_OUTPUT_USD_PER_MTOK=5.00

REPLAY_PROTECTION_ENABLED=true
REPLAY_LEDGER_BACKEND=sqlite
REPLAY_LEDGER_PATH=data/replay-ledger.sqlite3
REPLAY_WINDOW_SECONDS=900

LOG_POSTGRES_DSN=postgresql://...
LOG_SPLUNK_HEC_URL=https://splunk.example.com:8088
LOG_SPLUNK_HEC_TOKEN=<token>
LOG_SPLUNK_SSL_VERIFY=true
```

For more than one API replica, replace the SQLite replay ledger with a shared datastore such as Postgres or Redis before relying on same-context single-use protection.

Set cost guard prices to match the model configured in `LLM_MODEL`. The defaults are deliberately easy to demonstrate, not a substitute for an organization-specific budget policy.

## Key Management

- Keep keys out of source control and images.
- Use separate keys by environment.
- Use `KEY_ID` for the active signing key.
- Keep recently retired keys in `GUARD_BAND_KEYS` for verification only during a rollover window.
- Remove retired keys after all valid wrapped content has expired.

## Replay Ledger

`memory` is useful for local development and tests.

`sqlite` persists consumed nonces across process restarts and is acceptable for a single-node pilot. Mount the ledger path on durable storage. The default Compose stack mounts `/app/data` as `app_data`.

Use a shared ledger for multi-worker or multi-replica deployments. The key requirement is atomic insert with a uniqueness constraint on `(canonical_context, key_id, nonce)` and TTL pruning.

## Authorization

Guard Bands verification is necessary but not sufficient for sensitive actions.

Before a tool call runs, require:

- valid Guard Band verification
- tenant and user context match
- policy path matches the requested action
- caller has the role or entitlement for the action
- high-risk actions have approval or additional controls

See [`docs/AUTHORIZATION.md`](AUTHORIZATION.md) and `reference_app/support_app.py`.

## TLS and Network

- Terminate TLS at the load balancer, ingress, or reverse proxy.
- Keep app-to-database and app-to-Splunk traffic encrypted where your environment supports it.
- Restrict direct access to the FastAPI service and databases.
- Set request body limits at the proxy and app layer.

## Audit Operations

At minimum, alert on:

- verification failures by tenant and policy path
- replay detections
- unknown key id errors
- unsupported tool calls
- spikes in malformed marker errors

Avoid logging raw document content. The built-in audit events log metadata such as event type, key id, context keys, success/failure, and error reason.

## Deployment Checklist

- [ ] `SECRETS_BACKEND` set (`env`/`aws`/`vault`); `SECRET_KEY` and `GUARD_BAND_KEYS` resolved from a secret manager, not committed.
- [ ] TLS enforced before traffic reaches the API (Caddy overlay or platform ingress).
- [ ] Container runs as non-root with a healthcheck (shipped in the Dockerfile).
- [ ] SSO/API gateway configured (bundled Keycloak in production mode, or an external IdP).
- [ ] Replay protection enabled with durable or shared storage.
- [ ] Cost guard threshold and model pricing configured.
- [ ] Audit sink configured and retention policy set.
- [ ] Authorization checks added before sensitive tools.
- [ ] CI and CodeQL required before merge.
- [ ] Dependency alerts reviewed.
- [ ] Backup and restore tested for audit and replay stores.
