# Key Management Expectations

Guard Bands uses HMAC-SHA256. Anyone with the signing key can create content that verifies, so key handling is part of the security boundary.

## POC Expectations

- `SECRET_KEY` must be set before startup. The app intentionally exits if it is missing.
- Generate a local evaluation key with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

- Keep `.env` out of version control.
- Use different keys for development, test, staging, and production.
- Treat `key_id` as public metadata that identifies which secret signed a Guard Band. It is not the secret.
- Set `KEY_ID` to choose the active signing key.
- Optionally set `GUARD_BAND_KEYS` to a JSON object for rotation-style verification:

```bash
GUARD_BAND_KEYS='{"key001":"active-secret","key000":"retired-secret"}'
KEY_ID=key001
```

## Production Expectations

- Store signing keys in a managed secret system such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, or a KMS-backed service.
- Scope keys by environment and, where appropriate, by tenant or application boundary.
- Rotate keys on a documented schedule and immediately after suspected exposure.
- Support a verification grace window during rotation: sign with the active key, verify with active and recently retired keys, then retire old keys after the maximum replay window has passed.
- Never log raw keys, raw untrusted content, or full context values in audit events.
- Restrict signing access more tightly than verification access when those roles can be separated.
- Use TLS for all traffic that carries wrapped content or contexts. Guard Bands provide integrity, not confidentiality.

## Current POC Gap

The current implementation includes a small static key resolver suitable for local evaluation. A production implementation should replace this with a resolver backed by a secrets manager or KMS that chooses verification keys by `kid`, environment, tenant, and rotation state.
