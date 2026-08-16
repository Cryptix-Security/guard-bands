# Key Management Expectations

Guard Bands supports HMAC-SHA256 and Ed25519. Anyone with an HMAC key can both
sign and verify; an Ed25519 verifier can hold only the public key. Key handling
is part of the security boundary.

## Application Expectations

- Load keys from application configuration or a key manager; the library never
  reads environment variables or creates fallback keys.
- Generate a local evaluation key with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

- Keep `.env` out of version control.
- Use different keys for development, test, staging, and production.
- Treat `key_id` as public metadata that identifies which secret signed a Guard Band. It is not the secret.
- Set `KEY_ID` to choose the active signing key.
- Construct a resolver with active and recently retired keys during rotation:

```python
from guardbands import GuardBandCrypto, StaticKeyResolver

resolver = StaticKeyResolver(
    {"key001": b"active-secret", "key000": b"retired-secret"},
    signing_key_id="key001",
)
crypto = GuardBandCrypto(key_resolver=resolver)
```

## Production Expectations

- Store signing keys in a managed secret system such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, or a KMS-backed service.
- Scope keys by environment and, where appropriate, by tenant or application boundary.
- Rotate keys on a documented schedule and immediately after suspected exposure.
- Support a verification grace window during rotation: sign with the active key, verify with active and recently retired keys, then retire old keys after the maximum replay window has passed.
- Never log raw keys, raw untrusted content, or full context values in audit events.
- Restrict signing access more tightly than verification access when those roles can be separated.
- Use TLS for all traffic that carries wrapped content or contexts. Guard Bands provide integrity, not confidentiality.

## Resolver boundary

The library includes a small static key resolver and a `KeyResolver` protocol.
It is appropriate for keys already loaded into the process, including secrets
fetched during startup and cached public verification keys. It is synchronous:
applications must not hide blocking KMS, Vault, HSM, or network calls behind
it when running in FastAPI, MCP, or another event loop.

Non-exportable and remotely operated keys require a distinct async boundary.
The proposed handle-based interface, immutable-version rotation rules, failure
behavior, and delivery plan are in
[`REMOTE_SIGNING.md`](REMOTE_SIGNING.md). That API is not implemented yet.
