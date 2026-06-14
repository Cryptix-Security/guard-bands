# Guard Bands - Quick Start Guide

**Proof-of-Concept Implementation**

This guide walks you through building and running the Guard Bands POC that demonstrates cryptographic protection against prompt injection attacks.

## Prerequisites

- **Python 3.8+**
- **Anthropic API Key** - Using Claude for this POC
- **Git** (for cloning the repository)
- **Docker + Docker Compose** (optional for local Postgres; required for the full SSO stack)

## Installation

### 1. Clone and Setup

```bash
git clone https://github.com/Cryptix-Security/guard-bands.git
cd guard-bands

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip3 install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Generate a secure secret key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Edit `.env` and set at minimum:

```
SECRET_KEY=<output from the command above>
ANTHROPIC_API_KEY=sk-ant-api03-your-actual-key-here
DEBUG=false

# CORS — comma-separated allowed origins
ALLOWED_ORIGINS=http://localhost:3000
```

**Audit logging** (optional but recommended):

```
# Local Postgres — start with: docker compose up -d
LOG_POSTGRES_DSN=postgresql://guard_bands:changeme@localhost:5432/guard_bands

# Splunk HEC — leave blank to disable
LOG_SPLUNK_HEC_URL=https://splunk.example.com:8088
LOG_SPLUNK_HEC_TOKEN=
LOG_SPLUNK_INDEX=guard_bands
```

If neither sink is configured, audit events are written as structured JSON to stdout.

## Running the POC

Two modes — choose based on what you're testing:

### Option A: Direct (no SSO, rapid dev)

```bash
# Optional: start Postgres for audit logs
docker compose up -d postgres

python3 -m uvicorn app.main:app --reload
# API available at http://localhost:8000
```

### Option B: Full stack (SSO enforced)

```bash
docker compose up --build
# API entry point: http://localhost:4180  (oauth2-proxy)
# Keycloak admin:  http://localhost:8080  (admin / $KEYCLOAK_ADMIN_PASSWORD)
```

Wait for all services to be healthy (~60s first run while Keycloak initialises).

The server starts at `http://localhost:8000`

**Interactive API Docs**: Visit `http://localhost:8000/docs`

### Authenticating Against the SSO Stack

When running Option B, all requests to port 4180 require a valid Bearer token.

**Step 1 — Get a token from Keycloak (password grant for dev/testing):**

```bash
TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/guard-bands/protocol/openid-connect/token \
  -d "client_id=guard-bands-api" \
  -d "client_secret=dev-client-secret-change-in-prod" \
  -d "username=testuser" \
  -d "password=testpass123" \
  -d "grant_type=password" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
```

**Step 2 — Call the API with the token:**

```bash
curl -X POST http://localhost:4180/wrap \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content": "doc text", "context": {"request_id": "r1", "user": "alice"}}'
```

For production/enterprise clients, use the `client_credentials` grant type instead of `password`. The test user (`testuser` / `testpass123`) exists only in the dev realm import.

### Run the Security Tests

Open a new terminal (keep server running):

```bash
cd guard-bands
source venv/bin/activate
python3 test_manual.py
```

**What it tests:**
- ✅ Valid content verification
- ✅ Context tampering protection
- ✅ Content modification detection
- ✅ Forged guard band rejection
- ✅ Unwrapped content handling

### Run the LLM Demo

```bash
python3 demo_llm_attack.py
```

**What it demonstrates:**
1. Prompt injection without protection
2. Same attack with Guard Bands enabled
3. Cryptographic verification process
4. Safe extraction of legitimate data

## API Endpoints

### Wrap Content

Wrap untrusted content with cryptographic guard bands:

```bash
curl -X POST "http://localhost:8000/wrap" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "User document content here",
    "context": {"request_id": "req-001", "user": "alice"}
  }'
```

**Response:**
```json
{
  "wrapped_content": "⟪INERT:START:r:nonce:h:hash⟫\nUser document content here\n⟪INERT:END:mac:signature:kid:key001⟫",
  "nonce": "abc123...",
  "content_hash": "xyz789..."
}
```

### Verify Guard Bands

Verify cryptographic signatures:

```bash
curl -X POST "http://localhost:8000/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "wrapped_content": "⟪INERT:START:...⟫content⟪INERT:END:...⟫",
    "context": {"request_id": "req-001", "user": "alice"}
  }'
```

**Response:**
```json
{
  "valid": true,
  "content": "User document content here",
  "nonce": "abc123...",
  "key_id": "key001"
}
```

### Chat with Protected LLM

Send queries to Claude with guard band awareness:

```bash
curl -X POST "http://localhost:8000/chat" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Analyze this document: ⟪INERT:START:...⟫content⟪INERT:END:...⟫",
    "context": {"request_id": "req-001", "user": "alice"}
  }'
```

## Project Architecture

```
guard-bands/
├── app/
│   ├── main.py              # FastAPI server & endpoints
│   ├── crypto.py            # HMAC signing & verification
│   ├── llm.py               # Claude integration & tools
│   ├── models.py            # Pydantic data models
│   ├── config.py            # Environment configuration
│   ├── audit.py             # AuditEvent + AuditLogger (fan-out)
│   ├── middleware/
│   │   └── auth.py          # SSO header middleware (reads oauth2-proxy headers)
│   └── sinks/
│       ├── base.py          # Abstract AuditSink
│       ├── console.py       # Structured JSON → stdout (always on)
│       ├── postgres.py      # PostgreSQL sink (asyncpg)
│       └── splunk.py        # Splunk HEC sink
├── keycloak/
│   └── realm-export.json    # Auto-imported realm (client + test user)
├── tests/
│   └── __init__.py
├── test_manual.py           # Security test suite
├── demo_llm_attack.py       # Interactive LLM demo
├── Dockerfile               # App container image
├── docker-compose.yml       # Full stack: Postgres, Keycloak, oauth2-proxy, app
├── requirements.txt         # Python dependencies
├── .env.example             # Configuration template
└── .gitignore               # Git ignore rules
```

## How It Works

### 1. Content Wrapping

When untrusted content enters the system:

```python
# Server wraps content with cryptographic markers
wrapped = wrap_content(
    content="User document",
    context={"request_id": "req-001", "user": "alice"}
)
```

The result includes:
- **Nonce**: Random value for uniqueness
- **Hash**: SHA-256 of content
- **MAC**: HMAC signature binding content + context
- **Key ID**: Identifier for the signing key

### 2. LLM Detection

Claude is trained (via system prompt) to:
- Detect guard band markers
- Treat wrapped content as untrusted
- Call verification before processing

### 3. Verification

The LLM uses a tool to verify:

```python
result = verify_guard_bands(
    wrapped_content=wrapped,
    context={"request_id": "req-001", "user": "alice"}
)
```

Verification checks:
- Content hash matches
- MAC signature is valid
- Context matches exactly

### 4. Safe Processing

Only after successful verification does Claude process the content as legitimate data.

## Security Properties

### What Guard Bands Prevent

✅ **Naive Injection** - Basic command insertion attempts  
✅ **Crafted Boundaries** - Forged guard band markers  
✅ **Context Confusion** - Blurring data vs instructions  
✅ **Replay Attacks** - Reusing markers in wrong context  

### What Guard Bands Reduce

🔸 **Multi-turn Attacks** - Harder with per-turn validation  
🔸 **Social Engineering** - Difficult to trick users  
🔸 **Supply Chain** - Provides verification trail  

### Known Limitations

❌ **Model Compliance** - Cannot prevent all policy violations  
❌ **Key Compromise** - Security depends on key management  
❌ **Semantic Attacks** - Doesn't address misleading legitimate content  

## Troubleshooting

### Port Already in Use

```bash
# Kill process on port 8000
lsof -ti:8000 | xargs kill -9

# Or use different port
python3 -m uvicorn app.main:app --reload --port 8001
```

### Module Not Found

```bash
# Activate venv
source venv/bin/activate

# Reinstall dependencies
pip3 install -r requirements.txt
```

### API Key Errors

- Verify key at [console.anthropic.com](https://console.anthropic.com)
- Check `.env` exists in project root
- Ensure no extra spaces in `.env`
- Restart server after editing `.env`

### Verification Failures

- Ensure context matches exactly between wrap and verify
- Check that SECRET_KEY hasn't changed
- Verify content hasn't been modified

## Example Session

```bash
# Terminal 1 - Start server
$ python3 -m uvicorn app.main:app --reload
INFO: Uvicorn running on http://127.0.0.1:8000

# Terminal 2 - Run demo
$ python3 demo_llm_attack.py

🛡️  GUARD BANDS POC - LLM Security Demo

======== DEMO WITHOUT GUARD BANDS ========
Claude's response: [May or may not be fooled by injection]

======== DEMO WITH GUARD BANDS ========
✓ Content wrapped with cryptographic signatures
✓ Claude detects guard bands
✓ Claude calls verification tool
✓ Verification successful
✓ Legitimate data extracted safely
✗ Malicious instructions ignored

✅ Demo Complete!
```

## Next Steps

1. **Read the main [README](README.md)** for conceptual background
2. **Review [Guard-Bands-Paper.pdf](Guard-Bands-Paper.pdf)** for technical details
3. **Explore `app/crypto.py`** to understand the cryptography
4. **Modify `demo_llm_attack.py`** to test your own attack scenarios
5. **Try different LLM models** by changing the model parameter

## Development

### Adding New Test Cases

Edit `test_manual.py`:

```python
def test_your_attack():
    print_section("TEST: Your Custom Attack")
    # Your test code here
```

### Changing the Model

Edit `app/llm.py`:

```python
# Switch to Claude Sonnet 4
model = "claude-sonnet-4-20250514"

# Or Claude 3.5 Haiku (more vulnerable for demos)
model = "claude-3-5-haiku-20241022"
```

### Customizing Guard Band Format

Edit `app/crypto.py` to modify:
- Marker format (⟪INERT:START⟫)
- Hash algorithm (default: SHA-256)
- MAC algorithm (default: HMAC-SHA256)
- Nonce generation

## Production Considerations

This is a POC. For production use, consider:

- **Key rotation** - Implement regular SECRET_KEY updates
- **Key management** - Use proper secrets management (AWS Secrets Manager, etc.)
- **Rate limiting** - Per-user limits already in place; tune thresholds for your traffic
- **HTTPS** - Guard bands don't encrypt; terminate TLS at the load balancer, not oauth2-proxy
- **Time expiration** - Add timestamp validation to nonces to prevent stale replay attacks
- **Production secrets** - Replace `dev-client-secret-change-in-prod` and the cookie secret; rotate regularly
- **Keycloak persistence** - Switch from H2 (dev) to Postgres backend for Keycloak in production
- **Enterprise IdP** - Connect Keycloak to your LDAP/Active Directory or SAML provider via Keycloak identity federation
- **Audit log retention** - Set Postgres table partitioning or Splunk index TTL as appropriate

## Contributing

Found a vulnerability or have ideas for improvement?

1. Open an issue describing the problem
2. Submit a PR with fixes or enhancements
3. Start a discussion about new features

## Resources

- **GitHub**: [github.com/Cryptix-Security/guard-bands](https://github.com/Cryptix-Security/guard-bands)
- **Paper**: [Guard-Bands-Paper.pdf](Guard-Bands-Paper.pdf)
- **Anthropic**: [docs.anthropic.com](https://docs.anthropic.com)
- **FastAPI**: [fastapi.tiangolo.com](https://fastapi.tiangolo.com)

## License

MIT License - See [LICENSE](LICENSE) for details

## Author

**Monte (Montgomery) Toren**  
contact@cryptix.com  
[Cryptix Security](https://github.com/Cryptix-Security)

---

*This POC demonstrates a novel approach to LLM security. Use responsibly and always test thoroughly before deploying in production environments.*
