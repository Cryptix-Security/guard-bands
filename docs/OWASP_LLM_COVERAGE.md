# OWASP Top 10 for LLM Applications — Coverage

This maps Guard Bands to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/).

Guard Bands is a boundary-enforcement mechanism, not a complete LLM security
system. It directly addresses one risk and partially mitigates two others. The
remaining risks are out of scope and listed explicitly so this mapping reflects
what the control actually does, not what it aspires to.

| Risk | Coverage | Mechanism |
|---|---|---|
| **LLM01 Prompt Injection** | **Primary** | Untrusted content is wrapped in HMAC-signed boundary markers and verified server-side before it can act as instructions. Covers direct injection and indirect injection via documents, RAG content, email, web pages, and tool results. |
| **LLM06 Excessive Agency** | **Partial** | Fail-closed enforcement: guard-banded content cannot reach a tool call or policy-controlled action without a valid signature, constraining what untrusted data can trigger. Does not reduce the underlying permissions of the tools themselves. |
| **LLM10 Unbounded Consumption** | **Partial** | Preflight chat cost estimation with an organization threshold, per-user actual-cost logging, per-user/IP rate limiting, and a 50 KB content limit bound resource and cost exhaustion. Does not address model-level compute abuse. |

## Addressed

### LLM01 — Prompt Injection (primary)

This is the reason Guard Bands exists. Content that arrives through the same
channel as trusted instructions is wrapped in cryptographically signed markers
and treated as inert data until verified. The MAC authenticates the content and
all marker metadata (version, key id, issuer, and issued/expiry timestamps), so
markers cannot be forged, tampered with, or downgraded. The application enforces
that guard-banded content is verified before a final response or tool call, and
fails closed otherwise — so verification is a code-enforced gate, not a prompt
suggestion the model can be talked out of.

### LLM06 — Excessive Agency (partial)

Guard Bands does not decide what a tool may do, but it does gate whether
untrusted content is allowed to reach one. Because sensitive tool calls require
a valid signature bound to the expected context, injected instructions inside
unverified content cannot drive privileged actions. This reduces the blast
radius of excessive agency; it complements, and does not replace, least-privilege
tool design and authorization.

### LLM10 — Unbounded Consumption (partial)

The reference API includes a preflight cost guard (estimate plus configurable
threshold confirmation), per-user actual-cost logging in the audit trail,
per-user or per-IP rate limiting, and a 50 KB request content limit. These bound
per-request and per-user consumption and cost, and surface anomalies in audit
logs.

## Not addressed

These risks are outside the scope of a content-boundary control. Pair Guard
Bands with dedicated controls for them.

- **LLM02 Sensitive Information Disclosure** — Guard Bands does not prevent a
  model from disclosing information it can access. (It can block injection-driven
  exfiltration, but only as a downstream effect of LLM01.)
- **LLM03 Supply Chain** — not a control for model, dataset, or dependency
  provenance.
- **LLM04 Data and Model Poisoning** — does not address training, fine-tuning,
  or embedding data integrity.
- **LLM05 Improper Output Handling** — addresses inputs, not validation or
  encoding of model outputs.
- **LLM07 System Prompt Leakage** — does not protect the system prompt.
- **LLM08 Vector and Embedding Weaknesses** — wrapping retrieved documents helps
  with indirect injection (LLM01), but does not address embedding inversion or
  vector-store access control.
- **LLM09 Misinformation** — explicitly out of scope: verified content can still
  be authentic and misleading. Guard Bands proves provenance and integrity, not
  truthfulness.
