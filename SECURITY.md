# Security Policy

Guard Bands is an experimental security library. Please report suspected
vulnerabilities privately before opening public issues.

## Reporting a Vulnerability

Email: mtoren@cryptix.com

Please include:

- affected commit or release
- description of the vulnerability
- reproduction steps or proof of concept
- expected security impact
- suggested mitigation, if known

## Scope

In scope:

- Guard Band wrapping and verification bypasses
- marker parsing, canonicalization, or cross-language interoperability flaws
- context-binding or replay-protection weaknesses
- FastAPI middleware enforcement bypasses
- MCP input, output, call-binding, or normalization bypasses
- key resolver or replay-ledger weaknesses in the library

Out of scope:

- model hallucination without a Guard Bands boundary issue
- malicious but correctly signed content
- denial-of-service reports that require unrealistic local access
- issues in third-party services unless the repo config meaningfully contributes

## Supported Versions

Only the default branch and the latest tagged release are actively maintained.

The pre-`1.0.0` independent review scope and release gate are documented in
[`docs/EXTERNAL_REVIEW.md`](docs/EXTERNAL_REVIEW.md).
