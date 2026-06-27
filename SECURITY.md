# Security Policy

Guard Bands is a proof-of-concept security project. Please report suspected vulnerabilities privately before opening public issues.

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
- context-binding or replay-protection weaknesses
- tool-call enforcement bypasses
- key-management or audit-log security issues
- dependency or deployment vulnerabilities in the POC

Out of scope:

- model hallucination without a Guard Bands boundary issue
- malicious but correctly signed content
- denial-of-service reports that require unrealistic local access
- issues in third-party services unless the repo config meaningfully contributes

## Supported Versions

Only the default branch and the latest tagged POC release are actively maintained.

