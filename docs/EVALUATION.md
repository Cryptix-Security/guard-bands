# Evaluation

Guard Bands should be evaluated against its actual threat model: untrusted
content should not transfer instruction authority into sensitive tool
execution unless the surrounding application explicitly authorizes that action.

This project does not claim to be a general jailbreak or prompt-classification
detector. Benchmarks that ask "does this string look malicious?" are useful for
detectors, but they are not the core security claim here.

## AgentDojo-Style Structural Workflow Smoke Test

Run:

```bash
make agentdojo-style-eval
```

or:

```bash
python scripts/evaluate_agentdojo_style.py
```

No LLM API key is required.

The script drives the two-channel data plane and control plane through
FastAPI's test client. It uses a fresh ephemeral Ed25519 keypair for local
evaluation unless `DUAL_CHANNEL_SIGNING_KEY` and `DUAL_CHANNEL_VERIFY_KEY` are
already set.

## Current Local Result

```text
Passed 12/12 structural cases
Unsafe-action / boundary cases passed: 10/10
```

Cases:

| Category | Case | Expected Result |
|---|---|---|
| benign utility | benign summarize | allowed |
| authority transfer | data says `issue_refund` but requested action is summarize | summarize only |
| authorization | viewer attempts refund with injected document | blocked |
| benign utility | operator legitimate refund with verified evidence | allowed |
| unwrapped data | raw tool-output injection | rejected |
| integrity | tampered wrapped document | rejected |
| context binding | cross-tenant replay | rejected |
| ingest hardening | marker smuggling at ingest | rejected |
| channel binding | wrong channel binding | rejected |
| provenance | foreign issuer | rejected |
| multi-document | split injection across documents | summarize only |
| role separation | control plane attempts to forge data-plane provenance | rejected |

## What This Measures

The smoke test measures structural invariants:

- data-plane content cannot select actions
- tool execution is selected only through the control channel
- role authorization still applies to sensitive actions
- raw, tampered, wrong-context, wrong-channel, or foreign-issuer content fails
  closed
- the control plane holds only the Ed25519 public key and cannot mint
  data-plane signatures

## What This Does Not Measure

This is not the full AgentDojo benchmark suite. It does not measure:

- model task success under natural-language planning
- adaptive attacks against a specific model
- general jailbreak classification
- semantic ambiguity in verified-but-malicious content
- production false-positive rates

It also does not remove the final model-hop limitation: current model APIs
still converge trusted instructions and verified data into one token stream.
The goal is to enforce provenance and authority boundaries in the application
around that hop.

## Adversarial Red-Team of the Control Plane

The two-channel control plane is a signature verifier plus an authorization
gate — not an LLM endpoint — so the meaningful red-team is not a natural-language
jailbreak (those are simply invalid bands) but an attack on the enforcement
surface itself:

```bash
make redteam-control-plane
```

`scripts/redteam_control_plane.py` runs a battery of bypass attempts against the
live FastAPI apps (no API key, no network): hand-forged markers, tampered body
and metadata, valid signatures from the wrong keypair, HMAC-vs-Ed25519 algorithm
confusion, foreign issuer, wrong-channel and cross-tenant bands, context-object
swaps, expired bands, homoglyph markers, oversized content, malformed context
types, nested-marker smuggling, and authorization bypass (viewer refund,
operator refund without a verified document, unknown actions).

A case fails only if the attacker obtains a verified-and-authorized result they
should not have. At the current revision all cases are defended (0 bypasses),
and the script exits non-zero if any bypass is found, so it doubles as a
regression guard. Its core cases are also covered as unit tests in
`tests/test_dual_channel.py`.

## Future Evaluation Work

Useful next steps:

- integrate a real subset of AgentDojo task suites where Guard Bands can be
  mapped cleanly to tool/action gates
- add latency metrics for wrap, verify, ingest, execute, and replay-ledger
  checks
- add benign workflow coverage so false-positive behavior is visible
- document known failure modes for action-open tasks where the trusted user
  intentionally delegates action selection to untrusted content
