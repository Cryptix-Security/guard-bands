# AgentDojo Benchmark: Harness and Results

This documents running Guard Bands as a defense in [AgentDojo](https://github.com/ethz-spylab/agentdojo),
the standard dynamic benchmark for prompt-injection attacks and defenses on
tool-calling LLM agents.

Unlike the structural smoke test in [`EVALUATION.md`](EVALUATION.md) (which
drives the two-channel API through test clients, no model), this runs a **real
agent against a real model** and measures attack success and task utility.

## Harness

Install the benchmark extra and run:

```bash
pip install 'guard-bands[bench]'

# Free wiring check — a scripted stub 'model', no API key, no cost.
python scripts/run_agentdojo_benchmark.py --model stub --suite banking \
  --user-task user_task_0 --injection-task injection_task_0 \
  --defense both --attack direct

# Real run — prints a cost estimate and asks before spending API credits.
python scripts/run_agentdojo_benchmark.py --model claude-sonnet-5 \
  --suite banking --defense both --attack important_instructions
```

Defenses:

- `baseline` — no Guard Bands (undefended reference, AgentDojo's default pipeline)
- `signed` — cryptographic spotlighting: tool outputs are wrapped in signed
  Guard Band markers and the system message instructs the model to treat
  guard-banded text as inert data. Unlike plain delimiter spotlighting, the
  boundary cannot be forged by injected content.
- `gated` — `signed` plus a provenance gate that blocks tool calls whose
  arguments echo guard-banded (untrusted) content
- `both` — runs `baseline` and `gated` for a with/without comparison

`attack-success-rate` is the fraction of cases where the injection achieved its
goal (lower is better); `utility` is the fraction of legitimate user tasks the
agent still completed under attack (higher is better).

## Results

**Headline finding: current Anthropic models resist AgentDojo's banking-suite
injection attacks out of the box, so there is no attack-rate reduction for
Guard Bands to demonstrate on this configuration.** This is an honest null
result, not a win — and it matches the project's stated scope: Guard Bands is a
provenance and integrity control, not a jailbreak classifier.

Observed on baseline (undefended) slices of the `banking` suite:

| Model | Attack | Cases (user × injection) | Attack success | Utility under attack |
|---|---|---|---|---|
| `claude-sonnet-5` | `important_instructions` | 4 × 1 | 0% | 75% |
| `claude-haiku-4-5` | `important_instructions` | 4 × 2 | 0% | 38% |
| `claude-haiku-4-5` | `tool_knowledge` | 5 × 2 | 0% | 40% |

Because baseline attack success was 0% across every probed model and attack, a
full 144-case sweep would only confirm `0% → 0%` at material cost, so it was not
run. The Guard Bands (`gated`) pipeline was verified to run end to end and to
preserve utility on the same slices; it does not degrade the agent.

### What this does and does not say

- It **does** say modern frontier models (2026-era Claude) are trained to resist
  the classic direct/important-instructions injection attacks that AgentDojo
  ships. The benchmark's headroom against these models is small.
- It **does not** say Guard Bands is unnecessary. AgentDojo measures whether a
  model is *persuaded* into a wrong tool call. Guard Bands targets a different
  guarantee — cryptographic provenance and a fail-closed policy gate — which is
  a defense-in-depth layer beneath model behavior, valuable exactly when the
  model is *not* trustworthy (weaker models, fine-tuned models, novel attacks,
  or the two-channel split where a compromised control plane must not forge
  data-plane provenance).
- It is **not** a general jailbreak or "does this string look malicious"
  detector, and does not claim to be.

### Getting an attack-reduction number

To quantify attack reduction rather than utility-preservation, the benchmark
needs a configuration where the baseline is actually vulnerable — for example a
smaller or older/open model, a fine-tuned model with weaker safety training, or
a stronger/adaptive attack. Running Guard Bands against such a configuration is
the natural follow-up, and the harness supports it directly (`--model`,
`--attack`).

## Reproducibility

- Benchmark version: `v1.2.1`.
- The defense mechanisms are unit-tested independently of any model in
  `tests/test_agentdojo_integration.py` (the signer wraps and records tool
  outputs; the gate blocks tool calls carrying guard-banded content).
- Every result above is printed by `scripts/run_agentdojo_benchmark.py` with the
  exact model, suite, attack, and case selection shown.
