# Cost Guard

Guard Bands can estimate LLM request cost before submitting a prompt to the provider. The estimate is useful for budget controls, but it is approximate.

## What Can Be Known Before Submission

Preflight can estimate:

- system prompt tokens
- user message tokens
- Guard Band marker overhead
- tool definition overhead
- configured output token budget
- estimated cost using configured model prices

Preflight cannot know the exact final cost because the model has not generated output yet. Tool calls, retries, and final output length can change actual usage.

## Configuration

```bash
COST_GUARD_ENABLED=true
COST_GUARD_THRESHOLD_USD=1.00
COST_GUARD_INPUT_USD_PER_MTOK=1.00
COST_GUARD_OUTPUT_USD_PER_MTOK=5.00
LLM_MAX_OUTPUT_TOKENS=2048
```

Prices are USD per million tokens. Update them when changing models or providers.

The default threshold is intentionally low enough for demos. Production deployments should set thresholds by organization, tenant, or route.

## Dry-Run Estimate

Use `/chat/estimate-cost` to get a preflight estimate without calling the model:

```bash
curl -s -X POST "$API_URL/chat/estimate-cost" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Summarize this document",
    "context": {"request_id": "req-001"},
    "max_output_tokens": 1000
  }'
```

Response shape:

```json
{
  "model": "claude-3-5-haiku-20241022",
  "method": "approx_chars_per_token",
  "currency": "USD",
  "input_tokens_estimate": 1500,
  "output_tokens_budget": 1000,
  "estimated_input_cost_usd": 0.0015,
  "estimated_output_cost_usd": 0.005,
  "estimated_total_cost_usd": 0.0065,
  "threshold_usd": 1.0,
  "threshold_exceeded": false,
  "requires_confirmation": false,
  "pricing": {
    "input_usd_per_mtok": 1.0,
    "output_usd_per_mtok": 5.0
  }
}
```

## Threshold Confirmation

`/chat` estimates before submission. If the estimate crosses the configured threshold, the API returns HTTP 402 and does not call the model.

The client can show the estimate to the user, then resubmit with:

```json
{
  "approve_estimated_cost": true
}
```

## Final Actual Cost

Successful `/chat` responses include both the preflight estimate and actual provider-token cost:

```json
{
  "usage": {
    "input_tokens": 1800,
    "output_tokens": 220
  },
  "cost": {
    "preflight_estimate": {
      "estimated_total_cost_usd": 0.0065
    },
    "actual": {
      "input_tokens": 1800,
      "output_tokens": 220,
      "total_cost_usd": 0.0029
    }
  }
}
```

Actual cost is computed from provider-reported input and output tokens. If multiple tool-call iterations happen, usage is accumulated across calls.
