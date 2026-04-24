# Eval Compare (Runtime)

Compare a runtime-audit report against ground-truth findings.

## Steps

1. Read the ground-truth file. Parse each `FINDING` entry.
2. Read the report (`{target-host}-runtime-audit-{ts}.md`). Extract:
   - **Findings** (CONFIRMED + LIKELY)
   - **Leads**
3. For each ground-truth finding, determine how the report handled it:
   - **CONFIRMED_LIVE** — found in Findings as CONFIRMED
   - **LIKELY** — found in Findings as LIKELY (signal but not proof)
   - **LEAD_ONLY** — present only in Leads
   - **MISSED** — not present
4. Also count **false positives** — CONFIRMED findings in the report that don't match any ground-truth.

## Output

Write `summary.md`:

```
## Eval Results

| Metric | Value |
|--------|-------|
| CONFIRMED_LIVE | {n} / {total} ({pct}%) |
| LIKELY | {n} |
| LEAD_ONLY | {n} |
| MISSED | {n} |
| False positives | {n} |
| Probes attempted | {n} |
| Probes blocked (WAF/429) | {n} |

### Per-ground-truth breakdown

| Status | Severity | ID | Endpoint | Bug class | Notes |
|--------|----------|----|----------|-----------|-------|
| CONFIRMED_LIVE | High | H-1 | POST /rest/products | sqli | canary extracted |
| LIKELY | Medium | M-2 | GET /api/Feedbacks | missing-auth | 200 on unauth but empty set |
| LEAD_ONLY | Medium | M-3 | /admin/metrics | admin-exposure | 403 but existed |
| MISSED | Medium | M-4 | websocket-auth | no WS probes fired in default mode |
```

## Rules

- A finding at a slightly different endpoint but same class → still matched.
- A CONFIRMED in the report with no matching ground-truth → false-positive. These are important — a noisy skill is worse than a quiet one.
- Leads are not counted as true positives. But a ground-truth finding that appears only as a Lead is LEAD_ONLY (partial credit in the eval, but the skill didn't confirm).
- Destructive-only findings in ground-truth are skipped unless the run was `--destructive`.
