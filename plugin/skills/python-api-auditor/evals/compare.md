# Eval Compare

Compare an audit report against ground truth findings. You will be given two files:

1. **Ground truth** — the benchmark file with known findings
2. **Report** — the audit output (`final-report.md` or `full-output.txt`)

## Steps

1. Read the ground truth file. Parse each `FINDING` line and its `description:` line.
2. Read the report file. Identify two sections:
   - **Findings** — between `## Findings` and `## Leads`
   - **Leads** — from `## Leads` to end of file
3. For each ground truth finding, determine if the report caught it. Use semantic matching — the report doesn't need the exact same words, but must describe the same vulnerability at the same file/route or equivalent location. Classify each as:
   - **FOUND** — in the Findings section at matching file + route/function + root cause.
   - **LEAD** — in the Leads section only.
   - **MISSED** — not in either.

## Output

Write `summary.md` to the run directory with this exact format:

```
## Eval Results

| Metric | Value |
|--------|-------|
| Recall (findings) | {found} / {total} ({pct}%) |
| In leads only | {leads} |
| Missed | {missed} |
| High | {high_found} / {high_total} |
| Medium | {med_found} / {med_total} |
| Reported findings | {count from report} |

### Per-finding breakdown

| Status | Severity | ID | File/Route | Bug Class |
|--------|----------|----|------------|-----------|
| FOUND | High | H-1 | routes/users.py :: GET /users/{id} | bola |
| LEAD | Medium | M-2 | core/auth.py :: verify_token | jwt-alg-confusion |
| MISSED | Medium | M-3 | webhook.py :: POST /stripe | webhook-replay |
```

## Rules

- Match semantically.
- Findings in Leads section don't count toward recall.
- Same root cause at a different function in the same file → still FOUND.
- Multiple ground-truth findings merged into one report finding → count all as FOUND.
