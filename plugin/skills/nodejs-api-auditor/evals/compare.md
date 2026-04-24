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
   - **FOUND** — the vulnerability appears in the Findings section. Report identifies the same file, the same route or function, and the same root cause (even if described differently).
   - **LEAD** — the vulnerability appears only in the Leads section.
   - **MISSED** — not present in either section.

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
| FOUND | High | H-1 | routes/users.ts :: GET /users/:id | bola |
| LEAD | Medium | M-2 | lib/auth.ts :: verifyToken | jwt-alg-confusion |
| MISSED | Medium | M-3 | routes/webhook.ts :: POST /stripe | webhook-replay |
```

## Rules

- Match semantically, not by keyword grep. "Handler returns order without tenant check" matches `bola` even without that exact word.
- A finding in the Leads section is NOT a finding — don't count it toward recall.
- Same root cause at a different function in the same file → still FOUND.
- Multiple ground-truth findings merged into one report finding → count all as FOUND.
