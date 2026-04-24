# Report Formatting (Dynamic)

## Report Path

Save the report to `assets/findings/{target-host}-runtime-audit-{timestamp}-{rand4}.md` where:
- `{target-host}` is the hostname of the target (e.g., `localhost-3000`, `staging-example-com`). Replace `.` and `:` with `-`.
- `{timestamp}` is `YYYYMMDD-HHMMSS` at scan start.
- `{rand4}` is 4 hex chars from `openssl rand -hex 2` to prevent same-second collisions.

Copy all per-probe `.http` transcripts into `assets/transcripts/{timestamp}-{rand4}/` and link to them from the report.

## Output format selection

The orchestrator honors `--format <markdown|json>` (default `markdown`). Same findings, different serialization.

---

## Markdown format

````
# 🎯 Runtime Audit — <target-host>

---

## Scope

|                                  |                                                              |
| -------------------------------- | ------------------------------------------------------------ |
| **Target**                       | http://localhost:3000                                        |
| **Tier**                         | local                                                        |
| **Autostart**                    | no / yes (pid=<N>, via `<cmd>`, env=.env.test / .env REAL)   |
| **Destructive probes**           | OFF / ON                                                     |
| **Safe mode**                    | bands 1-only / bands 1-2 / bands 1-3                         |
| **Auth contexts**                | A: X-API-Key:dev-api-*** · B: X-API-Key:other-***            |
| **Request rate**                 | 1 req/sec sustained, 10 burst                                |
| **From static report**           | `assets/findings/<name>-api-audit-report-<ts>.md` (or none)  |
| **Severity threshold**           | info (or whatever `--severity-threshold` was set to)         |
| **Probes fired**                 | 142                                                          |
| **Probes blocked by WAF/429**    | 3                                                            |
| **Transcripts**                  | `assets/transcripts/20260423-123000-a1b2/`                   |

---

## Summary

| Severity | CONFIRMED | LIKELY | LEAD |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High     | 2 | 1 | 0 |
| Medium   | 3 | 0 | 1 |
| Low      | 1 | 0 | 2 |
| Info     | 0 | 0 | 0 |

---

## Findings

[HIGH · 95] **1. <Title>** — CONFIRMED

`METHOD /path` · Severity: **High** · Confidence: 95 · CWE-639 · OWASP API1:2023 · [transcript](assets/transcripts/20260423-123000-a1b2/012-bola-verify.http)

**Reproduction**

```bash
# 1. Seed: context A creates a resource
curl -sS -X POST http://localhost:3000/api/v1/certify \
  -H "X-API-Key: ***_A" \
  -H "Content-Type: application/json" \
  -d '{"platformId":"platform-a",...}'
# -> 200 {"data":{"certificationId":"abc-123",...}}

# 2. Probe: context B reads it with no auth error
curl -sS http://localhost:3000/api/v1/verify/abc-123 \
  -H "X-API-Key: ***_B"
# -> 200 {"data":{"certification":{"platformId":"platform-a",...}}}
```

**Observation**
Context B (platform-b) successfully read context A's (platform-a) full certification record. Response body contains `platform-a` as `platformId` — proof of cross-tenant leak.

**Fix**
See `assets/findings/abcp-service-api-audit-report-20260423-123000.md:finding-1`.

---

[MEDIUM · 88] **2. <Title>** — LIKELY

`METHOD /path` · Severity: **Medium** · Confidence: 88 · [transcript](...)

**Observation**
<What the response looked like; why it's LIKELY, not CONFIRMED.>

---

Findings List

| # | Status | Severity | Confidence | Title | OWASP |
|---|---|---|---|---|---|
| 1 | CONFIRMED | High | [95] | <title> | API1:2023 |
| 2 | LIKELY | Medium | [88] | <title> | API2:2023 |

---

## Verification of static report (if --from-report was passed)

| Static Finding | Location | Runtime Status |
|---|---|---|
| #1 Cross-platform BOLA | `SupabaseCertificationRepository.ts:58` | ✅ CONFIRMED_LIVE (see finding 1) |
| #2 BFLA on /admin/review/* | `server.ts:78` | ✅ CONFIRMED_LIVE (see finding 3) |
| #3 Reviewer ID trust | `review.ts:95` | ⚠️ NOT_REPRODUCIBLE — endpoint rejected the probe body shape |
| #5 CORS wildcard+credentials | `middleware/enhanced.ts:169` | ✅ CONFIRMED_LIVE (see finding 5) |
| #6 Hardcoded default key | `index.ts:33` | ⚠️ NOT_REPRODUCIBLE — deploy had API_KEYS set |
| #8 Missing body size cap | `server.ts:42` | 🚫 OUT_OF_SCOPE — not a live-probe-able issue |

---

## Leads

_Suspicious behavior short of proof._

- **<Title>** — `METHOD /path` — [transcript](...) — Signal: <what was odd> — Missing: <what's needed to promote>

---

## Probes attempted but blocked

| Probe | Target | Reason |
|---|---|---|
| SQLi time-based | `/api/v1/verify/:id` | WAF 403 (Cloudflare) |

---

## Probes skipped (configured)

| Probe family | Reason |
|---|---|
| Band 3 brute-force | `--destructive` not passed |
| POST /certify mutations | `skip_paths` in runtime-audit.yaml (triggers LLM + chain tx) |

---

## Cleanup status

✅ All created resources deleted.

OR:

⚠️ CLEANUP FAILED on 2 resources — manually delete:
- `DELETE /api/v1/certify/abc-123` (context A)

---

> ⚠️ Dynamic testing covers only the endpoints probed with the credentials supplied. Untested endpoints, alternate auth flows, and data-state-dependent logic are not covered. Use alongside a static audit.

````

## Rules for markdown output

- Every finding links to a transcript file. No transcript = not a finding.
- `CONFIRMED` requires the reproduction to demonstrate the impact in the response body.
- Sort: **severity first** (Critical → Info), then status (CONFIRMED → LIKELY), then confidence descending within each bucket.
- Leads are unsorted.
- The "Verification of static report" section is ONLY printed if `--from-report` was passed.
- Include the probes-blocked table even when empty (print "None" row).
- Include cleanup status as a terminal check.

---

## JSON format (`--format json`)

Emit to the same path with `.json` extension. Schema:

```json
{
  "meta": {
    "skill": "runtime-audit",
    "skill_version": "0.2.0",
    "target": "http://localhost:3000",
    "tier": "local",
    "generated_at": "2026-04-23T12:30:00Z",
    "mode": "default",
    "autostart": {"enabled": true, "pid": 28966, "command": "pnpm dev", "env": ".env"},
    "destructive": false,
    "safe_mode": "bands-1-only",
    "from_report": "assets/findings/abcp-service-api-audit-report-20260423-123000.md",
    "severity_threshold": "info",
    "transcripts_dir": "assets/transcripts/20260423-123000-a1b2/"
  },
  "summary": {
    "total_findings": 6,
    "by_status": {"confirmed": 4, "likely": 2, "lead": 3},
    "by_severity": {"critical": 0, "high": 2, "medium": 3, "low": 1, "info": 0},
    "probes_fired": 142,
    "probes_blocked": 3,
    "probes_skipped": 12
  },
  "findings": [
    {
      "id": 1,
      "title": "CORS wildcard + credentials",
      "status": "confirmed",
      "severity": "high",
      "confidence": 95,
      "endpoint": "OPTIONS /api/v1/registry",
      "bug_class": "cors-wildcard-credentials",
      "group_key": "localhost:3000 | OPTIONS /api/v1/registry | cors-wildcard-credentials",
      "reproduction": "curl -sSI -X OPTIONS http://localhost:3000/api/v1/registry -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET'",
      "observation": "Preflight response: Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true",
      "transcript": "assets/transcripts/20260423-123000-a1b2/002-cors.http",
      "cwe": "CWE-942",
      "owasp_api_top10": "API8:2023",
      "static_finding_ref": "#5"
    }
  ],
  "leads": [...],
  "static_verification": [
    {"id": "#1", "location": "SupabaseCertificationRepository.ts:58", "status": "confirmed_live", "finding_ref": 1},
    {"id": "#3", "location": "review.ts:95", "status": "not_reproducible", "reason": "endpoint rejected probe body shape"}
  ],
  "probes_blocked": [
    {"probe": "sqli-time-based", "target": "/api/v1/verify/:id", "reason": "WAF 403"}
  ],
  "cleanup": {"status": "ok", "resources_failed": []}
}
```

## CI integration

`--exit-code-on <severity>` returns non-zero if any CONFIRMED finding at or above the threshold. LIKELY/LEAD do not trigger exit codes by default (add `--include-likely` to include them).
