# Report Formatting

## Report Path

Save the report to `assets/findings/{project-name}-api-audit-report-{timestamp}-{rand4}.md` where:
- `{project-name}` is the repo root basename
- `{timestamp}` is `YYYYMMDD-HHMMSS` at scan start
- `{rand4}` is 4 hex chars from `openssl rand -hex 2` — prevents filename collisions on re-runs

## Output format selection

The orchestrator honors `--format <markdown|json>` (default `markdown`). Both formats contain the same findings; only the serialization differs.

---

## Markdown format

````
# 🔐 API Security Review — <Project or service name>

---

## Scope

|                                  |                                                              |
| -------------------------------- | ------------------------------------------------------------ |
| **Mode**                         | ALL / default / filename                                     |
| **Framework**                    | Express / NestJS / Fastify / Koa / Next.js / mixed           |
| **Files reviewed**               | `routes/users.ts` · `routes/orders.ts`<br>`lib/auth.ts` · `lib/db.ts` |
| **Confidence threshold (1-100)** | 75                                                           |
| **Severity threshold**           | info (or whatever `--severity-threshold` was set to)         |
| **Diff mode**                    | off (or `since <ref>` if `--since` was passed)               |

---

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High     | 2 |
| Medium   | 3 |
| Low      | 1 |
| Info     | 0 |

---

## Findings

[HIGH · 95] **1. <Title>**

`routes/users.ts :: GET /users/:id` · Severity: **High** · Confidence: 95 · CWE-639 · OWASP API1:2023

**Description**
<The vulnerable pattern and why an attacker can exploit it, in 1 short sentence>

**Fix**

```diff
- router.get('/users/:id', async (req, res) => {
-   const user = await db.user.findUnique({ where: { id: req.params.id } });
-   res.json(user);
- });
+ router.get('/users/:id', requireAuth, async (req, res) => {
+   const user = await db.user.findUnique({ where: { id: req.params.id, tenantId: req.user.tenantId } });
+   if (!user) return res.sendStatus(404);
+   res.json(user);
+ });
```
---

[MEDIUM · 82] **2. <Title>**

`lib/auth.ts :: verifyToken` · Severity: **Medium** · Confidence: 82 · CWE-327 · OWASP API2:2023

**Description**
<The vulnerable pattern and why an attacker can exploit it, in 1 short sentence>

**Fix**

```diff
- jwt.verify(token, publicKey);
+ jwt.verify(token, publicKey, { algorithms: ['RS256'], audience: API_AUD, issuer: EXPECTED_ISS });
```
---

< ... all above-threshold findings >

---

[LOW · 75] **3. <Title>**

`routes/uploads.ts :: POST /upload` · Severity: **Low** · Confidence: 75

**Description**
<The vulnerable pattern and why an attacker can exploit it, in 1 short sentence>

---

< ... all below-threshold findings (description only, no Fix block) >

---

Findings List

| # | Severity | Confidence | Title | OWASP |
|---|---|---|---|---|
| 1 | High | [95] | <title> | API1:2023 |
| 2 | Medium | [82] | <title> | API2:2023 |
| 3 | Low | [75] | <title> | — |

---

## Leads

_Vulnerability trails with concrete code smells where the full exploit path could not be completed in one analysis pass. These are not false positives — they are high-signal leads for manual review. Not scored._

- **<Title>** — `file.ts :: function` — Code smells: <missing middleware, unvalidated input, etc.> — <1-2 sentence description of the trail and what remains unverified>

---

## Suppressed findings

_Findings matched against `.audit-ignore` and excluded from the report body. Listed for transparency._

| Group key | Reason (from .audit-ignore) |
|---|---|
| `src/routes/legacy.ts \| GET /healthz \| info-disclosure` | Known, tracked in JIRA-1234 |

(Omit this section if no suppressions.)

---

> ⚠️ This review was performed by an AI assistant. AI analysis can never verify the complete absence of vulnerabilities and no guarantee of security is given. Professional security reviews, bug bounty programs, and production monitoring (WAF, SIEM, anomaly detection) are strongly recommended for any production API.

````

### Rules for markdown output

- Sort findings by **severity first** (Critical → High → Medium → Low → Info), then by **confidence descending** within each severity.
- Findings below the confidence threshold get a description but no **Fix** block.
- Draft findings directly in report format — do not re-generate.
- Location format:
  - Route: `file :: METHOD /path`
  - Function: `file :: functionName`
  - Middleware: `file :: middlewareName` or `file :: app.use(...)`

---

## JSON format (`--format json`)

Emit to the same path but with `.json` extension. Schema:

```json
{
  "meta": {
    "skill": "nodejs-api-auditor",
    "skill_version": "0.2.0",
    "project": "abcp-service",
    "generated_at": "2026-04-23T12:30:00Z",
    "mode": "default",
    "files_reviewed": ["routes/users.ts", "routes/orders.ts"],
    "framework": "express",
    "confidence_threshold": 75,
    "severity_threshold": "info",
    "diff_mode": null
  },
  "summary": {
    "total_findings": 6,
    "by_severity": {"critical": 0, "high": 2, "medium": 3, "low": 1, "info": 0},
    "suppressed_count": 0
  },
  "findings": [
    {
      "id": 1,
      "title": "Cross-platform BOLA via findById",
      "severity": "high",
      "confidence": 93,
      "location": {
        "file": "src/infrastructure/database/SupabaseCertificationRepository.ts",
        "line": 58,
        "symbol": "findById"
      },
      "route": "GET /api/v1/verify/:id",
      "bug_class": "bola",
      "group_key": "SupabaseCertificationRepository.ts | findById | bola",
      "description": "findById(id) queries Supabase without a platform_id predicate, so any authenticated caller reads any platform's certification.",
      "fix": "Add .eq('platform_id', platformId) and pass req.platformId through from apiKeyAuth.",
      "cwe": "CWE-639",
      "owasp_api_top10": "API1:2023",
      "references": ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"]
    }
  ],
  "leads": [
    {
      "title": "LLM prompt injection via description / metadata",
      "location": {"file": "src/infrastructure/llm/HybridABCPAnalyzer.ts"},
      "code_smells": "free-text description and unbounded metadata flow into LLM prompts",
      "description": "Verify whether the prompt layer uses delimited user-content tags..."
    }
  ],
  "suppressed": [
    {"group_key": "src/routes/legacy.ts | GET /healthz | info-disclosure", "reason": "JIRA-1234"}
  ]
}
```

### Rules for JSON output

- Use snake_case for keys.
- `severity` is lowercase (`critical | high | medium | low | info`).
- `confidence` is an integer 0-100.
- `owasp_api_top10` uses the `APIN:YYYY` format (e.g., `API1:2023`).
- `cwe` uses `CWE-N` format when applicable; omit if none.
- `group_key` is mandatory for every finding; matches the dedup key.
- Leads have no `confidence` and no `severity`.

## CI integration

If `--exit-code-on <severity>` is set, after emitting the report the orchestrator returns a non-zero exit code when any finding's severity is at or above the threshold.

Severity order for comparison: `critical > high > medium > low > info`.

Example: `--exit-code-on high` returns 1 if any Critical or High finding was emitted, 0 otherwise.
