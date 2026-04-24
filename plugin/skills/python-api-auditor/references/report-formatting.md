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
| **Framework**                    | FastAPI / Django / Flask / Starlette / Tornado / mixed       |
| **Files reviewed**               | `routes/users.py` · `routes/orders.py`<br>`core/auth.py` · `db.py` |
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

`routes/users.py :: GET /users/{id}` · Severity: **High** · Confidence: 95 · CWE-639 · OWASP API1:2023

**Description**
<The vulnerable pattern and why an attacker can exploit it, in 1 short sentence>

**Fix**

```diff
- @router.get("/users/{id}")
- async def get_user(id: str):
-     return await db.users.find_one({"_id": id})
+ @router.get("/users/{id}", response_model=UserPublic)
+ async def get_user(id: str, user: User = Depends(get_current_user)):
+     doc = await db.users.find_one({"_id": id, "tenant_id": user.tenant_id})
+     if not doc:
+         raise HTTPException(404)
+     return doc
```
---

[MEDIUM · 82] **2. <Title>**

`core/auth.py :: verify_token` · Severity: **Medium** · Confidence: 82 · CWE-327 · OWASP API2:2023

**Description**
<The vulnerable pattern and why an attacker can exploit it, in 1 short sentence>

**Fix**

```diff
- jwt.decode(token, key)
+ jwt.decode(token, key, algorithms=["RS256"], audience=API_AUD, issuer=EXPECTED_ISS)
```
---

< ... all above-threshold findings >

---

[LOW · 75] **3. <Title>**

`routes/uploads.py :: POST /upload` · Severity: **Low** · Confidence: 75

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

- **<Title>** — `file.py :: function` — Code smells: <missing dependency, unvalidated input, etc.> — <1-2 sentence description>

---

## Suppressed findings

_Findings matched against `.audit-ignore` and excluded from the report body. Listed for transparency._

| Group key | Reason |
|---|---|
| `app/legacy.py \| GET /health \| info-disclosure` | Known, tracked in JIRA-1234 |

(Omit this section if no suppressions.)

---

> ⚠️ This review was performed by an AI assistant. AI analysis can never verify the complete absence of vulnerabilities and no guarantee of security is given. Professional security reviews, bug bounty programs, and production monitoring (WAF, SIEM, anomaly detection) are strongly recommended for any production API.

````

### Rules for markdown output

- Sort findings by **severity first** (Critical → High → Medium → Low → Info), then by **confidence descending** within each severity.
- Findings below the confidence threshold get a description but no **Fix** block.
- Draft findings directly in report format — do not re-generate.
- Location format:
  - Route: `file.py :: METHOD /path`
  - Function: `file.py :: function_name`
  - Dependency / decorator: quote the decorator line

---

## JSON format (`--format json`)

Emit to the same path but with `.json` extension. Schema:

```json
{
  "meta": {
    "skill": "python-api-auditor",
    "skill_version": "0.2.0",
    "project": "my-fastapi-app",
    "generated_at": "2026-04-23T12:30:00Z",
    "mode": "default",
    "files_reviewed": ["app/routes/users.py", "app/core/auth.py"],
    "framework": "fastapi",
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
      "title": "BOLA on /users/{id}",
      "severity": "high",
      "confidence": 93,
      "location": {
        "file": "app/routes/users.py",
        "line": 42,
        "symbol": "get_user"
      },
      "route": "GET /users/{id}",
      "bug_class": "bola",
      "group_key": "app/routes/users.py | get_user | bola",
      "description": "get_user queries by id without a tenant predicate.",
      "fix": "Filter by user.tenant_id and add response_model.",
      "cwe": "CWE-639",
      "owasp_api_top10": "API1:2023"
    }
  ],
  "leads": [
    {
      "title": "Prompt injection via description",
      "location": {"file": "app/llm.py"},
      "code_smells": "free-text description flows into LLM prompt",
      "description": "Verify prompt layer uses delimited user-content tags..."
    }
  ],
  "suppressed": []
}
```

### Rules for JSON output

- snake_case keys.
- `severity` lowercase (`critical | high | medium | low | info`).
- `confidence` integer 0-100.
- `owasp_api_top10` format: `APIN:YYYY`.
- `cwe` format: `CWE-N`; omit if none.
- `group_key` mandatory for every finding.

## CI integration

With `--exit-code-on <severity>`: after emitting the report, return non-zero exit code if any finding's severity is at or above the threshold.

Severity order: `critical > high > medium > low > info`.

Example: `--exit-code-on high` returns 1 if any Critical or High finding was emitted.
