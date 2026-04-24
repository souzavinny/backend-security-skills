# Finding Judging (Dynamic)

Every runtime finding passes three sequential gates. Unlike the static auditor's four gates (which reason about *code*), these gates reason about *observed HTTP behavior*.

## Gate 1 — Signal differential

You must have a baseline (a matched control request) and an observed (the probe). Confirm the difference is attributable to the probe, not noise.

- Response size / status / timing differs consistently across 3 repeats → **clears**
- Difference only appears once of three → **DEMOTE** (flaky, LEAD)
- No difference → **REJECTED**

For time-based probes: baseline p99 + 3s is the threshold. Below that → noise.

## Gate 2 — Reproduction

You must be able to write a single `curl` command that demonstrates the finding. If you can't, it's a LEAD.

```
curl -X POST -H "X-API-Key: ***" -d '{"id":"<victim-id>"}' https://target/api/v1/...
# expected: 200 with victim's data
```

- Transcript captured, reproduction one command → **clears**
- Multi-step reproduction (two contexts, specific ordering) → **clears** but lower confidence (−10)
- Required specific server state not easy to recreate → **DEMOTE** to LEAD

## Gate 3 — Impact

The response actually demonstrates harm.

- Attacker reads data they shouldn't (cross-tenant, cross-user, PII) → **CONFIRMED**, Impact=High
- Attacker writes data they shouldn't → **CONFIRMED**, Impact=High
- Attacker executes code / causes DoS → **CONFIRMED**, Impact=Critical
- Attacker bypasses rate limit but no downstream harm observed → **CONFIRMED**, Impact=Low (still a finding)
- Response contains suggestive error message but no actionable data extracted → **LEAD** with "reproducible error surface" note

## Severity (separate from confidence)

Every finding carries **severity** AND **confidence**:
- **Severity** — how bad is this bug if exploited?
- **Confidence** — how sure are you the bug is real?

| Severity | When |
|---|---|
| **Critical** | Pre-auth RCE; unauthenticated full-tenant data exfiltration; fund movement by unprivileged actor; anon → admin escalation |
| **High** | Authenticated cross-tenant access; BFLA to admin; authenticated RCE; stored-XSS in admin surfaces; auth-bypass chains; leaked long-lived secrets |
| **Medium** | Session fixation; missing rate limit on auth endpoints; weak crypto on non-password data; verbose error leaks; CSRF on cookie APIs; open redirect on auth flow |
| **Low** | Missing security headers; version disclosure; user enumeration via response timing |
| **Info** | Fingerprinting with no direct exploit path |

Assigned independently of confidence. A Low-severity finding can still be CONFIRMED at 95.

## Confidence

Start at **100**, deduct:

- Baseline established across fewer than 3 repeats: **−10**
- Multi-step reproduction: **−10**
- Requires specific pre-state you had to seed: **−10**
- Exploit path completed but impact is bounded / low: **−15**
- Response matches vulnerable-signature but data extraction was blocked by WAF / framework / response-shape constraint: **−20** (still LIKELY, not CONFIRMED)
- Target was `staging` and the bug is config-specific (might not repro on `prod`): **−10**

Confidence ≥ 90 = **CONFIRMED**. 75–89 = **LIKELY**. Below 75 = **LEAD**.

## What counts as CONFIRMED vs LIKELY

| Finding | CONFIRMED requires | LIKELY suffices |
|---|---|---|
| BOLA | Context B retrieved context A's resource with `id` substitution, and the response contains A's fields (not just 200) | Context B got 200 where it should have gotten 403, but response body doesn't prove cross-tenancy |
| SQLi | Extracted arbitrary data (UNION, time-based, error-based with content) | Error page reveals SQL engine, or timing differential suggests sleep() executed |
| SSTI | Arithmetic evaluated and reflected (`{{7*7}}` → `49`) | Non-reflected response time differential |
| SSRF | Response body contains metadata-endpoint content (IAM credentials, hostname, service banner) | 500 on localhost probe but passed on remote probe |
| Open Redirect | Redirect to off-origin host went through, `Location` header confirms | Accepted off-origin value but response was 400 |
| CORS | `Access-Control-Allow-Origin: <attacker>` + `Allow-Credentials: true` in preflight response | ACAO reflects, no credentials |
| JWT alg:none | Modified payload accepted, server returned data as the forged identity | Server returned a different error for alg:none vs bad sig |
| Rate limit missing | N = limit+5 requests all succeeded with 2xx within the window | Got 429 but 40% later than expected |
| Webhook replay | Duplicate delivery triggered downstream state change (verify via DB / follow-up GET) | Endpoint accepted the replay but no observable downstream effect |
| Prompt injection | Canary string exfiltrated in response | Canary not exfiltrated but reply shape shifted materially |

## Safe patterns (don't flag)

- Generic 500 on a malformed request with no content leak.
- 200 with an empty result set for a BOLA probe (absence of data ≠ BOLA).
- 429 triggered by the probe itself (rate limit working, not a finding).
- TLS verification failing on self-signed dev certs (`--insecure` should have been passed, not a finding).
- Reflected canary in a `/echo` or clearly-marked utility endpoint.
- `Access-Control-Allow-Origin: *` **without** `Allow-Credentials: true` — acceptable for public read APIs (still worth noting for stateful routes).

## Do not report

- WAF blocks (401 from Cloudflare / Akamai) — the target is just defending. Note in the report that probes were upstream-blocked.
- Probe failures due to network issues — retry; persistent failures = LEAD for "target unreachable from test runner".
- Findings you can't reproduce after Gate 2 — drop.
- Informational response headers without an exploit path (unless the header itself is the finding, e.g., `X-Powered-By`).
