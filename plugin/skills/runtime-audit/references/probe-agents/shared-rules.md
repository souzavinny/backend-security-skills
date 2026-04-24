# Shared Probe Rules

Every probe-agent bundle contains this file plus its own specialty. These rules apply to all probes.

## Probe structure

Every probe is four parts:

1. **Baseline request** — a matched control that should elicit normal behavior.
2. **Attack request** — same shape, one payload substitution.
3. **Differential classifier** — what response delta constitutes a signal.
4. **Cleanup step** (Band 2/3 only) — undo the attack's side effect.

Write each probe as a function-like block:

```
PROBE: <agent>-<short-name>
BAND: 1 | 2 | 3
BASELINE:
  METHOD /path
  HEADERS {...}
  BODY {...}
ATTACK:
  METHOD /path
  HEADERS {...}
  BODY {...payload...}
SIGNAL:
  <what response delta indicates a hit>
CLEANUP:
  <DELETE / compensating transaction / none>
```

## Rate respect

Respect the configured rate (`--rate` flag, default 1/s). If a probe must issue many requests (enumeration, rate-limit verification), break them into chunks of 10 with sleeps in between.

Never fire two Band 3 probes from the same family in parallel.

## Transcript discipline

Every probe writes a `.http` file to `{run_dir}/` with the full request + response, named `{NNN}-{agent}-{probe}.http`:

```
### Request
POST /api/v1/certify HTTP/1.1
Host: localhost:3000
X-API-Key: ***
Content-Type: application/json

{"platformId":"runtime-audit-canary-9F3A","category":"SPORTS",...}

### Response  
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 512

{"success":true,"data":{"certificationId":"..."}}

### Classification
CONFIRMED | LIKELY | LEAD | NEGATIVE
Signal: <brief note>
```

## Canaries

Use a per-run random hex canary (`RUNTIME_AUDIT_CANARY_<random>`) in any payload that should echo back. Store the canary once at run start; reuse so every reflection is searchable with one grep.

Never embed the canary in URLs you don't control (no `http://attacker.com/<canary>` — that leaks to third parties).

## Error handling

- Connection refused / DNS failure → abort the run, print why.
- TLS failure → abort unless `--insecure`. Do not silently downgrade.
- 5xx from the target on a Band 1 probe → record, continue.
- 429 from the target → follow `Retry-After`; halve rate. Three 429s in a row → abort.
- 401/403 on a Band 1 probe against an assumed-public endpoint → normal, record fingerprint only.

## Never flag

- WAF-level blocks (Cloudflare, Akamai, AWS WAF): note in "Probes blocked" section, don't emit a finding.
- Target's own rate limit firing against the skill's probes: that's the target defending, not a finding (unless the rate-limit probe was specifically verifying its presence).
- Self-signed TLS on `localhost`: pass `--insecure` at target selection; don't emit a finding.

## Output

Probe agents return structured findings to the orchestrator. One per line:

```
FINDING | agent: <name> | host: <host> | endpoint: METHOD /path | bug_class: kebab-tag | status: CONFIRMED|LIKELY|LEAD | confidence: NN | transcript: {run_dir}/NNN-*.http
signal: <what was observed>
impact: <what damage it demonstrates>
reproduction: <1-line curl> 
```
