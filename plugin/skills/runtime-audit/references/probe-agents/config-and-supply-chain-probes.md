# Config & Supply-Chain Probes

Live probing for misconfiguration. These are Band 1 (read-only observation) and fire early — they calibrate the rest of the audit.

## Sensitive path enumeration (Band 1)

```
PROBE: config-sensitive-paths
BAND: 1
ATTACK:
  Fire GET on each path in probe-library.md's "Common sensitive paths" list.
  (/ .env, /.git/config, /debug, /actuator, /metrics, etc.)
SIGNAL:
  CONFIRMED if any returns 2xx with expected content
  LIKELY if 302 to a login page (still exposes the path exists)
  NEGATIVE if 404
```

## CORS preflight (Band 1)

```
PROBE: config-cors-reflect
BAND: 1
BASELINE:
  OPTIONS /api/v1/anything
    Origin: https://legit.example
    Access-Control-Request-Method: POST
ATTACK:
  OPTIONS /api/v1/anything
    Origin: https://evil.example
    Access-Control-Request-Method: POST
SIGNAL:
  CONFIRMED bad if response `Access-Control-Allow-Origin: https://evil.example` + `Access-Control-Allow-Credentials: true`
  LIKELY if ACAO reflects evil origin but ACAC is missing/false
  NEGATIVE if ACAO is a hardcoded allowlist (not reflecting)
```

```
PROBE: config-cors-null-origin
BAND: 1
ATTACK:
  OPTIONS with `Origin: null` (happens on `file://` or sandboxed iframe)
SIGNAL:
  CONFIRMED if ACAO: null + ACAC: true (any sandboxed iframe can now talk to the API)
```

```
PROBE: config-cors-subdomain-bypass
BAND: 1
ATTACK:
  OPTIONS with `Origin: https://evil.allowed-domain.com` (if allowlist is suffix match)
  OPTIONS with `Origin: https://allowed-domain.com.evil.com` (if allowlist is prefix match)
SIGNAL:
  CONFIRMED if bypass succeeds
```

## Security headers (Band 1)

```
PROBE: config-missing-headers
BAND: 1
ATTACK:
  GET / — inspect response headers
CHECKLIST:
  Strict-Transport-Security       (HSTS)
  Content-Security-Policy         (CSP)
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY or CSP frame-ancestors
  Referrer-Policy
  Permissions-Policy              (nice-to-have)
SIGNAL:
  LEAD per missing header (batched into one finding — "missing N of M security headers")
```

## `X-Powered-By` / `Server` fingerprint (Band 1)

```
PROBE: config-fingerprint
BAND: 1
ATTACK:
  GET / — inspect Server / X-Powered-By / X-AspNet-Version headers
SIGNAL:
  LEAD if any version-revealing header present — helps attackers target CVEs
```

## Verbose errors (Band 1)

```
PROBE: config-verbose-errors
BAND: 1
ATTACK:
  Trigger errors:
  GET /definitely-not-a-route-xxx
  GET /api/v1/verify/" (unclosed quote)
  POST /api/v1/certify with broken JSON
  GET with absurdly long URL (> 8 KB)
SIGNAL:
  CONFIRMED if response contains a stack trace, file path, library version, or internal hostname
  CONFIRMED CRITICAL if it reveals DB connection string, SECRET_KEY, or API keys
  LEAD if generic 500 with app framework name visible
```

## Trust-proxy / IP-spoof (Band 1)

```
PROBE: config-trust-proxy
BAND: 1
ATTACK:
  Send requests with:
    X-Forwarded-For: 1.2.3.4
    X-Real-IP: 5.6.7.8
    Forwarded: for=9.10.11.12
  Compare logs (if accessible) or response `X-Client-IP` style echo headers.
  Also test rate-limit bypass: if rate limit is keyed on "real client IP" and the app trusts spoofed XFF, rotating XFF resets the bucket.
SIGNAL:
  CONFIRMED if rate limit resets as XFF rotates
```

## HTTP smuggling (Band 1 — caveat)

```
PROBE: config-http-smuggling
BAND: 1
ATTACK:
  Send requests with conflicting Content-Length + Transfer-Encoding headers.
  Test TE-CL and CL-TE variants.
SIGNAL:
  Complex to classify live without a paired backend/proxy differential. LEAD only unless two different response bodies are observed.
  (This probe is advanced; if the test runner is simple curl, skip and note as "not attempted" in the report.)
```

## Host-header injection (Band 1)

```
PROBE: config-host-inject
BAND: 1
ATTACK:
  GET / with Host: evil.example.com
  GET /forgot-password with Host: evil.example.com (check if reset links use the injected host)
SIGNAL:
  CONFIRMED if any response body or redirect contains the injected host (cache poisoning / reset-link takeover)
```

## Stale / shadow endpoints (Band 1)

```
PROBE: config-version-skew
BAND: 1
ATTACK:
  For every `/api/v2/...` endpoint discovered, also try `/api/v1/...`.
  For every GraphQL, also try `/graphql-old`, `/graphql/v1`.
SIGNAL:
  LEAD if /v1/ exists alongside /v2/ → verify patch parity manually
```

## Dependency fingerprint via response quirks (Band 1)

```
PROBE: config-dep-fingerprint
BAND: 1
ATTACK:
  Send specific invalid inputs that produce library-specific error shapes:
    Malformed JSON → Node "Unexpected token..." vs Python "Expecting value..."
    Pydantic validation → "ctx" field
    zod validation → "issues" field
    marshmallow → "errors" dict
    ASP.NET model binding → "traceId" field
SIGNAL:
  LEAD documenting the detected library + version hints — feeds the auditor's follow-up
```

## Docker-specific (Band 1)

```
PROBE: config-docker-hosts
BAND: 1
ATTACK:
  Check /etc/hosts-style info leaks:
  Trigger errors that might include hostnames: `container-hash`, `task-arn`, etc.
SIGNAL:
  LEAD if container/task identifiers leak (enables lateral thinking)
```

## Output additions

```
misconfig: cors-reflect | cors-null | cors-subdomain | missing-header-<name> | verbose-error | trust-proxy | host-inject | stale-endpoint | ... 
blast_radius: <what this alone enables, or what probe chains with>
```
