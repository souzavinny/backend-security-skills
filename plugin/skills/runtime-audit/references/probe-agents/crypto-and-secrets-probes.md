# Crypto & Secrets Probes

Live verification of crypto weaknesses and secret leakage. Observes network/response side-channels and common mistakes.

## TLS probes (Band 1)

```
PROBE: crypto-tls-weak
BAND: 1
ATTACK:
  Connect with openssl s_client -connect host:443 -tls1 / -tls1_1
  Check cipher suite offers
TOOLS:
  openssl s_client -connect {host}:443 -servername {host} </dev/null
  nmap --script ssl-enum-ciphers -p 443 {host}
SIGNAL:
  LEAD if SSLv3, TLS 1.0, TLS 1.1 accepted
  LIKELY if RC4, DES, or export ciphers offered
  CONFIRMED if certificate is expired, self-signed on prod, or hostname mismatch
```

## HSTS / secure cookie (Band 1)

```
PROBE: crypto-hsts
BAND: 1
ATTACK:
  Request home page over HTTPS, inspect `Strict-Transport-Security` header
SIGNAL:
  LEAD if missing or max-age < 15552000 (6mo)
```

```
PROBE: crypto-cookie-flags
BAND: 1
ATTACK:
  Observe any Set-Cookie on auth endpoints
SIGNAL:
  LIKELY if a session cookie lacks HttpOnly, Secure, or SameSite attributes
```

## HMAC timing side-channel (Band 2)

For webhook endpoints that verify an HMAC:

```
PROBE: crypto-hmac-timing
BAND: 2
ATTACK:
  Send 100 requests with slightly-different bogus signatures (differing at byte position 0, 1, 2, ..., 63).
  Measure response timing.
SIGNAL:
  LIKELY if a monotonic timing curve is observable (signature compared byte-by-byte)
  HARD to get CONFIRMED without a lot of samples and a quiet network — note as LIKELY
```

## Webhook replay (Band 2)

```
PROBE: crypto-webhook-replay
BAND: 2
PREREQ:  a captured legit signed webhook OR a known test-mode HMAC secret
ATTACK:
  1. Deliver the signed payload → expect 2xx with effect.
  2. Deliver the EXACT same payload (same sig, same timestamp) → expect 4xx.
  3. Deliver the same payload with timestamp shifted +1h → expect 4xx (stale).
SIGNAL:
  CONFIRMED replay-missing if step 2 succeeds
  CONFIRMED freshness-missing if step 3 succeeds
```

## Webhook signature strip (Band 2)

```
PROBE: crypto-webhook-sig-strip
BAND: 2
ATTACK:
  Deliver a legit payload WITHOUT the signature header.
  Deliver with an empty signature.
  Deliver with a garbage signature.
SIGNAL:
  CONFIRMED bypass if any variant succeeds
```

## Secret-in-response probe (Band 1)

For every endpoint that returns a record:

```
PROBE: crypto-response-secret-leak
BAND: 1
BASELINE:
  Collect response bodies from Band 1 discovery.
ANALYZE:
  grep for regex patterns matching known secret formats:
    AKIA[0-9A-Z]{16}
    -----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----
    sk_live_[0-9a-zA-Z]{24,}
    ghp_[0-9a-zA-Z]{36}
    xox[baprs]-[0-9a-zA-Z-]{10,}
    eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}    (JWT — flag only if context is weird)
    [A-Fa-f0-9]{64}                                                    (plausible hex-encoded secret — low signal)
    Bearer [A-Za-z0-9_\-\.]{20,}                                      (leaked bearer in body)
SIGNAL:
  CONFIRMED if secret-format match found in a 2xx response body (not an error dump)
  Redact immediately; do not print the secret in logs.
```

## Secret-in-error probe (Band 1)

```
PROBE: crypto-error-secret-leak
BAND: 1
ATTACK:
  Deliberately trigger 500s:
  - Content-Type: text/xml on a JSON endpoint
  - Oversized body
  - Malformed JSON
  - Invalid UTF-8
  - Known SQL-error-inducing payloads (see injection probes)
SIGNAL:
  CONFIRMED if error page contains:
    connection strings (postgres://user:pass@host)
    stack trace with file paths revealing server layout
    library version numbers
    SECRET_KEY, JWT_SECRET, API keys
    AWS ARNs or resource IDs
```

## TLS-verification bypass (Band 1)

```
PROBE: crypto-tls-strict
BAND: 1
ATTACK:
  Connect with a deliberately-bad client cert or a known-revoked cert
  Connect with wrong SNI
SIGNAL:
  CONFIRMED bad if server accepts — likely TLS verification is not enforced
  Expected behavior: 495/496 or TLS abort
```

## JWT signing-key disclosure (Band 1)

Some apps expose JWKS with private keys by mistake:

```
PROBE: crypto-jwks-private-key
BAND: 1
ATTACK:
  GET /.well-known/jwks.json
  GET /jwks
  GET /keys
SIGNAL:
  CONFIRMED (CRITICAL) if the JWK has a `d` field (RSA/EC private key component — indicates published private key)
  Most JWKS have only public components (n, e for RSA; x, y for EC). `d` = private. CRITICAL finding.
```

## Output additions

```
primitive: tls | hsts | cookie-flag | hmac-timing | webhook-replay | webhook-sig | response-leak | error-leak | jwks-private
leaked_value: <sanitized indicator — never the raw secret>
severity: critical|high|medium|low
```
