# Resource & Business-Logic Probes

Live verification of rate limits, races, idempotency, and abuse flows. Most probes require `--destructive` because they issue many requests or mutate data.

## Rate-limit verification (Band 2)

```
PROBE: rate-limit-sustained
BAND: 2
PREREQ: Endpoint has a documented rate limit OR target has `X-RateLimit-*` headers revealing the limit.
ATTACK:
  Read the limit from headers (or use `--expected-rate N`).
  Fire N + 5 requests within the advertised window (1 minute / 1 hour).
SIGNAL:
  CONFIRMED enforced: 429 returned at or before request N+1
  CONFIRMED missing: all N+5 succeeded with 2xx
  LIKELY loose: 429 arrived later than N+1 (by > 20%)
```

```
PROBE: rate-limit-key-rotation
BAND: 2
ATTACK:
  If two auth contexts (A, B) are available, fire N requests from A (hit the limit), then immediately N from B (should be fresh budget — this is expected).
  Instead probe: rotate user-agent, rotate IP header (X-Forwarded-For spoof), rotate random headers.
  Is the limit keyed on anything the attacker can cheaply change?
SIGNAL:
  CONFIRMED bypass if the same auth token, rotating only X-Forwarded-For / User-Agent / X-Request-ID, multiplies budget.
```

```
PROBE: rate-limit-per-ip-vs-per-key
BAND: 2
ATTACK:
  Fire from a single IP with many fresh tokens (if you have them or can sign up).
  OR fire from many IPs with the same token.
SIGNAL:
  If single-IP-many-tokens is unlimited → per-IP limit missing.
  If many-IP-single-token is unlimited → per-auth limit missing.
  Finding: the complement of whichever is enforced.
```

## Body-size / payload DoS (Band 2)

```
PROBE: resource-body-limit
BAND: 2
ATTACK:
  POST a 10 MB JSON body to an endpoint that accepts JSON.
  POST a 100 MB body.
SIGNAL:
  CONFIRMED missing if 10 MB succeeds (2xx) or 413 arrives only at 100 MB+
  Expected: 413 Payload Too Large at or below 1 MB for most APIs
```

```
PROBE: resource-json-depth
BAND: 2
ATTACK:
  POST a body with 10,000 levels of nesting: { "a": { "a": { "a": ... } } }
SIGNAL:
  CONFIRMED if server returns 5xx stack overflow or hangs > 10s (parser DoS)
```

```
PROBE: resource-regex-redos
BAND: 2
ATTACK:
  For any endpoint that accepts a user-supplied regex or fuzzy-match query:
  Submit a crafted string that triggers catastrophic backtracking on a common library:
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
  applied to `(a+)+$`-shape patterns
SIGNAL:
  CONFIRMED if response time spikes > 10s
```

## Pagination / limit bypass (Band 1)

```
PROBE: resource-pagination-cap
BAND: 1
BASELINE:
  GET /items?limit=20 → returns up to 20
ATTACK:
  GET /items?limit=100000
  GET /items?limit=-1
  GET /items?limit=null
  GET /items?limit=9999999999999999999999
SIGNAL:
  CONFIRMED missing cap if N > 1000 items returned in one response
  CONFIRMED integer-overflow if -1 / large / null returns all items
  LIKELY if response time spikes (DB doing the unbounded work even if result is trimmed server-side)
```

## Race conditions (Band 2–3)

```
PROBE: resource-race-unique
BAND: 2
PREREQ: An endpoint that creates a uniquely-keyed resource (email signup, username, coupon redemption).
ATTACK:
  Fire 10 parallel POSTs with the identical unique-key payload.
SIGNAL:
  CONFIRMED if > 1 of the 10 return 2xx (uniqueness not enforced atomically)
  Note: sometimes visible only via post-hoc GET — "SELECT ... WHERE email=..." returns N rows.
```

```
PROBE: resource-race-balance
BAND: 3
PREREQ: An account with a non-zero balance (test account). --destructive.
ATTACK:
  Fire 10 parallel POSTs withdrawing the balance.
SIGNAL:
  CONFIRMED if balance goes negative OR total withdrawn exceeds starting balance.
  EXTREMELY destructive — never on real accounts. Test-mode only.
```

## Idempotency (Band 2)

```
PROBE: resource-idempotency-key
BAND: 2
ATTACK:
  POST /mutating with header `Idempotency-Key: runtime-audit-<rand>`
  POST /mutating with identical headers and body → expect same result / cached response
  POST /mutating with same key but DIFFERENT body → expect 409 / 422
SIGNAL:
  CONFIRMED missing: step 2 creates a duplicate (verify via list GET)
  CONFIRMED loose: step 3 succeeds with different outcome
```

## Bulk / scraping (Band 1)

```
PROBE: resource-scraping
BAND: 1
ATTACK:
  For each enumerable ID resource, attempt sequential enumeration (ID=1..1000) with the given rate.
  Tally successes.
SIGNAL:
  CONFIRMED scrapable if > 100 sequential fetches succeed without CAPTCHA, throttle, or anomaly detection.
  Finding severity depends on data value (usernames = low; PII = high; financial records = critical).
```

## Expensive operation enumeration (Band 2)

```
PROBE: resource-expensive-ops
BAND: 2
ATTACK:
  Submit requests with worst-case inputs to endpoints suspected of DB-heavy operations:
  - Full-text search with "%"
  - Export endpoints (CSV, PDF)
  - Aggregation / reporting endpoints
SIGNAL:
  LIKELY if response time > 10s consistently → CPU-or-DB amplification
  CONFIRMED DoS if response times correlate with concurrent requests (not truly parallel processing)
```

## Email/SMS pump (Band 3)

```
PROBE: resource-comms-pump
BAND: 3
PREREQ: --destructive AND --canary-email (controlled inbox) or --canary-sms (controlled phone)
ATTACK:
  Submit 20 forgot-password / verify / resend requests against the canary contact.
SIGNAL:
  CONFIRMED if all 20 trigger emails/SMS (count received at canary)
  LIKELY if first N send then get throttled (but N is high, e.g., > 5/minute)
```

## Coupon / referral abuse (Band 3 — opt-in per flow)

```
PROBE: resource-coupon-brute
BAND: 3
ATTACK:
  If a coupon-code-redemption endpoint exists: fire 1000 codes (alphanumeric enumeration).
SIGNAL:
  CONFIRMED if any code is validated AND rate limit didn't fire
```

## Output additions

```
abuse_vector: rate-sustained | rate-key-rotation | body-size | json-depth | redos | pagination | race-unique | race-balance | idempotency | scraping | expensive-op | comms-pump | coupon-brute
observed_limit: <what the rate limit actually was>
expected_limit: <what it should have been based on docs / headers>
```
