---
image: bkimminich/juice-shop:latest
port: 3000
startup_wait: 30
auth_context_a: {"header": "Authorization: Bearer <user-A-jwt>", "seed_via": "POST /api/Users with {email:'a@test.invalid',password:'xxx'}"}
auth_context_b: {"header": "Authorization: Bearer <user-B-jwt>", "seed_via": "POST /api/Users with {email:'b@test.invalid',password:'xxx'}"}
---

# Ground Truth — OWASP Juice Shop (Runtime)

Source: [OWASP/juice-shop](https://github.com/juice-shop/juice-shop). Runs at `http://localhost:3000`.

Curated subset of vulnerabilities that a runtime audit in default (non-destructive) mode should catch or flag as LEAD.

## Findings (expected)

FINDING | id: H-1 | severity: High | endpoint: POST /rest/user/login | bug_class: sqli-authbypass
description: Login form passes raw `email` into a raw SQL query — `' OR '1'='1-- ` authenticates as the first user (admin in the default dataset). Runtime probe should CONFIRM via auth bypass.

FINDING | id: H-2 | severity: High | endpoint: GET /rest/basket/{id} | bug_class: bola
description: Basket retrieval returns any user's basket if the requester provides a valid (but unrelated) JWT. Runtime probe with two contexts should CONFIRM cross-context read.

FINDING | id: H-3 | severity: High | endpoint: GET /ftp and /ftp/{file} | bug_class: directory-traversal
description: FTP listing exposes an unrestricted directory; null-byte and double-extension tricks allow traversal to sensitive files.

FINDING | id: H-4 | severity: High | endpoint: GET /api/Users | bug_class: excessive-data-exposure
description: The /api/Users endpoint returns all users including password hashes. Runtime probe's response-leak scan (authz-bopla-response-leak / crypto-response-secret-leak) should flag.

FINDING | id: H-5 | severity: High | endpoint: PUT /api/Users/{id} | bug_class: mass-assignment
description: User update accepts the `role` field in the body; a regular user can elevate themselves to admin. Runtime probe should CONFIRM via follow-up GET.

FINDING | id: M-1 | severity: Medium | endpoint: GET /rest/products/search | bug_class: sqli-error-based
description: Product search concatenates `q` into SQL. Probe should see SQL error in response body → LIKELY.

FINDING | id: M-2 | severity: Medium | endpoint: * | bug_class: cors-wildcard
description: CORS returns `Access-Control-Allow-Origin: *` with credentials header behavior depending on route. Config probe should flag.

FINDING | id: M-3 | severity: Medium | endpoint: GET / | bug_class: missing-security-headers
description: No HSTS, no CSP, no X-Content-Type-Options. Config probe should emit a batched header-missing LEAD.

FINDING | id: M-4 | severity: Medium | endpoint: * | bug_class: fingerprint-x-powered-by
description: Responses include `X-Powered-By: Express`. Config probe should flag.

FINDING | id: M-5 | severity: Medium | endpoint: GET /rest/user/change-password | bug_class: csrf-missing
description: Change-password is a GET with query-string parameters — trivially CSRF-able. Runtime probe (config + authn) should flag.

FINDING | id: M-6 | severity: Medium | endpoint: GET /redirect | bug_class: open-redirect
description: Redirect endpoint accepts arbitrary URL. Runtime probe should CONFIRM.

FINDING | id: M-7 | severity: Medium | endpoint: POST /api/Feedbacks | bug_class: xss-stored
description: Feedback body reflects HTML unescaped. Runtime probe canary reflection → LIKELY (since XSS impact requires a browser render, not raw HTTP).

## Destructive-only (only runs with --destructive)

FINDING | id: D-1 | severity: Medium | endpoint: POST /rest/user/login | bug_class: brute-force
description: No rate limit on login → brute-force succeeds at arbitrary rate.

FINDING | id: D-2 | severity: Medium | endpoint: POST /api/Users | bug_class: missing-email-verification
description: Registration doesn't verify email. Pump probe should succeed at creating N accounts.

## Not expected to be found in default run (require intrusive probes or state-specific preconditions)

FINDING | id: X-1 | severity: Low | endpoint: various | bug_class: jwt-alg-none
description: Juice Shop's JWT verification has historically been alg:none vulnerable in some configurations. Expected LIKELY at best without specific token mutation.

## Notes

- Juice Shop is intentionally verbose about its vulnerabilities via `/api/Challenges` — probes that find these are "playing on easy mode". Report recall above 70% is the baseline bar.
- False positive rate should be < 10%. Juice Shop has heavy error-message decoration which can trip detection.
