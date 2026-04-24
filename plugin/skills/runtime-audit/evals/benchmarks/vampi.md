---
image: erev0s/vampi:latest
port: 5000
startup_wait: 15
auth_context_a: {"header": "Authorization: Bearer <user-A-token>", "seed_via": "POST /users/v1/register"}
auth_context_b: {"header": "Authorization: Bearer <user-B-token>", "seed_via": "POST /users/v1/register"}
---

# Ground Truth — OWASP VAmPI (Runtime)

Source: [erev0s/VAmPI](https://github.com/erev0s/VAmPI). Flask + SQLAlchemy vulnerable API.

## Findings (expected)

FINDING | id: H-1 | severity: High | endpoint: PUT /users/v1/{username}/email | bug_class: bola
description: Email update works for any user-name path param regardless of caller. Runtime probe should CONFIRM via two-context probe.

FINDING | id: H-2 | severity: High | endpoint: PUT /users/v1/{username}/password | bug_class: bola
description: Password reset same shape — any-user password change. Full account takeover.

FINDING | id: H-3 | severity: High | endpoint: DELETE /users/v1/{username} | bug_class: bfla
description: Delete user is admin-only by convention but not enforced — any auth'd caller deletes any user.

FINDING | id: H-4 | severity: High | endpoint: GET /books/v1/{title} | bug_class: sqli
description: Title is interpolated into raw SQL. UNION payloads extract `users` table.

FINDING | id: H-5 | severity: High | endpoint: POST /users/v1/register | bug_class: mass-assignment
description: `admin: true` in registration body is accepted — anonymous caller creates admin account.

FINDING | id: M-1 | severity: Medium | endpoint: GET /users/v1 | bug_class: excessive-data-exposure
description: Returns all users including password hashes and emails.

FINDING | id: M-2 | severity: Medium | endpoint: POST /users/v1/login | bug_class: user-enumeration
description: Different responses for unknown user vs wrong password.

FINDING | id: M-3 | severity: Medium | endpoint: * | bug_class: missing-rate-limit
description: No rate limiting anywhere.

FINDING | id: M-4 | severity: Medium | endpoint: GET / | bug_class: missing-security-headers
description: None of HSTS/CSP/X-Frame-Options/X-Content-Type-Options set.

FINDING | id: M-5 | severity: Medium | endpoint: * | bug_class: jwt-weak-secret
description: JWT signed with a short hardcoded secret. Runtime probe limited — secret cracking is out of scope unless offline post-hoc.

## Not expected in default run

FINDING | id: X-1 | severity: Medium | endpoint: various | bug_class: missing-auth
description: Several endpoints claim auth-required but skip the check under specific conditions — detected by Band 1 auth-strip probe (send without token).

## Notes

- VAmPI has fewer endpoints than Juice Shop — eval recall target is 80%+ on default run.
- No WebSocket / GraphQL surface to probe.
