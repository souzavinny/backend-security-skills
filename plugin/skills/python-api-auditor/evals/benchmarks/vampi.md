---
repo_url: https://github.com/erev0s/VAmPI
repo_ref: master
---

# Ground Truth — OWASP VAmPI (Vulnerable API)

Source: Flask + SQLAlchemy intentionally-vulnerable REST API demonstrating the OWASP API Top 10. Upstream: [erev0s/VAmPI](https://github.com/erev0s/VAmPI).

## Findings

FINDING | id: H-1 | severity: High | file: api_views/users.py | function: login_user | bug_class: jwt-weak-secret
description: Login issues JWTs signed with a short hardcoded secret loaded from vulnerable config, enabling offline brute-force and arbitrary identity forgery.

FINDING | id: H-2 | severity: High | file: api_views/users.py | function: update_email | bug_class: bola
description: update_email accepts a username path parameter and updates any user's email with no ownership check, allowing account takeover via email reset flow.

FINDING | id: H-3 | severity: High | file: api_views/users.py | function: update_password | bug_class: bola
description: update_password lets any authenticated user change any other user's password by passing the target username in the path, enabling full account takeover.

FINDING | id: H-4 | severity: High | file: api_views/users.py | function: delete_user | bug_class: bfla
description: delete_user is reachable by non-admin authenticated users despite being intended for admins, allowing any user to delete any account.

FINDING | id: H-5 | severity: High | file: api_views/books.py | function: get_by_title | bug_class: sql-injection
description: Book lookup concatenates the user-supplied title into a raw SQL query via string formatting, enabling UNION-based data extraction.

FINDING | id: M-1 | severity: Medium | file: api_views/users.py | function: register_user | bug_class: mass-assignment
description: register_user trusts the client-supplied admin flag in the request body, letting an anonymous caller create an admin account at signup.

FINDING | id: M-2 | severity: Medium | file: api_views/users.py | function: get_user | bug_class: excessive-data-exposure
description: get_user returns the full user record including password hash and email when queried by username.

FINDING | id: M-3 | severity: Medium | file: app.py | function: (app config) | bug_class: missing-rate-limit
description: No rate limiting on login, registration, or password-update endpoints, enabling credential stuffing and brute force.

FINDING | id: M-4 | severity: Medium | file: app.py | function: (app config) | bug_class: security-misconfig
description: Missing security headers, CORS not restricted, error responses leak internal details.

FINDING | id: M-5 | severity: Medium | file: api_views/users.py | function: login_user | bug_class: user-enumeration
description: Login returns distinguishable error messages for unknown-user vs wrong-password, allowing enumeration of valid accounts.

FINDING | id: M-6 | severity: Medium | file: api_views/books.py | function: add_new_book | bug_class: bola
description: Books can be created with an arbitrary `user` field, letting callers assign books to other users.
