---
repo_url: https://github.com/appsecco/dvna
repo_ref: master
scope_dir: core
---

# Ground Truth — Damn Vulnerable NodeJS Application (DVNA)

Source: AppSecCo DVNA — Express + Sequelize app covering the OWASP Top 10. Upstream: [appsecco/dvna](https://github.com/appsecco/dvna).

## Findings

FINDING | id: H-1 | severity: High | file: core/appHandler.js | function: userEdit | bug_class: sql-injection
description: userEdit builds a raw SQL UPDATE by concatenating form fields, exposing classic SQLi with the ability to modify arbitrary rows.

FINDING | id: H-2 | severity: High | file: core/appHandler.js | function: productSearch | bug_class: sql-injection
description: productSearch uses `sequelize.query` with an interpolated search term, enabling UNION-based data extraction.

FINDING | id: H-3 | severity: High | file: core/appHandler.js | function: redirect | bug_class: open-redirect
description: redirect sends the user to any URL provided in the query string with no allowlist, enabling phishing.

FINDING | id: H-4 | severity: High | file: core/appHandler.js | function: ping | bug_class: command-injection
description: The ping endpoint passes the user-supplied address through `child_process.exec`, giving unauthenticated RCE.

FINDING | id: H-5 | severity: High | file: core/appHandler.js | function: calc | bug_class: code-injection
description: The calc endpoint uses `eval()` on a user-supplied expression, providing arbitrary JavaScript execution.

FINDING | id: H-6 | severity: High | file: core/appHandler.js | function: showProduct | bug_class: xxe
description: Product XML import uses a libxml parser with external-entity resolution enabled, leaking local files and enabling SSRF.

FINDING | id: M-1 | severity: Medium | file: server.js | function: (session config) | bug_class: insecure-session
description: Session is configured without `httpOnly`/`secure` flags and with a hardcoded secret, enabling cookie theft via XSS and trivial forgery.

FINDING | id: M-2 | severity: Medium | file: core/passport.js | function: verify | bug_class: weak-crypto
description: Password verification uses an unsalted fast hash, letting attackers reverse stolen hashes via precomputed tables.

FINDING | id: M-3 | severity: Medium | file: core/appHandler.js | function: login | bug_class: missing-rate-limit
description: Login has no rate limit or lockout, enabling credential stuffing and brute force.

FINDING | id: M-4 | severity: Medium | file: core/appHandler.js | function: forgotPw | bug_class: user-enumeration
description: forgotPw returns different responses for existing vs non-existing accounts, enabling user enumeration.

FINDING | id: M-5 | severity: Medium | file: core/appHandler.js | function: listProducts | bug_class: bola
description: listProducts returns products keyed by owner without verifying the caller owns them, leaking other users' inventory.

FINDING | id: M-6 | severity: Medium | file: server.js | function: (headers) | bug_class: security-misconfig
description: No security headers, no CSP, directory listing enabled, stack traces returned on error.
