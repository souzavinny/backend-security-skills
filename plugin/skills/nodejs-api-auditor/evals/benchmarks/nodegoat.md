---
repo_url: https://github.com/OWASP/NodeGoat
repo_ref: master
scope_dir: app
---

# Ground Truth — OWASP NodeGoat

Source: OWASP NodeGoat — an Express + MongoDB app demonstrating the OWASP Top 10 for Node.js. Upstream: [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat).

## Findings

FINDING | id: H-1 | severity: High | file: app/data/allocations-dao.js | function: getByUserIdAndYear | bug_class: nosql-injection
description: Allocation lookup accepts a raw user-supplied `userId` and builds a Mongo query object without coercion, allowing `$gt`/`$ne` operator injection.

FINDING | id: H-2 | severity: High | file: app/routes/contributions.js | function: handleContributionsUpdate | bug_class: server-side-js-injection
description: Contributions route uses `eval()` on user-supplied pre-tax/after-tax/roth percentages, enabling arbitrary JavaScript execution in the server process.

FINDING | id: H-3 | severity: High | file: app/routes/profile.js | function: handleProfileUpdate | bug_class: stored-xss
description: Profile fields are stored unsanitized and rendered server-side without escaping, enabling stored XSS that hijacks other sessions.

FINDING | id: H-4 | severity: High | file: app/routes/research.js | function: handleResearch | bug_class: ssrf
description: The research endpoint fetches any URL supplied by the user server-side, with no allowlist or private-IP blocking, giving attackers access to cloud metadata and internal services.

FINDING | id: H-5 | severity: High | file: app/routes/memos.js | function: handleMemos | bug_class: bola
description: Memo retrieval does not filter by owner, so any authenticated user can read all memos.

FINDING | id: M-1 | severity: Medium | file: config/env/development.js | function: (config) | bug_class: weak-crypto
description: Password hashing uses a weak, fast hash that is trivially brute-forceable against leaked hashes.

FINDING | id: M-2 | severity: Medium | file: app/routes/session.js | function: handleLoginRequest | bug_class: session-fixation
description: The login handler does not regenerate the session ID on successful authentication, letting an attacker who plants a session cookie ride it into the victim's authenticated session.

FINDING | id: M-3 | severity: Medium | file: app/routes/index.js | function: (routes) | bug_class: missing-csrf
description: State-changing routes do not verify a CSRF token despite using cookie-based sessions, enabling cross-site form submissions.

FINDING | id: M-4 | severity: Medium | file: server.js | function: (app setup) | bug_class: security-misconfig
description: Missing security headers (no helmet / CSP / HSTS / X-Frame-Options), directory listing enabled for static assets, and `x-powered-by` exposed.

FINDING | id: M-5 | severity: Medium | file: app/routes/profile.js | function: handleProfileUpdate | bug_class: mass-assignment
description: Profile update merges the request body into the user document, letting clients set `isAdmin` or `role` fields.

FINDING | id: M-6 | severity: Medium | file: app/routes/contributions.js | function: (validation) | bug_class: insufficient-input-validation
description: Contribution percentages are not bounds-checked server-side, enabling negative values and integer overflow in downstream calculations.
