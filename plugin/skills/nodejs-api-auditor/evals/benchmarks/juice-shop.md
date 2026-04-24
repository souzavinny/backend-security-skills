---
repo_url: https://github.com/juice-shop/juice-shop
repo_ref: master
scope_dir: routes
---

# Ground Truth — OWASP Juice Shop

Source: the app is intentionally riddled with vulnerabilities from the OWASP Top 10 and API Top 10 challenge list. Ground-truth below is a curated subset a competent auditor should catch on the `routes/` layer.

Upstream: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) · Challenge list: https://pwning.owasp-juice.shop/

## Findings

FINDING | id: H-1 | severity: High | file: routes/login.ts | function: login | bug_class: sql-injection
description: login() builds an SQL query by string-interpolating the submitted email, enabling UNION-based extraction and the classic `' OR 1=1--` admin bypass.

FINDING | id: H-2 | severity: High | file: routes/basket.ts | function: retrieveBasket | bug_class: bola
description: Basket retrieval trusts the `:id` path param and does not enforce ownership, letting any authenticated user read any other user's basket.

FINDING | id: H-3 | severity: High | file: routes/userProfile.ts | function: updateUserProfile | bug_class: ssti
description: The user profile template renders a user-controlled username via Pug, allowing server-side template injection and RCE.

FINDING | id: H-4 | severity: High | file: routes/fileUpload.ts | function: fileUpload | bug_class: unrestricted-file-upload
description: File upload accepts arbitrary extensions and oversized files without size/type enforcement, enabling path traversal via malicious zip entries and DoS via large uploads.

FINDING | id: H-5 | severity: High | file: routes/easterEgg.ts | function: servePromotionVideo | bug_class: directory-traversal
description: The static file path accepts `..`-bearing inputs and serves arbitrary files from the container filesystem.

FINDING | id: H-6 | severity: High | file: lib/insecurity.ts | function: authorize | bug_class: jwt-alg-confusion
description: JWT verification accepts `alg:none` tokens, allowing forgery of any user identity including admin.

FINDING | id: M-1 | severity: Medium | file: routes/coupon.ts | function: applyCoupon | bug_class: weak-crypto
description: Coupon codes are derived from a weak timestamp-seeded generator and can be brute-forced offline for free discounts.

FINDING | id: M-2 | severity: Medium | file: routes/userProfile.ts | function: updateUserProfile | bug_class: mass-assignment
description: Profile update reflects the request body directly into the user record, letting clients set fields like `role` that grant elevated privileges.

FINDING | id: M-3 | severity: Medium | file: routes/search.ts | function: searchProducts | bug_class: nosql-or-sql-injection
description: Search endpoint concatenates the query parameter into a SQL LIKE clause, yielding injection.

FINDING | id: M-4 | severity: Medium | file: routes/redirect.ts | function: performRedirect | bug_class: open-redirect
description: Redirect endpoint uses a weak allowlist that can be bypassed via URL-encoding tricks, enabling phishing pivots.

FINDING | id: M-5 | severity: Medium | file: app.ts | function: (cors config) | bug_class: cors-misconfig
description: CORS is configured to reflect any origin with credentials, allowing malicious sites to read authenticated responses.

FINDING | id: M-6 | severity: Medium | file: routes/login.ts | function: login | bug_class: missing-rate-limit
description: Login endpoint has no rate limit or account lockout, enabling credential stuffing at scale.

FINDING | id: M-7 | severity: Medium | file: routes/captcha.ts | function: generateCaptcha | bug_class: weak-captcha
description: Captcha challenges use trivial arithmetic and are solved programmatically, defeating the bot mitigation.

FINDING | id: M-8 | severity: Medium | file: routes/order.ts | function: placeOrder | bug_class: race-condition
description: Placing an order debits the wallet in a non-atomic read-then-write sequence, letting parallel requests double-spend.
