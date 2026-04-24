# Attack Vectors (Node.js Backend APIs)

Pattern library organized by OWASP API Security Top 10 (2023) + Node-specific vectors. Each entry: shape, sink/source, concrete exploit, safe form. Grep patterns are POSIX ERE.

---

## API1:2023 — Broken Object Level Authorization (BOLA)

**1.1 Raw-ID find without ownership filter**
- Shape: `findUnique({ where: { id: req.params.id } })`, `findById(req.params.id)`, `WHERE id = $1`
- Exploit: enumerate IDs, read any user's resource
- Safe: `{ id, userId: req.user.id }` or `{ id, tenantId: req.user.tenantId }`

**1.2 Trusted client-supplied `userId` / `tenantId`**
- Shape: `Payment.create({ userId: req.body.userId, ... })`
- Exploit: move funds / create resources on behalf of other users
- Safe: server derives scope field from session

**1.3 Aggregation missing tenant filter on joined tables**
- Shape: `$lookup` / `JOIN` where only outer table is scoped
- Exploit: join leaks rows from other tenants

---

## API2:2023 — Broken Authentication

**2.1 JWT `algorithms` not specified**
- Shape: `jwt.verify(token, key)` (2-arg)
- Exploit: `alg:none`; HS256 signed with RSA public key
- Grep: `jwt\.verify\([^,)]+,[^,)]+\)` with no 3rd arg

**2.2 JWT audience / issuer not validated**
- Shape: verify options missing `audience` + `issuer`
- Exploit: token from sibling service accepted

**2.3 Password compared with `===` or fast hash**
- Shape: `hash === req.body.password`, `md5(pwd)`
- Exploit: timing attack / rainbow table / offline brute-force

**2.4 Session not regenerated on login**
- Shape: no `req.session.regenerate()` in login handler
- Exploit: session fixation

**2.5 Reset token predictable / long-lived / reusable**
- Shape: `Math.random()` token, 24h expiry, no single-use flag
- Exploit: guess + reuse

**2.6 MFA state client-modifiable**
- Shape: `req.body.mfaPassed` trusted, or pre-MFA session grants full access
- Exploit: skip MFA

---

## API3:2023 — Broken Object Property Level Authorization (BOPLA)

**3.1 Mass assignment**
- Shape: `.update(..., req.body)`, `Object.assign(doc, req.body)`
- Exploit: set `isAdmin`, `tenantId`, `balance`
- Safe: destructure allowed fields

**3.2 Excessive field exposure**
- Shape: `res.json(user)` returning full doc
- Exploit: leak `passwordHash`, `mfaSecret`, `emailVerificationToken`, PII
- Safe: whitelist via response DTO / select projection

**3.3 Prisma `data: req.body` without shape**
- Shape: Prisma creates/updates with raw body
- Exploit: set relational fields you shouldn't

---

## API4:2023 — Unrestricted Resource Consumption

**4.1 Missing rate limit on amplification endpoints**
- Shape: `/login`, `/password-reset`, `/verify-phone`, `/signup` with no limiter
- Exploit: credential stuffing, SMS pump ($), user enumeration, account flood

**4.2 Client-controlled `limit` / `size`**
- Shape: `Number(req.query.limit)` passed to DB query
- Exploit: `?limit=1000000` → memory blow-up

**4.3 Unbounded body / upload**
- Shape: no `express.json({ limit })`, `multer({ limits })`
- Exploit: large bodies DoS parser

**4.4 Regex DoS (catastrophic backtracking)**
- Shape: `/^(\w+)+$/.test(req.body.x)` / `new RegExp(req.query.p)`
- Exploit: input causes exponential runtime

**4.5 Sync crypto in request path**
- Shape: `bcrypt.hashSync(pwd, 14)` in handler
- Exploit: event-loop stall at modest concurrency

**4.6 `qs` deep parse on query string**
- Shape: `?a[b][c][d][e]=...`
- Exploit: deep nesting crash

---

## API5:2023 — Broken Function Level Authorization (BFLA)

**5.1 Admin route on public router tree**
- Shape: `router.delete('/admin/users/:id', handler)` with no role guard
- Exploit: regular user calls admin action

**5.2 HTTP method confusion**
- Shape: `GET /users/:id` auth-gated, `DELETE /users/:id` missing guard
- Exploit: delete without permission

**5.3 NestJS roles without guard**
- Shape: `@Roles('admin')` decorator without `@UseGuards(RolesGuard)`
- Exploit: decorator is metadata; no enforcement

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

**6.1 Bulk checkout / limited-edition race**
- Shape: no per-user cap on limited inventory
- Exploit: scalper scripts grab entire drop

**6.2 Referral / coupon farming**
- Shape: no cap on referrals, no throwaway-email detection
- Exploit: self-referral or codes brute-forced

**6.3 Workflow step skip**
- Shape: KYC step 3 reachable without 1–2 completed
- Exploit: bypass verification

---

## API7:2023 — SSRF

**7.1 User-URL fetch**
- Shape: `fetch(req.body.url)`, `axios.get(req.query.image)`
- Exploit: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- Safe: allowlist + resolve-then-connect + block private IPs

**7.2 Headless browser user-goto**
- Shape: `page.goto(req.body.url)`
- Exploit: worst-case SSRF (rendered SPA can chain)

**7.3 URL parsing differential**
- Shape: naive `new URL(x).hostname` allowlist check
- Exploit: `http://allowed.com@169.254.169.254/`, IPv6 `[::]`, decimal IPs

**7.4 Legacy `request` library + `file://`**
- Shape: `request(req.body.url, ...)`
- Exploit: `file:///etc/passwd` → LFI

---

## API8:2023 — Security Misconfiguration

**8.1 CORS reflects Origin with credentials**
- Shape: `cors({ origin: true, credentials: true })`
- Exploit: any site reads the user's session via CSRF-with-credentials

**8.2 `trust proxy` too wide**
- Shape: `app.set('trust proxy', true)`
- Exploit: spoof `X-Forwarded-For` to bypass IP-based rate limits

**8.3 Verbose errors in production**
- Shape: Express default handler + no `NODE_ENV=production`
- Exploit: stack traces leak paths, deps, internal logic

**8.4 Debug endpoints live**
- Shape: `/env`, `/debug`, Swagger UI without auth
- Exploit: enumerate secrets, schema

**8.5 Missing security headers**
- Shape: no `helmet()` / manual equivalents
- Exploit: clickjacking, MIME sniffing, missing HSTS

**8.6 Cookie flags missing**
- Shape: session cookie without `httpOnly`, `secure`, `sameSite`
- Exploit: XSS reads session, CSRF via cross-site cookie

---

## API9:2023 — Improper Inventory Management

**9.1 Unpatched /v1/ after /v2/ deploy**
- Shape: both versions registered, only v2 has recent fixes
- Exploit: hit v1 with known CVE

**9.2 `/internal/` reachable externally**
- Shape: ingress allows, app doesn't gate
- Exploit: call service-to-service endpoint as outsider

**9.3 Staging/test endpoints in prod**
- Shape: `/test/*`, `/seed/*`, `/debug/*` registered conditionally
- Exploit: reset / seed data

**9.4 Feature flag default-on for unfinished endpoint**
- Shape: `if (flags.newExport) app.get('/export', ...)` with flag default `true`
- Exploit: reach unfinished / unhardened handler

---

## API10:2023 — Unsafe Consumption of APIs

**10.1 Trusting 3rd-party webhook body fields**
- Shape: `if (req.body.status === 'paid') markPaid()` without signature verify and without re-fetch
- Exploit: forge webhook

**10.2 Reflecting 3rd-party HTML into email**
- Shape: address API returns HTML, server interpolates into email template
- Exploit: injected HTML / stored XSS in email

**10.3 OIDC role claim trusted without validation**
- Shape: `user.role = idToken.role` without issuer allowlist
- Exploit: issuer controlled by attacker grants admin

---

## Node-specific add-ons

**N.1 Prototype pollution**
- Shape: `Object.assign({}, req.body)`, `lodash.merge(cfg, req.body)` (pre-4.17.21), `qs` deep-parse
- Exploit: `__proto__.isAdmin = true` → gadget fires on any object check
- Grep: `__proto__`, `Object\.prototype`, `lodash.*merge`

**N.2 `child_process.exec` with concat**
- Shape: `exec(\`cmd ${req.body.x}\`)`
- Exploit: shell metachars → RCE
- Safe: `execFile('cmd', [arg1, arg2])`

**N.3 `path.join` for user-controlled path**
- Shape: `fs.readFile(path.join(ROOT, req.params.name))`
- Exploit: `../../etc/passwd`
- Safe: `path.resolve` + `startsWith(ROOT)` check OR allowlist regex

**N.4 `dangerouslySetInnerHTML` from API response**
- Shape: React SSR using API response as HTML
- Exploit: stored XSS
- Safe: sanitize via `dompurify` before render

**N.5 `Buffer.allocUnsafe(size)` with user-controlled size**
- Shape: allocates from heap without zeroing → info leak
- Safe: `Buffer.alloc(size)` (zeroed)

**N.6 `eval` / `new Function` / `vm.runInNewContext`**
- Shape: user input evaluated as JS
- Exploit: RCE
- Note: `vm` is NOT a sandbox

**N.7 WebSocket upgrade without auth re-check**
- Shape: upgrade accepts any connection, later messages act as authenticated
- Exploit: unauthenticated persistent channel

**N.8 GraphQL introspection in prod**
- Shape: Apollo default `introspection: true`
- Exploit: full schema leak

**N.9 GraphQL depth / cost unlimited**
- Shape: no `depthLimit` / `costAnalysis`
- Exploit: nested query DoS

**N.10 Next.js API route without `bodyParser` size cap**
- Shape: default `bodyParser: true` with no `sizeLimit`
- Exploit: 100MB JSON body DoS

---

## Grep cheat-sheet

```
jwt\.verify\([^,)]+,[^,)]+\)                    # missing algorithms option
algorithms.*['"]none['"]                        # alg:none
ignoreExpiration.*true                          # JWT ignores exp
Math\.random\(\)                                # weak randomness
crypto\.createHash\(['"](md5|sha1)              # weak hash
child_process\.exec\(                           # shell exec
\{\s*shell:\s*true                              # spawn with shell
\.raw\(.*\$\{                                   # SQL string interpolation
\$queryRawUnsafe                                # Prisma raw
Sequelize\.literal\(                            # sequelize literal
req\.body\.(isAdmin|role|userId|tenantId)       # client-controlled privilege
\.update\(.*req\.body\)                         # mass assignment
Object\.assign\(.*req\.body\)                   # mass assignment / proto pollution
path\.join\([^,]+,\s*req\.                      # path traversal source
res\.redirect\(req\.(query|body|params)         # open redirect
cors\(\{[^}]*origin:\s*true                     # CORS reflects origin
trust proxy.*true                               # too-wide trust
rejectUnauthorized:\s*false                     # TLS bypass
NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0       # TLS bypass env
DEBUG\s*=\s*true                                # debug in prod
introspection:\s*true                           # GraphQL introspection
yaml\.load\(                                    # old js-yaml
pickle|node-serialize                           # unsafe deserializer
fetch\(req\.                                    # SSRF primitive
page\.goto\(req\.                               # SSRF via headless
```
