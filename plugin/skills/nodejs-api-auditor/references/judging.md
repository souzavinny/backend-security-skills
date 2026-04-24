# Finding Validation

Every finding passes four sequential gates. Fail any gate → **rejected** or **demoted** to lead. Later gates are not evaluated for failed findings.

## Gate 1 — Refutation

Construct the strongest argument that the finding is wrong. Find the middleware, guard, validator, framework default, or upstream check that kills the attack — quote the exact line and trace how it blocks the claimed step.

- Concrete refutation (specific check blocks exact claimed step, e.g. `helmet()` sets CSP, `zod.parse()` rejects shape, `requireAuth` middleware is mounted before the route) → **REJECTED** (or **DEMOTE** if code smell remains)
- Speculative refutation ("probably validated upstream", "framework probably handles this") → **clears**, continue. You must quote the actual guard.

## Gate 2 — Reachability

Prove the vulnerable state is reachable in a deployed API.

- Structurally impossible (env gate like `if (NODE_ENV === 'production') return` fully blocks the branch; route registered only under an admin-only router tree) → **REJECTED**
- Requires privileged actions outside normal API use (manual DB edit, admin-only setup endpoint) → **DEMOTE**
- Achievable through normal client usage, a crafted HTTP request, or a public endpoint → **clears**, continue

## Gate 3 — Trigger

Prove an unauthenticated or under-privileged actor can execute the attack.

- Only authenticated admin roles can trigger and the role is audited → **DEMOTE**
- Costs exceed extraction value (e.g. compute-bound DoS on a cheap endpoint) → **REJECTED** unless the endpoint is rate-unlimited
- Unauthenticated, low-privileged, or cross-tenant actor triggers profitably → **clears**, continue

## Gate 4 — Impact

Prove material harm to an identifiable victim.

- Self-harm only (user can only hurt their own account) → **REJECTED**
- Dust-level, no compounding (rate-limit miss on a trivially cheap endpoint) → **DEMOTE**
- Data theft, account takeover, privilege escalation, cross-tenant access, RCE, fund movement, integrity corruption, availability loss at scale → **CONFIRMED**

## Severity (separate from confidence)

Every confirmed finding carries **severity** AND **confidence**. They answer different questions:
- **Severity** — how bad is this bug if exploited?
- **Confidence** — how sure are you the bug is real?

Assign severity from Gate 4's impact classification:

| Severity | When |
|---|---|
| **Critical** | Pre-auth RCE; unauthenticated full-tenant data exfiltration; fund / money movement by an unprivileged actor; privilege escalation from anon → admin |
| **High** | Authenticated cross-tenant data access (BOLA across tenants); BFLA reaching admin endpoints; authenticated RCE; stored-XSS in admin-visible surfaces; auth-bypass chains; leaked long-lived secrets |
| **Medium** | Session fixation; missing rate limit on auth-adjacent endpoints; weak-crypto on non-password data; verbose error leaks with internal paths / DB schema; CSRF on session-cookie APIs; open redirect on auth flow |
| **Low** | Missing security headers; `X-Powered-By` / version disclosure; clickjacking on non-sensitive pages; user enumeration via response-timing |
| **Info** | Informational fingerprinting with no direct exploit path — stylistic / defense-in-depth |

Severity is assigned independently of confidence. A Low-severity finding can still have Confidence 95.

## Confidence

Start at **100**, deduct: partial attack path **-20**, bounded non-compounding impact **-15**, requires specific (but achievable) state **-10**. Confidence ≥ 80 gets description + fix. Below 80 gets description only. Below 75 becomes a LEAD.

## Safe patterns (do not flag)

- `helmet()` mounted before routes → standard security headers are set
- `cors({ origin: allowlist, credentials: true })` with explicit origin allowlist (not `true`, not reflected)
- `express-rate-limit` / `@fastify/rate-limit` / `@nestjs/throttler` on auth-adjacent endpoints
- `zod` / `joi` / `class-validator` schema parsing at the boundary with `strict()` / `whitelist: true`
- Parameterized queries via Knex `.where({})`, Prisma, TypeORM `QueryBuilder` with parameters, or driver placeholders (`?`, `$1`)
- `crypto.timingSafeEqual` for HMAC / token compares
- `bcrypt` / `argon2` / `scrypt` for passwords (NOT MD5/SHA1)
- `jwt.verify(token, key, { algorithms: ['RS256'] })` with explicit algorithm allowlist AND audience/issuer validation
- `cookie-session` / `express-session` with `httpOnly: true, secure: true, sameSite: 'lax'|'strict'`
- `execFile(cmd, [args])` — argv form, NOT `exec(string)`
- `path.resolve(root, userInput)` followed by prefix check (`resolved.startsWith(root)`)
- NestJS `@UseGuards(AuthGuard)` at controller level + `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })` globally
- Fastify `preHandler` hook enforcing auth at route declaration

## Lead promotion

Before finalizing leads, promote where warranted:

- **Cross-route echo.** Same root cause confirmed as FINDING in one route → promote in every route where the identical pattern appears.
- **Multi-agent convergence.** 2+ agents flagged same code, lead was demoted (not rejected) → promote to FINDING at confidence 75.
- **Partial-path completion.** Only weakness is incomplete trace but path is reachable and unguarded → promote to FINDING at confidence 75, description only.

## Leads

High-signal trails for manual investigation. No confidence score, no fix — title, code smells, and what remains unverified.

## Do Not Report

- Linter/formatter nits, TypeScript `any` usage, naming.
- Missing rate limit on an endpoint that is itself admin-only and has no compute amplification.
- "X library has had CVEs historically" without a current vulnerable version or vulnerable usage path.
- Missing CSRF token on a stateless JSON API that uses bearer tokens AND does not set cookies — CSRF is a cookie-session concern.
- Missing `helmet()` when the app explicitly sets equivalent headers manually.
- "Admin can do admin things" — admin privileges by design are not findings unless there's a concrete escalation path from a lower role.
- Generic "dependency X is outdated" without a CVE and a reachable call pattern.
