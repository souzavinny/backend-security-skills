# Output Templates

Templates for the four output files `api-recon` writes. Copy the structure, fill with project-specific data, never fabricate.

---

## `architecture.json`

Route graph + auth matrix + trust boundaries as structured JSON.

```json
{
  "meta": {
    "generated_at": "YYYY-MM-DDTHH:MM:SSZ",
    "commit": "abcdef1",
    "branch": "main",
    "framework": "fastapi | express | nestjs | django | flask | ...",
    "language": "python | node",
    "project_name": "basename-of-root"
  },
  "stats": {
    "source_files": 42,
    "test_files": 12,
    "route_count": 35,
    "contributor_count": 7
  },
  "actors": [
    { "id": "unauth", "name": "Unauthenticated external user", "tier": "public" },
    { "id": "user", "name": "Authenticated user", "tier": "auth" },
    { "id": "admin", "name": "Platform admin", "tier": "admin" },
    { "id": "webhook", "name": "Stripe / third-party webhook", "tier": "partner" }
  ],
  "routes": [
    {
      "id": "r-1",
      "method": "GET",
      "path": "/users/{id}",
      "handler": "routes/users.py:get_user",
      "auth_tier": "auth",
      "role_required": null,
      "input_sources": ["path.id", "query.include"],
      "db_writes": [],
      "db_reads": ["users"],
      "external_calls": [],
      "rate_limited": false,
      "response_shape_constrained": true,
      "response_model": "UserPublic"
    }
  ],
  "trust_boundaries": [
    { "from": "unauth", "to": "auth", "gate": "POST /auth/login", "controls": ["password check", "mfa"] },
    { "from": "user", "to": "admin", "gate": "role check", "controls": ["is_staff flag"] },
    { "from": "api", "to": "external", "gate": "outbound webhook", "controls": ["HMAC", "retry budget"] }
  ],
  "external_services": [
    { "id": "stripe", "direction": "in+out", "auth": "signed webhook + api key", "scope": "payments" },
    { "id": "s3", "direction": "out", "auth": "iam role", "scope": "user-uploads" }
  ]
}
```

Rules:
- Emit only what you can cite from the code. No fabricated `external_services`.
- `auth_tier` is one of: `public`, `auth`, `role`, `admin`, `partner`, `internal`.
- `input_sources` use `path.*`, `query.*`, `body.*`, `header.*`, `cookie.*` prefixes.
- Every `route` must have a `handler` pointer of the form `file:line` or `file:symbol`.

---

## `recon.md`

Under 500 lines. Readable standalone.

```markdown
# API Security Recon — <project-name>

**Commit:** `abcdef1` · **Branch:** `main` · **Framework:** FastAPI · **Generated:** YYYY-MM-DD

## 1. Overview

- **Scope:** <N> source files (<framework>), <N> test files
- **Routes:** <N> total — <A> public, <B> auth-required, <C> admin/role-gated
- **Contributors:** <N> distinct authors over the tracked history
- **Third-party integrations:** <list — stripe, s3, sendgrid, etc.>
- **Backwards-compatibility surface:** <list deprecated routes or note "none observed">

## 2. Threat & Trust Model

### Actors

| Actor | Trust | Capabilities |
|---|---|---|
| Unauthenticated external | none | Reach every public route |
| Authenticated user | low | All auth routes; ownership-scoped data |
| Admin | high | Administrative routes |
| Partner webhook | signed | POST /webhooks/*; gated by HMAC + timestamp + nonce |

### Trust boundaries

- **Unauth → Auth:** login / token exchange — describe gate and known weaknesses
- **User → User (horizontal):** which routes could allow cross-user access
- **User → Admin (vertical):** which routes could allow privilege escalation
- **API → External:** outbound HTTP — which endpoints allow caller-controlled URLs

### Key attack surfaces

- **Surface 1 — <name>** [invariants.md#i-3] — description, file:line
- **Surface 2 — <name>** [invariants.md#i-7] — description, file:line

(Pull each surface from a gap in invariants.md. Cross-reference by anchor.)

## 3. Invariants (pointer)

> Auth coverage: N/M routes · Tenant isolation: N/M · Rate limit: N/M · Response shape: N/M
> Full catalog: [invariants.md](invariants.md)

## 4. Entry Points (pointer)

> N routes catalogued. Detail: [entry-points.md](entry-points.md)

## 5. Dependencies & Supply Chain

- **Language runtime:** <node version / python version>
- **Primary framework:** <name + version>
- **Auth lib:** <jwt / passport / authlib / authjs / ...>
- **ORM / DB:** <prisma / sequelize / sqlalchemy / django ORM / ...>
- **Crypto:** <bcrypt / argon2 / passlib / ...>
- **Pinning status:** <pinned exactly / range / unpinned>
- **Lockfile committed:** <yes / no>
- **Known high-risk deps:** <list — or note "none observed">

## 6. Test & Monitoring Signals

- **Test files:** <N>
- **Test framework:** <jest / vitest / pytest / unittest / ...>
- **Security-relevant tests:** <count of tests exercising auth / authz / injection / rate-limit>
- **Gaps:** <missing categories — auth edge cases, BOLA coverage, rate-limit, etc.>

## 7. Git History Signals (if available)

- **Recent touches to auth code:** <commit list or "none in last N">
- **Recent touches to authz code:** <same>
- **Hotspots:** <files with high churn on security-sensitive paths>

## Recon Verdict

**Tier:** 🟢 Audit-ready · 🟡 Prep recommended · 🔴 High-risk pre-audit (pick one)

**Justification:** 2–4 sentences linking to the specific invariant gaps, missing tests, or config risks that drive the tier.

**Top three pre-audit actions:**
1. <concrete action — "add Depends(get_current_user) to routes/admin.py:12,18,25">
2. <concrete action — "enable response_model on every route in routes/users.py">
3. <concrete action — "add rate limit to POST /auth/login, /auth/forgot, /auth/verify">
```

---

## `entry-points.md`

```markdown
# Entry Points

## Protocol flow paths

<6–15 lines of arrow chains showing major user journeys.>

- User onboarding: `POST /auth/signup` ◄── email verify ◄── `POST /auth/verify-email` → `POST /auth/login` → `GET /me`
- Purchase: `GET /products` → `POST /cart` → `POST /checkout` → Stripe webhook → `POST /orders/mark-paid`
- Admin data export: `POST /admin/export` (admin-only) → `S3 presigned upload` → download link emailed

## Public (unauthenticated) routes

Full detail for each. These are the first audit targets.

### `POST /auth/login`
- **Handler:** `routes/auth.py:login` (line 42)
- **Input:** `body.email`, `body.password`
- **DB effects:** reads `users`, writes `login_attempts`
- **External calls:** none
- **Rate limited:** no ⚠️
- **Response model:** `LoginResponse` (access_token, refresh_token)
- **Notes:** user enumeration via response timing not currently mitigated.

### `GET /products`
- ...

## Auth-required routes

Compact table for breadth, detail only where notable.

| Method | Path | Handler | Ownership scope | Rate limited |
|---|---|---|---|---|
| GET | /users/{id} | routes/users.py:get_user | ✅ tenant + owner | no |
| POST | /orders | routes/orders.py:create_order | ✅ session-derived | yes (10/min) |
| GET | /orders/{id} | routes/orders.py:get_order | ⚠️ only tenant, not owner | no |

## Admin / role-gated routes

| Method | Path | Handler | Role | Notes |
|---|---|---|---|---|
| DELETE | /admin/users/{id} | routes/admin.py:delete_user | is_staff | |
| POST | /admin/export | routes/admin.py:export | is_staff | writes to S3 |

## Partner / webhook routes

| Method | Path | Handler | Signer | Verified | Replay-protected |
|---|---|---|---|---|---|
| POST | /webhooks/stripe | webhooks/stripe.py:handle | Stripe | ✅ | ⚠️ timestamp only, no nonce |
```

---

## `invariants.md`

Section-by-section catalog. Blocks are `#### {letter}-N` heading-anchored so recon.md can cross-link.

```markdown
# API Invariants

## §1 Enforced Auth (per-route)

#### A-1
- **Route:** `GET /users/{id}`
- **Gate:** `Depends(get_current_user)` at `routes/users.py:12`
- **Enforced:** ✅ Yes

#### A-2
- **Route:** `POST /admin/users`
- **Gate:** `Depends(require_admin)` at `routes/admin.py:5`
- **Enforced:** ✅ Yes

## §2 Tenant isolation

#### T-1
- **Property:** Every `orders` read carries a `tenant_id` predicate.
- **Enforced:** ❌ No
- **Gap:** `routes/orders.py:45 get_order` reads `Order.query.get(id)` without tenant filter.
- **Risk:** BOLA across tenants.

## §3 Ownership

#### O-1
- **Property:** `/orders/{id}` accessible only to the creating user or admins.
- **Enforced:** ⚠️ Partial
- **Gap:** Handler checks tenant but not user — any user in the same tenant reads any order.

## §4 Rate limiting

#### R-1
- **Property:** `POST /auth/login` rate limited per-IP AND per-username.
- **Enforced:** ❌ No
- **Gap:** No limiter applied. Credential stuffing trivial.
- **File:** `routes/auth.py:42`

## §5 Response shape

#### S-1
- **Property:** No route returns `password_hash` / `mfa_secret` / verification tokens.
- **Enforced:** ⚠️ Partial
- **Gap:** `GET /me` returns full user model without `response_model` — leaks hashed password.
- **File:** `routes/me.py:8`

## §6 Input validation

#### V-1
- **Property:** Every body parameter is validated against a pydantic model with `extra="forbid"`.
- **Enforced:** ✅ Yes (all 23 POST routes use pydantic schemas)

## §7 Idempotency

#### I-1
- **Property:** Money-moving POST accepts `Idempotency-Key` and enforces uniqueness.
- **Enforced:** ❌ No
- **Gap:** `POST /payments` has no idempotency handling.
- **Risk:** Duplicate payments on client retry.
```

Rules:
- Every block cites a file:line in the "File" or "Gate" field.
- "Enforced" is ✅ Yes, ⚠️ Partial, or ❌ No.
- Don't invent invariants. Only list properties you can confirm or disconfirm from the code.
- Anchor IDs (`A-1`, `T-1`, etc.) must be stable so recon.md can link.
