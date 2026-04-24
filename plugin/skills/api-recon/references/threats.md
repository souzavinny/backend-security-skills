# API Threat Profiles

Threat models for backend APIs, organized by framework, by AuthN/AuthZ flow, by integration boundary, and by lifecycle phase. Used by `api-recon` to populate Section 2 (threat & trust model) of the readiness report.

---

## Framework-Type Profiles

### Express (Node.js)

**Primary risks:**
- Middleware ordering errors (auth after body-parser, errorHandler not last)
- Opt-in security (no helmet / rate-limit / validation by default)
- CORS misconfig (`origin: true` + credentials)
- `trust proxy: true` enables X-Forwarded-For spoofing
- No default body-size limit (DoS)
- `x-powered-by` disclosure

**Primary adversaries:**
- Unauthenticated external — hits every route that lacks explicit auth middleware
- Cross-tenant authenticated user — any BOLA is directly exploitable
- Scraper / abuser — no rate-limit defaults means amplification endpoints are open

### NestJS (Node.js)

**Primary risks:**
- `ValidationPipe` is opt-in unless set as `APP_PIPE`
- `@Roles` without `@UseGuards(RolesGuard)` is decoration only
- Service layer often holds ownership logic — DTOs alone don't prevent BOLA
- Global guards via `APP_GUARD` may be missing in custom modules

**Primary adversaries:**
- Authenticated user abusing service-level logic that skipped ownership
- Admin-route discovery via HTTP method confusion

### Fastify (Node.js)

**Primary risks:**
- Schema validation is enabled when a schema is declared — routes without a schema bypass entirely
- `preHandler` hook scoping (app / plugin / route)
- Rate-limit plugin scope

### Next.js API routes (Node.js)

**Primary risks:**
- Each route file (`pages/api/*.ts` or `app/api/*/route.ts`) requires independent auth
- `bodyParser` size default is 1 MB — can be raised accidentally
- Middleware runs on every request but can be bypassed if misconfigured
- Server Actions — same auth concerns, different surface

### FastAPI (Python)

**Primary risks:**
- Auth opt-in via `Depends(get_current_user)` — easy to miss on a single route
- `response_model` opt-in — missing it leaks every field of the returned model
- Async handlers calling sync libs (bcrypt, PIL, subprocess) block the loop
- CORS middleware explicit
- Custom exception handlers leak tracebacks

**Primary adversaries:**
- External unauthenticated caller hitting a route whose author forgot `Depends`
- Cross-tenant caller reading data because `response_model` lets the whole DB doc through

### Django / DRF (Python)

**Primary risks:**
- `DEBUG=True` / hardcoded `SECRET_KEY` / `ALLOWED_HOSTS=['*']` in prod
- DRF default `DEFAULT_PERMISSION_CLASSES = [AllowAny]`
- `ModelViewSet` with `queryset = Model.objects.all()` — BOLA by default
- `fields = "__all__"` on serializers — excessive exposure
- `@csrf_exempt` on cookie-session endpoints

**Primary adversaries:**
- Accidental public endpoint due to `AllowAny`
- BOLA via unscoped `get_queryset`
- Session-forging attacker with leaked `SECRET_KEY`

### Flask (Python)

**Primary risks:**
- Nothing is on by default — each security control must be explicit
- Client-side signed sessions have no revocation
- `debug=True` exposes the Werkzeug debugger with a PIN that's crackable under info leaks → RCE
- SSTI risk via `render_template_string`

### Starlette / Tornado / Sanic / aiohttp (Python)

**Primary risks:**
- Bespoke middleware stacks — each is its own audit
- Auth fully DIY
- WebSocket auth timing (`accept` before vs after auth)

---

## Auth Lifecycle Threats

### Login

- Credential stuffing (missing per-user rate limit + lockout)
- User enumeration via distinct error responses / timing
- Session fixation (session ID not rotated on success)
- Pre-auth session that grants partial access before MFA

### Password reset

- Token predictable (weak RNG)
- Token long-lived / reusable
- Reset response leaks whether account exists
- Change doesn't invalidate existing sessions/tokens
- Reset link sent over HTTP

### OAuth / OIDC

- Missing PKCE (public clients)
- Missing / unvalidated `state`
- Missing `nonce` validation on id_token
- Redirect URI regex/prefix instead of exact match
- Refresh token without rotation + reuse detection
- Mixing OAuth signing key with internal service-auth key

### MFA

- Pre-auth session grants access before MFA
- MFA flag settable client-side
- TOTP compared with `==` (timing)
- Recovery codes reusable / unhashed
- MFA bypass via password-reset flow

### Sessions

- `httponly` / `secure` / `sameSite` missing
- Client-side signed sessions holding sensitive state
- Long-lived session without idle timeout
- Session binding (IP / UA) missing where relevant

---

## Integration-Boundary Threats

### Inbound webhooks

- Signature verified against JSON-reparsed body (key reordering)
- HMAC compared with `==` (timing)
- No timestamp check (replay)
- No event-id idempotency (double-apply)
- Verbose error on bad signature helps enumeration

### Outbound HTTP from API (SSRF)

- User-URL fetched server-side → cloud metadata, internal network
- URL parsing differentials (`user@host`, decimal IPs, IPv6)
- Redirect follow → 302 to metadata endpoint
- Headless browser `page.goto` = worst-case SSRF
- DNS rebinding

### Third-party API responses

- Trusting response body fields (OAuth role claim, payment status) without validation / re-fetch
- Reflecting third-party HTML into emails
- Response shape drift breaking downstream auth decisions

### Object storage (S3 / GCS / R2)

- Long-TTL presigned URLs
- Bucket-wide (not object-scoped) presigned URLs
- Upload URLs without content-type + size pins
- Public-read-write buckets for user content
- Leaked IAM role via SSRF → broader AWS access

### LLM / AI integrations

- Direct prompt injection (user input into system prompt)
- Indirect prompt injection (agent reads attacker-controlled content)
- LLM output piped into eval/SQL/shell/HTML
- Tool-use authorization (model calls tools with service permissions, not user permissions)
- Budget DoS (unbounded max_tokens, user-chosen model)
- System-prompt exfiltration (if prompt contains secrets)

### GraphQL

- Introspection enabled in prod
- Missing depth / complexity limits
- Field-level authz missing
- Batching / alias DoS
- Fragment recursion

---

## Lifecycle / Temporal Threats

- **Deploy freshness:** new route goes out without a guard in the first deploy; rollback skipped.
- **Dependency bump:** minor version bump pulls a compromised release (supply chain).
- **Feature-flag default:** new endpoint behind a flag that's default-on in one env.
- **Staging endpoint in prod bundle:** conditional registration on `NODE_ENV` with `NODE_ENV` unset.
- **Deprecated endpoint left live:** `/v1/` remains unpatched after `/v2/`.
- **Secret rotation:** rotation procedure not wired into the service; leaked secret = persistent.

---

## Composability Risks

- **Shared DB across tenants** — if tenant scope breaks in one service, all tenants impacted.
- **Shared auth service** — if it forges JWTs for a sibling service, cross-service escalation.
- **Background jobs (Celery / BullMQ / Sidekiq)** — run with service permissions; task payload-injection = privileged code path.
- **Shared object storage** — one service's bad ACL leaks data from another that uses the same bucket.
- **Shared secrets manager** — leaked service account reads all secrets.

---

## Adversary Catalog

| Adversary | Capability | Typical vector |
|---|---|---|
| Unauthenticated external | HTTP client, anon user | Missing auth, public routes, SSRF to metadata |
| Authenticated user | Valid account, has token | BOLA, BFLA, BOPLA, horizontal escalation |
| Low-privilege tenant admin | Admin within own tenant | Cross-tenant via shared infrastructure, privilege escalation to platform admin |
| Compromised third-party | Signed webhook sender, OAuth issuer | Forged webhook, replay, HTML injection via response |
| Insider | Code commit access | Hardcoded secret, debug endpoint, feature flag |
| Supply-chain | Malicious npm/PyPI publish | Postinstall script, typosquat, dependency confusion |
| LLM prompt-injection | Controls content read by agent | Tool-use exfiltration, poisoned action, system-prompt leak |
