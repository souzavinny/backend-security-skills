# Finding Validation

Every finding passes four sequential gates. Fail any gate → **rejected** or **demoted** to lead. Later gates are not evaluated for failed findings.

## Gate 1 — Refutation

Construct the strongest argument that the finding is wrong. Find the dependency, middleware, validator, framework default, or upstream check that kills the attack — quote the exact line and trace how it blocks the claimed step.

- Concrete refutation (specific check blocks exact claimed step, e.g. `Depends(get_current_user)` on the route, `pydantic` model rejects shape, Django `@permission_required` decorator, explicit `response_model` on a FastAPI route) → **REJECTED** (or **DEMOTE** if code smell remains)
- Speculative refutation ("probably validated upstream", "framework probably handles this") → **clears**, continue. You must quote the actual guard.

## Gate 2 — Reachability

Prove the vulnerable state is reachable in a deployed API.

- Structurally impossible (env gate like `if not settings.DEBUG: return` fully blocks the branch; route registered only under an admin-only router tree / blueprint) → **REJECTED**
- Requires privileged actions outside normal API use (admin `manage.py` command, direct DB edit) → **DEMOTE**
- Achievable through normal client usage, a crafted HTTP request, or a public endpoint → **clears**, continue

## Gate 3 — Trigger

Prove an unauthenticated or under-privileged actor can execute the attack.

- Only authenticated admin roles can trigger and the role is audited → **DEMOTE**
- Costs exceed extraction value (compute-bound DoS on a cheap endpoint) → **REJECTED** unless endpoint is rate-unlimited
- Unauthenticated, low-privileged, or cross-tenant actor triggers profitably → **clears**, continue

## Gate 4 — Impact

Prove material harm to an identifiable victim.

- Self-harm only (user can only hurt their own account) → **REJECTED**
- Dust-level, no compounding → **DEMOTE**
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
| **Low** | Missing security headers; version disclosure; clickjacking on non-sensitive pages; user enumeration via response-timing |
| **Info** | Informational fingerprinting with no direct exploit path — stylistic / defense-in-depth |

Severity is assigned independently of confidence. A Low-severity finding can still have Confidence 95.

## Confidence

Start at **100**, deduct: partial attack path **-20**, bounded non-compounding impact **-15**, requires specific (but achievable) state **-10**. Confidence ≥ 80 gets description + fix. Below 80 gets description only. Below 75 becomes a LEAD.

## Safe patterns (do not flag)

- FastAPI `Depends(get_current_user)` / `dependencies=[Depends(require_auth)]` at router or route level
- FastAPI route with `response_model=UserPublic` explicitly constraining the response shape
- Django DRF `permission_classes = [IsAuthenticated]` / `IsAdminUser` with `get_queryset()` filtered by `self.request.user`
- Django `@login_required` / `@permission_required` / `LoginRequiredMixin`
- Flask-Login `@login_required` + a session auth check inside the route
- `pydantic.BaseModel` with `model_config = ConfigDict(extra="forbid")` rejecting extra fields
- Parameterized queries: `cursor.execute("SELECT ... WHERE id = %s", (id,))`, Django ORM `.filter(id=id)`, SQLAlchemy `session.execute(select(...).where(T.id == id))` with bound params
- `yaml.safe_load(...)` (NOT `yaml.load` without `SafeLoader`)
- `subprocess.run([cmd, arg1, arg2])` argv form (NOT `shell=True`)
- `bcrypt` / `argon2-cffi` / `passlib[bcrypt]` for password hashing
- `secrets.token_urlsafe(32)` / `secrets.token_hex(32)` for token generation
- `hmac.compare_digest(a, b)` for HMAC compare (NOT `==`)
- `jwt.decode(token, key, algorithms=['RS256'], audience=..., issuer=...)` with explicit algorithms list AND audience/issuer
- Django `CSRF_COOKIE_SECURE = True`, `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SECURE_SSL_REDIRECT = True`
- Django `ALLOWED_HOSTS` set (not `['*']`)
- `DEBUG = False` in production
- SQLAlchemy `text(":x").bindparams(x=value)` (bound, NOT f-string)
- Python 3.12+ `tarfile.extractall(path, filter='data')`

## Lead promotion

Before finalizing leads, promote where warranted:

- **Cross-route echo.** Same root cause confirmed as FINDING in one route → promote in every route where the identical pattern appears.
- **Multi-agent convergence.** 2+ agents flagged same code, lead was demoted (not rejected) → promote to FINDING at confidence 75.
- **Partial-path completion.** Only weakness is incomplete trace but path is reachable and unguarded → promote to FINDING at confidence 75, description only.

## Leads

High-signal trails for manual investigation. No confidence score, no fix — title, code smells, and what remains unverified.

## Do Not Report

- Linter/formatter nits, typing stubs, naming.
- Missing rate limit on an endpoint that is itself admin-only with no compute amplification.
- "X library has had CVEs historically" without a current vulnerable version or vulnerable usage path.
- Missing CSRF on a stateless JSON API that uses bearer tokens AND does not set cookies — CSRF is a cookie-session concern.
- "Admin can do admin things" — admin privileges by design are not findings unless there's a concrete escalation path.
- Generic "dependency X is outdated" without a CVE and a reachable call pattern.
