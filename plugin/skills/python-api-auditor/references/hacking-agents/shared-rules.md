# Shared Scan Rules

## Reading

Your bundle has two sections:

1. **Core source** (inline) — read in parallel chunks (offset + limit), compute offsets from the line count in your prompt. `pyproject.toml` / `requirements.txt` is included — outdated or high-CVE deps matter.
2. **Peripheral file manifest** — file paths under `# Peripheral Files (read on demand)`. Read only those relevant to your specialty.

When matching handlers, check both the handler body AND every layer of its dependency/middleware stack (FastAPI `Depends`, `dependencies=[]` on router/app, Django middleware + permission classes, Flask blueprint-level `before_request`, Starlette `Middleware`).

## Dependency resolution (Python frameworks)

Before claiming a route is missing auth/validation/rate-limit, trace **the full chain** that applies:

1. **FastAPI**: `app.include_router(router, dependencies=[Depends(auth)])` applies to every route on the router. `@router.get(..., dependencies=[...])` adds route-level. `Depends(get_current_user)` on a parameter runs before the handler. Global middleware via `app.add_middleware(...)`.
2. **Django**: `MIDDLEWARE` list runs in order for every request. `DEFAULT_PERMISSION_CLASSES` in DRF settings applies to every viewset unless overridden. `@method_decorator` + `dispatch` for class-based views.
3. **Flask**: `@app.before_request` / `@blueprint.before_request` runs for every matched route in that scope. `@login_required` decorator at route.
4. **Starlette**: `Middleware(...)` stack defined at app construction. `dependencies=` on routes.

Never claim "no auth on route X" if auth is applied via a router-level `dependencies=` or a `before_request` higher in the file.

## Cross-route patterns

When you find a bug in one route, **weaponize that pattern across every other route in the bundle.** Search by route path AND by code pattern. Finding BOLA in `GET /orders/{id}` means you check every other `/{id}` endpoint — missing a repeat instance is an audit failure.

After scanning: escalate every finding to its worst exploitable variant (DoS may hide data exfiltration; BOLA may hide BFLA). Then revisit every handler where you found something and attack the other branches (error paths, 4xx responses that leak data).

## Framework defaults worth remembering

- **FastAPI**: no auth by default. `response_model` must be set or handlers leak everything they return. `Query(..., regex=...)` / pydantic `constr` enforce shape; without them anything passes. CORS middleware explicit.
- **Django**: `DEBUG=True` by default in dev settings — returns stack traces + SECRET_KEY leak on error page. `ALLOWED_HOSTS=[]` rejects all requests in prod — common deploy mistake. CSRF middleware is on by default — disabling it opens cookie-session CSRF.
- **DRF**: `DEFAULT_PERMISSION_CLASSES = [AllowAny]` default — must be tightened. `get_queryset()` must scope to the authenticated user; default `.all()` is a BOLA wellspring.
- **Flask**: no auth, no rate limit, no validation, no CSRF. `debug=True` enables the Werkzeug PIN + RCE on error pages.
- **Starlette / Tornado / Sanic**: each has its own middleware idiom; auth is always opt-in.

## Do not report

- Admin-only endpoints doing admin things without an escalation path.
- Missing CSRF on a token-auth JSON API that does not use cookies.
- `DEBUG = True` in a development-only settings module not referenced by prod.
- Type hints being loose (`Any`, `dict`) — type system is not security.
- CVEs in transitively-dead dependencies.

## Output

Return structured blocks only — no preamble, no narration.

FINDINGs have concrete, unguarded, exploitable attack paths. LEADs have real code smells with partial paths — default to LEAD over dropping.

**Every FINDING must have a `proof:` field** — concrete values, traced request, or state sequence from the actual code. No proof = LEAD, no exceptions.

**One vulnerability per item.** Same root cause = one item. Different fixes needed = separate items.

```
FINDING | file: path/file.py | function: name-or-METHOD-path | bug_class: kebab-tag | group_key: file | function-or-route | bug-class
path: request → dependency chain → handler → state change → response
proof: concrete request + expected response demonstrating the bug
description: one sentence
fix: one-sentence suggestion

LEAD | file: path/file.py | function: name-or-METHOD-path | bug_class: kebab-tag | group_key: file | function-or-route | bug-class
code_smells: what you found
description: one sentence explaining trail and what remains unverified
```

The `group_key` enables deduplication: `file | route-or-function | bug_class`. Agents may add custom fields.

## .audit-ignore suppression

Before finalizing findings, the orchestrator reads `.audit-ignore` at repo root if present (or the path passed via `--audit-ignore`).

**Format** — one rule per line:

```
# Comments start with #
app/legacy.py | GET /healthz | info-disclosure            # known, JIRA-1234
app/llm/* | * | llm-budget                                # whole glob
* | * | x-powered-by                                       # suppress everywhere

# Bug-class-level suppression
bug-class: missing-security-headers                       # suppress every finding with this bug_class
```

**Matching rules:**

- Exact match on `group_key` fields, OR glob (`*` matches any single field, path-globs like `app/**/*.py` work for the file component).
- A matched finding is **dropped from the report body** and listed in the "Suppressed findings" table for transparency.
- Suppression never silences a CRITICAL finding. Critical findings always appear, with a warning next to them that a suppression rule was ignored.

## `--since <git-ref>` diff mode

When `--since` is set, filter findings after Phase 4 dedup:

1. `git log --name-only --pretty=format: <ref>..HEAD` to get changed files.
2. For each changed file, `git diff --unified=0 <ref>..HEAD -- <file>` and extract `@@ -A,B +C,D @@` hunks.
3. Keep a finding iff its `location.line` falls within any hunk range for its `location.file`.
4. Findings without a known line (e.g., app-level config) stay if their file was changed at all.

Print the diff-mode banner in the report Scope section: `**Diff mode**: since <ref> (<N> changed files, <M> changed hunks)`.
