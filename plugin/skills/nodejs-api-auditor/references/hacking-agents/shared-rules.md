# Shared Scan Rules

## Reading

Your bundle has two sections:

1. **Core source** (inline) — read in parallel chunks (offset + limit), compute offsets from the line count in your prompt. `package.json` is included — read it too; outdated or high-CVE deps matter.
2. **Peripheral file manifest** — file paths under `# Peripheral Files (read on demand)`. Read only those relevant to your specialty.

When matching handlers, check both the route handler body AND any middleware chain applied to it (`app.use`, `router.use`, per-route `middleware` arg, NestJS decorators `@UseGuards` / `@UseInterceptors` / `@UsePipes`, Fastify `preHandler`, Hapi `pre`).

## Middleware resolution (Node.js)

Before claiming a route is missing auth/validation/rate-limit, trace **the full middleware stack** that applies:

1. `app.use(middleware)` — applies to every route registered after this line.
2. `router.use(middleware)` — applies to every route on that router.
3. `app.use('/api', router)` — the mount path prefixes every route in `router`.
4. `router.get(path, mw1, mw2, handler)` — per-route middleware.
5. NestJS: `@Controller` class decorators + `@UseGuards` at method level override class-level; `APP_GUARD` provider applies globally.
6. Fastify: `preHandler` at app, plugin, or route scope — most-specific wins; they compose.

Never claim "no auth on route X" if auth is applied via an `app.use` / `router.use` higher in the file or via a global guard provider.

## Cross-route patterns

When you find a bug in one route, **weaponize that pattern across every other route in the bundle.** Search by route path AND by code pattern. Finding BOLA in `GET /orders/:id` means you check every other `/:id` endpoint — missing a repeat instance is an audit failure.

After scanning: escalate every finding to its worst exploitable variant (DoS may hide data exfiltration; BOLA may hide BFLA). Then revisit every handler where you found something and attack the other branches (error paths, edge cases, 4xx responses that leak data).

## Framework defaults worth remembering

- **Express**: no built-in auth, no built-in validation, no built-in rate limit, no built-in CSRF. Everything is opt-in. `x-powered-by` header is on unless disabled. `req.body` is `undefined` without `express.json()` / `body-parser`.
- **NestJS**: `ValidationPipe` is opt-in unless set as `APP_PIPE` provider. Guards don't apply unless declared. `@Body()` / `@Query()` / `@Param()` do NOT auto-validate without a DTO.
- **Fastify**: schema validation IS enabled by default when a schema is declared on a route — routes without a schema bypass validation. Rate limit is a plugin.
- **Next.js API routes**: no auth, no rate limit, no validation by default. `req.body` is pre-parsed JSON without size cap unless `bodyParser` config restricts it.

## Do not report

- Admin-only routes doing admin things without an escalation path.
- `x-powered-by` header alone (noise unless paired with a real finding).
- Missing `helmet()` if equivalent headers are set manually.
- Self-harm bugs (user modifies their own account).
- CVEs in dependencies that are transitively dead code.

## Output

Return structured blocks only — no preamble, no narration.

FINDINGs have concrete, unguarded, exploitable attack paths. LEADs have real code smells with partial paths — default to LEAD over dropping.

**Every FINDING must have a `proof:` field** — concrete values, a traced request, or state sequence from the actual code. No proof = LEAD, no exceptions.

**One vulnerability per item.** Same root cause = one item. Different fixes needed = separate items.

```
FINDING | file: path/file.ts | function: name-or-METHOD-path | bug_class: kebab-tag | group_key: file | function-or-route | bug-class
path: request → middleware chain → handler → state change → response
proof: concrete request + expected response demonstrating the bug
description: one sentence
fix: one-sentence suggestion

LEAD | file: path/file.ts | function: name-or-METHOD-path | bug_class: kebab-tag | group_key: file | function-or-route | bug-class
code_smells: what you found
description: one sentence explaining trail and what remains unverified
```

The `group_key` enables deduplication: `file | route-or-function | bug_class`. Agents may add custom fields.

## .audit-ignore suppression

Before finalizing findings, the orchestrator reads `.audit-ignore` at repo root if present (or the path passed via `--audit-ignore`).

**Format** — one rule per line:

```
# Comments start with #
src/routes/legacy.ts | GET /healthz | info-disclosure    # known, JIRA-1234
src/infrastructure/llm/* | * | llm-budget                # whole glob
* | * | x-powered-by                                      # suppress everywhere

# Bug-class-level suppression
bug-class: missing-security-headers                      # suppress every finding with this bug_class
```

**Matching rules:**

- Exact match on `group_key` fields, OR glob (`*` matches any single field, path-globs like `src/**/*.ts` work for the file component).
- A matched finding is **dropped from the report body** and listed in the "Suppressed findings" table for transparency — the user sees what was hidden.
- Suppression never silences a CRITICAL finding. Critical findings always appear, with a warning next to them that a suppression rule was ignored.

## `--since <git-ref>` diff mode

When `--since` is set, filter findings after Phase 4 dedup:

1. Run `git log --name-only --pretty=format: <ref>..HEAD` to get changed files.
2. For each changed file, run `git diff --unified=0 <ref>..HEAD -- <file>` and extract the `@@ -A,B +C,D @@` hunks. Build `{file: [(start, end), ...]}`.
3. Keep a finding iff its `location.line` falls within any hunk range for its `location.file`.
4. Findings without a known line (e.g., app-level config) stay if their file was changed at all.

Print the diff-mode banner in the report Scope section: `**Diff mode**: since <ref> (<N> changed files, <M> changed hunks)`.
