---
name: nodejs-api-auditor
description: Security audit of Node.js backend APIs while you develop. Trigger on "api audit", "audit this api", "review api security", "check this endpoint". Modes - default (full repo) or a specific filename.
---

# Node.js API Security Audit

You are the orchestrator of a parallelized Node.js backend API security audit.

## Mode Selection

**Exclude pattern:** skip directories `node_modules/`, `dist/`, `build/`, `coverage/`, `test/`, `tests/`, `__tests__/`, `__mocks__/`, `.next/`, `.nuxt/` and files matching `*.test.*`, `*.spec.*`, `*Mock*.*`, `*.d.ts`.

- **Default** (no arguments): scan all `.ts`, `.tsx`, `.js`, `.mjs`, `.cjs` files using the exclude pattern. Use Bash `find` (not Glob).
- **`$filename ...`**: scan the specified file(s) only.

**Framework detection.** Read `package.json` to classify the app. Record the primary framework (Express, Fastify, NestJS, Koa, Hapi, Next.js API routes) — it determines which framework-specific rules each agent applies.

**Flags:**

- `--file-output` (off by default) — also write the report to a markdown file per `{resolved_path}/report-formatting.md`. Never write unless explicitly passed.
- `--format <markdown|json>` (default `markdown`) — output format. Both contain the same findings; JSON is for CI / tooling integration.
- `--severity-threshold <critical|high|medium|low|info>` (default `info`) — omit findings below this severity from the report body. Still listed in the summary counts.
- `--exit-code-on <critical|high|medium|low>` (default off) — return non-zero exit code if any finding's severity is at or above this. For CI gating.
- `--since <git-ref>` (default off) — diff mode. After assembling findings, filter to only those whose `(file, line)` was modified vs `<ref>`. Uses `git log --name-only <ref>..HEAD` and `git diff --unified=0 <ref>..HEAD -- <file>` to compute line ranges.
- `--audit-ignore <path>` (default `.audit-ignore` at repo root, if it exists) — see `references/hacking-agents/shared-rules.md` for the file format. Suppresses findings by `group_key` match.

## Orchestration

**Turn 1 — Discover.** Print the banner, then make these parallel tool calls in one message:

a. Bash `find` for in-scope source files per mode selection.
b. **Resolve `SKILL_DIR`** (the path where this skill's `references/` directory lives). Do NOT rely on `Glob` — it is cwd-scoped and the skill is usually mounted outside cwd (e.g. `/tmp/<plugin-dir>/skills/nodejs-api-auditor/`). Use Bash with multiple fallbacks:

```bash
# Try, in order: find SKILL.md for *this* skill across likely mount points.
SKILL_DIR=""
for root in "$CLAUDE_PLUGIN_ROOT" "$HOME/.claude" "/tmp" "$(pwd)"; do
  [ -z "$root" ] && continue
  [ -d "$root" ] || continue
  found=$(find -L "$root" -maxdepth 8 -type f -path '*/nodejs-api-auditor/SKILL.md' 2>/dev/null | head -1)
  if [ -n "$found" ]; then
    SKILL_DIR="$(dirname "$found")"
    break
  fi
done
if [ -z "$SKILL_DIR" ] || [ ! -d "$SKILL_DIR/references" ]; then
  echo "⚠️  Could not resolve SKILL_DIR. Falling back to inline-rules mode (see Turn 3)."
  SKILL_DIR=""
fi
echo "SKILL_DIR=$SKILL_DIR"
```

c. ToolSearch `select:Agent` (required for spawning sub-agents in Turn 3).
d. Read `package.json` at the target repo root (framework detection).
e. Bash `mktemp -d /tmp/api-audit-XXXXXX` → store as `{bundle_dir}`.
f. (No cross-turn timestamp. Turn 4 computes its own `TS` + `RAND` inline — shell state does not persist across Bash tool calls.)

**Turn 2 — Prepare.** Two branches:

**Branch A — `SKILL_DIR` resolved** (preferred). In one message, parallel:
- `Read $SKILL_DIR/references/report-formatting.md`
- `Read $SKILL_DIR/references/judging.md`
- `Read $SKILL_DIR/references/hacking-agents/shared-rules.md`
- `Read $SKILL_DIR/references/attack-vectors/attack-vectors.md`
- If `.audit-ignore` exists at repo root, `Read .audit-ignore`.

Then build `{bundle_dir}/source.md` in a single Bash command using `cat` + in-scope source files + `package.json`. Print line counts.

For each of the 8 agent rule files under `$SKILL_DIR/references/hacking-agents/`, Bash `cp "$SKILL_DIR/references/hacking-agents/{agent}.md" "{bundle_dir}/{agent}.md"`. The bundle_dir copy gives sub-agents a cwd-adjacent path that Read will always resolve.

**Branch B — `SKILL_DIR` unresolved**. Skip file staging. In Turn 3, inline the persona summary (see Appendix A of this SKILL.md) in each Agent prompt directly. Sub-agents operate on just the source files + the inline summary. This is a reduced-coverage fallback; note it in the final report's Scope section as "sub-agents ran with inline rules (SKILL_DIR unresolved)".

**Turn 3 — Spawn.** In one message, spawn all 8 agents as parallel foreground Agent calls.

Prompt template (substitute real values per agent):

```
You are the {agent-name} agent for a Node.js backend API audit.

== Your rules ==
[Branch A] Read `{bundle_dir}/{agent-name}.md` AND `{bundle_dir}/shared-rules.md`. These contain your persona's attack-plan, vulnerable-pattern catalog, safe patterns, and output-field spec.
[Branch B] Your persona summary is inlined below. Your output format is specified below.

{if Branch B — paste the matching Appendix A summary here}

== Your targets ==
Read these source files in parallel before producing findings:
{list all in-scope source file paths — one per line}

Also Read `{repo_root}/package.json` for dependency + framework context.
Target framework: {framework} (from package.json detection).

== Required output fields ==
For every FINDING, include ALL of these fields (even if blank "—"):
  severity: critical | high | medium | low | info   (per judging.md rubric)
  confidence: integer 0-100
  bug_class: kebab-tag (e.g., `bola`, `sqli`, `jwt-alg-confusion`)
  group_key: "{file} | {function-or-route} | {bug_class}"   (mandatory — drives dedup)
  proof: concrete code citation or trace (no proof → demote to LEAD)
  description: one short sentence
  fix: one-sentence suggestion (required only if confidence ≥ 80)
  cwe: "CWE-N" when applicable; omit if none
  owasp_api_top10: "APIN:YYYY" (e.g., "API1:2023"); omit if none
  file:line: cite the file and starting line number for location

For every LEAD, include: bug_class, group_key, code_smells, description, file:line.

Do NOT include severity or confidence on LEADs.

Return findings + leads as structured blocks. One vulnerability per block. Multiple vulnerabilities in the same file are separate blocks.
```

**Turn 4 — Deduplicate, validate & output.** Single-pass.

1. **Deduplicate.** Parse every FINDING and LEAD from all 8 agents. Group by `group_key`. Exact-match first; then merge synonymous `bug_class` tags sharing the same file and function. Keep the best version per group, number sequentially, annotate `[agents: N]`.

   Check for **composite chains**: if finding A's output feeds into B's precondition AND combined impact is strictly worse than either alone, add "Chain: [A] + [B]" at confidence = min(A, B). Common API chains: missing-auth + BOLA → full tenant takeover; SSRF + weak-egress → cloud-metadata theft; prototype-pollution + eval → RCE.

2. **Gate evaluation.** Run each deduplicated finding through the four gates in `judging.md`. Do not skip or reorder. Evaluate each finding exactly once.

   **Single-pass protocol:** evaluate every relevant code path ONCE in fixed order (auth middleware → input parsing → handler body → persistence → response). One-line verdict per path: `BLOCKS`, `ALLOWS`, `IRRELEVANT`, or `UNCERTAIN`. Commit after all paths. `UNCERTAIN` = `ALLOWS`.

3. **Apply `.audit-ignore`** (if loaded in Turn 2): drop matching findings from the report body, retain them in the "Suppressed findings" section. Never suppress Critical severity.

4. **Apply `--since <ref>`** (if set): filter findings to those whose `file:line` falls within the changed hunks (see `shared-rules.md § --since <git-ref> diff mode`).

5. **Lead promotion & rejection guardrails.**
   - Promote LEAD → FINDING (confidence 75) if complete exploit chain traced in source, OR `[agents: 2+]` demoted (not rejected) the same issue.
   - `[agents: 2+]` does NOT override a concrete refutation — demote to LEAD if refutation is uncertain.
   - No "assumed deployer intent" reasoning — evaluate what the code _allows_.
   - Missing middleware on a router is a real finding when there is no equivalent per-route guard. Don't dismiss with "probably handled elsewhere".

6. **Fix verification** (confidence ≥ 80 only): trace the attack with fix applied; verify no new regression; list all locations if the pattern repeats.

7. **Compute the output filename — MANDATORY and SELF-CONTAINED.**

Run EXACTLY this Bash block. It computes the full filename from scratch — do NOT rely on any variable set in an earlier Turn (shell state does not persist across Bash tool calls):

```bash
PROJECT=$(basename "$(pwd)")
TS=$(date +%Y%m%d-%H%M%S)
RAND=$(openssl rand -hex 2 2>/dev/null || printf '%04x' $RANDOM)
OUT_DIR="assets/findings"
mkdir -p "$OUT_DIR"
# For --format markdown (default):
OUT_PATH="$OUT_DIR/${PROJECT}-api-audit-report-${TS}-${RAND}.md"
# For --format json: swap .md for .json
echo "OUT_PATH=$OUT_PATH"
```

Capture the echoed `OUT_PATH` value LITERALLY. Pass that exact string as the `file_path` argument to the Write tool in step 8.

**Rules (non-negotiable):**
- The filename MUST contain the full `${TS}-${RAND}` suffix. `${TS}` is the 15-char `YYYYMMDD-HHMMSS` date; `${RAND}` is 4 hex chars.
- The filename MUST NOT be simplified to `security-audit-report.md`, `audit.md`, `{project}-api-audit-report-{date}-audit.md`, or any other shorter form. Downstream tools (runtime-audit `--from-report`, CI diff) glob on this exact pattern.
- Compute once in this step. Do not recompute between step 7 and step 8 — the timestamp would drift.
- If `openssl` is unavailable, the `printf '%04x' $RANDOM` fallback handles it. Do not fall back to a hand-picked suffix.

**Sanity check before moving on:** verify the computed OUT_PATH matches the regex `^assets/findings/[^/]+-api-audit-report-[0-9]{8}-[0-9]{6}-[0-9a-f]{4}\.(md|json)$`. If it doesn't, stop and recompute — a malformed filename breaks the downstream pipeline.

8. **Write the report** to `$OUT_PATH` per `report-formatting.md`. Follow the markdown OR JSON template per `--format`. The Scope section MUST include:
   - Mode, Framework, Files reviewed
   - `SKILL_DIR resolved: yes | no (fallback inline-rules mode)`
   - `Confidence threshold`, `Severity threshold`, `Diff mode`
   - Summary table of findings by severity

9. **Print a terse terminal confirmation** of the form: `Report written to <OUT_PATH>. {N} findings: {A} Critical, {B} High, {C} Medium, {D} Low, {E} Info.`

10. **Apply exit-code gating.** If `--exit-code-on <severity>` was passed and any finding at or above that severity exists: exit non-zero.

## Appendix A — Compact agent summaries (Branch B fallback)

When `SKILL_DIR` is unresolved (Turn 2 Branch B), inline the matching summary below into each Agent prompt. These are condensed versions of `references/hacking-agents/*.md` sufficient for the agent to operate. Recall is reduced vs the full rule sheets, but the skill still produces useful output.

### authz-agent
Focus: BOLA / BFLA / BOPLA / tenant isolation. Find every route with a user-supplied ID, every mutating endpoint without a role/tier gate, every DB query that lacks a tenant predicate.
Patterns: `findUnique/findById/.get(id)` without `where: { id, userId/tenantId }`; raw SQL `WHERE id = $1` missing tenant predicate; `req.body.userId/platformId/tenantId` trusted into server state; DRF `queryset = Model.objects.all()`; `/admin/*` routes mounted under the same auth gate as user routes; `Object.assign(doc, req.body)` mass assignment; `res.json(user)` returning `passwordHash`/`mfaSecret`.
Safe: server-derived scope fields, explicit DTOs, `requireAdmin`/`RolesGuard` on admin routers, whitelisted pydantic/zod schemas.

### authn-agent
Focus: JWT forgery, session hijack, password + MFA flows. Verify `algorithms` whitelist, audience/issuer, expiry, timing-safe compare, session regeneration on login, reset-token single-use.
Patterns: `jwt.verify(token, key)` (2-arg — no algorithms), `algorithms: ['none']`, `ignoreExpiration: true`, `crypto.createHash('md5'|'sha1')` near password vars, `Math.random()` / `Date.now()` token generation, `cookie: {}` without httpOnly/secure/sameSite, `session()` with `session.regenerate` absent after login, `req.body.isAdmin`/`role`/`mfa_passed` trusted.
Safe: `jwt.verify(token, key, { algorithms: ['RS256'], audience, issuer })`, `bcrypt.compare`, `crypto.timingSafeEqual`, `req.session.regenerate()` on auth success, PKCE + state on OAuth.

### injection-agent
Focus: SQL / NoSQL / command / SSTI / XXE / path traversal / prototype pollution / header injection / ReDoS.
Patterns: template-literal SQL with `${req.*}`, `knex.raw`/`$queryRawUnsafe`/`Sequelize.literal` with interpolation; `{$where:...}` / `{$ne: null}` reachable from body; `child_process.exec(`string`)` or `spawn(cmd, { shell: true })`; `Handlebars.compile(req.body.*)`, `render_template_string(user_input)`; `libxmljs.parseXml(x, { noent: true })`; `path.join(ROOT, req.*)`; `Object.assign({}, req.body)` / lodash pre-4.17.21 `merge`; `new RegExp(req.*)` or catastrophic regex on user input.
Safe: parameterized queries, `execFile(cmd, [args])` argv form, zod+`strict`, pydantic `extra="forbid"`, `defusedxml`, `path.resolve(root, name) + startsWith` check.

### deserialization-and-ssrf-agent
Focus: unsafe parsers + outbound HTTP where caller controls the URL.
Patterns: `node-serialize.unserialize`, `yaml.load(` without SafeLoader (js-yaml<4), `pickle.loads`, `eval(` / `new Function(` / `vm.runInNewContext`; `fetch/axios/got(req.body.url)`, `page.goto(req.body.url)` (headless), user URL → `http://169.254.169.254/latest/meta-data/` (AWS IMDS), `127.0.0.1:6379`, `file:///etc/passwd`; `request()` legacy lib; URL bypasses (`user@host`, decimal IPs, redirect chains).
Safe: deny pickle/node-serialize on untrusted input, `yaml.safeLoad`, SSRF allowlist + resolve-then-connect + block RFC1918/link-local, disable redirect follow.

### crypto-and-secrets-agent
Focus: weak primitives, non-constant-time compare, nonce reuse, secrets in source / logs / responses.
Patterns: `crypto.createHash('md5'/'sha1')` for passwords, `===` on HMAC/hash strings, AES ECB, static IV in GCM, `Math.random()`/`Date.now()` for tokens, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, webhook verify against JSON-reparsed body instead of raw, regex for committed keys (`AKIA[0-9A-Z]{16}`, `-----BEGIN * PRIVATE KEY-----`, `sk_live_[0-9a-zA-Z]{24,}`, `ghp_[0-9a-zA-Z]{36}`).
Safe: `bcrypt/argon2/scrypt`, `crypto.timingSafeEqual`, GCM with random 96-bit nonce, HMAC over raw bytes, `crypto.randomBytes`, secrets manager / env injection.

### resource-and-business-logic-agent
Focus: rate limits, DoS amplifiers, races, idempotency, bulk/scraping abuse.
Patterns: no limiter on `/login`/`/password-reset`/`/verify-phone`/`/signup`; `Number(req.query.limit)` passed to DB without cap; `express.json()` without `limit`; `new RegExp(req.*)`; `bcrypt.hashSync` in handler path; check-then-act balance updates without atomic `WHERE balance >= amount`; POST mutations without Idempotency-Key; GraphQL missing depth/complexity limits or introspection-on-in-prod.
Safe: `express-rate-limit`/`@nestjs/throttler`/Redis-backed limiter with auth+IP key, pagination max, atomic conditional updates, idempotency-key table, GraphQL `depthLimit` + cost analysis.

### config-and-supply-chain-agent
Focus: middleware order, CORS, headers, deps, Docker, CI, shadow APIs.
Patterns: `cors({ origin: true, credentials: true })` OR `*` + credentials; `helmet()` missing or after routes; `app.disable('x-powered-by')` absent; `app.set('trust proxy', true)` blanket; `errorHandler` not last, or leaks `err.message` outside `NODE_ENV==='production'`; `.env` / `/debug` / `/admin` reachable publicly; Swagger UI in prod; unpinned `package.json` ranges, no lockfile, `postinstall` scripts on untrusted deps; typosquats; Docker `:latest` base, root user, `.env` in image layer; `trust proxy: true` × `express-rate-limit` = XFF rotation bypass; Next.js Server Actions missing in-action auth + validation.
Safe: helmet → cors(allowlist) → rate-limit → json(limit) → auth → routes → errorHandler; explicit CORS allowlist; pinned deps + lockfile committed; multi-stage Docker with non-root.

### llm-and-integration-agent
Focus: prompt injection (direct + indirect), LLM-to-tool authz, tool-schema injection, memory poisoning, confused deputy across agents, webhook verify, GraphQL, 3rd-party response trust, object-storage presigned URLs.
Patterns: user free-text → system prompt concat; agent tool dispatched with service creds (not user scope); tool `description` sourced from DB / CMS / user content; persistent memory writable by user and retrieved without provenance; sub-agent runs orchestrator's scope; LLM output piped to `eval`/SQL/shell/innerHTML; unbounded `max_tokens`; user-controlled `model` param; system prompt containing secrets; webhook verify against JSON-reparsed body; long-lived / bucket-wide presigned URLs; WebSocket upgrade without per-connection auth.
Safe: delimited user-content tags (`<user>...</user>`), tool-call re-checks caller ACL, hardcoded tool descriptions, per-user/tenant memory scope with source-of-origin metadata, raw-body HMAC verify, short-TTL object-scoped presigned URLs.

## Banner

Before doing anything else, print this exactly:

```

 █████╗ ██████╗ ██╗    █████╗ ██╗   ██╗██████╗ ██╗████████╗ ██████╗ ██████╗
██╔══██╗██╔══██╗██║   ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝██╔═══██╗██╔══██╗
███████║██████╔╝██║   ███████║██║   ██║██║  ██║██║   ██║   ██║   ██║██████╔╝
██╔══██║██╔═══╝ ██║   ██╔══██║██║   ██║██║  ██║██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║     ██║   ██║  ██║╚██████╔╝██████╔╝██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                            Node.js API Auditor

```
