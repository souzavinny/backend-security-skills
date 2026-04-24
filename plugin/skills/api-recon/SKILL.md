---
name: api-recon
description: "Generates an api-recon/ folder containing a pre-audit reconnaissance report for a backend API. Produces route-graph, entry-point catalog, auth matrix, invariants, and an architecture diagram. Language-agnostic (Node.js / Python). Triggers on 'api-recon', 'api recon', 'api reconnaissance', 'api readiness', 'api audit readiness', 'run recon on this api', 'prep this api', 'summarize this api'."
---

# API Recon

Generate an `api-recon/` folder at the project root containing pre-audit reconnaissance artifacts for a backend API. Pipeline: 3 phases, always sequential.

`$SKILL_DIR` = the directory containing this SKILL.md. Resolve it with Bash (the path you loaded this skill from may not be directly accessible):

```bash
SKILL_DIR=""
for root in "$CLAUDE_PLUGIN_ROOT" "$HOME/.claude" "/tmp" "$(pwd)"; do
  [ -z "$root" ] && continue
  [ -d "$root" ] || continue
  found=$(find -L "$root" -maxdepth 8 -type f -path '*/api-recon/SKILL.md' 2>/dev/null | head -1)
  if [ -n "$found" ]; then
    SKILL_DIR="$(dirname "$found")"
    break
  fi
done
[ -z "$SKILL_DIR" ] && echo "⚠️  SKILL_DIR unresolved — some optional steps (SVG) will skip."
```

If `SKILL_DIR` resolves: Read `$SKILL_DIR/references/*.md` and invoke `$SKILL_DIR/scripts/*.py` normally.

If not: skip the optional SVG/scripts paths and proceed with inline fallbacks (the core 3-phase workflow still runs — only enhancement steps are gated on `SKILL_DIR`).

## Progress tracking (MANDATORY)

Before anything else, call TodoWrite with these 3 todos (all `pending`):

1. `Phase 1: Enumerate & measure codebase`
2. `Phase 2: Classify entry points, auth matrix, invariants`
3. `Phase 3: Write api-recon report files`

Transitions (update via TodoWrite — never batch):
- Mark Phase 1 `in_progress` before running enumeration.
- When Phase 1's parallel batch returns, in ONE TodoWrite call mark Phase 1 `completed` and Phase 2 `in_progress`.
- When Phase 2 finishes, in ONE TodoWrite call mark Phase 2 `completed` and Phase 3 `in_progress`.
- After Phase 3's output files are written, mark Phase 3 `completed`.

Rule: exactly one todo is `in_progress` at any time.

## Phase 1 — Enumerate & Measure

If the user specifies a path, use it as project root. Otherwise use cwd.

**Language detection.** In one Bash call:

```bash
PROJECT="${1:-.}"
cd "$PROJECT"
mkdir -p api-recon

# signals
HAS_PKG=$([ -f package.json ] && echo yes || echo no)
HAS_PYPROJECT=$([ -f pyproject.toml ] && echo yes || echo no)
HAS_REQS=$([ -f requirements.txt ] && echo yes || echo no)
HAS_SETUP=$([ -f setup.py ] && echo yes || echo no)
HAS_PIPFILE=$([ -f Pipfile ] && echo yes || echo no)

echo "pkg_json=$HAS_PKG pyproject=$HAS_PYPROJECT requirements=$HAS_REQS setup=$HAS_SETUP pipfile=$HAS_PIPFILE"

# Node.js framework hint
if [ "$HAS_PKG" = "yes" ]; then
  grep -E '"(express|fastify|@nestjs/core|koa|@hapi/hapi|next)"' package.json || true
fi

# Python framework hint
if [ "$HAS_PYPROJECT" = "yes" ] || [ "$HAS_REQS" = "yes" ] || [ "$HAS_SETUP" = "yes" ]; then
  grep -rE '^(fastapi|django|flask|starlette|tornado|aiohttp|sanic)' pyproject.toml requirements.txt setup.py 2>/dev/null || true
fi

# file counts
find . -type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) \
  -not -path './node_modules/*' -not -path './dist/*' -not -path './.next/*' -not -path './build/*' 2>/dev/null | wc -l
find . -type f -name '*.py' \
  -not -path './venv/*' -not -path './.venv/*' -not -path './env/*' -not -path './__pycache__/*' \
  -not -path './.tox/*' 2>/dev/null | wc -l

# test counts
find . -type f \( -name '*.test.*' -o -name '*.spec.*' -o -name 'test_*.py' -o -name '*_test.py' \) \
  -not -path './node_modules/*' -not -path './venv/*' 2>/dev/null | wc -l
```

**Immediately after**, launch the following in a SINGLE message (parallel):

1. **Preload reference files** (2 parallel Read calls — required in context for Phases 2–3):
   - `$SKILL_DIR/references/threats.md`
   - `$SKILL_DIR/references/templates.md`

2. **Spec / doc detection** (1 Glob):
   `**/{openapi,swagger,api-spec,README,ARCHITECTURE,THREAT*}.{yml,yaml,json,md,pdf}` excluding `node_modules/`, `venv/`, `.venv/`, `dist/`, `build/`, `api-recon/`.
   - ≤5 docs, each ≤300 lines: read directly in Phase 2's parallel message.
   - >5 docs OR any doc >300 lines: launch a subagent (`sonnet`) that reads them and returns a structured extraction (actors, trust assumptions, stated invariants, design decisions) in ≤200 lines.

3. **Git metadata** (1 Bash call):
   ```bash
   git rev-parse --short=7 HEAD 2>/dev/null || echo "no-git"
   git log --oneline -20 2>/dev/null || true
   git log --format="%aN" 2>/dev/null | sort -u | wc -l   # contributor count
   ```

## Phase 2 — Entry Points, Auth Matrix, Invariants

ALL tool calls in this phase go in ONE parallel message: source file reads, route-scan greps, and any subagents.

### Route scan (language-specific greps)

Run ALL of these Bash calls in parallel. Only the ones matching your detected framework will produce useful output; that's fine.

```bash
# Express / Fastify / Koa / Hapi route registrations
grep -rnE "(app|router|fastify)\.(get|post|put|patch|delete|options|head|all)\(" \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' --include='*.cjs' \
  . 2>/dev/null | grep -v node_modules | grep -v dist | grep -v .next || true

# NestJS controllers
grep -rnE "@(Controller|Get|Post|Put|Patch|Delete|Options|Head|All)\(" \
  --include='*.ts' . 2>/dev/null | grep -v node_modules | grep -v dist || true

# Next.js app-router routes (file-based)
find . -type f \( -name 'route.ts' -o -name 'route.js' -o -name 'route.tsx' \) \
  -path '*/app/api/*' -not -path './node_modules/*' 2>/dev/null || true

# FastAPI / Starlette
grep -rnE "@(app|router|api)\.(get|post|put|patch|delete|options|head|websocket)\(" \
  --include='*.py' . 2>/dev/null | grep -v venv | grep -v .venv || true

# Flask
grep -rnE "@(app|bp|blueprint)\.(route|get|post|put|patch|delete)\(" \
  --include='*.py' . 2>/dev/null | grep -v venv | grep -v .venv || true

# Django urls.py
grep -rnE "^(\s*)(path|re_path|url)\(" --include='urls.py' . 2>/dev/null | grep -v venv || true
```

### Auth scan (per-language)

```bash
# JS/TS auth guards
grep -rnE "(requireAuth|authGuard|AuthGuard|authenticate|passport\.|preHandler|@UseGuards)" \
  --include='*.ts' --include='*.js' . 2>/dev/null | grep -v node_modules || true

# Python auth gates
grep -rnE "(Depends\(.*get_current_user\)|@login_required|@permission_required|permission_classes|IsAuthenticated|AuthGuard)" \
  --include='*.py' . 2>/dev/null | grep -v venv || true
```

### Source file reads

- ≤20 source files: one Read per file.
- >20 source files: group by subsystem (routes/, controllers/, handlers/, services/), launch one subagent per subsystem (model `sonnet`, up to 5).

### Classification (after greps return)

For EACH route, classify into one of three:

1. **Public** — no auth guard applies (no router-level `dependencies=`, no `@UseGuards`, no `before_request` auth, no `@login_required` decorator, no `permission_classes` other than `AllowAny`).
2. **Auth-required** — an authentication dependency applies but no role check.
3. **Role-gated / Admin-only** — a role or admin permission gate applies (`requireAdmin`, `@permission_required('is_staff')`, `IsAdminUser`, explicit role check in body).

Note: WebSocket / SSE endpoints count as routes.

### Auth matrix

For each route record:
- Method + path
- Handler file:line
- Auth tier (Public / Auth / Admin / Role-X)
- Input sources (path param, query, body, header)
- External effects (DB writes, 3rd-party API calls, email/SMS, file ops)
- Rate-limit middleware applied (yes/no, which)

### Invariant synthesis

Walk the following taxonomy and produce invariant candidates:

1. **Tenant isolation** — For each route that reads/writes a tenant-scoped resource, confirm every query carries a tenant filter. Gaps = BOLA risk.
2. **Ownership** — For each route with a path-param ID, confirm ownership check. Gaps = BOLA risk.
3. **Rate-limit coverage** — For each amplification endpoint (login, reset, signup, any endpoint triggering email/SMS), confirm a limiter applies. Gaps = abuse risk.
4. **Idempotency** — For each state-changing POST, note whether idempotency-key logic exists.
5. **Auth coverage** — All non-Public routes have a documented auth tier. A route without a check at all is a 🚨 invariant violation.
6. **Response-model constraint** — For each route, does it limit the output shape (pydantic `response_model`, explicit DTO, DRF serializer with narrow fields)? Gaps = data-over-exposure risk.
7. **Input validation coverage** — For each body/query parameter, is it validated (zod/joi/pydantic/class-validator/DRF serializer)?

Each invariant row: `ID`, `property`, `applies-to`, `enforced`, `gap (if any)`, `source file:line`.

## Phase 3 — Write Output

All output files go into `api-recon/` at the project root. Write in a SINGLE message so files are created concurrently:

1. **`api-recon/architecture.json`** — route graph + auth matrix. Follow the architecture format in `references/templates.md`.

2. **`api-recon/recon.md`** — executive summary. Under 500 lines. Sections:
   - Overview (framework, LOC, route count, contributors, git scope)
   - Actor / trust model
   - Auth tier distribution (count of Public / Auth / Admin)
   - Key attack surfaces (pulled from invariant gaps — BOLA, BFLA, rate-limit gaps, etc.)
   - Test coverage (test file count, framework)
   - **Verdict** — tiered: 🟢 Ready / 🟡 Needs prep / 🔴 High-risk pre-audit

3. **`api-recon/entry-points.md`** — full route catalog per the entry-points template in `references/templates.md`. Start with flow paths (major user journeys), then per-tier detail.

4. **`api-recon/invariants.md`** — catalog of invariants with On-chain Yes/No-equivalent (here: Enforced / Gap) per the invariant template in `references/templates.md`. Sections: Enforced auth / Enforced tenant isolation / Enforced ownership / Enforced rate limiting / Enforced validation / Response shape / Gaps.

5. **`api-recon/architecture.svg`** — call `scripts/generate_svg.py` if present, otherwise skip. (Scripts are a best-effort rendering — the JSON is authoritative.)

### Architecture SVG (optional)

```bash
if [ -x "$SKILL_DIR/scripts/generate_svg.py" ]; then
  python3 "$SKILL_DIR/scripts/generate_svg.py" api-recon/architecture.json api-recon/architecture.svg || echo "SVG generation skipped"
fi
```

### Terminal verdict

After all files written, read the `## Recon Verdict` section from `api-recon/recon.md` and print it verbatim to the terminal.

## Constraints

- Under 500 lines for `recon.md`.
- No fabrication. If you cannot determine a thing, say so.
- Phases 1–3 fully autonomous. No user interaction.
- Single pass. No partial outputs.
- Never reference specific bug-bounty or audit-contest platforms.

---

Before doing anything else, print this exactly:

```
 █████╗ ██████╗ ██╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║██████╔╝██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║██╔═══╝ ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║██║     ██║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                          API Recon
```
