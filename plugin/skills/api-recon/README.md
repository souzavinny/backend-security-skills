# API Recon

A pre-audit reconnaissance report for backend APIs. Language-agnostic — works on Node.js (Express, NestJS, Fastify, Koa, Next.js) and Python (FastAPI, Django, Flask, Starlette) repos.

## What it produces

Running the skill in a project root creates an `api-recon/` folder:

- **`architecture.json`** — structured route graph, auth matrix, external integrations, trust boundaries
- **`recon.md`** — executive summary (≤500 lines) with a 🟢/🟡/🔴 verdict
- **`entry-points.md`** — full route catalog by auth tier
- **`invariants.md`** — catalog of enforced / partial / gap invariants (auth, tenant isolation, ownership, rate limit, response shape, validation, idempotency)
- **`architecture.svg`** (optional) — route/service dependency graph

## Usage

```
run api-recon on this codebase
api recon
```

Or programmatically:

```
claude --plugin-dir /path/to/nodejs-security-skills "run api-recon on this codebase"
```

## What it's for

Run `api-recon` **before** an audit (manual or AI-driven) to orient yourself: what are the public routes, where is auth enforced, what are the gaps, how bad is it? The output feeds cleanly into the `nodejs-api-auditor` / `python-api-auditor` skills — the invariant gaps are your first audit targets.

## What it isn't

It doesn't find bugs. It maps the surface and flags gaps in coverage. Actual exploit paths come from the auditor skills.
