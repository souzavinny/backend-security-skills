# Backend API Security Skills

AI-powered security skills for **Node.js and Python backend APIs**. Targeted to
REST / GraphQL / webhook APIs.

## Skills

| Skill | Mode | What it does |
|---|---|---|
| [`api-recon`](plugin/skills/api-recon/) | static | Pre-audit reconnaissance — route graph, auth matrix, invariants, architecture map. Language-agnostic. Run this first on unfamiliar repos. |
| [`nodejs-api-auditor`](plugin/skills/nodejs-api-auditor/) | static | Audits Node.js APIs (Express, NestJS, Fastify, Koa). 8 parallel agents, confidence-ranked findings. |
| [`python-api-auditor`](plugin/skills/python-api-auditor/) | static | Audits Python APIs (FastAPI, Django, Flask, Starlette). Same agent roster, Python grep patterns. |
| [`runtime-audit`](plugin/skills/runtime-audit/) | **dynamic** | Fires real HTTP probes at a running API. Verifies static findings with curl-equivalent reproductions. Safety-gated by target tier. |

**Static vs dynamic.** The auditors read source code and reason about it — good for breadth, sometimes issues false positives. `runtime-audit` sends real requests to a running target — good for proof, bounded by the endpoints and credentials you give it. Use them together: static finds the surface, dynamic confirms the exploits.

Each static auditor runs 8 focused agents in parallel: `authz`, `authn`, `injection`,
`deserialization-and-ssrf`, `crypto-and-secrets`,
`resource-and-business-logic`, `config-and-supply-chain`,
`llm-and-integration`. `runtime-audit` mirrors the same 8 personas as HTTP probe agents.

## Install

**From the marketplace** (inside any Claude Code session):

```
/plugin marketplace add souzavinny/backend-security-skills
/plugin install backend-security-skills
/reload-plugins
```

Once installed, invoke from within a target repo:

```
audit this api
review api security on src/routes/orders.ts
run api-recon on this codebase
run runtime audit              # zero-config; autodetects or prompts
```

**Developer / local install** (pin to your checkout):

```
claude --plugin-dir /path/to/backend-security-skills/plugin "audit this api"
claude --plugin-dir /path/to/backend-security-skills/plugin "run api-recon on this codebase"
```

For repeated runs on the same repo, drop a [`runtime-audit.yaml`](plugin/skills/runtime-audit/runtime-audit.example.yaml) and skip the prompts entirely.

## Output

Each auditor writes a confidence-ranked report to:

```
assets/findings/{project}-api-audit-report-{YYYYMMDD-HHMMSS}.md
```

Sorted **by severity first** (Critical → High → Medium → Low → Info), then confidence. Findings at or above the confidence threshold (default 75) include a diff-style fix; below-threshold findings get description only. Leads (partial exploit paths) are listed unscored for manual follow-up.

### Integration flags

Every skill supports:

- `--format json` — machine-readable output (same findings, JSON schema). For Jira / Linear / Slack / CI integrations.
- `--severity-threshold <critical|high|medium|low|info>` — omit lower-severity findings from the report body.
- `--exit-code-on <severity>` — non-zero exit if any finding at or above the threshold. Makes CI gating trivial: `run runtime audit --exit-code-on high` fails the pipeline on any new High or Critical.

Static auditors also support:

- `--since <git-ref>` — diff mode. Filter findings to only those in code changed vs `<ref>`. Ideal for PR review: `audit this api --since main`.
- `--audit-ignore <path>` — suppress findings by `group_key` match (default: `.audit-ignore` at repo root).

`runtime-audit` also supports:

- `--non-interactive` — fail fast in CI if the 3-way fork would be reached (prints the required flags).

`api-recon` writes to `api-recon/` at the project root:

- `architecture.json` — route graph, auth matrix, trust boundaries
- `recon.md` — executive summary, threat model, verdict
- `entry-points.md` — full route catalog with auth, params, downstream calls
- `invariants.md` — tenant isolation, ownership, rate-limit, idempotency invariants
- `architecture.svg` — rendered route/service dependency graph

`runtime-audit` writes to `assets/findings/` + `assets/transcripts/`:

- `{target-host}-runtime-audit-{ts}.md` — findings ranked `CONFIRMED` / `LIKELY` / `LEAD` with curl-equivalent reproductions
- `assets/transcripts/{ts}/NNN-*.http` — full HTTP request/response transcripts per probe

## Tips

- **Scope tight.** Point the auditor at the 1–3 files you changed, not the whole
  repo. Smaller scope = denser context per agent = higher-signal findings.
- **Run twice.** LLM output is non-deterministic — a second pass often catches
  things the first missed.
- **Typical pipeline:** `api-recon` → static auditor → `runtime-audit` with `--from-report` to
  verify the static findings live. This stacks breadth (static) with proof (dynamic).
- **Never point `runtime-audit` at production without explicit authorization.** The skill
  refuses non-local targets without `--tier staging`/`--tier prod` flags — respect that.

## Evals

Each skill ships benchmark ground-truth for public vulnerable apps:

- Node (static): OWASP Juice Shop, OWASP NodeGoat, Damn Vulnerable NodeJS App
- Python (static): OWASP VAmPI, django.nV, Damn Small Vulnerable Web
- Runtime: Juice Shop + VAmPI (dockerized, runs live via `docker compose`)

See `{skill}/evals/runner.md` to reproduce.

## License · Contributing

[MIT](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
