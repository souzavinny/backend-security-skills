# Python API Auditor

A security agent that audits Python backend APIs. Findings in minutes, not weeks.

Built for:

- **Python devs** who want a security check before every commit
- **Security researchers** looking for fast wins before a manual review
- **Anyone** shipping a FastAPI / Django / Flask / Starlette API

Not a substitute for a formal audit — but the check you should never skip.

## How it works

1. Detects the framework from `pyproject.toml` / `requirements.txt` / `setup.py`.
2. Bundles in-scope source with 8 per-agent rule sheets.
3. Spawns 8 specialized agents in parallel:
   - `authz` — BOLA, BFLA, BOPLA, tenant isolation, DRF `get_queryset`
   - `authn` — PyJWT, OAuth, session, Django auth, MFA
   - `injection` — SQL (raw / ORM), NoSQL, command, SSTI (Jinja2), XXE, tar/zip slip, path traversal
   - `deserialization-and-ssrf` — pickle, yaml, SSRF, cloud metadata
   - `crypto-and-secrets` — weak hashing, HMAC, randomness, Django SECRET_KEY
   - `resource-and-business-logic` — rate limiting, DoS, races, abuse
   - `config-and-supply-chain` — DEBUG, ALLOWED_HOSTS, CORS, deps, Docker
   - `llm-and-integration` — prompt injection, webhook verify, GraphQL (strawberry/graphene)
4. Deduplicates, gate-evaluates through the 4-gate judging framework, produces a confidence-ranked report.

## Usage

```
audit this api
review api security on app/routes/orders.py
```

Or with `--file-output` to write the report to `assets/findings/`:

```
audit this api with --file-output
```

## Tips

- **Scope tight.** 1–3 files > whole-repo scan.
- **Run twice.** Non-determinism.
- **Run `api-recon` first** on unfamiliar repos.

## Evals

```bash
cd python-api-auditor
# follow evals/runner.md — runs against OWASP VAmPI, django.nV, DSVW
```
