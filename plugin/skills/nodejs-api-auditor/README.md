# Node.js API Auditor

A security agent that audits Node.js backend APIs. Findings in minutes, not weeks.

Built for:

- **Node devs** who want a security check before every commit
- **Security researchers** looking for fast wins before a manual review
- **Anyone** shipping an Express / NestJS / Fastify / Koa / Next.js API

Not a substitute for a formal audit — but the check you should never skip.

## How it works

1. Detects the framework from `package.json`.
2. Bundles in-scope source with 8 per-agent rule sheets.
3. Spawns 8 specialized agents in parallel:
   - `authz` — BOLA, BFLA, BOPLA, tenant isolation
   - `authn` — JWT, OAuth, session, MFA
   - `injection` — SQL, NoSQL, command, SSTI, XXE, path traversal, prototype pollution
   - `deserialization-and-ssrf` — node-serialize, yaml, SSRF, cloud metadata
   - `crypto-and-secrets` — weak hashing, HMAC, randomness, secret leakage
   - `resource-and-business-logic` — rate limiting, DoS, races, abuse
   - `config-and-supply-chain` — CORS, middleware order, deps, postinstall
   - `llm-and-integration` — prompt injection, webhook verification, GraphQL
4. Deduplicates, gate-evaluates through the 4-gate judging framework (Refutation → Reachability → Trigger → Impact), produces a confidence-ranked report.

## Usage

```
audit this api
review api security on src/routes/orders.ts
```

Or with `--file-output` to write the report to `assets/findings/`:

```
audit this api with --file-output
```

## Tips

- **Scope tight.** 1–3 files > whole-repo scan. Denser context per agent.
- **Run twice.** Non-determinism means a second pass often surfaces what the first missed.
- **Run `api-recon` first** on unfamiliar repos.

## Evals

```bash
cd nodejs-api-auditor
# follow evals/runner.md — runs against OWASP Juice Shop, NodeGoat, DVNA
```
