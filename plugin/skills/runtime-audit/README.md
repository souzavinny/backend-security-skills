# Runtime Audit

Dynamic security testing for running backend APIs. Sends real HTTP requests to a live target and confirms vulnerabilities with reproducible transcripts.

Built for:

- **Verifying findings** from `nodejs-api-auditor` / `python-api-auditor` against a running service
- **Catching runtime-only bugs** static analysis can't see (auth bypass chains, reflected XSS, real SSRF, rate-limit effectiveness)
- **Pre-production smoke** before a deploy goes public

Not a substitute for a manual pen-test or an authorized red team — but the check you should never skip before shipping.

## Quickstart

From a target repo:

```
run runtime audit
```

The skill resolves the target in this order:

1. **Positional URL** — `runtime audit https://staging.example.com`
2. **`runtime-audit.yaml`** at repo root (zero prompts, CI-friendly — see [example](runtime-audit.example.yaml))
3. **Already-running server** on common ports (3000, 5000, 8000, 8080, 4000, 8888)
4. **Interactive fork** if none of the above — picks one of: start-it-for-me, I'll-start-it, I-have-a-URL

That's it. One command, figures out the rest.

## Two ways to configure

### Interactive — zero setup

```
run runtime audit
```

Skill asks once:

```
🔍 No runtime-audit.yaml, no running server, no URL supplied.

  [1] Start the server for me.    (needs .env.test)
  [2] I'll start it — wait for me.
  [3] I have a URL: ______________
```

Pick one, answer any follow-ups, get a report.

### Config file — no prompts, reproducible

Drop `runtime-audit.yaml` in the target repo root:

```yaml
target: http://localhost:3000

start:
  command: pnpm dev
  env_file: .env.test
  wait_for: http://localhost:3000/health
  timeout: 30

auth:
  primary:   { header: X-API-Key, value_env: TARGET_KEY_A }
  secondary: { header: X-API-Key, value_env: TARGET_KEY_B }

skip_paths:
  - /api/v1/certify         # costs LLM + chain tx — skip unless destructive
  - /api/v1/admin/review/*
```

Run `run runtime audit`. No prompts, no guesswork. Good for CI and for the second / third / Nth run on the same repo.

See [`runtime-audit.example.yaml`](runtime-audit.example.yaml) for the annotated schema and [`references/startup.md`](references/startup.md) for the deep version.

## Safety tiers

Applied automatically by hostname:

| Tier | Matched by | Default | Flags needed |
|---|---|---|---|
| `local` | `localhost`, `127.0.0.1`, RFC1918, `*.local` | ✅ | none |
| `staging` | `staging.`, `stage.`, `.dev`, `preview.`, `ngrok.`, `trycloudflare.` | opt-in | `--tier staging` |
| `prod` | anything else | explicit only | `--tier prod --authorized-by "<name>"` + interactive confirm |

Destructive tests (mutations, brute-force, rate-limit breach) are always off by default. Opt in with `--destructive`.

## The `.env.test` gate

When the skill autostarts your server, it looks for `.env.test` first. **No `.env.test`?** the skill refuses to autostart and tells you how to create one — OR re-run with `--use-real-env` to accept the risk (Band 2/3 probes are then disabled unless you also pass `--destructive`).

Rationale: your real `.env` has live DB creds, LLM API keys, hot wallets, etc. Probing a server wired to those can trigger real charges and real external writes. A `.env.test` with scoped / mock / testnet values gives you safety by construction.

See [`references/startup.md`](references/startup.md) for the `.env.test` recipe and what it should look like per framework.

## Output

A markdown report at `assets/findings/{target-host}-runtime-audit-{timestamp}.md` and HTTP transcripts at `assets/transcripts/{timestamp}/`. Each finding links to its transcript for reproduction.

## Useful flags

- `--destructive` — allow mutating probes
- `--tier <local|staging|prod>` — override tier detection
- `--from-report <path>` — verify a static-audit report's findings live (auto-loaded from `assets/findings/*-api-audit-report-*.md` if omitted)
- `--use-real-env` — allow autostart with the real `.env` (band downgrade applies)
- `--no-autostart` — never start a server; require already-running target
- `--rate N` — sustained requests/sec (default 1)
- `--auth "Header: value"` / `--auth-b` — inline auth headers

## What it is not

- Not a fuzzer — curated payloads, not random permutations.
- Not a replacement for `ffuf` / `nuclei` / ZAP — targets logic flaws with context, not protocol compliance.
- Not authorized red-teaming — runs with credentials and authorization **you provide**. Targeting a service you don't control is your legal problem.

## Prerequisites

- `curl` (ships with macOS/Linux)
- `jq` (recommended; skill degrades if missing)
- **Either** an already-running server, **or** the target repo set up to start (with `.env.test` or a `runtime-audit.yaml` that covers the autostart recipe)
