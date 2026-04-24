# Startup — Target Resolution, Config Schema, Autostart Recipes

Covers: the `runtime-audit.yaml` schema, framework/port auto-detection, autostart flow with `.env.test` hygiene, and cleanup registration.

---

## `runtime-audit.yaml` — schema

Place at repo root. With this file present, Phase 1 is fully automatic.

```yaml
# ── Target ───────────────────────────────────────────────────────────────
# Required. Where the skill sends probes.
target: http://localhost:3000

# ── Tier ─────────────────────────────────────────────────────────────────
# Optional. Defaults to auto-detect from target hostname.
# local | staging | prod
tier: local

# ── Startup (optional) ───────────────────────────────────────────────────
# If present, the skill will start the server before probing and kill it after.
# Omit this whole block to require an already-running server.
start:
  # Shell command to run. Must start a foreground server that listens on `target`.
  command: pnpm dev

  # Path to env file, relative to repo root. Skill refuses to autostart with
  # the repo's default .env unless --use-real-env is passed.
  env_file: .env.test

  # URL to poll for readiness. When it returns any 2xx/4xx (not 5xx / not timeout),
  # the server is "up". Must match `target` scheme+host+port.
  wait_for: http://localhost:3000/health

  # Seconds to wait for readiness before giving up.
  timeout: 30

  # Optional: working directory for `command`, relative to repo root.
  cwd: .

# ── Authentication (optional) ────────────────────────────────────────────
# Either literal headers, or env-var references, or seed instructions.
auth:
  primary:
    header: X-API-Key
    value_env: TARGET_KEY_A          # preferred — don't commit secrets
    # value_literal: dev-api-key-12345  # fallback — do NOT commit real secrets
  secondary:
    header: X-API-Key
    value_env: TARGET_KEY_B
    # or: seed a test account
    # seed:
    #   method: POST
    #   path: /api/v1/auth/register
    #   body: '{"email":"rt-b@example.invalid","password":"test-pw-xyz"}'
    #   extract: ".token"              # jq path

# ── Probe bands & scope ──────────────────────────────────────────────────
# Opt in to mutating probes. Default false.
destructive: false

# Paths to skip entirely. Supports globs. Useful for endpoints that trigger
# paid external services (LLMs, on-chain writes, SMS).
skip_paths:
  - /api/v1/certify              # costs LLM call + DB + on-chain tx
  - /api/v1/admin/review/*       # finalizes on-chain decisions
  - /api/v1/send-*

# ── Rate limiting (skill's self-throttle) ────────────────────────────────
rate:
  per_second: 1
  burst: 10
```

Every field is optional except `target`. Minimal yaml:

```yaml
target: http://localhost:3000
```

---

## Framework detection

Used when the skill needs to autostart (fork path [1]) or suggest a command (fork path [2]).

### Node.js

1. Read `package.json`.
2. Look at `scripts`:
   - Prefer `dev` → `pnpm dev` / `npm run dev` / `yarn dev` (pick per package manager signal below).
   - Fall back to `start` if no `dev`.
   - If neither: infer from `main` / `type: module` / presence of `tsx`, `ts-node`, `nodemon`.
3. Package manager signal:
   - `pnpm-lock.yaml` → `pnpm`
   - `yarn.lock` → `yarn`
   - `package-lock.json` → `npm`
   - `bun.lockb` → `bun`
4. Port inference:
   - Grep `src/index.ts` / `src/main.ts` / `server.ts` / `app.ts` for `listen(`.
   - Env var `PORT` default.
   - Fallback: 3000.

### Python

1. Read `pyproject.toml` / `requirements.txt` / `setup.py`.
2. Detect framework:
   - `fastapi` / `starlette` present → suggest `uvicorn <module>:app --reload --port 8000`. Module is inferred from `main.py` / `app.py` at repo root or `<pkg>/__init__.py` that imports FastAPI.
   - `django` present → `python manage.py runserver 0.0.0.0:8000`.
   - `flask` present → `flask --app <module> run --port 5000`.
3. Virtualenv detection: if `.venv/` or `venv/` exists, prefix commands with `.venv/bin/` / `venv/bin/`.

### Appendix A — suggested commands table

| Signal | Suggested command | Default port |
|---|---|---|
| `pnpm-lock.yaml` + `scripts.dev` | `pnpm dev` | 3000 |
| `package-lock.json` + `scripts.dev` | `npm run dev` | 3000 |
| `yarn.lock` + `scripts.dev` | `yarn dev` | 3000 |
| FastAPI app (pyproject) | `uvicorn main:app --reload --port 8000` | 8000 |
| Django (manage.py) | `python manage.py runserver 0.0.0.0:8000` | 8000 |
| Flask (`flask` in deps) | `flask --app app run --port 5000` | 5000 |

---

## `.env.test` convention

When the skill autostarts, it loads `.env.test` by default. If the file is absent, the skill refuses to autostart unless `--use-real-env` is passed (with a safety-band downgrade).

### Why

The target's real `.env` typically contains:
- Live DB credentials (Supabase service key, Postgres URI)
- Live external API keys (OpenAI, Stripe, Twilio, SendGrid)
- Hot wallet private keys
- Webhook signing secrets

Probing a server wired to those can trigger real charges, real emails, real on-chain writes. Exactly what runtime-audit is designed to find — but not *also* what it should *cause*.

### What belongs in `.env.test`

Same variable names as `.env`, but values that point to:
- **Local or mock DB**: in-memory SQLite, a Supabase project scoped to `test`, a docker-compose Postgres.
- **Stub external services**: `OPENAI_API_KEY=sk-stub` if your code's error path handles this, OR a local mock on `http://localhost:1080` (see [mockserver](https://www.mock-server.com/)).
- **Testnet wallets with zero balance** (so nothing moves on-chain even if a signed tx is sent).
- **Webhook secrets that are known only to the test runner.**

### What the skill does

When autostarting with `.env.test`:
1. `env -i $(cat .env.test | xargs) PORT=<inferred> <start.command>` — replace env entirely, don't merge with the user's shell environment.
2. Capture stdout/stderr to `{run_dir}/server.log`.
3. Watch the wait_for URL per the yaml; report up/down.

When autostarting with `--use-real-env`:
1. Print the warning from `safety.md`.
2. Downgrade SAFE MODE to bands 1-only unless `--destructive` is also on.
3. Skip any probe that would touch a path flagged as side-effect-heavy (see next section).

### `.env.test.example`

Ship an example in the target repo. The skill can help generate one from `.env`:

```
# First run will detect .env keys and offer: "generate .env.test.example?"
# If accepted: reads .env keys (NOT values), writes .env.test.example with
# placeholder values and a banner comment.
```

---

## Side-effect-heavy paths

Auto-skipped when running with `--use-real-env` and no `--destructive`, unless an explicit `skip_paths` in yaml overrides the defaults.

Heuristics (any match → skipped probe):
- Method is `POST`/`PUT`/`PATCH`/`DELETE` AND path contains any of:
  - `/certify`, `/pay`, `/charge`, `/invoice`
  - `/send`, `/notify`, `/email`, `/sms`
  - `/webhook` (outbound-triggering)
  - `/mint`, `/burn`, `/transfer`, `/approve`, `/execute` (chain-adjacent)
  - `/admin/` + any mutating verb
- Routes that the loaded static report flagged as having external calls (e.g., "calls NEROChainService.certifyMarket" — skip POSTs to that route).

Each skipped probe appears in the report as `SKIPPED (safe mode)` with an explanation and the override flag the user could pass.

---

## Autostart recipe (used by Phase 1 path [1])

```bash
# 1. Detect framework + resolve command + port (see Appendix A)
CMD="<detected>"
PORT="<detected>"

# 2. Resolve env
if [ -f .env.test ]; then
  ENV_FILE=.env.test
  MODE=safe
elif [ -f .env ] && [ "$USE_REAL_ENV" = "1" ]; then
  ENV_FILE=.env
  MODE=real
else
  echo "No .env.test. Re-run with --use-real-env to accept the risk, or create .env.test."
  exit 1
fi

# 3. Start in background, capture pid + logs
set -a; source "$ENV_FILE"; set +a
PORT=$PORT $CMD > "{run_dir}/server.log" 2>&1 &
PID=$!
echo $PID > "{run_dir}/server.pid"

# 4. Wait for readiness
for i in $(seq 1 "$TIMEOUT"); do
  if curl -sS -o /dev/null --max-time 1 "$WAIT_FOR"; then
    break
  fi
  sleep 1
done

# 5. If not up: print last 20 lines of server.log, kill pid, abort.
```

Teardown (end of Phase 3 or on any abort):

```bash
PID=$(cat "{run_dir}/server.pid")
kill -TERM "$PID" 2>/dev/null
sleep 2
kill -KILL "$PID" 2>/dev/null || true
```

---

## Troubleshooting prompts (fork path [2])

After printing the detected command and waiting for the user to start it, if re-probe fails, print:

```
Still no server on :{port}. Common causes:
  - Wrong port — check your start logs. Re-run with
      runtime audit http://localhost:<your-port>
  - Server crashed on startup — check its stdout for missing env vars
  - Firewall / corporate VPN blocking localhost — try 127.0.0.1:<port>

Reply with 'retry' to re-probe, or Ctrl-C to cancel.
```
