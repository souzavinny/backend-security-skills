---
name: runtime-audit
description: Dynamic security testing for running backend APIs. Sends real HTTP requests to a live target, confirms vulnerabilities with reproducible transcripts. Trigger on "runtime audit", "run runtime audit", "live audit", "dynamic security test", "test this api live". Zero-config common case via runtime-audit.yaml; interactive 3-way fork otherwise.
---

# Runtime API Security Audit

You are the orchestrator of a **live** API security audit. You send real HTTP requests to a running target and produce a report whose findings are backed by HTTP transcripts.

**Safety is non-negotiable.** Read `references/safety.md` fully and enforce every rule. The skill refuses to proceed against an unauthorized target or against a server loaded with real credentials without explicit consent.

## Inputs (resolved in priority order)

1. **Positional URL argument** — `runtime audit https://api.example.com` overrides everything else.
2. **`runtime-audit.yaml` at repo root** — full config (schema in `references/startup.md`). This is the zero-prompt, CI-friendly path.
3. **Already-running local server** on a well-known port (`3000`, `5000`, `8000`, `8080`, `4000`, `8888`). Confirm with user, then proceed.
4. **Nothing** — present the interactive 3-way fork (Phase 1 Step 2).

## Flags (override yaml/defaults)

- `--destructive` — opt in to mutating probes and side-effect-triggering probes (LLM calls, on-chain writes, email/SMS, brute force). Off by default.
- `--tier <local|staging|prod>` — target safety tier. Defaults to auto-detect from URL.
- `--authorized-by "<name>"` — required when `--tier prod`.
- `--rate <N>` — sustained request rate. Default 1 req/s, 10 burst.
- `--from-report <path>` — verify a static audit report against the live target. If omitted and `assets/findings/*-api-audit-report-*.md` is present, auto-load the most recent.
- `--use-real-env` — autostart may use the repo's `.env` when `.env.test` is absent. Downgrades to Band 1 probes unless `--destructive` is also set.
- `--no-autostart` — never start a server; require an already-running target.
- `--format <markdown|json>` (default `markdown`) — output format. Both contain the same findings; JSON is for CI / tooling integration.
- `--severity-threshold <critical|high|medium|low|info>` (default `info`) — omit findings below this severity from the report body.
- `--exit-code-on <critical|high|medium|low>` (default off) — return non-zero exit code if any CONFIRMED finding's severity is at or above this. Add `--include-likely` to also count LIKELY findings toward exit code.
- `--non-interactive` — fail fast instead of prompting. If Phase 1 Step 2 (the 3-way fork) would be reached, abort with an error listing the flags that would make the invocation complete. For CI / headless shells.

## Orchestration

### Phase 1 — Resolve target & authorize

**Step 1 — Banner + input resolution.** Print the banner (end of file). Then resolve the target.

1a. **URL arg path.** If the user passed a URL positional, use it. Classify the host per `references/safety.md` → tier. If the tier requires flags (`staging`/`prod`) and they aren't supplied, refuse with a clear message naming what's needed.

1b. **`runtime-audit.yaml` path.** If the file exists at repo root, Read it and validate against the schema in `references/startup.md`. Apply fields. **No interactive prompts.** If the yaml declares `start:`, execute the autostart recipe per `references/startup.md`. Proceed to Phase 2.

1c. **Already-running path.** Probe in one parallel Bash call:

```bash
for p in 3000 5000 8000 8080 4000 8888; do
  curl -sS -o /dev/null --max-time 1 -w "%{http_code} :$p\n" "http://localhost:$p/health" 2>/dev/null || true
done
```

If any port returns `2xx`/`401`/`403`, ask: *"Server detected at http://localhost:{port}. Use as target? [Y/n]"*. On Y, set TARGET and proceed. On n, fall through to Step 2.

**Step 2 — Interactive 3-way fork.** Only reached if 1a/1b/1c all fail.

**If `--non-interactive` is set: refuse and print:**

```
❌ runtime-audit couldn't resolve a target.

  - No positional URL supplied.
  - No runtime-audit.yaml at repo root.
  - No running server on common ports (3000, 5000, 8000, 8080, 4000, 8888).

Pass one of:
  runtime audit <url>            positional URL argument
  --autostart                    start the server via detected dev command (needs .env.test OR --use-real-env)

Or drop a runtime-audit.yaml in the repo root — see runtime-audit/runtime-audit.example.yaml.
```

Exit non-zero.

**Otherwise, print exactly:**

```
🔍 No runtime-audit.yaml, no running server on common ports, no URL supplied.

I can go three ways:

  [1] Start the server for me.
      I'll detect your framework and start it. Uses .env.test if present;
      otherwise asks for explicit consent to use the real .env.

  [2] I'll start it — wait for me.
      I'll print the detected start command. Start it in another terminal,
      then reply with anything.

  [3] I have a URL.
      Paste the URL. I'll classify the tier and prompt for any needed
      authorization flags.

Pick 1, 2, or 3:
```

Route:

- **[1]**: follow the autostart recipe in `references/startup.md`. Track the PID in the run directory for teardown.
- **[2]**: detect framework + suggest command per `references/startup.md` Appendix A. Print, then wait for any non-empty user reply. Re-probe common ports; if found, set TARGET. Else print a troubleshooting hint and wait once more. After two failed waits, abort with a clear message.
- **[3]**: prompt "URL: ". Read. Classify tier. Apply the same gates as Step 1a.

**Step 3 — Credentials.** Priority:
1. `runtime-audit.yaml` `auth:` block.
2. Env vars `TARGET_KEY_A` / `TARGET_KEY_B` (or `TARGET_BEARER`).
3. `--auth` / `--auth-b` flags.
4. If target is local AND repo has an obvious signup/register route, offer to seed two test accounts (Band 2 — asks consent first).
5. Otherwise, proceed with no auth. BOLA probes degrade to LEAD.

**Step 4 — Resolve `SKILL_DIR` and load references.**

First resolve `SKILL_DIR` — do not use `Glob` (cwd-scoped, misses the plugin mount). Use Bash:

```bash
SKILL_DIR=""
for root in "$CLAUDE_PLUGIN_ROOT" "$HOME/.claude" "/tmp" "$(pwd)"; do
  [ -z "$root" ] && continue
  [ -d "$root" ] || continue
  found=$(find -L "$root" -maxdepth 8 -type f -path '*/runtime-audit/SKILL.md' 2>/dev/null | head -1)
  if [ -n "$found" ]; then
    SKILL_DIR="$(dirname "$found")"
    break
  fi
done
if [ -z "$SKILL_DIR" ] || [ ! -d "$SKILL_DIR/references" ]; then
  echo "❌ Could not resolve SKILL_DIR. runtime-audit cannot run without its references/. Aborting."
  exit 1
fi
```

Unlike the static auditors, runtime-audit has **hard dependencies** on safety.md (tier gate), probe-library.md, judging.md. Failing to load them is a blocking error — abort rather than proceed with reduced coverage (the safety implications are too significant).

Then parallel Reads:
- `$SKILL_DIR/references/safety.md`
- `$SKILL_DIR/references/startup.md` (already loaded if Step 2 path [1] ran)
- `$SKILL_DIR/references/probe-library.md`
- `$SKILL_DIR/references/judging.md`
- `$SKILL_DIR/references/report-formatting.md`

For each probe-agent file referenced in Phase 2, similarly use `$SKILL_DIR/references/probe-agents/{name}.md`.

Also: `mktemp -d /tmp/runtime-audit-XXXXXX` → `{run_dir}`.

**Step 5 — Auto-load static report.** If `--from-report` is unset, Glob `assets/findings/*-api-audit-report-*.md` at repo root. One match → use it. Multiple matches → pick the newest by filename timestamp and confirm with the user.

**Step 6 — Safety preamble.** Print before any probe:

```
TARGET:        <url>
TIER:          <local|staging|prod>
AUTOSTART:     <no | yes (pid=<N>, via `<command>`, env=<.env.test | .env (REAL)>)>
DESTRUCTIVE:   <on|off>
RATE:          <N> req/s (burst <M>)
AUTH A:        <header redacted>
AUTH B:        <header redacted | not supplied>
FROM REPORT:   <path | none>
SAFE MODE:     <bands 1-only | bands 1-2 | bands 1-3>
```

If `env=.env (REAL)`, print the warning in `references/safety.md` and downgrade to bands 1-only unless `--destructive` is also set.

### Phase 2 — Arm

Build the test matrix:

1. If a static report is loaded → every finding becomes a verification probe keyed on its `bug_class`. Load the matching `references/probe-agents/*` file.
2. If an OpenAPI spec is reachable → enumerate every `(method, path, params)`.
3. Otherwise → crawl common paths per `references/probe-library.md`.

Classify every probe into a band:
- **Band 1** — Read-only (GET, OPTIONS, HEAD, fingerprinting). Always allowed.
- **Band 2** — Safe-writes (create a tagged test resource, clean up on exit). Gated on SAFE MODE.
- **Band 3** — Destructive (DELETE real resources, brute-force, rate-limit breach, known-bad external triggers). Requires `--destructive` + tier check per `safety.md`.

Respect `skip_paths` from the yaml: any probe targeting an excluded path becomes `SKIPPED_BY_CONFIG` in the report.

Print the matrix: count per band, examples, skipped count, safety mode. Do NOT probe yet.

### Phase 3 — Execute

Run bands in order, honoring `--rate`:

- Band 1 — always.
- Band 2 — only if SAFE MODE allows.
- Band 3 — only if allowed AND per-family CONFIRM prompts pass (per `safety.md`).

Each probe:
1. Construct per its probe-agent block.
2. Fire baseline (matched control) first, then attack.
3. Write `{run_dir}/{NNN}-{probe-name}.http` with both requests + responses. Redact auth headers with `***`.
4. Classify per `references/judging.md`.
5. Push any created resource to `{run_dir}/cleanup.txt`.

Cleanup runs at phase end AND on any abort path (error, Ctrl-C).

### Phase 4 — Deduplicate & Report

1. Group findings by `(host | endpoint | bug_class)`. Merge. Annotate `[agents: N]`.
2. If `--from-report` was used, cross-reference: tag each static finding as `CONFIRMED_LIVE`, `NOT_REPRODUCIBLE`, or `OUT_OF_SCOPE`.
3. Write report per `references/report-formatting.md` to `assets/findings/{target-host}-runtime-audit-{timestamp}.md`.
4. Copy transcripts to `assets/transcripts/{timestamp}/`.
5. If autostart was used, tear down the server (SIGTERM then SIGKILL after 5s). Record the autostart provenance in the Scope section of the report.
6. Print the Verdict block to the terminal.

## Probe Agents (8 personas)

| Agent | HTTP angle |
|---|---|
| `authz-probes` | BOLA via cross-context fetch; BFLA via method/role swap; BOPLA via extra-field injection |
| `authn-probes` | JWT `alg:none` forgery, missing/expired token acceptance, session-fixation replay, reset-token single-use, MFA skip |
| `injection-probes` | SQLi/NoSQLi/command/SSTI/XXE payloads in every input slot; canary timing |
| `deserialization-and-ssrf-probes` | URL params → `169.254.169.254` + `localhost:6379` + `file://`; pickle/yaml headers |
| `crypto-and-secrets-probes` | Webhook replay, signature stripping, HMAC timing differential, TLS downgrade |
| `resource-and-business-logic-probes` | Fire 2× rate limit → expect 429; parallel race on unique constraint; idempotency-key replay |
| `config-and-supply-chain-probes` | CORS preflight with malicious `Origin`, `/.env` / `/debug` probe, stale-route probe, `trust proxy` spoof via `X-Forwarded-For` |
| `llm-and-integration-probes` | Prompt-injection canaries in free-text inputs; check for reflection; check for tool-use path that escalates |

## Banner

```
 █████╗ ██████╗ ██╗    ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗███╗   ███╗███████╗
██╔══██╗██╔══██╗██║    ██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║████╗ ████║██╔════╝
███████║██████╔╝██║    ██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║██╔████╔██║█████╗
██╔══██║██╔═══╝ ██║    ██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║██║╚██╔╝██║██╔══╝
██║  ██║██║     ██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║██║ ╚═╝ ██║███████╗
╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝
                            Runtime Audit (Dynamic)
```

## Constraints

- **Never skip safety gates.** Autostart with real `.env` downgrades bands.
- **Never store auth tokens** in transcripts — redact with `***`.
- **Never run Band 3 on `prod`** without `--destructive --i-really-mean-it` and an interactive confirm.
- **Never hammer** past the configured rate. Back off on 429.
- **Never follow redirects** across hosts without re-applying the tier gate.
- **Single pass.** No partial reports.
- **Report honestly.** `LIKELY` is not `CONFIRMED`.
- **Always tear down** any server the skill started — including on Ctrl-C and errors.
