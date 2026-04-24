# Safety

The runtime auditor fires **real HTTP requests at a live target**. Before any probe executes, the target must pass the safety gate defined here. If the gate fails, stop and print the reason — do not proceed.

## Target classification

The target URL's hostname (after any redirects) determines the tier:

### Tier: `local`

**Matches (default, no extra flag needed):**
- `localhost`, `127.0.0.1`, `::1`
- Any `*.local` (mDNS)
- Any RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- `host.docker.internal`

**Allowed:** all probe bands. Destructive still requires `--destructive`.

### Tier: `staging`

**Matches (must be `--tier staging`):**
- Hostnames containing `staging.`, `stage.`, `.dev`, `preview.`, `pr-*.`, `ngrok.io`, `ngrok-free.app`, `trycloudflare.com`
- Explicit allowlist in `.runtime-audit.yaml` if present

**Allowed:** Bands 1 and 2. Band 3 (destructive) requires `--destructive` AND interactive confirmation per-host.

### Tier: `prod`

**Matches (must be `--tier prod --authorized-by "<name>"`):**
- Anything that's not `local` or `staging`

**Allowed:** Band 1 only by default. Bands 2–3 require `--destructive --i-really-mean-it` AND interactive confirmation.

## Hard prohibitions

The skill refuses, regardless of tier or flags:

- Targets on disallowed allowlists baked into the skill:
  - `*.gov`, `*.mil`, `*.edu` (unless `--authorized-by` + explicit allowlist entry)
  - Cloud provider metadata IPs as targets: `169.254.169.254`, `fd00:ec2::254`
  - Known public endpoints of major services (`api.github.com`, `api.openai.com`, `api.anthropic.com`, etc.) — the skill's job is to test **your** service, not probe third parties
- Any hostname the user does not control or is not authorized to test. The skill cannot verify authorization automatically — trust the `--authorized-by` declaration but treat mismatched tiers as refusals.

## Redirect handling

If a probe returns a `3xx` with a `Location:` header pointing to a different host:
1. Apply the tier gate to the new host.
2. If the new host fails the gate, **do not follow** — record as a finding (trust-boundary leak) and stop the probe.
3. Never silently follow cross-host redirects.

## Rate limiting (self-imposed)

Defaults:
- Sustained: 1 req/sec across all probes
- Burst: 10 req/sec for up to 2 seconds, then throttled
- Backoff: on `429 Too Many Requests`, halt that probe's queue for 60 s and report "target rate limit — respected"

Configurable via `--rate N` and `--burst M`. Never exceed `--rate 100 --burst 500`; the skill caps there.

## Credential handling

- Auth tokens supplied via flags (`--auth`) or env (`TARGET_API_KEY`, `TARGET_BEARER`).
- Tokens are **redacted in transcripts** — write `X-API-Key: ***` (preserve first 8 chars only if they form a provider prefix like `sk_live_` / `ghp_`).
- Tokens never appear in the report file.
- Tokens never logged to `stdout`.

## Destructive probes — consent protocol

For each Band 3 probe family (brute-force, DELETE on real data, email/SMS pump, money-moving POST, on-chain write), print this confirmation before running the first probe in that family:

```
ABOUT TO RUN: {family} against {target}
Expected side effects: {list}
Cleanup plan: {what will be undone}
Type CONFIRM to proceed, anything else to skip this family:
```

Skip the family on anything other than exact `CONFIRM`. Record the skip in the report.

When running non-interactively (`--yes` flag), Band 3 is still blocked unless the user ALSO passed `--i-really-mean-it` AND the target is `local` or explicitly-confirmed `staging`.

## Cleanup guarantee

Every resource created during Bands 2–3 is tracked in `{run_dir}/cleanup.txt` (one row per resource: URL, method, credentials context, created_at). At phase end — or on any hard error — the cleanup stack is processed in reverse order:

```
for entry in reverse(cleanup_stack):
    DELETE entry.url using entry.credentials
    verify 2xx/4xx (404 is fine — already gone)
```

If cleanup fails on a resource, flag it prominently in the report: `⚠️ CLEANUP FAILED — manually delete {url}`.

## Autostart safety — `.env.test` gate

The skill can start the target server itself (Phase 1 fork path [1], or `runtime-audit.yaml` with a `start:` block). When it does, env-file selection determines what probes are safe to run.

### `.env.test` present → full SAFE MODE

Treat as though the user assembled a scoped test environment on purpose.
- All bands allowed (subject to the other flags).
- No path-level skip of side-effect-heavy endpoints.

### `.env.test` absent, `--use-real-env` not passed → refuse to autostart

Print:

```
❌ Can't autostart — no .env.test found at repo root.

Autostarting with your real .env would load live credentials (DB, LLM
providers, wallets, SMS, etc.). Probes that trigger those endpoints would
cause real charges and real external writes.

Options:
  [a] Create a .env.test with scoped/mock values. See references/startup.md.
  [b] Re-run with --use-real-env. Probes against side-effect-heavy paths
      will be SKIPPED unless you also pass --destructive.
  [c] Start the server yourself (in safe conditions) and point me at the URL.
```

### `.env.test` absent, `--use-real-env` passed → downgrade bands

- Downgrade SAFE MODE to **bands 1-only** unless `--destructive` is also set.
- Additionally skip probes matching the side-effect-heavy heuristics in `references/startup.md` (any mutating verb on paths like `/certify`, `/send-*`, `/pay`, `/admin/*`, `/mint`, etc.).
- Print in the safety preamble:

```
⚠️  AUTOSTART uses REAL .env. Bands 2–3 disabled. Skipped routes will appear
    in the report's "Probes skipped" section with override instructions.
```

- `--destructive --use-real-env` together lifts the band downgrade but keeps per-family CONFIRM prompts. Users have to acknowledge each side-effect family explicitly.

## What this does NOT protect against

- **User error.** You point the skill at the wrong URL with the wrong tier and confirm — it will run.
- **Out-of-band effects.** If an endpoint triggers a webhook that charges a credit card, the webhook still fires even after Band 3 cleanup.
- **Legal exposure.** Testing a service you don't control or authorize is on you.

If you cannot guarantee you are authorized, do not run the skill against that target.
