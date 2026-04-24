# Contributing

Thanks for helping improve these skills. Short guide:

## Adding a finding pattern

If you've seen a real-world API vulnerability that the auditor missed, encode it.

1. Identify which of the 8 agents owns it (`authz`, `authn`, `injection`,
   `deserialization-and-ssrf`, `crypto-and-secrets`,
   `resource-and-business-logic`, `config-and-supply-chain`,
   `llm-and-integration`).
2. Add a pattern entry to the relevant
   `{skill}/references/hacking-agents/{agent}.md` — include the vulnerable
   shape, a grep pattern if possible, and a safe-pattern counter-example.
3. Add a row to `{skill}/references/attack-vectors/attack-vectors.md` under
   the matching OWASP API category.
4. If there's a public repo demonstrating it, add it to
   `{skill}/evals/benchmarks/` with pinned commit + ground-truth entry.

## Adding a new agent

High bar — 8 agents is already a lot of parallel context. If you genuinely need a
new persona:

1. Open an issue first describing the coverage gap existing agents miss.
2. Add `{skill}/references/hacking-agents/{new-agent}.md`.
3. Add a bundle row to `{skill}/SKILL.md` Turn 2.
4. Add the spawn call to `{skill}/SKILL.md` Turn 3.
5. Rerun the full eval loop on all benchmarks and include results in the PR.

## Testing

Before opening a PR, run the eval loop:

```bash
cd nodejs-api-auditor  # or python-api-auditor
# follow evals/runner.md
```

Recall on the existing benchmark ground-truth must not regress.

## Style

- Markdown files: wrap at 100 cols where practical.
- Keep agent files focused — one persona, one attack surface.
- No comments in code blocks that restate what the code does.

## Gotchas

### claude-mem plugin creates `CLAUDE.md` files everywhere

If you use the claude-mem Claude Code plugin, each significant edit spawns a `CLAUDE.md` activity log inside the touched directory. The root `.gitignore` excludes these globally (`**/CLAUDE.md`), but:

- Do not commit them manually.
- If you edit a `CLAUDE.md` thinking it's a real project file, you're editing a plugin artifact.
- The user-facing docs are `README.md` at each skill root and `SKILL.md` for the orchestrator.

### Versioning

Each skill has a `VERSION` file (SemVer). Bump on:
- **Major**: breaking change to SKILL.md triggers / flag names / output filename convention.
- **Minor**: new probe agents, new flags, new coverage sections.
- **Patch**: content fixes, typo corrections, grep-pattern refinements.

### Auto-loading the latest static report in runtime-audit

`runtime-audit` auto-loads the most recent `assets/findings/*-api-audit-report-*.md` when `--from-report` isn't set. If the report is stale (older than the git HEAD's last commit to the audited files), the skill should warn. This behavior isn't yet enforced in code — verify manually that the report is fresh before relying on the cross-reference table.
