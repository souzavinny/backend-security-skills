# Eval Runner (Runtime)

Runs the `runtime-audit` skill against benchmark apps hosted locally. Each benchmark starts a real server, captures baseline behavior, runs the skill, and compares findings to ground truth.

## Prereqs

- Docker (benchmarks ship as `docker compose` stacks)
- `curl`, `jq`
- Ports 3000–3010 free

## Usage

```
claude "read evals/runner.md and run all benchmarks"
claude "read evals/runner.md and run juice-shop"
```

## Setup

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
SKILL_DIR="$REPO_ROOT/runtime-audit"
mkdir -p /tmp/runtime-audit-plugin/skills && ln -sfn "$SKILL_DIR" /tmp/runtime-audit-plugin/skills/runtime-audit
COMMIT=$(git -C "$REPO_ROOT" rev-parse --short=7 HEAD)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
echo "commit=$COMMIT timestamp=$TIMESTAMP"
```

## Run

Each benchmark in `evals/benchmarks/` has YAML frontmatter with: `image` (docker image), `port`, `startup_wait`, `auth_context_a`, `auth_context_b`, `ground_truth` (list of expected findings).

Order: **juice-shop → vampi** (Node, then Python — different servers so no cross-contamination).

```bash
BENCHMARKS_DIR="$SKILL_DIR/evals/benchmarks"
RESULTS_DIR="$SKILL_DIR/evals/results"

for name in juice-shop vampi; do
  BENCH="$BENCHMARKS_DIR/$name.md"
  [ -f "$BENCH" ] || continue

  IMAGE=$(awk -F': ' '/^image:/{print $2; exit}' "$BENCH")
  PORT=$(awk -F': ' '/^port:/{print $2; exit}' "$BENCH")
  WAIT=$(awk -F': ' '/^startup_wait:/{print $2; exit}' "$BENCH")
  RUN_DIR="$RESULTS_DIR/$name/$TIMESTAMP-$COMMIT"
  mkdir -p "$RUN_DIR"

  echo "=== Starting $name ($IMAGE on :$PORT) ==="
  docker run -d --rm --name "eval-$name" -p "$PORT:$PORT" "$IMAGE" > /dev/null
  sleep "${WAIT:-20}"

  # verify target is up
  curl -sSf "http://localhost:$PORT/" > /dev/null || { docker stop "eval-$name"; continue; }

  # run the skill
  cd "$RUN_DIR"
  claude --print --plugin-dir /tmp/runtime-audit-plugin --dangerously-skip-permissions \
    "run runtime audit on http://localhost:$PORT --tier local" 2>&1 | tee full-output.txt

  # collect outputs
  cp "$BENCH" "$RUN_DIR/ground-truth.md"

  echo "=== Stopping $name ==="
  docker stop "eval-$name" > /dev/null
done
echo "All benchmarks complete."
```

After all complete, for each `{run_dir}`: read `evals/compare.md`, diff the generated report against the ground-truth file, write `summary.md`.

## Notes

- Benchmarks are intentionally vulnerable — running them anywhere other than localhost is a bad idea. The runner enforces tier=local.
- Skill runs **without** `--destructive` by default for eval repeatability. Benchmarks ground-truth reflects the safe-band expectations; destructive-only findings are listed separately in ground-truth and not expected to appear in default runs.
- Network: the skill's canary URLs require outbound internet on the test runner. If running offline, skip SSRF OOB probes (they'll report as LEAD).
