# Eval Runner

Run the `python-api-auditor` skill against public vulnerable Python API repos and compare results to ground truth.

## Usage

```
claude "read evals/runner.md and run all benchmarks"
claude "read evals/runner.md and run vampi"
```

## Setup

```bash
REPO_ROOT="$(git rev-parse --show-toplevel)"
SKILL_DIR="$REPO_ROOT/python-api-auditor"
mkdir -p /tmp/py-api-audit-plugin/skills && ln -sfn "$SKILL_DIR" /tmp/py-api-audit-plugin/skills/python-api-auditor
COMMIT=$(git -C "$REPO_ROOT" rev-parse --short=7 HEAD)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
echo "commit=$COMMIT timestamp=$TIMESTAMP"
```

## Run

Each `.md` in `evals/benchmarks/` is a benchmark with YAML frontmatter: `repo_url`, `repo_ref` (optional), `scope_dir` (optional — defaults to repo root).

Run benchmarks **sequentially** in this fixed order: **vampi → vulnerable-django → dsvw**. Each run gets a fresh `claude` process.

```bash
BENCHMARKS_DIR="$SKILL_DIR/evals/benchmarks"
RESULTS_DIR="$SKILL_DIR/evals/results"

for name in vampi vulnerable-django dsvw; do
  BENCH="$BENCHMARKS_DIR/$name.md"
  [ -f "$BENCH" ] || continue

  REPO_URL=$(awk -F': ' '/^repo_url:/{print $2; exit}' "$BENCH")
  REPO_REF=$(awk -F': ' '/^repo_ref:/{print $2; exit}' "$BENCH")
  SCOPE_DIR=$(awk -F': ' '/^scope_dir:/{print $2; exit}' "$BENCH")

  CLONE_DIR="/tmp/eval-$name"
  [ -d "$CLONE_DIR" ] || git clone --depth 1 ${REPO_REF:+--branch "$REPO_REF"} "$REPO_URL" "$CLONE_DIR"

  WORK_DIR="$CLONE_DIR${SCOPE_DIR:+/$SCOPE_DIR}"
  RUN_DIR="$RESULTS_DIR/$name/$TIMESTAMP-$COMMIT"

  echo "=== Starting $name ==="
  mkdir -p "$RUN_DIR"
  cd "$WORK_DIR" && mkdir -p assets/findings
  claude --print --plugin-dir /tmp/py-api-audit-plugin --dangerously-skip-permissions \
    "run python api auditor on this codebase with --file-output" 2>&1 | tee "$RUN_DIR/full-output.txt"
  LATEST_REPORT=$(ls -t assets/findings/*.md 2>/dev/null | head -1)
  [ -n "$LATEST_REPORT" ] && cp "$LATEST_REPORT" "$RUN_DIR/final-report.md"
  cp "$BENCH" "$RUN_DIR/ground-truth.md"
  echo "=== Finished $name ==="
done
echo "All benchmarks complete."
```

After all complete, for each `{run_dir}`: read `evals/compare.md`, compare `{run_dir}/ground-truth.md` against `{run_dir}/final-report.md`, write `summary.md` to `{run_dir}/`. Print each summary and `=== All done. {count} benchmarks. ===`.
