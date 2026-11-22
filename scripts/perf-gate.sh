#!/usr/bin/env bash
# Compare scan time of two checkouts on the same clean corpus.
#
# Usage: scripts/perf-gate.sh <base-checkout> <head-checkout>
#
# The head checkout's examples/perf_gate.rs is copied into the base checkout so
# both revisions run the same benchmark code. There are two corpora from the
# head checkout: its Rust sources (code) and its Markdown docs (prose), each
# limited to UTF-8 files the base revision leaves unchanged. Paths are listed
# one per line, so file names containing a newline are not supported. Both
# binaries run in alternating rounds; the per-case median of the round medians
# is compared, and the script fails when any head case is slower
# than base by more than PERF_GATE_THRESHOLD (default 1.15).
set -euo pipefail

base=$(cd "$1" && pwd)
head=$(cd "$2" && pwd)
rounds=${PERF_GATE_ROUNDS:-5}
threshold=${PERF_GATE_THRESHOLD:-1.15}
work=$(mktemp -d)

cp "$head/examples/perf_gate.rs" "$base/examples/perf_gate.rs"
for dir in "$base" "$head"; do
  cargo build --quiet --release --example perf_gate --manifest-path "$dir/Cargo.toml"
done
base_bin="$base/target/release/examples/perf_gate"
head_bin="$head/target/release/examples/perf_gate"

list_files() {
  git -C "$head" ls-files -z -- "$@" | tr '\0' '\n' | sed "s|^|$head/|"
}
list_files 'src/*.rs' >"$work/code.all"
list_files 'docs/*.md' README.md >"$work/prose.all"
for corpus in code prose; do
  "$base_bin" clean "$work/$corpus.all" >"$work/$corpus.list"
  echo "$corpus corpus: $(wc -l <"$work/$corpus.list") of $(wc -l <"$work/$corpus.all") files"
done

for round in $(seq "$rounds"); do
  echo "round $round/$rounds"
  for corpus in code prose; do
    "$base_bin" bench "$corpus" "$work/$corpus.list" | sed 's/^/base,/' >>"$work/results.csv"
    "$head_bin" bench "$corpus" "$work/$corpus.list" | sed 's/^/head,/' >>"$work/results.csv"
  done
done

python3 - "$work/results.csv" "$threshold" <<'PY'
import os
import statistics
import sys
from collections import defaultdict

path, threshold = sys.argv[1], float(sys.argv[2])
times = defaultdict(list)
changed = defaultdict(set)
for line in open(path):
    revision, case, median_us, was_changed = line.strip().split(",")
    times[(revision, case)].append(float(median_us))
    changed[(revision, case)].add(was_changed)

cases = sorted({case for _, case in times})
rows = ["| case | base µs | head µs | head/base |", "|---|---:|---:|---:|"]
failed = []
for case in cases:
    base = statistics.median(times[("base", case)])
    head = statistics.median(times[("head", case)])
    ratio = head / base
    mark = ""
    if ratio > threshold:
        failed.append(case)
        mark = " ❌"
    rows.append(f"| {case} | {base:.0f} | {head:.0f} | {ratio:.3f}{mark} |")
    if "1" in changed[("head", case)]:
        print(f"::warning::{case}: head changes corpus text that base leaves unchanged")

report = "\n".join(rows)
print(report)
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a") as out:
        out.write(f"### Scan time, head vs base (fail above {threshold:.2f}x)\n\n{report}\n")
if failed:
    print(f"::error::slower than {threshold:.2f}x base: {', '.join(failed)}")
    sys.exit(1)
PY
