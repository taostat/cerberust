#!/usr/bin/env bash
# Compare scan time of two checkouts on the same clean corpus.
#
# Usage: scripts/perf-gate.sh <base-checkout> <head-checkout>
#
# The head checkout's examples/perf_gate.rs is copied into the base checkout so
# both revisions run the same benchmark code. The corpus is the head checkout's
# own Rust sources and Markdown docs, limited to files the base revision leaves
# unchanged. Both binaries run in alternating rounds; the per-case median of the
# round medians is compared, and the script fails when any head case is slower
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

git -C "$head" ls-files -- 'src/*.rs' 'docs/*.md' README.md |
  sed "s|^|$head/|" >"$work/all.list"
"$base_bin" clean "$work/all.list" >"$work/clean.list"
echo "corpus: $(wc -l <"$work/clean.list") of $(wc -l <"$work/all.list") files"

for round in $(seq "$rounds"); do
  echo "round $round/$rounds"
  "$base_bin" bench "$work/clean.list" | sed 's/^/base,/' >>"$work/results.csv"
  "$head_bin" bench "$work/clean.list" | sed 's/^/head,/' >>"$work/results.csv"
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
