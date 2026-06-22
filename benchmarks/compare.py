#!/usr/bin/env python3
"""Merge the two result JSONs into ``benchmarks/RESULTS.md``.

Reads ``benchmarks/results/cerberust.json`` (written by the Rust bench) and
``benchmarks/results/llm_guard.json`` (written by ``run_llm_guard.py``), joins
them per scanner, computes the speedup (cerberust samples/sec ÷ LLM Guard
samples/sec), and renders the comparison table plus an honest summary.
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).parent
CB = HERE / "results" / "cerberust.json"
LG = HERE / "results" / "llm_guard.json"
OUT = HERE / "RESULTS.md"

# The order scanners are listed in the table.
ORDER = ["PII", "Secrets", "Regex", "BanSubstrings", "PromptInjection"]

# The LLM Guard scanner each row compares against (for the table header note).
COUNTERPART = {
    "PII": "Anonymize",
    "Secrets": "Secrets",
    "Regex": "Regex",
    "BanSubstrings": "BanSubstrings",
    "PromptInjection": "PromptInjection",
}


def load(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {row["scanner"]: row for row in data.get("scanners", [])}


def fmt_speed(sps: float) -> str:
    if sps >= 1_000_000:
        return f"{sps / 1_000_000:.2f}M/s"
    if sps >= 1_000:
        return f"{sps / 1_000:.1f}k/s"
    return f"{sps:.0f}/s"


def fmt_pr(row: dict | None) -> str:
    if not row:
        return "—"
    return f"{row['precision']:.2f} / {row['recall']:.2f}"


def speedup(cb: dict | None, lg: dict | None) -> str:
    if not cb or not lg or lg["samples_per_sec"] == 0:
        return "—"
    return f"{cb['samples_per_sec'] / lg['samples_per_sec']:.0f}×"


def main() -> None:
    cb = load(CB)
    lg = load(LG)
    if not cb:
        raise SystemExit(f"missing {CB}; run `cargo bench --bench comparison` first")

    rows = []
    for name in ORDER:
        g = cb.get(name)
        lrow = lg.get(name)
        if not g and not lrow:
            continue
        rows.append(
            "| {scanner} ({cp}) | {cb_speed} | {lg_speed} | {sp} | {cb_pr} | {lg_pr} |".format(
                scanner=name,
                cp=COUNTERPART[name],
                cb_speed=fmt_speed(g["samples_per_sec"]) if g else "—",
                lg_speed=fmt_speed(lrow["samples_per_sec"]) if lrow else "—",
                sp=speedup(g, lrow),
                cb_pr=fmt_pr(g),
                lg_pr=fmt_pr(lrow),
            )
        )

    table = (
        "| Scanner (vs LLM Guard) | cerberust speed | LLM Guard speed | speedup | "
        "cerberust P/R | LLM Guard P/R |\n"
        "|---|---|---|---|---|---|\n" + "\n".join(rows)
    )

    inject_table(table)
    print(f"updated table in {OUT}")
    print(table)


# The table is regenerated from the result JSONs; the surrounding prose is
# hand-written and preserved. compare.py only rewrites the region between these
# markers.
BEGIN = "<!-- BENCH-TABLE:BEGIN -->"
END = "<!-- BENCH-TABLE:END -->"


def inject_table(table: str) -> None:
    block = f"{BEGIN}\n{table}\n{END}"
    if OUT.exists():
        text = OUT.read_text(encoding="utf-8")
        if BEGIN in text and END in text:
            pre = text[: text.index(BEGIN)]
            post = text[text.index(END) + len(END) :]
            OUT.write_text(pre + block + post, encoding="utf-8")
            return
    raise SystemExit(
        f"{OUT} is missing the {BEGIN} / {END} markers — restore them "
        "(see the committed RESULTS.md) before regenerating the table."
    )


if __name__ == "__main__":
    main()
