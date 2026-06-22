#!/usr/bin/env python3
"""The LLM Guard (Python) side of the LLM Guard comparison.

Reads the same labeled corpus the Rust harness reads
(``benchmarks/corpus/corpus.jsonl``), runs each LLM Guard input scanner that
overlaps a cerberust scanner, and measures the same two things per scanner:

* **speed** — samples/sec over the corpus. The regex/PII/secret scanners are
  timed across repeated passes (the matcher work is cheap, so a single pass is
  noisy); the ML ``PromptInjection`` scanner is timed once per sample (inference
  dominates, so one pass is the honest throughput, matching the Rust side).
* **detection** — precision/recall of each scanner's ``valid`` flag against the
  corpus ground-truth label. LLM Guard's ``scan`` returns
  ``(sanitized, is_valid, risk)``; ``is_valid == False`` (or a changed sanitized
  text for the redacting scanners) is the "flag".

The ``PromptInjection`` threshold is set to **0.5** to match cerberust's default,
so the ML comparison is the *same model* (``deberta-v3-base-prompt-injection-v2``)
at the *same threshold* — ``ort`` (Rust) vs ``transformers`` (Python).

Writes ``benchmarks/results/llm_guard.json``; ``compare.py`` merges it with the
Rust side into ``RESULTS.md``.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).parent
DEFAULT_CORPUS = HERE / "corpus" / "corpus.jsonl"
DEFAULT_OUT = HERE / "results" / "llm_guard.json"

# Match cerberust's PromptInjectionScanner default block threshold.
PI_THRESHOLD = 0.5
# Repeated passes for the cheap (non-ML) scanners, mirroring the Rust harness.
FAST_PASSES = 5


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn_: int = 0
    tn: int = 0

    def observe(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif not predicted and actual:
            self.fn_ += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return 1.0 if denom == 0 else self.tp / denom

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn_
        return 1.0 if denom == 0 else self.tp / denom


def load_corpus(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def score(scanner, corpus: list[dict], truth_fn, flag_fn) -> tuple[Metrics, float]:
    """Score detection and time throughput for one scanner.

    ``flag_fn(sanitized, is_valid, original)`` returns whether the scanner
    flagged the sample; ``truth_fn(sample)`` returns its ground-truth label.
    Detection is scored on one pass; throughput is the best of ``FAST_PASSES``
    timed passes (best = least scheduler noise).
    """
    metrics = Metrics()
    for sample in corpus:
        sanitized, is_valid, _risk = scanner.scan(sample["text"])
        flagged = flag_fn(sanitized, is_valid, sample["text"])
        metrics.observe(flagged, bool(truth_fn(sample)))

    # Warm-up, then timed passes.
    for sample in corpus:
        scanner.scan(sample["text"])
    best = float("inf")
    for _ in range(FAST_PASSES):
        start = time.perf_counter()
        for sample in corpus:
            scanner.scan(sample["text"])
        best = min(best, time.perf_counter() - start)
    samples_per_sec = len(corpus) / best if best > 0 else 0.0
    return metrics, samples_per_sec


def score_ml(scanner, corpus: list[dict], label_key: str) -> tuple[Metrics, float]:
    """Score the ML scanner: detection + single-pass throughput (inference-bound)."""
    metrics = Metrics()
    # Warm-up inference (lazy graph allocation on first call).
    if corpus:
        scanner.scan(corpus[0]["text"])
    start = time.perf_counter()
    for sample in corpus:
        _sanitized, is_valid, _risk = scanner.scan(sample["text"])
        metrics.observe(not is_valid, bool(sample.get(label_key, False)))
    elapsed = time.perf_counter() - start
    samples_per_sec = len(corpus) / elapsed if elapsed > 0 else 0.0
    return metrics, samples_per_sec


def has_label(key: str):
    """Ground-truth function: the sample's boolean label ``key``."""
    return lambda sample: bool(sample.get(key, False))


def email_pii_truth(sample: dict) -> bool:
    """Ground truth for the email-targeting Regex scanner (email-bearing PII)."""
    return ("@" in sample["text"]) and bool(sample.get("pii", False))


def result_row(name: str, metrics: Metrics, sps: float) -> dict:
    return {
        "scanner": name,
        "samples_per_sec": round(sps, 2),
        "precision": round(metrics.precision, 4),
        "recall": round(metrics.recall, 4),
        "tp": metrics.tp,
        "fp": metrics.fp,
        "fn": metrics.fn_,
        "tn": metrics.tn,
    }


def redacting_flag(sanitized: str, _is_valid: bool, original: str) -> bool:
    """A redacting scanner flags a sample when it rewrote the text."""
    return sanitized != original


def blocking_flag(_sanitized: str, is_valid: bool, _original: str) -> bool:
    """A blocking scanner flags a sample when it marks it invalid."""
    return not is_valid


def run(corpus: list[dict], skip_ml: bool) -> list[dict]:
    from llm_guard.input_scanners import (
        Anonymize,
        BanSubstrings,
        Regex,
        Secrets,
    )
    from llm_guard.vault import Vault

    rows: list[dict] = []

    # PII — Anonymize redacts recognized entities; flag = text changed.
    print("running Anonymize (PII) ...", flush=True)
    anonymize = Anonymize(Vault())
    m, sps = score(anonymize, corpus, has_label("pii"), redacting_flag)
    rows.append(result_row("PII", m, sps))

    # Secrets — redacts detected secrets; flag = text changed or blocked.
    print("running Secrets ...", flush=True)
    secrets = Secrets()
    m, sps = score(
        secrets,
        corpus,
        has_label("secret"),
        lambda san, valid, orig: (san != orig) or (not valid),
    )
    rows.append(result_row("Secrets", m, sps))

    # Regex — same email pattern the Rust side uses, redacting on match. Scored
    # against the email-bearing PII positives, mirroring the Rust harness.
    print("running Regex ...", flush=True)
    regex = Regex(
        patterns=[r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"],
        is_blocked=True,
        redact=True,
    )
    m, sps = score(
        regex,
        corpus,
        email_pii_truth,
        lambda san, valid, orig: (san != orig) or (not valid),
    )
    rows.append(result_row("Regex", m, sps))

    # BanSubstrings — same trigger phrases the Rust side blocks on.
    print("running BanSubstrings ...", flush=True)
    ban = BanSubstrings(
        substrings=[
            "ignore all previous instructions",
            "ignore previous instructions",
            "disregard the above",
            "system override",
            "you are now dan",
        ],
        case_sensitive=False,
        redact=False,
    )
    m, sps = score(ban, corpus, has_label("injection"), blocking_flag)
    rows.append(result_row("BanSubstrings", m, sps))

    if not skip_ml:
        from llm_guard.input_scanners import PromptInjection
        from llm_guard.input_scanners.prompt_injection import MatchType

        print(
            f"running PromptInjection (deberta-v3-base-v2, threshold={PI_THRESHOLD}) ...",
            flush=True,
        )
        pi = PromptInjection(threshold=PI_THRESHOLD, match_type=MatchType.FULL)
        m, sps = score_ml(pi, corpus, "injection")
        rows.append(result_row("PromptInjection", m, sps))

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument(
        "--skip-ml",
        action="store_true",
        help="Skip the PromptInjection ML scanner (which downloads ~440MB on first run).",
    )
    args = parser.parse_args()

    corpus = load_corpus(Path(args.corpus))
    print(f"llm-guard benchmark over {len(corpus)} samples\n", flush=True)

    rows = run(corpus, skip_ml=args.skip_ml)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps({"engine": "llm-guard", "scanners": rows}, indent=2) + "\n",
        encoding="utf-8",
    )

    print()
    for r in rows:
        print(
            f"  {r['scanner']:<16} {r['samples_per_sec']:>12.0f} samples/s   "
            f"P={r['precision']:.3f} R={r['recall']:.3f}  "
            f"(tp={r['tp']} fp={r['fp']} fn={r['fn']} tn={r['tn']})"
        )
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
