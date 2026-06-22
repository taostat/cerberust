# Benchmarks

cerberust is measured head-to-head against
[`llm-guard`](https://github.com/protectai/llm-guard) (Python) on a **shared
labeled corpus** — same scanners, same detection job — for both **speed**
(samples/sec) and **detection** (precision/recall). The numbers below are real,
reproducible, and come with their caveats stated.

> These are measured numbers from one machine (Apple Silicon, macOS). Absolute
> throughput is hardware- and load-dependent — **the speedup ratios are the durable
> signal, not the raw samples/sec.**

## The corpus

A 290-sample labeled corpus: 100 PII positives, 96 secret positives, 30 prompt
injections, and the rest clean or near-miss negatives. Both implementations read the
*same* `corpus.jsonl` and score precision/recall against the *same* per-sample
ground-truth labels.

## Results

| Scanner (vs llm-guard) | cerberust speed | llm-guard speed | speedup | cerberust P/R | llm-guard P/R |
|---|---|---|---|---|---|
| PII (Anonymize) | 1.34M/s | 65/s | ~20,500× | 1.00 / 1.00 | 0.75 / 0.89 |
| Secrets | 1.31M/s | 1.4k/s | ~940× | 1.00 / 1.00 | 1.00 / 0.45 |
| Regex | 7.81M/s | 124.5k/s | ~63× | 1.00 / 1.00 | 1.00 / 1.00 |
| Ban-substrings | 1.16M/s | 135.5k/s | ~9× | 1.00 / 0.27 | 1.00 / 0.27 |
| Prompt-injection | 126/s | 96/s | ~1× | 0.30 / 0.93 | 0.30 / 0.93 |

*Speed is samples/sec over the whole corpus. The deterministic scanners are timed
across repeated warm passes (after the one-time regex compilation); the ML scanner is
timed once per sample, where inference dominates. P/R is precision/recall against the
ground-truth label.*

## What each row actually compares

Not every row is the same *kind* of comparison — being honest about that is the whole
point of the methodology.

- **Prompt-injection — the clean apples-to-apples.** Both sides run the *same model*
  (`deberta-v3-base-prompt-injection-v2`) at the *same 0.5 threshold*; the only
  difference is the runtime — cerberust's `ort` (ONNX Runtime, CPU) vs `llm-guard`'s
  `transformers` (PyTorch, MPS on this box). Detection is **byte-identical** (same 28
  TP / 65 FP / 2 FN / 195 TN). That's the headline parity result: cerberust's
  inference path reproduces `llm-guard`'s classification exactly. The low precision
  (0.30) is a property of *this model at 0.5* on a corpus of short benign prompts,
  not of either implementation — `llm-guard`'s own default threshold is 0.92, which
  trades recall for precision. We pinned both to 0.5 for a like-for-like comparison.

- **Regex / Ban-substrings — identical patterns, identical detection.** Both run the
  same email regex / the same trigger phrases, so P/R matches by construction; the
  comparison is **pure matcher speed**. Ban-substrings recall is 0.27 on both because
  a five-phrase keyword list only covers a third of the injection set — the honest
  ceiling of a literal-substring baseline, and exactly why the ML scanner exists.

- **PII / Secrets — different detectors, same job.** cerberust uses regex + checksums
  (Luhn, IPv4 range, entropy backstop); `llm-guard` uses Presidio NER (PII) and
  detect-secrets (Secrets). Detection differs because the *approaches* differ, so
  these rows compare both speed **and** detection quality on structured PII /
  known-format secrets.

## Summary

cerberust wins decisively on the deterministic scanners and ties the ML scanner.

- **Speed:** 9× to ~20,000× faster on every regex/checksum/literal scanner. The PII
  and Secrets gaps are largest because `llm-guard` runs a spaCy NER pipeline (PII)
  and a multi-rule Python scanner (Secrets) where cerberust runs compiled regex +
  checksums.
- **Detection parity:** on this structured corpus cerberust matches or beats
  `llm-guard`. It's perfect (P=R=1.0) on PII and Secrets; `llm-guard`'s Presidio NER
  misses/over-flags some structured PII (0.75 / 0.89) and its detect-secrets recall
  is 0.45 (it doesn't recognize several OpenAI / Stripe / labelled-`key=value`
  forms). The ML prompt-injection scanner is **identical** to `llm-guard`'s.

## The honest caveats

We'd rather you trust the numbers than be wowed by them, so:

1. **The PII/Secrets detection edge reflects a *structured* corpus** — entities with
   a recognizable shape, which regex + checksum handles natively. On free-text names
   and addresses (NER's strength), a Presidio-style detector would lead until
   cerberust's planned `gline-rs` NER detector lands.
2. **Ban-substrings recall (0.27) is low on both sides by design.** It's a keyword
   baseline, not a detector.
3. **The ML scanner's absolute throughput depends heavily on hardware.** The ~1.3×
   here is *not* a durable multiple the way the deterministic-scanner ratios are.
   Read the ML row as "ties on accuracy, runtime is a wash."

## Reproduce it

```sh
# 1. Build the corpus (no heavy deps)
python3 benchmarks/generate_corpus.py

# 2. cerberust side (Rust) — deterministic scanners
cargo bench --bench comparison

#    …plus the ML row (needs the DeBERTa-v3 weights + the feature)
scripts/fetch-model.sh
CERBERUST_MODEL_DIR="$HOME/.cache/cerberust/deberta-v3-base-prompt-injection-v2" \
  cargo bench --features prompt-injection --bench comparison

# 3. llm-guard side (Python venv with llm-guard installed)
benchmarks/.venv/bin/python benchmarks/run_llm_guard.py

# 4. Merge both result JSONs into the table
python3 benchmarks/compare.py
```

Full setup — including the Python 3.11 venv `llm-guard` requires and the Presidio
spaCy model wheels — is in `benchmarks/README.md`. The raw measured table and the
written analysis live in `benchmarks/RESULTS.md`.
