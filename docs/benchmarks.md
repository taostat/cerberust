# Benchmarks

A guardrail's job is to **not corrupt the prompt your user paid for**. A
wrongly-redacted word is the expensive error; a missed free-text name is only a
convenience gap. So cerberust optimizes for **precision** — deterministic regex +
checksums — over the recall of a fuzzy NER model that over-redacts ordinary words.

These numbers measure cerberust against
[`llm-guard`](https://github.com/protectai/llm-guard) (Python) on a shared labeled
corpus, and we **only race like-for-like**: where both sides run the same algorithm
or model, it's a fair speed comparison; where the *approaches* differ (our regex +
checksums vs its NER), we report accuracy and our own throughput — not a speed
multiple against a neural net. All numbers are real, reproducible, and caveated.

> These are measured numbers from one machine (Apple Silicon, macOS). Absolute
> throughput is hardware- and load-dependent — **the speedup ratios are the durable
> signal, not the raw samples/sec.**

## The corpus

A 290-sample labeled corpus: 100 PII positives, 96 secret positives, 30 prompt
injections, and the rest clean or near-miss negatives. Both implementations read the
*same* `corpus.jsonl` and score precision/recall against the *same* per-sample
ground-truth labels.

## Same detector, faster runtime (the like-for-like races)

Where both sides run the *same* algorithm or model, detection is identical — the
only variable is speed:

| Scanner | cerberust | llm-guard | speedup | detection |
|---|---|---|---|---|
| Regex (same patterns) | 7.81M/s | 124.5k/s | ~63× | identical — 1.00 / 1.00 both |
| Ban-substrings (same phrases) | 1.16M/s | 135.5k/s | ~9× | identical — 1.00 / 0.27 both |
| Prompt-injection (same model) | 126/s | 96/s | ~1× (tie) | byte-identical — same 28 TP / 65 FP / 2 FN / 195 TN |

## PII & Secrets — a different approach, on purpose

cerberust detects PII and secrets with deterministic regex + checksums (Luhn, IPv4
range, entropy backstop); `llm-guard` runs a spaCy NER pipeline (PII) and a
multi-rule Python scanner (Secrets). The approaches differ, so we don't headline a
speed multiple against a neural net. What the deterministic approach delivers on the
**structured** corpus:

| Scanner | cerberust throughput | cerberust P/R | llm-guard P/R (same corpus) |
|---|---|---|---|
| PII (structured) | 1.34M/s | 1.00 / 1.00 | 0.75 / 0.89 |
| Secrets | ~440k/s | 1.00 / 1.00 | 1.00 / 0.45 |

Perfect precision and recall on entities with a recognizable shape — and, unlike an
NER pipeline, **no over-redaction of ordinary words**. NER's strength is free-text
names and addresses, which cerberust deliberately doesn't attempt (it's the
precision-for-recall trade a guardrail shouldn't make). Need free-text name coverage?
Pair cerberust with a dedicated NER tool.

*Speed is samples/sec over the corpus — deterministic scanners across warm passes
(after one-time regex compilation), the ML scanner once per sample where inference
dominates. P/R is precision/recall against the ground-truth labels.*

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

- **PII / Secrets — different detectors, not a speed race.** cerberust uses regex +
  checksums (Luhn, IPv4 range, entropy backstop); `llm-guard` uses Presidio NER (PII)
  and detect-secrets (Secrets). Because the *approaches* differ, we don't pit them on
  speed — we report cerberust's own throughput and the detection quality each reaches
  on the structured corpus. cerberust is perfect there and doesn't over-redact; NER
  leads on free-text names cerberust deliberately doesn't attempt.

## Summary

- **Like-for-like speed:** where the algorithm or model is the same, cerberust's Rust
  implementation is **~9× (ban-substrings) to ~63× (regex)** faster, and the ML
  prompt-injection scanner **ties** `llm-guard` — byte-identical detection, runtime a
  wash.
- **PII / Secrets — precision by design:** on the structured corpus the deterministic
  detectors hit perfect precision/recall and don't over-redact, where `llm-guard`'s
  NER scores 0.75 / 0.89 (PII) and detect-secrets recalls 0.45. We don't headline a
  speed multiple here — it's regex vs a neural net — but the throughput is high
  (hundreds of thousands to over a million samples/s) and, for a guardrail, the
  precision is the point.

## The honest caveats

We'd rather you trust the numbers than be wowed by them, so:

1. **It's regex-and-checksum vs NER — and on a *structured* corpus.** cerberust's PII
   edge is on entities with a recognizable shape (emails, cards, IBANs, IPs, SSNs),
   which regex + checksums handle natively and far faster than `llm-guard`'s spaCy
   NER pipeline. On free-text names and addresses (NER's strength), a Presidio-style
   NER detector would lead — **cerberust deliberately doesn't ship fuzzy NER**: it
   over-redacts ordinary words and domain terms, trading the precision a guardrail
   needs for recall. If you need free-text name coverage, pair cerberust with a
   dedicated NER tool. So read the PII/Secrets rows as "much faster and more precise
   *on structured entities*," not as a universal PII-detection win.
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
