# Benchmarks — cerberust vs LLM Guard

A credibility artifact: cerberust (Rust) measured head-to-head against
[LLM Guard](https://github.com/protectai/llm-guard) (Python) on a shared labeled
corpus, for both **speed** (samples/sec) and **detection** (precision/recall) on
the overlapping scanners. The measured table and a written summary live in
[RESULTS.md](RESULTS.md).

## Layout

| File | What it is |
|---|---|
| `generate_corpus.py` | Builds the labeled corpus (`corpus/corpus.jsonl`). No heavy deps. |
| `../benches/comparison.rs` | The cerberust (Rust) harness. Writes `results/cerberust.json`. |
| `run_llm_guard.py` | The LLM Guard (Python) harness. Writes `results/llm_guard.json`. |
| `compare.py` | Merges both JSONs into the table region of `RESULTS.md`. |
| `RESULTS.md` | The comparison table + honest summary. |

The corpus, the result JSONs, and the Python venv are **git-ignored** — they are
generated, machine-specific, or large. Regenerate them with the steps below.

## Overlapping scanners compared

| cerberust | LLM Guard | What is compared |
|---|---|---|
| `PiiScanner` | `Anonymize` | regex+checksum vs Presidio NER on structured PII |
| `SecretScanner` | `Secrets` | regex+entropy vs detect-secrets on known-format secrets |
| `RegexScanner` | `Regex` | same email pattern — pure matcher speed |
| `BanSubstringsScanner` | `BanSubstrings` | same trigger phrases — pure matcher speed |
| `PromptInjectionScanner` | `PromptInjection` | **same DeBERTa-v3 model**, `ort` vs `transformers` |

## Run it

### 1. Corpus

```sh
python3 benchmarks/generate_corpus.py    # writes benchmarks/corpus/corpus.jsonl
```

### 2. cerberust side (Rust)

The non-ML scanners need no model:

```sh
cargo bench --bench comparison
```

The ML PromptInjection row needs the DeBERTa-v3 weights and the
`prompt-injection` feature:

```sh
scripts/fetch-model.sh                    # ~739 MB into ~/.cache/cerberust/…
CERBERUST_MODEL_DIR="$HOME/.cache/cerberust/deberta-v3-base-prompt-injection-v2" \
  cargo bench --features prompt-injection --bench comparison
```

Both write `benchmarks/results/cerberust.json`. Override the corpus path with
`CERBERUST_CORPUS=…`.

### 3. LLM Guard side (Python)

LLM Guard pulls torch + transformers + spaCy/Presidio (large) and supports
Python **3.9–3.12** (it will not build on 3.13+). Create a 3.11 venv:

```sh
uv venv --python 3.11 benchmarks/.venv
VIRTUAL_ENV=benchmarks/.venv uv pip install -r benchmarks/requirements.txt
# Presidio loads en + zh spaCy pipelines; install both model wheels into the venv:
VIRTUAL_ENV=benchmarks/.venv uv pip install \
  https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl \
  https://github.com/explosion/spacy-models/releases/download/zh_core_web_sm-3.8.0/zh_core_web_sm-3.8.0-py3-none-any.whl
```

Then run (the first PromptInjection call downloads the HF model into the
transformers cache):

```sh
env -u VIRTUAL_ENV benchmarks/.venv/bin/python benchmarks/run_llm_guard.py
# --skip-ml drops the PromptInjection scanner (and its model download)
```

> Note: `python -m spacy download <model>` shells out to a package manager that
> may target the wrong environment — install the model **wheels directly** into
> `benchmarks/.venv` as above.

### 4. Merge

```sh
python3 benchmarks/compare.py             # rewrites the table region of RESULTS.md
```

## Methodology notes

- **Same corpus, same ground truth.** Both harnesses read `corpus/corpus.jsonl`
  and score precision/recall against the same per-sample labels.
- **Same model + threshold for PromptInjection.** Both run
  `deberta-v3-base-prompt-injection-v2` at threshold 0.5 (cerberust's default), so
  the ML row isolates `ort` vs `transformers`, not model or threshold choice.
- **Timing.** Cheap scanners are timed across repeated warm passes (after a
  warm-up that pays the one-time regex compilation); the ML scanner is timed once
  per sample because inference dominates. Absolute samples/sec is hardware- and
  load-dependent — read the speedup ratios, not the raw numbers.
