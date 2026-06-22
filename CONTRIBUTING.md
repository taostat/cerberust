# Contributing to cerberust

Thanks for your interest in improving `cerberust`. This guide covers the
build/test/lint loop, how to add a scanner, and the licensing terms for
contributions.

## Build, test, lint

The full gate CI runs (and the bar a PR must clear):

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test                                   # default features
cargo test --features wasm,prompt-injection  # optional-feature trees
cargo deny --all-features check              # advisories, licenses, bans, sources
```

`wasm` and `prompt-injection` are off by default so the core library stays lean
— each pulls a large dependency tree (wasmtime/cranelift; ort/ONNX Runtime,
tokenizers). The four `prompt-injection` integration tests are `#[ignore]`'d
because they load the ~739 MB DeBERTa-v3 weights; CI never runs them. To run
them locally, fetch the model first:

```sh
scripts/fetch-model.sh
CERBERUST_MODEL_DIR="$HOME/.cache/cerberust/deberta-v3-base-prompt-injection-v2" \
  cargo test --features prompt-injection --test prompt_injection -- --ignored
```

The WASM tests run against committed `.wasm` fixtures, so the WASM toolchain is
not required to run `cargo test --features wasm`. Rebuild the fixtures only when
an example guard's source changes (see the WASM section of the README).

## Adding a scanner

A scanner implements the `Scanner` trait (`src/scanner/mod.rs`): `id`,
`direction`, `disposition`, `scan`, and an optional `hold_back` for streaming.

1. Add a module under `src/scanners/` and implement `Scanner`.
2. Reuse the shared detect-and-redact machinery (collect byte-offset spans →
   resolve overlaps → intern into the `Vault` → rewrite span-by-span) if your
   scanner masks text. Pick a `RestorePolicy` (`RoundTrip` vs `OneWay`) rather
   than special-casing the data type. A block-only scanner rejects instead of
   rewriting and returns `valid = false`.
3. Re-export the public type from `src/scanners/mod.rs` and, if it is part of
   the crate's public surface, from `src/lib.rs`.
4. Declare the streaming `hold_back()` contract so the streaming runner bounds
   hold-back correctly on the output path.
5. Add tests — unit tests for detection and, where the behaviour spans chunks
   or round-trips, an integration test under `tests/`. Cover the edges (empty
   input, boundaries, overlapping spans), not only the happy path.
6. Update the README's "Scanners shipped" table and the `CHANGELOG.md`.

Keep new dependencies behind a feature flag if they are large or pull native
code, matching how `wasm` and `prompt-injection` are gated today.

## Commit conventions

- Imperative mood, concise subject line (≤72 chars), one logical change per
  commit.
- Keep `cargo fmt` and `cargo clippy` clean — CI rejects warnings.

## Licensing of contributions

`cerberust` is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at the user's option. By submitting a contribution
you agree that it is licensed under the same dual terms, per the Apache-2.0
license's inbound-equals-outbound contribution clause (section 5). No separate
CLA is required.
