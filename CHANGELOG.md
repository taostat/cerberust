# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`wasm` feature: upgrade `wasmtime` from 44.0.3 to 49.0.1**, fixing
  RUSTSEC-2026-0222, RUSTSEC-2026-0269 and RUSTSEC-2026-0316.

### Changed

- **Minimum supported Rust version is now 1.96** (was 1.83), the MSRV of
  wasmtime 49.
- The `wasm` feature no longer pulls `anyhow` as a direct dependency; wasmtime
  now uses its own error type.

## [0.1.1]

### Fixed

- **`PiiScanner` credit-card detection now requires a plausible issuer prefix
  as well as a Luhn-valid digit run.** This keeps real Visa/Mastercard/Amex/
  Discover/Diners/JCB-style cards redacted, while avoiding false positives from
  machine identifiers such as Discord snowflakes that happen to pass Luhn.

### Changed

- **`StreamOutput` no longer borrows the `ScannerStack` for its lifetime.** It is
  built from a shared `&ScannerStack` and the stack is passed per call —
  `push(&mut stack, chunk)` and `finish(&mut stack)` — so one runner can be held
  across many independent async frame callbacks (a per-frame SSE/JSON consumer)
  without a long-lived borrow. Hold-back, no-leak, and streaming-≡-unary
  guarantees are unchanged.

### Added

- **Content-free per-scanner report metrics.** Each `ScanEntry` now carries a
  `ScanMetrics` alongside its `valid`/`risk` verdict: `detections`, `redacted`,
  `restored`, `blocked`, a `by_entity_type` map of entity-type label → count, and
  `latency_us`. The `ScannerStack` derives these in its run loop (timing each
  `scan` and diffing the vault's type-keyed tallies), so the `Scanner::scan`
  surface stays a pure `text -> Verdict`. Every field is a count, a verdict, or a
  closed-vocabulary label — never matched content — so a report is safe to log or
  emit as metrics wholesale.
- **`RestoreEncoder` restore hook.** A caller-supplied transform applied to each
  restored original before it is spliced back into the output, installed via
  `ScannerStack::set_restore_encoder` — e.g. to JSON-escape a rehydrated value
  placed inside a JSON string in an SSE stream. It sees only the restored
  original, never the surrounding model text. The default is
  `RestoreEncoder::identity` (originals verbatim), so restore is unchanged unless
  a hook is set.

## [0.1.0]

Initial public release.

### Added

- **Two-tier architecture.** An inner `Scanner` + `ScannerStack` tier (pure
  `scan(text, ctx) -> Verdict` functions run in order, threading rewritten text
  and a shared `Vault`, short-circuiting on a blocking scanner, aggregating risk
  as the max, and restoring in LIFO order on the output path) under an outer
  `Middleware` + `MiddlewareChain` tier (a Vercel-AI-SDK-shaped interface that
  nests middlewares around a model call).
- **`GuardrailRunner` middleware** — wraps a `ScannerStack`, scanning input
  before the model and output after.
- **`TierPolicy`** — a fail-closed privacy-tier router guard that refuses to
  downgrade a confidential request to a model whose provider would see the
  prompt.
- **`Vault`** — a request-scoped placeholder↔original map with nonce-tagged
  sentinels and `Zeroize`-on-drop, with reversibility as a per-scanner
  `RestorePolicy` (`RoundTrip` vs `OneWay`) rather than a property of the data
  type.
- **Scanner suite:**
  - `PiiScanner` — email, phone, credit card (Luhn), IP, US SSN; reversible
    (`RoundTrip`).
  - `SecretScanner` — AWS/GitHub/Stripe/OpenAI/Google keys, Slack webhooks, PEM
    private keys, labelled `key=value`, URL credentials, high-entropy tokens;
    `OneWay` by default.
  - `RegexScanner` — caller-supplied patterns under per-entity labels, with
    configurable `RestorePolicy` and direction.
  - `BanSubstringsScanner` — block or redact configured literal substrings.
  - `BanTopicsScanner` — keyword-per-topic blocking.
  - `TokenLimitScanner` — reject over-budget input.
  - `RestoreScanner` — output-path restore for `RoundTrip` redactions.
- **Streaming output runner** — per-scanner `HoldBack` contract
  (`TokenBoundary` / `MaxLen(n)` / `WholeStream`) driving a byte-fed
  `regex-automata` DFA so a pattern straddling two chunks is never half-emitted;
  hold-back is bounded conservatively (hold while a match is live, flush when it
  goes dead).
- **ReDoS safety** — all built-in and caller-supplied patterns compile on the
  linear-time `regex` / `regex-automata` engines, so no input can cause
  catastrophic backtracking.
- **ML prompt-injection scanner** (`prompt-injection` feature, off by default) —
  `PromptInjectionScanner`, a DeBERTa-v3 sequence classifier
  (`protectai/deberta-v3-base-prompt-injection-v2`) run via ONNX Runtime through
  `ort`, blocking when `P(injection)` crosses a threshold (default 0.5). The
  ~739 MB weights are not vendored; `scripts/fetch-model.sh` downloads them.
- **Sandboxed WASM guards** (`wasm` feature, off by default) — `WasmScanner`
  loads a third-party guard compiled to a WebAssembly Component
  (`wit/guard.wit`: `scan(text) -> verdict`) and runs it as an ordinary
  `Scanner`. The guest is instantiated against an import-less `wasmtime` linker
  — no WASI, filesystem, network, or clock — so egress is impossible by
  construction, and a component importing any host capability is rejected at
  load.
- **Benchmark harness** (`benchmarks/`) — head-to-head precision/recall and
  throughput against Python's `llm-guard` over a shared labelled corpus.

[Unreleased]: https://github.com/taostat/cerberust/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/taostat/cerberust/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/taostat/cerberust/releases/tag/v0.1.0
