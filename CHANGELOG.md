# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `PiiScanner` now detects `+`-prefixed international phone numbers of 7–15
  digits in any grouping (for example, `+44 7700 900123` or `+33 1 23 45 67 89`).
  Previously only US-style 3-3-4 grouping was matched, so most non-US numbers
  passed through unredacted.

## [0.2.1]

### Added

- A scaling benchmark for regex, PII, secret and substring redaction, covering
  dense and isolated matches across 8–128 KiB inputs (`cargo bench --bench scaling`).

### Fixed

- `BanTopicsScanner` no longer panics after rejecting a match at either ASCII
  word boundary for a keyword beginning with a multi-byte UTF-8 character,
  even when no later match exists (for example, `élan` in `xélan` or `élanx`).

## [0.2.0]

### Security

- **`wasm` feature: move `wasmtime` from 44.0.3 to the 36.x long-term-support
  line (36.0.16)**, fixing RUSTSEC-2026-0222, RUSTSEC-2026-0269 and
  RUSTSEC-2026-0316.

### Added

- **`SecretScanner` recognizes 200 vendor credential formats ported from
  gitleaks v8.30.1**, generated from the vendored upstream config and matched
  with gitleaks' keyword prefilter, secret group, entropy minimum and
  allowlists. Generic, identifier, public-key and path-scoped rules are
  excluded (listed with reasons in `EXCLUDED`).
- **Taostats API keys** (`gm_live_`, `bm_live_`, `ts_live_`, `tao-<uuid>:<sig>`).
- **BIP39 seed phrases**, redacted as `SEED_PHRASE`: checksum-valid 12–24 word
  windows, and runs of exactly a mnemonic's length even with a bad checksum.
  Held back on streams so a phrase is never split.
- `Scanner::stream_hold_floor`: a scanner can set its own streaming hold point.
- A negative corpus and precision test requiring zero detections from the new
  rules on ordinary prompt content.

### Fixed

- The streaming runner no longer flushes part of a token. A shorter pattern
  alive inside a longer key could previously flush the key's prefix.

### Changed

- **Minimum supported Rust version is now 1.88** (was 1.83). wasmtime 36
  requires 1.86; `ort` (`prompt-injection` feature) and current `encoding_rs`
  releases (`wasm` feature) require 1.88.
- The streaming hold-back DFA is compiled once per pattern set and reused across
  streams, and keeps its lazy state cache across pushes.
- Secret-scanner throughput on the benchmark corpus is a little under half of
  0.1.1's (~570k samples/s), the cost of the added rules. Ported rules run only
  in windows around their keyword hits.
- A span matched by both an original vendor pattern and a ported rule keeps the
  original type name; spans only the new rules find use new type names (the
  gitleaks rule id upper-cased).

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

[Unreleased]: https://github.com/taostat/cerberust/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/taostat/cerberust/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/taostat/cerberust/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/taostat/cerberust/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/taostat/cerberust/releases/tag/v0.1.0
