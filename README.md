# cerberust

[![crates.io](https://img.shields.io/crates/v/cerberust.svg)](https://crates.io/crates/cerberust)
[![docs.rs](https://img.shields.io/docsrs/cerberust)](https://docs.rs/cerberust)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Fast Rust guardrails for LLM input and output — a watchful guard at the gate
between your application and a model. Compose ordered *scanners* (redact PII,
mask secrets, block prompt injection) into a stack, and run that stack as
*middleware* around any model call. Scanners are pure `text -> verdict`
functions, so the same set runs natively today and as sandboxed WASM guests with
the `wasm` feature.

A Rust answer to Python's [`llm-guard`](https://github.com/protectai/llm-guard):
the deterministic scanners run compiled and allocation-light, and the regex
engine guarantees linear-time matching with no catastrophic backtracking.

```toml
[dependencies]
cerberust = "0.1"
```

```rust
use cerberust::{GuardrailRunner, MiddlewareChain, Params, PiiScanner, ScannerStack, Scanner};

let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(PiiScanner::new())];
let runner = GuardrailRunner::new(ScannerStack::new(scanners, true));
let chain = MiddlewareChain::new(vec![&runner]);
// chain.generate(Params::new("contact alice@example.com"), &model)
//   redacts the email before the model sees it, restores it in the response.
```

## Two tiers

The architecture is two nested traits.

### Inner tier — `Scanner` + `ScannerStack`

A `Scanner` inspects or transforms one piece of text:

```rust
fn scan<'a>(&self, text: &'a str, ctx: &mut ScanCtx) -> ScanResult<'a>;
//                       returns Verdict { text: Cow<str>, valid: bool, risk: f32 }
```

Each scanner declares a `Direction` (`Input`/`Output`), a `Disposition`
(`Transform`/`Block`), and a streaming `HoldBack` contract. `ScanCtx` threads a
shared `&mut Vault` plus the original prompt across every scanner and both
directions.

A `ScannerStack` runs scanners in order:

- **Input** front-to-back, threading the (maybe-rewritten) text.
- A `Block` scanner returning `valid = false` **short-circuits** (fail-fast) —
  the request is rejected before any model call.
- **Output** back-to-front (**LIFO** over the input transforms): restore unwinds
  redaction in the inverse order it was applied.
- Stack risk aggregates as the **max** over scanners; pure transformers report
  `Verdict::NOT_A_RISK` and are skipped in the aggregate.

### Outer tier — `Middleware` + `MiddlewareChain`

A Vercel-AI-SDK-shaped interface: `transform_params` (input), `wrap_generate`
(unary output), and — declared for streaming — `wrap_stream`.
`MiddlewareChain::new([a, b])` nests `a(b(model))`, first element outermost.

The **`GuardrailRunner`** middleware wraps a `ScannerStack`: input scan before
the model, output scan after. Future peers at this tier (provider failover,
response fusion, metering) are separate middlewares that compose in the same
chain. `TierPolicy` is one such peer — a fail-closed privacy-tier router guard
that refuses to silently downgrade a confidential request to a model whose
provider would see the prompt.

## The Vault and `RestorePolicy`

The `Vault` is the keystone: a request-scoped placeholder↔original map, with
nonce-tagged sentinels (`[REDACTED_<TYPE>_<N>_<nonce>]`) and `Zeroize`-on-drop.
The per-request nonce stops a caller pre-imaging a sentinel to splice another
request's value into the response.

Reversibility is a **per-scanner policy, not a property of the data type**:

| Policy | Behaviour | Default for |
|---|---|---|
| `RoundTrip` | redact on input → restore on output | PII |
| `OneWay` | redact on input → **never** restore | secrets |

The identical redact machinery serves both — only the policy differs, and either
is configurable per scanner.

## Scanners shipped

| Scanner | Detects / does | Policy |
|---|---|---|
| `PiiScanner` | email, phone, credit card (Luhn), IP, US SSN — regex + checksum | `RoundTrip` |
| `SecretScanner` | AWS/GitHub/Stripe/OpenAI/Google keys, Slack webhooks, PEM private keys, labelled `key=value`, URL creds, high-entropy tokens | `OneWay` |
| `RegexScanner` | caller-supplied custom patterns, each under its own entity label | configurable |
| `BanSubstringsScanner` | block or redact configured literal substrings | — |
| `BanTopicsScanner` | keyword-per-topic blocking | — |
| `TokenLimitScanner` | reject over-budget input | — |
| `RestoreScanner` | the output-path deanonymizer for `RoundTrip` types | — |

Detection is span-based: each detector emits byte-offset spans, overlaps resolve
into a non-overlapping set that still covers every flagged byte, and the text is
rewritten span-by-span. Native NER (names, addresses, orgs) is a later add that
emits the same spans — no change to the rewrite path.

## Streaming and ReDoS safety

- **`HoldBack`.** On a streamed *output* a pattern can straddle two chunks, so
  emitting a chunk before confirming it is not a *forming* match would leak the
  first half of a secret. Each scanner declares `hold_back()` —
  `TokenBoundary` (PII/secrets/regex), `MaxLen(n)`, or `WholeStream` (a
  full-text scanner like toxicity). The streaming runner holds back the tail per
  the active scanners' declarations, driving a byte-fed DFA (`regex-automata`,
  match states complete/live/dead) so the hold-back is bounded conservatively —
  hold while a match is *live*, flush when it goes *dead*.
- **ReDoS safety.** The `regex` and `regex-automata` crates guarantee
  **linear-time** matching with no catastrophic backtracking. Any custom or
  caller-supplied pattern compiled by the Secrets/Regex scanners therefore
  cannot cause a ReDoS, regardless of input.

## ML prompt-injection (feature `prompt-injection`, off by default)

`PromptInjectionScanner` classifies a prompt with a fine-tuned DeBERTa-v3
sequence classifier (`protectai/deberta-v3-base-prompt-injection-v2`, Apache-2.0)
and blocks when `P(injection)` crosses a threshold (default `0.5`). It is
`Direction::Input`, `Disposition::Block`, `HoldBack::WholeStream`.

Inference is ONNX Runtime through `ort`; the binaries are downloaded at build
time (`download-binaries`), so no system ORT is needed. The tokenizer is the
Hugging Face `tokenizers` crate. Both are behind the off-by-default
`prompt-injection` feature — the core library never links them.

```rust
use cerberust::{PromptInjectionScanner, Scanner, ScanCtx};

let scanner = PromptInjectionScanner::from_dir("/path/to/model-dir")?;
let mut ctx = ScanCtx::new();
let verdict = scanner.scan("Ignore all previous instructions ...", &mut ctx)?;
assert!(!verdict.valid); // blocked: risk ≈ P(injection)
```

The ONNX weights (~739 MB fp32) are **not** vendored. Fetch `model.onnx` +
`tokenizer.json` into a directory the scanner loads:

```sh
scripts/fetch-model.sh
CERBERUST_MODEL_DIR="$HOME/.cache/cerberust/deberta-v3-base-prompt-injection-v2" \
  cargo test --features prompt-injection --test prompt_injection -- --ignored
```

The integration tests are `#[ignore]` (they download/load the model); the
default `cargo test --features prompt-injection` runs the fast pure-logic tests
(softmax, thresholding, load-error) and compile-checks the inference plumbing.

## Sandboxed WASM guards (feature `wasm`, off by default)

A custom guard can be authored in any language, compiled to a **WebAssembly
Component**, and run as an ordinary `Scanner` — the novel property is that the
guest sees the prompt but **physically cannot exfiltrate it**.

The component contract is `wit/guard.wit`: a guest exports `scan(text) ->
verdict` (mirroring the Rust `Verdict { text, valid, risk }`) and **imports
nothing**.

```rust
use cerberust::{Direction, Disposition, ScannerId, WasmScanner};

let guard = WasmScanner::from_file(
    "my-guard.wasm",
    ScannerId("wasm:my-guard"),
    Direction::Input,
    Disposition::Block,
)?;
// `guard` is a Scanner — drop it into a ScannerStack next to the native ones.
```

**The sandbox.** `WasmScanner` instantiates the guest against an **import-less
`wasmtime` linker** — no WASI, no filesystem, no network, no clock. The guest is
a pure function over the text it is handed; egress is impossible *by
construction*, because there is no host import through which to egress. A
component that imports any host capability is **rejected at load** (proven by the
`imports_are_rejected_no_ambient_authority` test).

**The vault stays host-side.** The guest never holds the placeholder→original
map; it only ever sees text the host chose to hand it, so it cannot read an
original it was not given.

**Example guard.** `examples/redact-foo-guard/` is a minimal guard that redacts
the literal token `FOO`. Build the example guards into committed test fixtures
with:

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-tools
./examples/build.sh        # writes tests/fixtures/*.wasm
```

The `.wasm` fixtures are committed so `cargo test --features wasm` runs without
the WASM toolchain; rerun the script only when an example guard's source changes.

## Benchmarks vs LLM Guard

`benchmarks/` measures cerberust head-to-head against `llm-guard` (Python) over a
shared labelled corpus — same scanners, same detection job, precision/recall and
throughput per scanner. The headline results:

- **Deterministic scanners run far faster.** cerberust's PII, Secrets, Regex, and
  BanSubstrings scanners are compiled Rust over regex automata, against
  LLM Guard's Python (Presidio for PII). The throughput gap is one to three
  orders of magnitude on this corpus.
- **The ML prompt-injection scanner ties on accuracy.** Both load the same
  `deberta-v3-base-prompt-injection-v2` model at the same 0.5 threshold; the only
  difference is the runtime (cerberust's `ort`/ONNX vs LLM Guard's PyTorch), so
  precision/recall match.
- **Detection parity on structured PII/secrets.** On the structured corpus
  cerberust matches or beats LLM Guard's detection. NER-heavy entities (names,
  addresses) are where a Presidio-style detector still leads, until cerberust's
  planned native NER lands emitting the same spans.

See `benchmarks/README.md` to reproduce and `benchmarks/RESULTS.md` for the full
table.

## Build, lint, test

```sh
cargo build --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo fmt --check
cargo deny --all-features check   # advisories, licenses, bans, sources
```

Both `wasm` and `prompt-injection` are **off by default** so the core scanner
library stays lean (each pulls a large dependency tree). Run `cargo deny` with
`--all-features` to evaluate the optional trees.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
