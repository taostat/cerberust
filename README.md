<p align="center">
  <img src="assets/cerberust-mark.svg" alt="cerberust" width="116" />
</p>

<h1 align="center">cerberust</h1>

<p align="center"><strong>Ship LLM features without shipping your users' secrets.</strong></p>

<p align="center">
  <a href="https://crates.io/crates/cerberust"><img src="https://img.shields.io/crates/v/cerberust.svg" alt="crates.io" /></a>
  <a href="https://docs.rs/cerberust"><img src="https://img.shields.io/docsrs/cerberust" alt="docs.rs" /></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg" alt="license: MIT OR Apache-2.0" /></a>
</p>

Your model will be handed PII it shouldn't keep, fed API keys pasted into a
prompt, and probed with jailbreaks. cerberust is the fast layer that sits between
your app and the model and stops it — redacting personal data, masking secrets so
they never reach a provider, and blocking prompt injection before a single token
is generated.

It's a Rust answer to Python's
[`llm-guard`](https://github.com/protectai/llm-guard): the same idea — composable
*scanners* you stack in front of a model — built to run compiled, allocation-light,
and **streaming-safe**, with a regex engine that can't be tripped into
catastrophic backtracking.

> cerberust began as the guardrail layer for **[gm](https://saygm.com)** —
> confidential, TEE-sealed LLM inference — and is developed in the open as a
> standalone library.

---

## Why cerberust

- **Fast.** The deterministic scanners run compiled Rust over regex automata —
  one to four orders of magnitude faster than a Python guardrail stack on the same
  corpus ([benchmarks](docs/benchmarks.md)).
- **Streaming-safe by design.** A secret split across two streamed chunks is never
  half-emitted. The runner holds back exactly the bytes that could still be
  completing a match, and nothing more.
- **Redaction with restore.** PII is tokenized on the way in and
  put back on the way out — your user still reads their own email address in the
  reply, but the model never saw it. Secrets get the same treatment and are
  *never* restored.
- **Cache-stable placeholders, optionally.** By default each request mints a fresh
  random nonce, so the same value redacts differently every time. Opt into
  deterministic mode and a value's placeholder becomes a keyed function of the
  value — byte-identical across requests — so a replayed conversation prefix
  redacts the same way turn after turn and stays friendly to a provider's prompt
  cache ([deterministic redaction](docs/scanners/restore.md#cache-stable-deterministic-redaction)).
- **Composable.** Scanners are pure `text -> verdict` functions. Stack them in any
  order; the stack threads the rewritten text and a shared vault through every one.
- **Extensible and sandboxed.** Bring your own patterns with a custom regex
  scanner, or write a guard in any language, compile it to WebAssembly, and run it
  with **no filesystem, network, or clock** — it physically cannot exfiltrate the
  text it inspects.
- **No surprises.** No catastrophic backtracking (linear-time matching,
  guaranteed), no secrets leaking through error paths, request-scoped state
  zeroized on drop.

## 30-second quickstart

```toml
[dependencies]
cerberust = "0.1"
```

```rust
use cerberust::{
    GuardrailRunner, MiddlewareChain, Params, PiiScanner, RestoreScanner,
    Scanner, ScannerStack, SecretScanner,
};

// Build a stack: redact PII, mask secrets, restore PII on the way back.
let scanners: Vec<Box<dyn Scanner>> = vec![
    Box::new(PiiScanner::new()),       // email/phone/card/IP/SSN/IBAN -> tokenized
    Box::new(SecretScanner::new()),    // API keys/secrets       -> masked, one-way
    Box::new(RestoreScanner::for_pii()), // PII rehydrated in the response
];
let runner = GuardrailRunner::new("guard", ScannerStack::new(scanners, true));
let chain = MiddlewareChain::new(vec![&runner]);

// chain.generate(Params::new("email alice@example.com, key AKIA…"), &model)
//   -> the model sees redacted text; the email comes back in the reply,
//      the secret never does.
```

`&model` is anything implementing the `Model` trait — point it at your existing
client. See [Getting started](docs/getting-started.md) for the full loop,
including streaming.

## The scanner lineup

**cerberust is pass-through by default.** Nothing runs until you add it to a
`ScannerStack`, so every scanner is opt-in by construction — you compose exactly the
ones you want. The *mode* below is what each does once you include it.
(`PromptInjectionScanner` and `WasmScanner` additionally sit behind off-by-default
cargo features, since they pull heavy dependencies.)

| Scanner | Protects you from | Mode when added |
|---|---|---|
| [`PiiScanner`](docs/scanners/pii.md) | leaking emails, phone numbers, credit cards, IPs, SSNs, and IBANs to a model provider | redact (round-trip — restore in the reply) |
| [`SecretScanner`](docs/scanners/secrets.md) | API keys, tokens, and private keys pasted into a prompt reaching a provider or being echoed back | redact, one-way (never restored) |
| [`RegexScanner`](docs/scanners/regex.md) | your *own* sensitive formats — ticket ids, account numbers, internal tokens | redact your patterns |
| [`BanSubstringsScanner`](docs/scanners/ban-substrings.md) | specific phrases you never want in a prompt or a reply | block on match |
| [`BanTopicsScanner`](docs/scanners/ban-topics.md) | whole subjects you've ruled out, defined by keywords | block on match |
| [`TokenLimitScanner`](docs/scanners/token-limit.md) | oversized prompts blowing your context budget or your bill | block when over the limit |
| [`RestoreScanner`](docs/scanners/restore.md) | — (the output half that puts redacted PII back in the reply) | restores a round-trip scanner |
| [`PromptInjectionScanner`](docs/scanners/prompt-injection.md) | jailbreaks and "ignore your instructions" attacks | block · needs `prompt-injection` feature |
| [`WasmScanner`](docs/scanners/wasm-guards.md) | running an *untrusted* custom guard safely (sandboxed, no egress) | runs your guard · needs `wasm` feature |

## Benchmarks at a glance

Measured head-to-head against `llm-guard` on a shared 290-sample labeled corpus
(Apple Silicon, macOS). Throughput is hardware-dependent — the **ratios** are the
durable signal.

| Scanner | cerberust | llm-guard | speedup |
|---|---|---|---|
| PII | 1.34M/s | 65/s | ~20,000× |
| Secrets | 1.31M/s | 1.4k/s | ~940× |
| Regex | 7.81M/s | 124.5k/s | ~63× |
| Ban-substrings | 1.16M/s | 135.5k/s | ~9× |
| Prompt-injection (same model) | 126/s | 96/s | ~1× (tie) |

On detection, cerberust scores perfect precision/recall on the structured PII and
secrets corpus where `llm-guard` misses some formats; the ML prompt-injection
scanner is byte-identical (same model, same threshold). Full methodology and the
honest caveats are in [docs/benchmarks.md](docs/benchmarks.md).

## Install

```toml
[dependencies]
cerberust = "0.1"
```

Two heavy capabilities are **off by default** so the core stays lean:

```toml
# ML prompt-injection (pulls ONNX Runtime + a tokenizer; downloads a ~739 MB model)
cerberust = { version = "0.1", features = ["prompt-injection"] }

# Sandboxed WASM guards (pulls the wasmtime runtime)
cerberust = { version = "0.1", features = ["wasm"] }
```

## Documentation

- [Introduction & threat model](docs/index.md)
- [Getting started](docs/getting-started.md)
- [Core concepts](docs/concepts.md) — scanners, the stack, middleware, the vault, streaming
- [Scanner reference](docs/scanners/) — one page per scanner
- [Benchmarks](docs/benchmarks.md)

## From the team behind gm

cerberust is the open-source guardrail library from **[gm](https://saygm.com)** —
confidential LLM inference on Bittensor. Point your existing OpenAI, Anthropic, or
Gemini SDK at the gm gateway and get identical behavior, sealed inside an Intel TDX
enclave so no operator or host ever sees your prompts.

<p align="center"><strong><a href="https://saygm.com">→ saygm.com</a></strong></p>

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.

cerberust ports the scanner-and-stack design pioneered by
[`llm-guard`](https://github.com/protectai/llm-guard) (Protect AI) to Rust. The
threat model, the scanner lineup, and the prompt-injection model are its
inspiration — with gratitude.
