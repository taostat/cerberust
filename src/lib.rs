//! `cerberust` — fast Rust guardrails for LLM input/output, a Rust `llm-guard`.
//!
//! # Two tiers
//!
//! - **Inner — [`Scanner`] + [`ScannerStack`].** A [`Scanner`] is a pure
//!   `scan(text, &mut ScanCtx) -> Verdict`. The [`ScannerStack`] runs scanners
//!   in order, threads the (maybe-rewritten) text and a shared [`Vault`],
//!   short-circuits on a `Block` scanner returning `valid = false`, aggregates
//!   risk as the max, and on the output path restores in LIFO order.
//! - **Outer — [`Middleware`] + [`MiddlewareChain`].** A Vercel-AI-SDK-shaped
//!   interface that nests middlewares around a model call. One middleware is
//!   implemented — the [`GuardrailRunner`] — which wraps a [`ScannerStack`]
//!   (input scan before, output scan after).
//!
//! The [`Vault`] is the keystone: a request-scoped placeholder↔original map,
//! zeroized on drop, with nonce-tagged sentinels. Reversibility is a per-scanner
//! [`RestorePolicy`] (`RoundTrip` vs `OneWay`), not a property of the data type.
//!
//! # Scanners shipped
//!
//! - [`PiiScanner`](scanners::PiiScanner) — reversible PII tokenization
//!   (`RoundTrip`).
//! - [`SecretScanner`](scanners::SecretScanner) — secret detection (`OneWay` by
//!   default).
//! - [`RestoreScanner`](scanners::RestoreScanner) — the output-path restore for
//!   `RoundTrip` redactions.
//! - [`RegexScanner`](scanners::RegexScanner) — caller-supplied custom patterns
//!   (`ReDoS`-safe, configurable `RestorePolicy` and direction).
//! - [`BanSubstringsScanner`](scanners::BanSubstringsScanner) — block or redact
//!   configured literal substrings.
//! - [`BanTopicsScanner`](scanners::BanTopicsScanner) — keyword-per-topic
//!   blocking.
//! - [`TokenLimitScanner`](scanners::TokenLimitScanner) — reject over-budget
//!   input.
//!
//! # ML prompt-injection (feature `prompt-injection`)
//!
//! With the `prompt-injection` feature,
//! [`PromptInjectionScanner`](scanners::PromptInjectionScanner) classifies a
//! prompt with a DeBERTa-v3 sequence classifier
//! (`protectai/deberta-v3-base-prompt-injection-v2`, the model `llm-guard`
//! ships) and blocks when `P(injection)` crosses a threshold. Inference is ONNX
//! Runtime via `ort` (binaries downloaded at build time, no system ORT); the
//! tokenizer is the Hugging Face `tokenizers` crate. The ~739 MB weights are not
//! vendored — `scripts/fetch-model.sh` downloads them into a directory the
//! scanner loads.
//!
//! # Sandboxed WASM guards (feature `wasm`)
//!
//! With the `wasm` feature, [`WasmScanner`](wasm::WasmScanner) loads a
//! third-party guard compiled to a WebAssembly Component (`wit/guard.wit`:
//! `scan(text) -> verdict`) and runs it as an ordinary [`Scanner`] — same
//! `scan(text, ctx) -> Verdict` surface as the native scanners. The guest is
//! instantiated against an import-less `wasmtime` linker, so it has no
//! filesystem, network, or clock: a custom guard sees the text it is handed and
//! returns a verdict, and can do nothing else. Egress is impossible by
//! construction — a component that imported any host capability is rejected at
//! load.

pub mod middleware;
pub mod scanner;
pub mod scanners;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use middleware::{
    Chunk, ChunkSink, ChunkSource, GuardrailRunner, Middleware, MiddlewareChain, MiddlewareError,
    Model, ModelSpec, Params, PrivacyTier, StreamModel, TierPolicy,
};
pub use scanner::{
    Blocked, Direction, Disposition, HoldBack, RestorePolicy, ScanCtx, ScanError, ScanReport,
    ScanResult, Scanner, ScannerId, ScannerStack, Threshold, Vault, Verdict,
};
pub use scanners::{
    BanSubstringsScanner, BanTopicsScanner, PiiScanner, RegexRule, RegexScanner, RestoreScanner,
    SecretScanner, TokenLimitScanner, Topic,
};
#[cfg(feature = "prompt-injection")]
pub use scanners::{PromptInjectionLoadError, PromptInjectionScanner};
#[cfg(feature = "wasm")]
pub use wasm::{WasmLoadError, WasmScanner};
