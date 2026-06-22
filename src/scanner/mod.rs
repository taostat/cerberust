//! The inner tier: the [`Scanner`] trait, the request-scoped [`ScanCtx`], and
//! the [`ScannerStack`] that composes scanners in order.
//!
//! A [`Scanner`] is a pure `scan(text, &mut ScanCtx) -> Verdict`. The stack
//! threads the (maybe-rewritten) text and a shared [`Vault`] through an ordered
//! list, short-circuits on a `Block` scanner returning `valid = false`, and
//! aggregates risk as the max. On the output direction it restores in LIFO
//! order — the inverse of the input transforms.

pub mod detect;
pub mod substitute;
pub mod types;
pub mod vault;

use thiserror::Error;

pub use types::{
    Direction, Disposition, HoldBack, RestorePolicy, ScanResult, ScannerId, Threshold, Verdict,
};
pub use vault::Vault;

/// An error a scanner may return. Distinct from a `Block` verdict: a `ScanError`
/// is a *malfunction* (a detector failed), whereas `valid = false` is a working
/// scanner doing its job. A malfunction on the caller-facing output path should
/// fail open (forward raw) — that policy lives in the middleware, not here.
#[derive(Debug, Error)]
pub enum ScanError {
    /// A scanner's internal detector or transform failed.
    #[error("scanner {scanner} failed: {reason}")]
    Detector { scanner: ScannerId, reason: String },
}

/// Request-scoped state threaded across every scanner and both directions.
///
/// Owns the [`Vault`] — the one secret that must stay host-side — so
/// vault/restore is a stack capability, not any single scanner's private field.
#[non_exhaustive]
pub struct ScanCtx {
    /// The shared placeholder↔original map. Any scanner may intern into it on
    /// input; restore reads it on output.
    pub vault: Vault,
    /// The original prompt, set once on the input path. Output scanners
    /// that need it (relevance, factual-consistency, later additions) read it
    /// here — this carries LLM Guard's output `scan(prompt, output)` second
    /// argument without widening the per-call signature.
    pub prompt: Option<String>,
}

impl ScanCtx {
    /// A fresh context with an empty vault and no prompt.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vault: Vault::new(),
            prompt: None,
        }
    }

    /// Set the original prompt (called once on the input path).
    #[must_use]
    pub fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }
}

impl Default for ScanCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// One scanner inspects or transforms text.
///
/// `scan` is the only hot-path method and maps 1:1 to the planned WASM `scan`
/// export: pure text-in/verdict-out, no I/O, no clock, no ambient randomness
/// (nonces are minted by the host [`Vault`], not the scanner).
pub trait Scanner: Send + Sync {
    /// Stable identifier (e.g. `native:pii`).
    fn id(&self) -> ScannerId;

    /// Which path this scanner runs on.
    fn direction(&self) -> Direction;

    /// Whether this scanner may block, or only transforms.
    fn disposition(&self) -> Disposition;

    /// Inspect/transform `text`. The borrowed [`Verdict::text`] lets a pure
    /// detector return the input with zero allocation.
    ///
    /// # Errors
    /// Returns a [`ScanError`] if the scanner's detector or transform
    /// malfunctions (distinct from a `Block` verdict, which is `valid = false`).
    fn scan<'a>(&self, text: &'a str, ctx: &mut ScanCtx) -> ScanResult<'a>;

    /// Token-inflation bound for an admission estimate (sentinels grow the
    /// request). Default `1.0`.
    fn max_input_inflation_ratio(&self) -> f64 {
        1.0
    }

    /// How much trailing text a streaming OUTPUT runner must hold back for this
    /// scanner. Default [`HoldBack::TokenBoundary`] — most patterns are
    /// token-bounded. A full-text scanner overrides to [`HoldBack::WholeStream`].
    ///
    /// Consumed by the streaming runner
    /// ([`stream`](crate::middleware::stream)): an incremental scanner
    /// (`TokenBoundary` / `MaxLen`) is driven by a byte-fed DFA built from its
    /// [`Scanner::stream_patterns`]; a `WholeStream` scanner forces buffer-and-
    /// gate (no token emits until the whole response is generated).
    fn hold_back(&self) -> HoldBack {
        HoldBack::TokenBoundary
    }

    /// The regex patterns this scanner redacts (or blocks on) when it runs on
    /// the OUTPUT path — the shapes the streaming runner's hold-back DFA must
    /// recognise so a match forming across a chunk boundary is never half-
    /// emitted. Default empty: a scanner that never redacts streamed output (a
    /// pure restore scanner, an input-only scanner) contributes nothing; the
    /// runner still holds back live vault sentinels for restore independently.
    ///
    /// These patterns drive *hold-back only*. The actual redaction is the
    /// scanner's own unary [`Scanner::scan`], run by the streaming runner over a
    /// prefix the DFA has already proven safe — so streaming output is identical
    /// to the unary `run_output` over the same bytes.
    fn stream_patterns(&self) -> Vec<String> {
        Vec::new()
    }
}

/// A single scanner's contribution to the [`ScanReport`].
#[derive(Debug, Clone, PartialEq)]
pub struct ScanEntry {
    pub scanner: ScannerId,
    pub valid: bool,
    pub risk: f32,
}

/// Per-request provenance: which scanners fired and their verdicts. This is the
/// "which guards fired" surface for an attestation/debug panel.
#[derive(Debug, Default, Clone)]
pub struct ScanReport {
    entries: Vec<ScanEntry>,
}

impl ScanReport {
    fn record(&mut self, scanner: ScannerId, verdict: &Verdict<'_>) {
        self.entries.push(ScanEntry {
            scanner,
            valid: verdict.valid,
            risk: verdict.risk,
        });
    }

    /// Every scanner that ran, in order.
    #[must_use]
    pub fn entries(&self) -> &[ScanEntry] {
        &self.entries
    }

    /// Stack-level risk: the max over scanners (a single high-risk scanner
    /// dominates). [`Verdict::NOT_A_RISK`] transformers are skipped.
    #[must_use]
    pub fn aggregate_risk(&self) -> f32 {
        self.entries
            .iter()
            .map(|e| e.risk)
            .filter(|r| *r >= 0.0)
            .fold(0.0_f32, f32::max)
    }
}

/// Why the stack rejected a request or response.
#[derive(Debug, Clone, PartialEq, Error)]
#[error("blocked by scanner {scanner} (risk {risk})")]
pub struct Blocked {
    pub scanner: ScannerId,
    pub risk: f32,
}

/// An ordered set of scanners for one direction, plus the shared context and
/// the accumulating report.
///
/// Split by direction so the middleware can hold one stack and drive input
/// before the model and output after. The same `ctx.vault` is shared across
/// both directions: input interns, output restores.
pub struct ScannerStack {
    input: Vec<Box<dyn Scanner>>,
    output: Vec<Box<dyn Scanner>>,
    fail_fast: bool,
    ctx: ScanCtx,
    report: ScanReport,
}

impl ScannerStack {
    /// Build a stack. Scanners are partitioned by their declared direction;
    /// `input` order is preserved, `output` is applied in reverse (LIFO).
    #[must_use]
    pub fn new(scanners: Vec<Box<dyn Scanner>>, fail_fast: bool) -> Self {
        let mut input = Vec::new();
        let mut output = Vec::new();
        for scanner in scanners {
            match scanner.direction() {
                Direction::Input => input.push(scanner),
                Direction::Output => output.push(scanner),
            }
        }
        Self {
            input,
            output,
            fail_fast,
            ctx: ScanCtx::new(),
            report: ScanReport::default(),
        }
    }

    /// The provenance report accumulated so far.
    #[must_use]
    pub fn report(&self) -> &ScanReport {
        &self.report
    }

    /// Read-only access to the shared context (e.g. to inspect the vault).
    #[must_use]
    pub fn ctx(&self) -> &ScanCtx {
        &self.ctx
    }

    /// The union of every output scanner's [`Scanner::stream_patterns`] — the
    /// shapes a streaming runner's hold-back DFA must recognise so a match
    /// forming across a chunk boundary is never half-emitted.
    #[must_use]
    pub fn output_stream_patterns(&self) -> Vec<String> {
        self.output
            .iter()
            .flat_map(|s| s.stream_patterns())
            .collect()
    }

    /// Whether any output scanner declares [`HoldBack::WholeStream`] — it cannot
    /// judge a chunk in isolation, so the streaming runner must buffer the whole
    /// response and gate before emitting anything (Mode B).
    #[must_use]
    pub fn output_needs_whole_stream(&self) -> bool {
        self.output
            .iter()
            .any(|s| s.hold_back() == HoldBack::WholeStream)
    }

    /// Run the input scanners front-to-back, threading the rewritten text. A
    /// `Block` scanner returning `valid = false` short-circuits to [`Blocked`]
    /// when `fail_fast` — the request is rejected before any model forward.
    ///
    /// The prompt is recorded on the context for output scanners to read.
    ///
    /// # Errors
    /// Returns [`Blocked`] when a `Block` scanner rejects and `fail_fast` is set.
    pub fn run_input(&mut self, text: &str) -> Result<String, Blocked> {
        self.ctx.prompt = Some(text.to_owned());
        let mut current = text.to_owned();
        for scanner in &self.input {
            // A malfunction on input is treated as clean-pass here; the
            // middleware owns the fail-open/closed policy.
            let Ok(verdict) = scanner.scan(&current, &mut self.ctx) else {
                continue;
            };
            self.report.record(scanner.id(), &verdict);
            let blocked = !verdict.valid && scanner.disposition() == Disposition::Block;
            current = verdict.text.into_owned();
            if blocked && self.fail_fast {
                return Err(Blocked {
                    scanner: scanner.id(),
                    risk: self.report.aggregate_risk(),
                });
            }
        }
        Ok(current)
    }

    /// Run the output scanners **back-to-front** (LIFO over the input vault),
    /// threading the rewritten text. Restore unwinds redaction in the inverse
    /// order it was applied. A failing `Block` output scanner short-circuits to
    /// [`Blocked`] when `fail_fast`.
    ///
    /// # Errors
    /// Returns [`Blocked`] when a `Block` scanner rejects and `fail_fast` is set.
    pub fn run_output(&mut self, text: &str) -> Result<String, Blocked> {
        let mut current = text.to_owned();
        for scanner in self.output.iter().rev() {
            let Ok(verdict) = scanner.scan(&current, &mut self.ctx) else {
                continue;
            };
            self.report.record(scanner.id(), &verdict);
            let blocked = !verdict.valid && scanner.disposition() == Disposition::Block;
            current = verdict.text.into_owned();
            if blocked && self.fail_fast {
                return Err(Blocked {
                    scanner: scanner.id(),
                    risk: self.report.aggregate_risk(),
                });
            }
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use std::borrow::Cow;

    use super::*;

    /// A scanner that uppercases on input and records a transform.
    struct Upper;
    impl Scanner for Upper {
        fn id(&self) -> ScannerId {
            ScannerId("test:upper")
        }
        fn direction(&self) -> Direction {
            Direction::Input
        }
        fn disposition(&self) -> Disposition {
            Disposition::Transform
        }
        fn scan<'a>(&self, text: &'a str, _ctx: &mut ScanCtx) -> ScanResult<'a> {
            Ok(Verdict::transformed(Cow::Owned(text.to_uppercase())))
        }
    }

    /// A block scanner that rejects any text containing "bad".
    struct BlockBad;
    impl Scanner for BlockBad {
        fn id(&self) -> ScannerId {
            ScannerId("test:blockbad")
        }
        fn direction(&self) -> Direction {
            Direction::Input
        }
        fn disposition(&self) -> Disposition {
            Disposition::Block
        }
        fn scan<'a>(&self, text: &'a str, _ctx: &mut ScanCtx) -> ScanResult<'a> {
            let risk = if text.to_lowercase().contains("bad") {
                1.0
            } else {
                0.0
            };
            Ok(Verdict::detected(text, risk, 0.5))
        }
    }

    #[test]
    fn input_threads_transformed_text() {
        let mut stack = ScannerStack::new(vec![Box::new(Upper)], true);
        assert_eq!(stack.run_input("hi").unwrap(), "HI");
    }

    #[test]
    fn block_scanner_short_circuits_fail_fast() {
        let mut stack = ScannerStack::new(vec![Box::new(BlockBad), Box::new(Upper)], true);
        let err = stack.run_input("this is bad").unwrap_err();
        assert_eq!(err.scanner, ScannerId("test:blockbad"));
        // Upper never ran — only the block scanner is in the report.
        assert_eq!(stack.report().entries().len(), 1);
    }

    #[test]
    fn clean_input_passes_all_scanners() {
        let mut stack = ScannerStack::new(vec![Box::new(BlockBad), Box::new(Upper)], true);
        assert_eq!(stack.run_input("all good").unwrap(), "ALL GOOD");
        assert!(stack.report().aggregate_risk().abs() < f32::EPSILON);
    }

    #[test]
    fn aggregate_risk_is_max_skipping_transformers() {
        let mut report = ScanReport::default();
        report.record(ScannerId("a"), &Verdict::detected("x", 0.3, 1.0));
        report.record(ScannerId("b"), &Verdict::transformed(Cow::Borrowed("x")));
        report.record(ScannerId("c"), &Verdict::detected("x", 0.7, 1.0));
        assert!((report.aggregate_risk() - 0.7).abs() < f32::EPSILON);
    }
}
