//! The vocabulary types of the scanner contract: [`ScannerId`], [`Direction`],
//! [`Disposition`], [`Verdict`], and the per-scanner [`RestorePolicy`].
//!
//! These are deliberately small and `Copy` where possible — the trait surface
//! (`scanner/mod.rs`) and the WASM runner follow-up both reduce to these few
//! value types plus one `scan` call.

use std::borrow::Cow;

use crate::scanner::ScanError;

/// A stable, human-readable scanner identifier (e.g. `native:pii`,
/// `native:secrets`). A newtype over `&'static str` so an id can never be
/// confused with arbitrary text on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScannerId(pub &'static str);

impl ScannerId {
    /// The underlying string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ScannerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// The direction a scanner runs on. Input scanners run on the request
/// front-to-back; output scanners run on the model response back-to-front
/// (LIFO over the input transforms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The request path.
    Input,
    /// The model-response path.
    Output,
}

/// How much trailing text a streaming OUTPUT runner must hold back before
/// emitting, so a pattern that straddles two chunks is never half-emitted.
///
/// This is a *trait-shape* declaration consumed by the streaming runner. On a
/// stream a match can span chunk
/// boundaries; emitting a chunk before confirming it is not a *forming* match
/// would leak the first half of a secret. The runner holds back the tail per
/// the active scanners' [`Scanner::hold_back`](crate::Scanner::hold_back).
///
/// The eventual streaming matcher should drive a byte-fed DFA
/// (`regex-automata`, match states complete/live/dead) rather than the
/// high-level `regex` crate: the DFA is what bounds the hold-back conservatively
/// — hold while a match is *live*, flush when it goes *dead*. The non-streaming
/// `scan` in this core uses `regex` for simplicity; nothing here precludes the
/// DFA slotting in behind the same `hold_back` contract later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldBack {
    /// Hold back to the last token boundary (whitespace). Most PII/secret
    /// patterns are token-bounded, so this is the redact/restore default.
    TokenBoundary,
    /// Hold back at most `usize` bytes — the longest pattern literal a match
    /// could still be completing.
    MaxLen(usize),
    /// Hold the whole stream: the scanner needs the complete response before it
    /// can judge (toxicity, relevance — future full-text scanners).
    WholeStream,
}

/// What a scanner does to text it disapproves of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Rewrites text in place (redact, restore). Never blocks the request.
    Transform,
    /// May reject the request/response (injection, toxicity, banned topic).
    Block,
}

/// Whether a scanner that interned values into the [`Vault`](crate::Vault)
/// restores them on the output path. A *policy*, not a property of the data
/// type: the identical redact machinery is `RoundTrip` for PII and `OneWay`
/// for secrets, and either is configurable per scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePolicy {
    /// Redact on input; restore the original on output. (PII default.)
    RoundTrip,
    /// Redact on input; never restore — the original never returns to the
    /// caller or the provider. (Secrets default.)
    OneWay,
}

/// One scanner's outcome. Mirrors LLM Guard's `(sanitized, valid, risk)`.
///
/// `text` is a [`Cow`] so a pure detector (the common case) returns the input
/// borrowed with zero allocation, while a transform returns the rewrite owned.
#[derive(Debug, Clone, PartialEq)]
pub struct Verdict<'a> {
    /// Possibly-rewritten text. For a pure detector, borrows the input.
    pub text: Cow<'a, str>,
    /// `false` ⇒ the stack should reject (honoured for `Block` scanners).
    pub valid: bool,
    /// `0.0` safe … `1.0` high. [`Verdict::NOT_A_RISK`] (`-1.0`) means "not a
    /// risk judgment" — a transformer that does not score.
    pub risk: f32,
}

impl<'a> Verdict<'a> {
    /// The sentinel risk a pure transformer returns: "not a risk judgment", so
    /// stack-level risk aggregation can skip it honestly.
    pub const NOT_A_RISK: f32 = -1.0;

    /// A transformer verdict: text rewritten (or borrowed unchanged), always
    /// valid, [`Verdict::NOT_A_RISK`].
    #[must_use]
    pub fn transformed(text: Cow<'a, str>) -> Self {
        Self {
            text,
            valid: true,
            risk: Self::NOT_A_RISK,
        }
    }

    /// Whether this verdict carries a risk judgment (a detector) rather than
    /// being a pure transform ([`Verdict::NOT_A_RISK`]).
    #[must_use]
    pub fn is_risk_judgment(&self) -> bool {
        self.risk >= 0.0
    }

    /// A detector verdict over borrowed input: `valid = risk < threshold`.
    #[must_use]
    pub fn detected(text: &'a str, risk: f32, threshold: f32) -> Self {
        Self {
            text: Cow::Borrowed(text),
            valid: risk < threshold,
            risk,
        }
    }
}

/// A risk threshold in `[0.0, 1.0]`. A newtype so a threshold can never be
/// silently swapped with a raw risk score, and so construction validates the
/// range once.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Threshold(f32);

impl Threshold {
    /// Construct a threshold, clamping into `[0.0, 1.0]`.
    #[must_use]
    pub fn new(value: f32) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    /// The underlying value.
    #[must_use]
    pub const fn get(self) -> f32 {
        self.0
    }
}

impl Default for Threshold {
    /// A permissive default: only an explicit `risk >= 1.0` blocks.
    fn default() -> Self {
        Self(1.0)
    }
}

/// Result of running one scanner.
pub type ScanResult<'a> = Result<Verdict<'a>, ScanError>;
