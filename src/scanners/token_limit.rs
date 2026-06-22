//! The token-limit scanner: reject input whose approximate token count exceeds a
//! configured maximum.
//!
//! The token count here is a whitespace/heuristic estimate, not a real
//! tokenizer: a request is split on whitespace and each whitespace-delimited
//! chunk contributes a count proportional to its length, approximating how a
//! BPE tokenizer fragments long runs. A model-accurate tokenizer (`tiktoken` /
//! the provider's BPE) is a later refinement; it plugs in behind
//! [`approx_token_count`] without changing the scanner's contract.
//!
//! [`Disposition::Block`], [`Direction::Input`]: the point is to reject an
//! over-budget prompt before it reaches the model, so this never runs on output
//! and never rewrites text.

use crate::scanner::{
    Direction, Disposition, HoldBack, ScanCtx, ScanResult, Scanner, ScannerId, Verdict,
};

/// Average characters per token a BPE tokenizer fragments a long run into. Four
/// is the conventional English-text rule of thumb; a long whitespace-free run
/// (a URL, a base64 blob) is counted as `ceil(len / 4)` tokens rather than one.
const CHARS_PER_TOKEN: usize = 4;

/// Approximate the token count of `text`: each whitespace-delimited chunk costs
/// `ceil(chars / CHARS_PER_TOKEN)` tokens, summed. A pure-whitespace string is
/// zero tokens.
#[must_use]
pub fn approx_token_count(text: &str) -> usize {
    text.split_whitespace()
        .map(|chunk| chunk.chars().count().div_ceil(CHARS_PER_TOKEN))
        .sum()
}

/// Rejects input exceeding `max_tokens` approximate tokens.
#[derive(Debug, Clone)]
pub struct TokenLimitScanner {
    max_tokens: usize,
}

impl TokenLimitScanner {
    /// This scanner's id.
    pub const ID: ScannerId = ScannerId("native:token-limit");

    /// A scanner that rejects input over `max_tokens` approximate tokens.
    #[must_use]
    pub fn new(max_tokens: usize) -> Self {
        Self { max_tokens }
    }

    /// The configured maximum.
    #[must_use]
    pub fn max_tokens(&self) -> usize {
        self.max_tokens
    }
}

impl Scanner for TokenLimitScanner {
    fn id(&self) -> ScannerId {
        Self::ID
    }

    fn direction(&self) -> Direction {
        Direction::Input
    }

    fn disposition(&self) -> Disposition {
        Disposition::Block
    }

    fn scan<'a>(&self, text: &'a str, _ctx: &mut ScanCtx) -> ScanResult<'a> {
        let over = approx_token_count(text) > self.max_tokens;
        let risk = if over { 1.0 } else { 0.0 };
        Ok(Verdict::detected(text, risk, 1.0))
    }

    fn hold_back(&self) -> HoldBack {
        // Input-only and block-only: it never runs on a stream, so the
        // hold-back contract is moot. WholeStream is the conservative declaration
        // for a scanner that judges complete text.
        HoldBack::WholeStream
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use super::*;

    #[test]
    fn under_limit_passes() {
        let scanner = TokenLimitScanner::new(10);
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("a short prompt", &mut ctx).unwrap();
        assert!(verdict.valid);
    }

    #[test]
    fn over_limit_blocks() {
        let scanner = TokenLimitScanner::new(3);
        let mut ctx = ScanCtx::new();
        let verdict = scanner
            .scan("one two three four five six", &mut ctx)
            .unwrap();
        assert!(!verdict.valid);
        assert!((verdict.risk - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn long_whitespace_free_run_counts_multiple_tokens() {
        // A 40-char run is ~10 tokens, not one.
        assert_eq!(approx_token_count(&"x".repeat(40)), 10);
    }

    #[test]
    fn whitespace_only_is_zero_tokens() {
        assert_eq!(approx_token_count("   \t\n  "), 0);
    }

    #[test]
    fn exactly_at_limit_passes() {
        let scanner = TokenLimitScanner::new(4);
        let mut ctx = ScanCtx::new();
        // Four single-char-ish words → four tokens, not over.
        assert!(scanner.scan("aa bb cc dd", &mut ctx).unwrap().valid);
    }
}
