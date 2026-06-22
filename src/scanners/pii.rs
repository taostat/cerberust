//! The PII scanner: detect structured PII (email, phone, card, IP, SSN),
//! tokenize each span into the [`Vault`], and restore on output.
//!
//! `RestorePolicy::RoundTrip`: the input pass interns and replaces, and a
//! companion [`RestoreScanner`](crate::scanners::RestoreScanner) on the output
//! path rehydrates the sentinels. Regex + checksum detectors today, with native
//! NER (`gline-rs`) a later add emitting the same
//! [`Span`](crate::scanner::detect::Span)s.
//!
//! On [`Direction::Output`] the same detector redacts PII the *model generated*
//! — the "Sensitive" output scanner (see [`PiiScanner::sensitive_output`]). That
//! is a different job from restoring the input PII: a fresh model-emitted email
//! or card number has no vault entry to round-trip, so it is masked `OneWay`.
//! Both run in one output pass — restore rehydrates the input sentinels while
//! this scanner redacts newly-generated PII.

use crate::scanner::detect::{detect_structured, resolve_overlaps, structured_pattern_sources};
use crate::scanner::{
    Direction, Disposition, RestorePolicy, ScanCtx, ScanResult, Scanner, ScannerId, Verdict,
};
use crate::scanners::redact::redact;

/// Detects and tokenizes structured PII, `RoundTrip` by default.
#[derive(Debug, Clone)]
pub struct PiiScanner {
    policy: RestorePolicy,
    direction: Direction,
}

impl PiiScanner {
    /// The id under which a [`RestoreScanner`](crate::scanners::RestoreScanner)
    /// declares it restores this scanner's redactions.
    pub const ID: ScannerId = ScannerId("native:pii");

    /// A PII scanner with the default `RoundTrip` policy (restore on output),
    /// running on [`Direction::Input`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: RestorePolicy::RoundTrip,
            direction: Direction::Input,
        }
    }

    /// The "Sensitive" output scanner: PII the *model generated* is redacted on
    /// [`Direction::Output`] under `OneWay` (no vault entry to restore — the
    /// value originated in the response, not the prompt). Pair it with the input
    /// `PiiScanner` + a [`RestoreScanner`](crate::scanners::RestoreScanner) to
    /// both round-trip the input PII and mask fresh model-emitted PII in one
    /// output pass.
    #[must_use]
    pub fn sensitive_output() -> Self {
        Self {
            policy: RestorePolicy::OneWay,
            direction: Direction::Output,
        }
    }

    /// Override the direction this scanner runs on. On [`Direction::Output`] it
    /// redacts PII the model emits — the streaming runner holds back PII forming
    /// across chunk boundaries before it reaches the caller.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Override the restore policy (e.g. `OneWay` to mask PII permanently).
    #[must_use]
    pub fn with_policy(mut self, policy: RestorePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// This scanner's restore policy.
    #[must_use]
    pub fn policy(&self) -> RestorePolicy {
        self.policy
    }
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for PiiScanner {
    fn id(&self) -> ScannerId {
        Self::ID
    }

    fn direction(&self) -> Direction {
        self.direction
    }

    fn disposition(&self) -> Disposition {
        Disposition::Transform
    }

    fn scan<'a>(&self, text: &'a str, ctx: &mut ScanCtx) -> ScanResult<'a> {
        let spans = resolve_overlaps(detect_structured(text));
        let restorable =
            self.direction == Direction::Input && self.policy == RestorePolicy::RoundTrip;
        Ok(Verdict::transformed(redact(
            text,
            &spans,
            &mut ctx.vault,
            restorable,
        )))
    }

    fn max_input_inflation_ratio(&self) -> f64 {
        // Sentinels are longer than the values they replace; the measured
        // bound for the PII path is 1.3.
        1.3
    }

    fn stream_patterns(&self) -> Vec<String> {
        structured_pattern_sources()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use crate::scanner::RestorePolicy;

    use super::*;

    #[test]
    fn redacts_email_into_vault() {
        let scanner = PiiScanner::new();
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("mail me at alice@x.com", &mut ctx).unwrap();
        assert!(verdict.text.contains("[REDACTED_EMAIL_1_"));
        assert!(!verdict.text.contains("alice@x.com"));
        assert_eq!(ctx.vault.len(), 1);
        // A transformer never scores.
        assert!(!verdict.is_risk_judgment());
        assert!(verdict.valid);
    }

    #[test]
    fn clean_text_borrows_unchanged() {
        let scanner = PiiScanner::new();
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("hello world", &mut ctx).unwrap();
        assert_eq!(verdict.text, "hello world");
        assert!(ctx.vault.is_empty());
    }

    #[test]
    fn policy_defaults_to_round_trip() {
        assert_eq!(PiiScanner::new().policy(), RestorePolicy::RoundTrip);
    }

    #[test]
    fn sensitive_output_redacts_model_generated_pii() {
        let scanner = PiiScanner::sensitive_output();
        assert_eq!(scanner.direction(), Direction::Output);
        assert_eq!(scanner.policy(), RestorePolicy::OneWay);
        let mut ctx = ScanCtx::new();
        let verdict = scanner
            .scan("the model leaked bob@y.com here", &mut ctx)
            .unwrap();
        assert!(verdict.text.contains("[REDACTED_EMAIL_1_"));
        assert!(!verdict.text.contains("bob@y.com"));
        assert_eq!(ctx.vault.len(), 1);
    }
}
