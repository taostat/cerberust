//! The secret scanner: detect API keys, tokens, and private-key headers via
//! known formats plus a high-entropy heuristic, tokenize into the [`Vault`],
//! and — by default — never restore.
//!
//! `RestorePolicy::OneWay`: the secret is interned and replaced on the way to
//! the model, and **no output scanner restores it**. The model and any
//! downstream provider never see the original, and the caller never gets it
//! echoed back. This is the policy difference from
//! [`PiiScanner`](crate::scanners::PiiScanner): identical redact machinery,
//! opposite restore default.

use crate::scanner::detect::{detect_secrets, resolve_overlaps, secret_pattern_sources};
use crate::scanner::{
    Direction, Disposition, RestorePolicy, ScanCtx, ScanResult, Scanner, ScannerId, Verdict,
};
use crate::scanners::redact::redact;

/// Detects and tokenizes secrets, `OneWay` by default (never restored).
#[derive(Debug, Clone)]
pub struct SecretScanner {
    policy: RestorePolicy,
    direction: Direction,
}

impl SecretScanner {
    /// This scanner's id.
    pub const ID: ScannerId = ScannerId("native:secrets");

    /// A secret scanner with the default `OneWay` policy (never restored),
    /// running on [`Direction::Input`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: RestorePolicy::OneWay,
            direction: Direction::Input,
        }
    }

    /// Override the direction this scanner runs on. On [`Direction::Output`] it
    /// redacts secrets the model emits — the streaming runner holds back a
    /// secret forming across chunk boundaries before it reaches the caller.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Override the restore policy (e.g. `RoundTrip` to echo secrets back —
    /// rare, but a per-scanner choice, not a data-type property).
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

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SecretScanner {
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
        let spans = resolve_overlaps(detect_secrets(text));
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
        1.3
    }

    fn stream_patterns(&self) -> Vec<String> {
        secret_pattern_sources()
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
    fn redacts_aws_key_into_vault() {
        let scanner = SecretScanner::new();
        let mut ctx = ScanCtx::new();
        let verdict = scanner
            .scan("here is AKIAIOSFODNN7EXAMPLE", &mut ctx)
            .unwrap();
        assert!(verdict.text.contains("[REDACTED_AWS_ACCESS_KEY_1_"));
        assert!(!verdict.text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(ctx.vault.len(), 1);
    }

    #[test]
    fn policy_defaults_to_one_way() {
        assert_eq!(SecretScanner::new().policy(), RestorePolicy::OneWay);
    }

    #[test]
    fn clean_text_borrows_unchanged() {
        let scanner = SecretScanner::new();
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("just some prose", &mut ctx).unwrap();
        assert_eq!(verdict.text, "just some prose");
        assert!(ctx.vault.is_empty());
    }
}
