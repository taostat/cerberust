//! The custom-pattern scanner: caller-supplied regexes, each tokenized into the
//! [`Vault`](crate::scanner::Vault) under its own entity label.
//!
//! This is the user-extensibility seam: a caller brings their own patterns
//! (internal ticket ids, customer numbers, an in-house secret format) and the
//! scanner redacts every match the same way [`PiiScanner`](crate::scanners::PiiScanner)
//! redacts structured PII — collect spans → resolve overlaps → intern → rewrite
//! span-by-span via the shared [`redact`] step. The only differences from PII
//! are that the patterns come from config and the entity label is whatever the
//! caller named it.
//!
//! `ReDoS` safety: patterns compile with the `regex` crate, whose matcher is
//! linear in the input length — it has no backtracking, so a pathological
//! pattern such as `(a+)+$` cannot blow up to exponential time the way a PCRE
//! engine would. Compilation is bounded by the crate's default size limit, so a
//! caller cannot smuggle a pattern that compiles to a giant automaton either. A
//! pattern that fails to compile is dropped at construction
//! ([`RegexScanner::new`] reports it), never at scan time.

use crate::scanner::detect::{resolve_overlaps, Span};
use crate::scanner::{
    Direction, Disposition, HoldBack, RestorePolicy, ScanCtx, ScanResult, Scanner, ScannerId,
    Verdict,
};
use crate::scanners::redact::redact;

use regex::Regex;

/// One caller-supplied rule: a compiled pattern and the entity label its matches
/// are interned under. The label becomes the `<TYPE>` in the sentinel, so a
/// [`RestoreScanner`](crate::scanners::RestoreScanner) configured for that label
/// rehydrates it on output under [`RestorePolicy::RoundTrip`].
#[derive(Debug, Clone)]
pub struct RegexRule {
    re: Regex,
    label: String,
    /// The source pattern, retained so the streaming runner can build a hold-
    /// back DFA from the same string the matcher compiled.
    source: String,
}

impl RegexRule {
    /// Compile `pattern` and pair it with `label`.
    ///
    /// # Errors
    /// Returns [`regex::Error`] when `pattern` is not a valid regex or exceeds
    /// the crate's compiled-size limit.
    pub fn new(pattern: &str, label: impl Into<String>) -> Result<Self, regex::Error> {
        Ok(Self {
            re: Regex::new(pattern)?,
            label: label.into(),
            source: pattern.to_owned(),
        })
    }

    /// The entity label matches are interned under.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The source pattern this rule compiled from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// Redacts matches of caller-supplied patterns, `RoundTrip` by default.
#[derive(Debug, Clone)]
pub struct RegexScanner {
    rules: Vec<RegexRule>,
    direction: Direction,
    policy: RestorePolicy,
}

impl RegexScanner {
    /// This scanner's id.
    pub const ID: ScannerId = ScannerId("native:regex");

    /// Build a scanner from compiled rules. Direction defaults to
    /// [`Direction::Input`], policy to [`RestorePolicy::RoundTrip`].
    #[must_use]
    pub fn new(rules: Vec<RegexRule>) -> Self {
        Self {
            rules,
            direction: Direction::Input,
            policy: RestorePolicy::RoundTrip,
        }
    }

    /// Build a scanner from `(pattern, label)` pairs, compiling each. Patterns
    /// that fail to compile are skipped and returned alongside the scanner so the
    /// caller can surface a configuration error rather than silently dropping a
    /// rule.
    #[must_use]
    pub fn from_patterns<'a>(
        patterns: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> (Self, Vec<(String, regex::Error)>) {
        let mut rules = Vec::new();
        let mut errors = Vec::new();
        for (pattern, label) in patterns {
            match RegexRule::new(pattern, label) {
                Ok(rule) => rules.push(rule),
                Err(e) => errors.push((pattern.to_owned(), e)),
            }
        }
        (Self::new(rules), errors)
    }

    /// Override the direction this scanner runs on (input, output, or — by
    /// registering the scanner in both directions — both).
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Override the restore policy. `RoundTrip` tokenizes and a paired
    /// [`RestoreScanner`](crate::scanners::RestoreScanner) rehydrates on output;
    /// `OneWay` redacts permanently.
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

    /// The entity labels this scanner interns under — the set a
    /// [`RestoreScanner`](crate::scanners::RestoreScanner) must own to rehydrate
    /// its `RoundTrip` redactions.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(RegexRule::label)
    }

    fn detect(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for rule in &self.rules {
            for m in rule.re.find_iter(text) {
                spans.push(Span::new(m.start(), m.end(), &rule.label, 0.99));
            }
        }
        spans
    }
}

impl Scanner for RegexScanner {
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
        let spans = resolve_overlaps(self.detect(text));
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

    fn hold_back(&self) -> HoldBack {
        HoldBack::TokenBoundary
    }

    fn stream_patterns(&self) -> Vec<String> {
        self.rules.iter().map(|r| r.source().to_owned()).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use std::time::Instant;

    use crate::scanners::RestoreScanner;

    use super::*;

    fn ticket_scanner() -> RegexScanner {
        let (scanner, errors) = RegexScanner::from_patterns([(r"TICKET-\d+", "TICKET_ID")]);
        assert!(errors.is_empty());
        scanner
    }

    #[test]
    fn redacts_custom_pattern_into_vault() {
        let scanner = ticket_scanner();
        let mut ctx = ScanCtx::new();
        let verdict = scanner
            .scan("see TICKET-4821 for details", &mut ctx)
            .unwrap();
        assert!(verdict.text.contains("[REDACTED_TICKET_ID_1_"));
        assert!(!verdict.text.contains("TICKET-4821"));
        assert_eq!(ctx.vault.len(), 1);
        assert!(!verdict.is_risk_judgment());
        assert!(verdict.valid);
    }

    #[test]
    fn round_trip_restores_custom_label() {
        let scanner = ticket_scanner();
        let restore =
            RestoreScanner::for_types(ScannerId("native:regex-restore"), ["TICKET_ID".to_owned()]);
        let mut ctx = ScanCtx::new();
        let redacted = scanner
            .scan("see TICKET-4821", &mut ctx)
            .unwrap()
            .text
            .into_owned();
        let out = restore.scan(&redacted, &mut ctx).unwrap();
        assert_eq!(out.text, "see TICKET-4821");
    }

    #[test]
    fn one_way_is_not_restored() {
        let scanner = ticket_scanner().with_policy(RestorePolicy::OneWay);
        assert_eq!(scanner.policy(), RestorePolicy::OneWay);
        // A restorer that owns no label leaves every sentinel in place — the
        // OneWay choice is enforced by simply never pairing a restorer.
        let restore = RestoreScanner::for_types(ScannerId("native:regex-restore"), []);
        let mut ctx = ScanCtx::new();
        let redacted = scanner
            .scan("see TICKET-4821", &mut ctx)
            .unwrap()
            .text
            .into_owned();
        let out = restore.scan(&redacted, &mut ctx).unwrap();
        assert!(out.text.contains("[REDACTED_TICKET_ID_1_"));
        assert!(!out.text.contains("TICKET-4821"));
    }

    #[test]
    fn clean_text_borrows_unchanged() {
        let scanner = ticket_scanner();
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("nothing matches here", &mut ctx).unwrap();
        assert_eq!(verdict.text, "nothing matches here");
        assert!(ctx.vault.is_empty());
    }

    #[test]
    fn invalid_pattern_is_reported_not_panicked() {
        let (scanner, errors) = RegexScanner::from_patterns([("(unclosed", "BAD")]);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, "(unclosed");
        assert_eq!(scanner.labels().count(), 0);
    }

    #[test]
    fn redos_pattern_compiles_and_runs_linear() {
        // A classic catastrophic-backtracking pattern under a PCRE engine. The
        // `regex` crate is backtracking-free, so this both compiles and runs in
        // linear time over an adversarial input.
        let (scanner, errors) = RegexScanner::from_patterns([(r"(a+)+$", "EVIL")]);
        assert!(errors.is_empty());
        let mut ctx = ScanCtx::new();
        let adversarial = format!("{}!", "a".repeat(50_000));
        let start = Instant::now();
        let verdict = scanner.scan(&adversarial, &mut ctx).unwrap();
        // No exponential blowup: the trailing `!` defeats the `$` anchor so the
        // pattern does not match, and the linear matcher returns promptly.
        assert!(start.elapsed().as_secs() < 2, "matcher was not linear");
        assert_eq!(verdict.text, adversarial);
    }
}
