//! The restore (deanonymize) output scanner: rehydrate `RoundTrip` sentinels on
//! the model response.
//!
//! This is the output half of a `RoundTrip` round-trip. It reads the same
//! [`Vault`](crate::scanner::Vault) the input scanners populated and substitutes
//! each sentinel back to its original. `OneWay` sentinels (secrets) are **not**
//! restored: the scanner is constructed with the set of entity types it owns,
//! and only those are rehydrated — so a secret interned by the `OneWay`
//! [`SecretScanner`](crate::scanners::SecretScanner) stays a sentinel forever.
//!
//! It declares [`Direction::Output`]; the [`ScannerStack`](crate::ScannerStack)
//! runs output scanners in LIFO order, so restore unwinds redaction in the
//! inverse order it was applied.

use std::borrow::Cow;
use std::collections::HashSet;

use crate::scanner::substitute::Substituter;
use crate::scanner::{
    Direction, Disposition, HoldBack, ScanCtx, ScanResult, Scanner, ScannerId, Verdict,
};

/// Restores the sentinels of the `RoundTrip` scanners it is configured for.
#[derive(Debug, Clone)]
pub struct RestoreScanner {
    /// The scanner ids this restorer is paired with, for provenance.
    id: ScannerId,
    /// Entity types to restore. A sentinel `[REDACTED_<TYPE>_<N>_<nonce>]` is
    /// restored only when `<TYPE>` is in this set — the `RoundTrip`/`OneWay`
    /// split enforced at restore time.
    types: HashSet<String>,
}

impl RestoreScanner {
    /// A restorer for the structured-PII entity types (the default companion to
    /// [`PiiScanner`](crate::scanners::PiiScanner)).
    #[must_use]
    pub fn for_pii() -> Self {
        let types = ["EMAIL", "PHONE", "US_SSN", "IP_ADDRESS", "CREDIT_CARD"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        Self {
            id: ScannerId("native:pii-restore"),
            types,
        }
    }

    /// A restorer for an explicit type set (e.g. custom `RoundTrip` scanners).
    #[must_use]
    pub fn for_types(id: ScannerId, types: impl IntoIterator<Item = String>) -> Self {
        Self {
            id,
            types: types.into_iter().collect(),
        }
    }

    /// The entity type embedded in a sentinel, if it parses as one. A sentinel
    /// is `[REDACTED_<TYPE>_<counter>_<nonce>]`; the type is everything between
    /// the `REDACTED_` prefix and the final two underscore-delimited fields.
    fn sentinel_type(sentinel: &str) -> Option<&str> {
        let inner = sentinel.strip_prefix("[REDACTED_")?.strip_suffix(']')?;
        // Strip the trailing `_<counter>_<nonce>` (two fields). The type itself
        // may contain underscores (US_SSN, AWS_ACCESS_KEY), so trim from the
        // right exactly twice.
        let without_nonce = inner.rsplit_once('_')?.0;
        let ty = without_nonce.rsplit_once('_')?.0;
        Some(ty)
    }
}

impl Scanner for RestoreScanner {
    fn id(&self) -> ScannerId {
        self.id
    }

    fn direction(&self) -> Direction {
        Direction::Output
    }

    fn disposition(&self) -> Disposition {
        Disposition::Transform
    }

    fn scan<'a>(&self, text: &'a str, ctx: &mut ScanCtx) -> ScanResult<'a> {
        let pairs: Vec<(String, String)> = ctx
            .vault
            .entries()
            .filter(|(sentinel, _)| {
                // Restore only sentinels this scanner owns by type AND that were
                // interned restorable (a `RoundTrip` input redaction) — so a
                // model-emitted value masked on output, which shares the entity
                // type but is not restorable, is never echoed back to the caller.
                ctx.vault.is_restorable(sentinel)
                    && Self::sentinel_type(sentinel).is_some_and(|ty| self.types.contains(ty))
            })
            .map(|(s, o)| (s.to_owned(), o.to_owned()))
            .collect();
        if pairs.is_empty() {
            return Ok(Verdict::transformed(Cow::Borrowed(text)));
        }
        let sub = Substituter::from_pairs(pairs.iter().map(|(s, o)| (s.as_str(), o.as_str())));
        Ok(Verdict::transformed(Cow::Owned(sub.substitute(text))))
    }

    fn hold_back(&self) -> HoldBack {
        // A sentinel can straddle two streamed chunks; the streaming runner
        // holds back the longest live sentinel prefix.
        HoldBack::TokenBoundary
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use crate::scanners::{PiiScanner, SecretScanner};

    use super::*;

    #[test]
    fn restores_pii_sentinel() {
        let pii = PiiScanner::new();
        let restore = RestoreScanner::for_pii();
        let mut ctx = ScanCtx::new();
        let redacted = pii
            .scan("mail alice@x.com", &mut ctx)
            .unwrap()
            .text
            .into_owned();
        // Model echoes the sentinel back; restore rehydrates it.
        let out = restore.scan(&redacted, &mut ctx).unwrap();
        assert_eq!(out.text, "mail alice@x.com");
    }

    #[test]
    fn does_not_restore_secret_sentinel() {
        let secrets = SecretScanner::new();
        let restore = RestoreScanner::for_pii();
        let mut ctx = ScanCtx::new();
        let redacted = secrets
            .scan("key AKIAIOSFODNN7EXAMPLE", &mut ctx)
            .unwrap()
            .text
            .into_owned();
        let out = restore.scan(&redacted, &mut ctx).unwrap();
        // The secret sentinel survives: a OneWay value is never rehydrated.
        assert!(out.text.contains("[REDACTED_AWS_ACCESS_KEY_1_"));
        assert!(!out.text.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn parses_multi_underscore_type() {
        assert_eq!(
            RestoreScanner::sentinel_type("[REDACTED_AWS_ACCESS_KEY_2_abcd1234]"),
            Some("AWS_ACCESS_KEY")
        );
        assert_eq!(
            RestoreScanner::sentinel_type("[REDACTED_US_SSN_1_deadbeef]"),
            Some("US_SSN")
        );
    }
}
