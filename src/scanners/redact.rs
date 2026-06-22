//! The shared redact step: rewrite `text` span-by-span, replacing each detected
//! span with its vault sentinel.
//!
//! Both [`PiiScanner`](crate::scanners::PiiScanner) and
//! [`SecretScanner`](crate::scanners::SecretScanner) call this over the spans
//! their own detectors produced. Interning is identical for either; the
//! `RestorePolicy` they carry decides only whether an output scanner later
//! restores the sentinel.

use std::borrow::Cow;

use crate::scanner::detect::Span;
use crate::scanner::Vault;

/// Rewrite `text`, replacing each span with its vault sentinel and emitting
/// everything else verbatim. Walks left-to-right so byte offsets stay valid.
/// Returns `Cow::Borrowed(text)` unchanged when there is nothing to redact.
///
/// `restorable` is threaded to [`Vault::intern`]: a `RoundTrip` input scanner
/// passes `true` so its sentinels rehydrate on output, while a `OneWay` scanner
/// (secrets, or model-emitted PII masked on the output path) passes `false` so
/// the restore pass never echoes the value back.
#[must_use]
pub fn redact<'a>(
    text: &'a str,
    spans: &[Span],
    vault: &mut Vault,
    restorable: bool,
) -> Cow<'a, str> {
    if spans.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for span in spans {
        // Skip a span that overlaps an already-emitted region or runs past the
        // end — overlap resolution should have removed these, but the rewrite
        // stays total either way.
        if span.start < cursor || span.end > text.len() {
            continue;
        }
        out.push_str(&text[cursor..span.start]);
        let original = &text[span.start..span.end];
        out.push_str(&vault.intern(&span.ty, original, restorable));
        cursor = span.end;
    }
    out.push_str(&text[cursor..]);
    Cow::Owned(out)
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
    fn empty_spans_borrow_unchanged() {
        let mut v = Vault::new();
        let out = redact("nothing here", &[], &mut v, true);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, "nothing here");
    }

    #[test]
    fn span_replacement_does_not_corrupt_substring() {
        // "Sam" as a span must not corrupt "Samsung" elsewhere.
        let mut v = Vault::with_nonce("deadbeef".to_owned());
        let out = redact(
            "Sam works at Samsung",
            &[Span::new(0, 3, "PERSON", 0.9)],
            &mut v,
            true,
        );
        assert_eq!(out, "[REDACTED_PERSON_1_deadbeef] works at Samsung");
    }
}
