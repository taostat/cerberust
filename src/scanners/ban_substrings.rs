//! The substring-ban scanner: reject or redact configured literal substrings.
//!
//! Two dispositions, chosen at construction:
//! - [`Disposition::Block`] — any configured substring present rejects the
//!   request/response. The matched substring is what the report flags.
//! - [`Disposition::Transform`] — each occurrence is interned into the
//!   [`Vault`](crate::scanner::Vault) and replaced with a sentinel, the same
//!   redact machinery the pattern scanners use, under a `OneWay` policy (a
//!   banned phrase is never echoed back).
//!
//! Matching is literal, not regex — a banned-words list does not need a pattern
//! engine — with an optional case-insensitivity flag. Case-insensitive matching
//! searches the original bytes directly (folding ASCII case only), then redacts
//! the original text at those offsets so casing outside the match is preserved.

use crate::scanner::detect::{resolve_overlaps, Span};
use crate::scanner::{
    Direction, Disposition, HoldBack, ScanCtx, ScanResult, Scanner, ScannerId, Verdict,
};
use crate::scanners::redact::redact;

/// The label banned-substring redactions are interned under.
const BANNED_LABEL: &str = "BANNED_SUBSTRING";

/// The risk a blocking hit scores: a configured ban is a definite policy hit.
const HIT_RISK: f32 = 1.0;

/// Blocks or redacts configured substrings.
#[derive(Debug, Clone)]
pub struct BanSubstringsScanner {
    substrings: Vec<String>,
    case_sensitive: bool,
    disposition: Disposition,
    direction: Direction,
}

impl BanSubstringsScanner {
    /// This scanner's id.
    pub const ID: ScannerId = ScannerId("native:ban-substrings");

    /// Build a scanner over `substrings`. Defaults: case-sensitive,
    /// [`Disposition::Block`], [`Direction::Input`].
    #[must_use]
    pub fn new(substrings: impl IntoIterator<Item = String>) -> Self {
        Self {
            substrings: substrings.into_iter().collect(),
            case_sensitive: true,
            disposition: Disposition::Block,
            direction: Direction::Input,
        }
    }

    /// A full-text OUTPUT gate: block the response if any of `phrases` appears
    /// anywhere in it, case-insensitively. This is the [`Disposition::Block`] +
    /// [`Direction::Output`] configuration, which declares
    /// [`HoldBack::WholeStream`] — so on a stream the runner buffers the whole
    /// response and gates once at the end, catching a phrase even when it is
    /// split across chunk boundaries. Non-ML: a literal phrase list, not a
    /// toxicity model.
    #[must_use]
    pub fn output_phrase_gate(phrases: impl IntoIterator<Item = String>) -> Self {
        Self::new(phrases)
            .case_insensitive()
            .with_direction(Direction::Output)
    }

    /// Match ignoring ASCII case.
    #[must_use]
    pub fn case_insensitive(mut self) -> Self {
        self.case_sensitive = false;
        self
    }

    /// Redact hits into the vault instead of blocking.
    #[must_use]
    pub fn redacting(mut self) -> Self {
        self.disposition = Disposition::Transform;
        self
    }

    /// Override the direction this scanner runs on.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// The byte spans of every configured substring present in `text`. Spans are
    /// returned for overlap resolution before redaction; for the block path only
    /// their emptiness matters.
    fn hits(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for needle in &self.substrings {
            if needle.is_empty() {
                continue;
            }
            let mut from = 0;
            while let Some(start) = if self.case_sensitive {
                text[from..].find(needle).map(|rel| from + rel)
            } else {
                find_ascii_case_insensitive(text, needle, from)
            } {
                let end = start + needle.len();
                spans.push(Span::new(start, end, BANNED_LABEL, HIT_RISK));
                from = end;
            }
        }
        spans
    }
}

/// Find an ASCII-case-insensitive match without making a lower-cased copy of
/// the full input. A single search locates the next candidate in either ASCII
/// case of the first character; separate searches would repeatedly scan the
/// entire remaining tail if one case is absent. The byte comparison verifies
/// the remaining needle with the same ASCII-only folding as `to_ascii_lowercase`.
fn find_ascii_case_insensitive(text: &str, needle: &str, from: usize) -> Option<usize> {
    let first = needle.chars().next()?;
    let lower = first.to_ascii_lowercase();
    let upper = first.to_ascii_uppercase();
    let needle_bytes = needle.as_bytes();
    let mut search_from = from;

    loop {
        let tail = text.get(search_from..)?;
        let relative = tail.find([lower, upper])?;
        let start = search_from + relative;
        let end = start.checked_add(needle_bytes.len())?;
        if text
            .as_bytes()
            .get(start..end)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(needle_bytes))
        {
            return Some(start);
        }
        search_from = start + first.len_utf8();
    }
}

impl Scanner for BanSubstringsScanner {
    fn id(&self) -> ScannerId {
        Self::ID
    }

    fn direction(&self) -> Direction {
        self.direction
    }

    fn disposition(&self) -> Disposition {
        self.disposition
    }

    fn needs_prompt(&self) -> bool {
        false
    }

    fn scan<'a>(&self, text: &'a str, ctx: &mut ScanCtx) -> ScanResult<'a> {
        let spans = resolve_overlaps(self.hits(text));
        match self.disposition {
            Disposition::Block => Ok(Verdict::detected(
                text,
                if spans.is_empty() { 0.0 } else { HIT_RISK },
                HIT_RISK,
            )),
            Disposition::Transform => {
                // A redacted banned substring is never echoed back (`OneWay`).
                Ok(Verdict::transformed(redact(
                    text,
                    &spans,
                    &mut ctx.vault,
                    false,
                )))
            }
        }
    }

    fn hold_back(&self) -> HoldBack {
        match self.disposition {
            // A redacting ban rewrites streamed output, so a banned substring
            // forming across a chunk boundary must be held; the DFA built from
            // `stream_patterns` bounds that hold-back.
            Disposition::Transform => HoldBack::TokenBoundary,
            // A blocking ban must judge the whole response before passing it.
            Disposition::Block => HoldBack::WholeStream,
        }
    }

    fn stream_patterns(&self) -> Vec<String> {
        // Hold-back patterns matter only when this scanner rewrites streamed
        // output. The blocking disposition buffers the whole stream instead.
        if self.disposition != Disposition::Transform {
            return Vec::new();
        }
        let mut patterns = Vec::new();
        for needle in &self.substrings {
            if needle.is_empty() {
                continue;
            }
            let escaped = regex::escape(needle);
            // Case-insensitive bans match either case at stream time, so the DFA
            // must too; the `(?i)` inline flag mirrors the scanner's own folding.
            patterns.push(if self.case_sensitive {
                escaped
            } else {
                format!("(?i){escaped}")
            });
        }
        patterns
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
    fn blocks_on_configured_substring() {
        let scanner = BanSubstringsScanner::new(["forbidden".to_owned()]);
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("this is forbidden text", &mut ctx).unwrap();
        assert!(!verdict.valid);
        assert!((verdict.risk - HIT_RISK).abs() < f32::EPSILON);
    }

    #[test]
    fn passes_when_no_substring_present() {
        let scanner = BanSubstringsScanner::new(["forbidden".to_owned()]);
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("perfectly fine text", &mut ctx).unwrap();
        assert!(verdict.valid);
    }

    #[test]
    fn case_sensitive_by_default() {
        let scanner = BanSubstringsScanner::new(["Forbidden".to_owned()]);
        let mut ctx = ScanCtx::new();
        assert!(scanner.scan("this is forbidden", &mut ctx).unwrap().valid);
    }

    #[test]
    fn case_insensitive_flag_matches_any_case() {
        let scanner = BanSubstringsScanner::new(["forbidden".to_owned()]).case_insensitive();
        let mut ctx = ScanCtx::new();
        assert!(!scanner.scan("this is FORBIDDEN", &mut ctx).unwrap().valid);
    }

    #[test]
    fn case_insensitive_search_handles_a_large_repeated_prefix() {
        // Searching separately for 'a' and absent 'A' rescans the entire tail
        // for every candidate, making this clean prefix quadratic to scan.
        let mut text = "a".repeat(8 * 1024 * 1024);
        text.push('b');
        let scanner = BanSubstringsScanner::new(["ab".to_owned()]).case_insensitive();
        let verdict = scanner.scan(&text, &mut ScanCtx::new()).unwrap();
        assert!(!verdict.valid);
        assert_eq!(verdict.text, text);
    }

    #[test]
    fn case_insensitive_redaction_preserves_unicode_and_original_casing() {
        let scanner = BanSubstringsScanner::new(["éFoo".to_owned(), "İbAr".to_owned()])
            .case_insensitive()
            .redacting();
        let mut ctx = ScanCtx::new().with_vault(crate::Vault::with_nonce("test".to_owned()));
        let text = "🦀 éfOO Éfoo İBAR ibar ß SS";
        let verdict = scanner.scan(text, &mut ctx).unwrap();
        let first = "[REDACTED_BANNED_SUBSTRING_1_test]";
        let second = "[REDACTED_BANNED_SUBSTRING_2_test]";
        assert_eq!(verdict.text, format!("🦀 {first} Éfoo {second} ibar ß SS"));
        assert_eq!(ctx.vault.original_for(first), Some("éfOO"));
        assert_eq!(ctx.vault.original_for(second), Some("İBAR"));
        assert_eq!(ctx.vault.len(), 2);
    }

    proptest::proptest! {
        #[test]
        fn case_insensitive_search_matches_ascii_lowercase_semantics(
            text_chars in proptest::collection::vec(proptest::prelude::any::<char>(), 0..64),
            needle_chars in proptest::collection::vec(proptest::prelude::any::<char>(), 0..8),
            from_offset in 0usize..64,
        ) {
            let text: String = text_chars.into_iter().collect();
            let needle: String = needle_chars.into_iter().collect();
            let from = text
                .char_indices()
                .map(|(index, _)| index)
                .chain(std::iter::once(text.len()))
                .find(|&index| index >= from_offset)
                .unwrap_or(text.len());
            let expected = if needle.is_empty() {
                None
            } else {
                let lower_text = text.to_ascii_lowercase();
                let lower_needle = needle.to_ascii_lowercase();
                lower_text[from..]
                    .find(&lower_needle)
                    .map(|relative| from + relative)
            };
            proptest::prop_assert_eq!(
                find_ascii_case_insensitive(&text, &needle, from),
                expected,
            );
        }
    }

    #[test]
    fn output_phrase_gate_blocks_whole_stream() {
        let scanner =
            BanSubstringsScanner::output_phrase_gate(["as an ai language model".to_owned()]);
        assert_eq!(scanner.direction(), Direction::Output);
        assert_eq!(scanner.disposition(), Disposition::Block);
        assert_eq!(scanner.hold_back(), HoldBack::WholeStream);
        let mut ctx = ScanCtx::new();
        let verdict = scanner
            .scan("Sure! As an AI language model, I cannot.", &mut ctx)
            .unwrap();
        assert!(!verdict.valid);
    }

    #[test]
    fn output_phrase_gate_passes_clean_response() {
        let scanner = BanSubstringsScanner::output_phrase_gate(["forbidden phrase".to_owned()]);
        let mut ctx = ScanCtx::new();
        assert!(
            scanner
                .scan("a perfectly ordinary answer", &mut ctx)
                .unwrap()
                .valid
        );
    }

    #[test]
    fn redacting_mode_tokenizes_the_hit() {
        let scanner = BanSubstringsScanner::new(["forbidden".to_owned()]).redacting();
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("this is forbidden text", &mut ctx).unwrap();
        assert_eq!(scanner.disposition(), Disposition::Transform);
        assert!(verdict.valid);
        assert!(verdict.text.contains("[REDACTED_BANNED_SUBSTRING_1_"));
        assert!(!verdict.text.contains("forbidden"));
        assert_eq!(ctx.vault.len(), 1);
    }
}
