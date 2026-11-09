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

use aho_corasick::{AhoCorasick, BuildError, MatchKind};

use crate::scanner::detect::{resolve_overlaps, Span};
use crate::scanner::{
    Direction, Disposition, HoldBack, ScanCtx, ScanError, ScanResult, Scanner, ScannerId, Verdict,
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
    /// Built once when case-insensitive matching is enabled. `None` keeps the
    /// case-sensitive path; a build failure is reported by `scan`.
    ascii_matcher: Option<Result<AhoCorasick, BuildError>>,
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
            ascii_matcher: None,
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

    /// Match ignoring ASCII case. Compiles the configured non-empty needles
    /// once; if they exceed the automaton's size limits, `scan` reports a
    /// [`ScanError::Detector`].
    #[must_use]
    pub fn case_insensitive(mut self) -> Self {
        if self.ascii_matcher.is_none() {
            self.ascii_matcher = Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .match_kind(MatchKind::Standard)
                    .build(self.substrings.iter().filter(|needle| !needle.is_empty())),
            );
        }
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
    fn hits(&self, text: &str) -> Result<Vec<Span>, ScanError> {
        let mut spans = Vec::new();
        if let Some(matcher) = &self.ascii_matcher {
            let matcher = matcher.as_ref().map_err(|error| ScanError::Detector {
                scanner: Self::ID,
                reason: error.to_string(),
            })?;
            // A global non-overlapping search would suppress hits of other
            // needles. Enumerate all matches in one O(text.len() + matches)
            // pass, accepting only leftmost non-overlapping hits per needle.
            let mut next_start = vec![0; matcher.patterns_len()];
            for hit in matcher.find_overlapping_iter(text) {
                let from = &mut next_start[hit.pattern().as_usize()];
                if hit.start() >= *from {
                    spans.push(Span::new(hit.start(), hit.end(), BANNED_LABEL, HIT_RISK));
                    *from = hit.end();
                }
            }
            return Ok(spans);
        }

        for needle in &self.substrings {
            if needle.is_empty() {
                continue;
            }
            let mut from = 0;
            while let Some(rel) = text[from..].find(needle) {
                let start = from + rel;
                let end = start + needle.len();
                spans.push(Span::new(start, end, BANNED_LABEL, HIT_RISK));
                from = end;
            }
        }
        Ok(spans)
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
        let spans = resolve_overlaps(self.hits(text)?);
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
            patterns.push(if self.ascii_matcher.is_none() {
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
    fn case_insensitive_search_handles_a_long_nearly_matching_needle() {
        // Verifying the whole needle at every first-byte candidate compares
        // 64 bytes at almost every position. Check results, not wall-clock time.
        let mut text = "a".repeat(32 * 1024 * 1024);
        let needle = format!("{}b", "a".repeat(63));
        let scanner = BanSubstringsScanner::new([needle]).case_insensitive();
        let verdict = scanner.scan(&text, &mut ScanCtx::new()).unwrap();
        assert!(verdict.valid);
        assert_eq!(verdict.text, text);

        // Reuse the scanner and match only at the end of the same long prefix.
        text.push('B');
        let verdict = scanner.scan(&text, &mut ScanCtx::new()).unwrap();
        assert!(!verdict.valid);
        assert_eq!(verdict.text, text);
    }

    #[test]
    fn case_insensitive_hits_are_non_overlapping_per_needle() {
        for (needles, text, expected) in [
            (vec!["aba"], "aBaBa", vec![(0, 3)]),
            (vec!["ab", "bc"], "aBc", vec![(0, 2), (1, 3)]),
            (vec!["abcd", "bc"], "aBcD", vec![(0, 4), (1, 3)]),
            (
                vec!["", "aa", "", "AA"],
                "aAaAa",
                vec![(0, 2), (0, 2), (2, 4), (2, 4)],
            ),
            (vec![], "abc", vec![]),
            (vec!["", ""], "abc", vec![]),
            (vec!["a"], "", vec![]),
        ] {
            let scanner = BanSubstringsScanner::new(needles.iter().map(|s| (*s).to_owned()))
                .case_insensitive();
            let mut actual: Vec<_> = scanner
                .hits(text)
                .unwrap()
                .into_iter()
                .map(|span| (span.start, span.end))
                .collect();
            actual.sort_unstable();
            assert_eq!(actual, expected, "{needles:?}, {text:?}");
        }
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

    // A small shared alphabet makes matches and overlaps frequent, while the
    // arbitrary-char arm still exercises the full Unicode range.
    fn matching_char() -> impl proptest::strategy::Strategy<Value = char> {
        proptest::prop_oneof![
            4 => proptest::sample::select(vec![
                'a', 'A', 'b', 'B', 'é', 'É', 'İ', 'i', 'ß', 'S', '\0', '🦀',
            ]),
            1 => proptest::prelude::any::<char>(),
        ]
    }

    proptest::proptest! {
        #[test]
        fn hits_preserve_per_needle_find_semantics(
            text_chars in proptest::collection::vec(matching_char(), 0..64),
            needle_chars in proptest::collection::vec(
                proptest::collection::vec(matching_char(), 0..8), 0..8,
            ),
        ) {
            let text: String = text_chars.into_iter().collect();
            let needles: Vec<String> = needle_chars
                .into_iter()
                .map(|chars| chars.into_iter().collect())
                .collect();
            for case_sensitive in [true, false] {
                let mut scanner = BanSubstringsScanner::new(needles.clone());
                let mut haystack = text.clone();
                if !case_sensitive {
                    scanner = scanner.case_insensitive();
                    haystack.make_ascii_lowercase();
                }
                let mut expected = Vec::new();
                for needle in &needles {
                    if needle.is_empty() {
                        continue;
                    }
                    let needle = if case_sensitive {
                        needle.clone()
                    } else {
                        needle.to_ascii_lowercase()
                    };
                    for (start, matched) in haystack.match_indices(&needle) {
                        expected.push(Span::new(start, start + matched.len(), BANNED_LABEL, HIT_RISK));
                    }
                }
                let mut actual = scanner.hits(&text).unwrap();
                actual.sort_by_key(|span| (span.start, span.end));
                expected.sort_by_key(|span| (span.start, span.end));
                proptest::prop_assert_eq!(actual, expected);
            }
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
