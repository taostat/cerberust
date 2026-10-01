//! The keyword topic-ban scanner: block a request/response that mentions a
//! banned topic, where each topic is defined by a list of keywords.
//!
//! This is the keyword tier of topic detection. A topic hits when any of its
//! keywords appears (ASCII-case-insensitively, on word-ish boundaries so
//! "class" does not trip a "ass" keyword). ML-based zero-shot topic
//! classification is a later ticket; the [`Scanner`] surface is identical, so
//! that detector slots in behind the same disposition without changing callers.
//!
//! On a hit the scanner returns [`Disposition::Block`] with `valid = false`. The
//! matched topic is recorded on the scanner's [`ScannerId`] — each `BanTopics`
//! instance is constructed with a stable id, and [`matched_topic`] exposes which
//! topic fired for the report/audit panel.
//!
//! [`matched_topic`]: BanTopicsScanner::matched_topic

use crate::scanner::{
    Direction, Disposition, HoldBack, ScanCtx, ScanResult, Scanner, ScannerId, Verdict,
};

/// The risk a topic hit scores.
const HIT_RISK: f32 = 1.0;

/// One banned topic: a name and the keywords that signal it.
#[derive(Debug, Clone)]
pub struct Topic {
    name: String,
    keywords: Vec<String>,
}

impl Topic {
    /// A topic named `name`, signalled by any of `keywords`.
    #[must_use]
    pub fn new(name: impl Into<String>, keywords: impl IntoIterator<Item = String>) -> Self {
        Self {
            name: name.into(),
            keywords: keywords
                .into_iter()
                .map(|k| k.to_ascii_lowercase())
                .collect(),
        }
    }

    /// The topic name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether any keyword appears in `lowered` (already lower-cased) on a
    /// word-ish boundary.
    fn hits(&self, lowered: &str) -> bool {
        self.keywords
            .iter()
            .any(|kw| !kw.is_empty() && contains_word(lowered, kw))
    }
}

/// Whether `keyword` appears in `haystack` (both lower-case) bounded by
/// non-alphanumeric characters, so a keyword is matched as a word rather than as
/// an arbitrary substring.
fn contains_word(haystack: &str, keyword: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(keyword) {
        let start = from + rel;
        let end = start + keyword.len();
        let left_ok = start == 0 || !is_word_byte(haystack.as_bytes()[start - 1]);
        let right_ok = end == haystack.len() || !is_word_byte(haystack.as_bytes()[end]);
        if left_ok && right_ok {
            return true;
        }
        // `start` is a character boundary because `find` returned a match.
        // Advance by the first character's byte width so overlapping matches
        // are still considered without slicing inside a UTF-8 codepoint.
        from = start + haystack[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Blocks text matching any configured banned topic.
#[derive(Debug, Clone)]
pub struct BanTopicsScanner {
    topics: Vec<Topic>,
    direction: Direction,
}

impl BanTopicsScanner {
    /// This scanner's id.
    pub const ID: ScannerId = ScannerId("native:ban-topics");

    /// Build a scanner over `topics`, running on [`Direction::Input`] by default.
    #[must_use]
    pub fn new(topics: impl IntoIterator<Item = Topic>) -> Self {
        Self {
            topics: topics.into_iter().collect(),
            direction: Direction::Input,
        }
    }

    /// Override the direction this scanner runs on.
    #[must_use]
    pub fn with_direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// The first banned topic `text` matches, if any — the topic to record in
    /// the report when this scanner blocks.
    #[must_use]
    pub fn matched_topic(&self, text: &str) -> Option<&str> {
        let lowered = text.to_ascii_lowercase();
        self.topics
            .iter()
            .find(|t| t.hits(&lowered))
            .map(Topic::name)
    }
}

impl Scanner for BanTopicsScanner {
    fn id(&self) -> ScannerId {
        Self::ID
    }

    fn direction(&self) -> Direction {
        self.direction
    }

    fn disposition(&self) -> Disposition {
        Disposition::Block
    }

    fn scan<'a>(&self, text: &'a str, _ctx: &mut ScanCtx) -> ScanResult<'a> {
        let risk = if self.matched_topic(text).is_some() {
            HIT_RISK
        } else {
            0.0
        };
        Ok(Verdict::detected(text, risk, HIT_RISK))
    }

    fn hold_back(&self) -> HoldBack {
        // A block-only scanner never rewrites a streamed chunk, so it imposes no
        // restore hold-back; the streaming runner decides per response whether
        // the whole text is needed to judge.
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

    fn scanner() -> BanTopicsScanner {
        BanTopicsScanner::new([
            Topic::new("violence", ["weapon".to_owned(), "attack".to_owned()]),
            Topic::new(
                "medical",
                ["diagnosis".to_owned(), "prescription".to_owned()],
            ),
        ])
    }

    #[test]
    fn blocks_on_keyword_and_reports_topic() {
        let scanner = scanner();
        let mut ctx = ScanCtx::new();
        let text = "how do I build a weapon";
        let verdict = scanner.scan(text, &mut ctx).unwrap();
        assert!(!verdict.valid);
        assert_eq!(scanner.matched_topic(text), Some("violence"));
    }

    #[test]
    fn passes_clean_text() {
        let scanner = scanner();
        let mut ctx = ScanCtx::new();
        let text = "what is the weather today";
        assert!(scanner.scan(text, &mut ctx).unwrap().valid);
        assert_eq!(scanner.matched_topic(text), None);
    }

    #[test]
    fn keyword_match_is_case_insensitive() {
        let scanner = scanner();
        let mut ctx = ScanCtx::new();
        assert!(!scanner.scan("need a PRESCRIPTION", &mut ctx).unwrap().valid);
    }

    #[test]
    fn keyword_matched_on_word_boundary() {
        let scanner = BanTopicsScanner::new([Topic::new("ban", ["ass".to_owned()])]);
        let mut ctx = ScanCtx::new();
        // "class" must not trip the "ass" keyword.
        assert!(scanner.scan("the class begins", &mut ctx).unwrap().valid);
        assert!(!scanner.scan("what an ass", &mut ctx).unwrap().valid);
    }

    #[test]
    fn retries_utf8_keyword_after_failed_word_boundary() {
        let scanner = BanTopicsScanner::new([Topic::new("ban", ["élan".to_owned()])]);
        let mut ctx = ScanCtx::new();
        assert!(!contains_word("xélan", "élan"));
        assert!(!scanner.scan("xélan élan", &mut ctx).unwrap().valid);
    }

    #[test]
    fn retries_three_byte_keyword_after_failed_word_boundary() {
        let scanner = BanTopicsScanner::new([Topic::new("ban", ["漢語".to_owned()])]);
        let mut ctx = ScanCtx::new();
        assert!(!contains_word("x漢語", "漢語"));
        assert!(!scanner.scan("x漢語 漢語", &mut ctx).unwrap().valid);
    }

    #[test]
    fn retries_four_byte_keyword_after_failed_word_boundary() {
        let scanner = BanTopicsScanner::new([Topic::new("ban", ["😀topic".to_owned()])]);
        let mut ctx = ScanCtx::new();
        assert!(!contains_word("x😀topic", "😀topic"));
        assert!(!scanner.scan("x😀topic 😀topic", &mut ctx).unwrap().valid);
    }

    #[test]
    fn unicode_keywords_retry_both_boundaries_and_preserve_overlaps() {
        // Include a single final codepoint, internal multibyte characters, and
        // a combining mark, as well as each multibyte leading width.
        for keyword in ["é", "élan", "漢", "漢語", "😀", "😀topic", "aé", "e\u{301}"] {
            for (text, expected) in [
                (String::new(), false),
                (keyword.to_owned(), true),
                (format!("({keyword})"), true),
                (format!("{keyword}x"), false),
                (format!("x{keyword}x"), false),
                (format!("{keyword}x {keyword}"), true),
                (format!("x{keyword}x {keyword}"), true),
                (format!("x{keyword} {keyword}x x{keyword}"), false),
            ] {
                assert_eq!(
                    contains_word(&text, keyword),
                    expected,
                    "{text:?}, {keyword:?}"
                );
            }
            let overlapping = format!("{keyword} {keyword}");
            assert!(contains_word(
                &format!("x{keyword} {keyword} {keyword}"),
                &overlapping,
            ));
        }
    }

    #[test]
    fn word_boundaries_keep_ascii_byte_semantics() {
        // Every ASCII neighbor, and representative Unicode letters, digits,
        // marks and symbols: non-ASCII bytes remain non-word boundaries.
        for neighbor in (0..=127)
            .map(char::from)
            .chain(['é', '漢', '😀', '\u{301}', '９'])
        {
            let expected = !(neighbor.is_ascii_alphanumeric() || neighbor == '_');
            for keyword in ["word", "élan", "漢語", "😀topic"] {
                assert_eq!(
                    contains_word(&format!("{neighbor}{keyword}"), keyword),
                    expected
                );
                assert_eq!(
                    contains_word(&format!("{keyword}{neighbor}"), keyword),
                    expected
                );
            }
        }
    }

    #[test]
    fn empty_keywords_are_ignored_and_unicode_case_is_preserved() {
        let scanner = BanTopicsScanner::new([Topic::new("ban", [String::new()])]);
        for text in ["", "x", "é", "漢", "😀"] {
            assert_eq!(scanner.matched_topic(text), None);
        }
        let scanner = BanTopicsScanner::new([Topic::new("主题😀", ["ÉLAN".to_owned()])]);
        assert_eq!(scanner.matched_topic("Élan"), Some("主题😀"));
        assert_eq!(scanner.matched_topic("élan"), None);
    }

    #[test]
    fn first_matching_topic_is_reported() {
        let scanner = scanner();
        assert_eq!(
            scanner.matched_topic("a weapon and a diagnosis"),
            Some("violence")
        );
    }
}
