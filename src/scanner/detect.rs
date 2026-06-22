//! Detection primitives: a [`Span`] type, structured-PII recognizers (regex +
//! checksum), and a secret-pattern ruleset with a Shannon-entropy backstop.
//!
//! Each detector emits [`Span`]s (byte offsets into the scanned text, an entity
//! type, and a 0–1 confidence). A scanner collects spans, resolves overlaps,
//! and rewrites span-by-span — no detector ever does a global string-replace.
//!
//! NER/entity recognition (names, addresses, orgs) is a later native-ML add via
//! an `ort`/`gline-rs` detector that emits the same [`Span`]s; the scanner code
//! is already span-based so it slots in without changing the rewrite path.

use std::sync::OnceLock;

use regex::Regex;

/// One detected entity: a byte range in the scanned text, its type, and a 0–1
/// confidence used for overlap resolution and thresholding.
#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub ty: String,
    pub confidence: f32,
}

impl Span {
    /// Construct a span.
    #[must_use]
    pub fn new(start: usize, end: usize, ty: &str, confidence: f32) -> Self {
        Self {
            start,
            end,
            ty: ty.to_owned(),
            confidence,
        }
    }
}

/// Resolve overlapping spans into a non-overlapping, start-sorted set that still
/// covers every detected byte — a redaction primitive must never leave a flagged
/// region unmasked.
///
/// Spans are ordered start-ascending, then widest-first, then highest-confidence.
/// A span is kept only when it extends coverage past the last byte already kept;
/// a span fully contained in an earlier one is dropped, and a span that starts
/// inside an earlier one but extends beyond it is clipped to the uncovered tail.
/// For two co-extensive spans (same range) the widest-first/confidence order
/// keeps the higher-confidence label — a credit-card Luhn hit over a stray phone
/// match on the same digits — without ever discarding coverage the way a plain
/// "keep the higher-confidence span" rule would.
#[must_use]
pub fn resolve_overlaps(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end))
            .then(cmp_confidence_desc(a, b))
    });
    let mut kept: Vec<Span> = Vec::with_capacity(spans.len());
    let mut covered_to = 0usize;
    for mut span in spans {
        if span.end <= covered_to {
            // Fully inside an already-kept region — its bytes are masked.
            continue;
        }
        if span.start < covered_to {
            // Starts inside a kept region but runs past it: redact only the
            // uncovered tail so the union stays masked without double-emitting.
            span.start = covered_to;
        }
        covered_to = span.end;
        kept.push(span);
    }
    kept
}

/// Order two spans by descending confidence, treating `NaN` as equal.
fn cmp_confidence_desc(a: &Span, b: &Span) -> std::cmp::Ordering {
    b.confidence
        .partial_cmp(&a.confidence)
        .unwrap_or(std::cmp::Ordering::Equal)
}

// ---------------------------------------------------------------------------
// Structured PII
// ---------------------------------------------------------------------------

/// Compile a literal pattern. Every pattern passed here is a crate-internal
/// constant known to compile; if one ever regresses, fall back to a shared
/// never-match regex rather than panicking on the detection path.
fn structured_rule(pat: &str) -> Regex {
    Regex::new(pat).unwrap_or_else(|_| never_match().clone())
}

/// A single shared regex that matches nothing — the fallback if a crate-
/// internal literal pattern ever fails to compile. `[^\s\S]` matches no
/// character; it is a fixed valid pattern compiled exactly once.
fn never_match() -> &'static Regex {
    static NEVER: OnceLock<Regex> = OnceLock::new();
    NEVER.get_or_init(|| match Regex::new(r"[^\s\S]") {
        Ok(re) => re,
        // Unreachable: `[^\s\S]` is always valid. Recurse rather than panic to
        // keep this total without an unwrap.
        Err(_) => never_match().clone(),
    })
}

/// The structured-PII source patterns, the single source both the compiled
/// detector regexes and the streaming hold-back DFA read. Order matches the
/// fields of [`StructuredRules`].
const STRUCTURED_PATTERNS: [&str; 5] = [
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    r"(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}\b",
    r"\b\d{3}-\d{2}-\d{4}\b",
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    // Candidate card numbers: 13–19 digits, optionally space/hyphen grouped.
    // The separator sits *between* digits (`\d(?:[ \-]?\d){12,18}`), never after
    // the last one, so a trailing space before the next word is not swallowed
    // into the match (which would redact `4111 1111 1111 1111 ` and corrupt the
    // following text).
    r"\b\d(?:[ \-]?\d){12,18}\b",
];

/// The structured-PII detector patterns as DFA hold-back source strings.
#[must_use]
pub fn structured_pattern_sources() -> Vec<String> {
    STRUCTURED_PATTERNS
        .iter()
        .map(|p| (*p).to_owned())
        .collect()
}

struct StructuredRules {
    email: Regex,
    phone: Regex,
    ssn: Regex,
    ip: Regex,
    digits: Regex,
}

fn structured_rules() -> &'static StructuredRules {
    static RULES: OnceLock<StructuredRules> = OnceLock::new();
    RULES.get_or_init(|| StructuredRules {
        email: structured_rule(STRUCTURED_PATTERNS[0]),
        phone: structured_rule(STRUCTURED_PATTERNS[1]),
        ssn: structured_rule(STRUCTURED_PATTERNS[2]),
        ip: structured_rule(STRUCTURED_PATTERNS[3]),
        digits: structured_rule(STRUCTURED_PATTERNS[4]),
    })
}

/// Detect structured PII: `EMAIL`, `PHONE`, `US_SSN`, `IP_ADDRESS`,
/// `CREDIT_CARD` (Luhn-checked). Checksums gate the candidates that would
/// otherwise over-match (a random 16-digit number is not a card).
#[must_use]
pub fn detect_structured(text: &str) -> Vec<Span> {
    let r = structured_rules();
    let mut spans = Vec::new();
    for m in r.email.find_iter(text) {
        spans.push(Span::new(m.start(), m.end(), "EMAIL", 0.95));
    }
    for m in r.phone.find_iter(text) {
        spans.push(Span::new(m.start(), m.end(), "PHONE", 0.85));
    }
    for m in r.ssn.find_iter(text) {
        spans.push(Span::new(m.start(), m.end(), "US_SSN", 0.9));
    }
    for m in r.ip.find_iter(text) {
        if is_valid_ipv4(m.as_str()) {
            spans.push(Span::new(m.start(), m.end(), "IP_ADDRESS", 0.85));
        }
    }
    for m in r.digits.find_iter(text) {
        if luhn_ok(m.as_str()) {
            spans.push(Span::new(m.start(), m.end(), "CREDIT_CARD", 0.95));
        }
    }
    spans
}

fn is_valid_ipv4(s: &str) -> bool {
    let octets: Vec<&str> = s.split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok())
}

/// Luhn mod-10 checksum over a possibly-spaced/hyphenated digit string.
fn luhn_ok(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut d = d;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// A compiled secret rule: a name (the sentinel type) and its regex.
struct SecretRule {
    ty: &'static str,
    re: Regex,
}

/// The vendor secret `(type, pattern)` source list — the single source both the
/// compiled detector regexes and the streaming hold-back DFA read.
const SECRET_PATTERNS: [(&str, &str); 8] = [
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    ("GITHUB_TOKEN", r"ghp_[A-Za-z0-9]{36}"),
    ("STRIPE_KEY", r"sk_live_[A-Za-z0-9]{24,}"),
    ("OPENAI_KEY", r"sk-[A-Za-z0-9]{20,}"),
    ("GOOGLE_API_KEY", r"AIza[0-9A-Za-z\-_]{35}"),
    (
        "SLACK_WEBHOOK",
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    ),
    // PEM private-key blocks: header through footer, any key type.
    (
        "PRIVATE_KEY",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    // PEM header alone, for truncated keys pasted without the footer.
    ("PRIVATE_KEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
];

/// The labelled `key=value` and URL-credential source patterns.
const CREDENTIAL_PATTERNS: [&str; 2] = [
    r#"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\b\s*[:=]\s*["']?([^\s"'&]{6,})"#,
    r"[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s/@]+)@",
];

/// The secret detector patterns as DFA hold-back source strings: every vendor
/// pattern plus the labelled-secret and URL-credential patterns. The high-
/// entropy backstop is intentionally **not** here — it is a per-token heuristic
/// with no regular shape, so the streaming runner bounds it with a token-length
/// hold-back instead of a DFA branch.
#[must_use]
pub fn secret_pattern_sources() -> Vec<String> {
    SECRET_PATTERNS
        .iter()
        .map(|(_, p)| (*p).to_owned())
        .chain(CREDENTIAL_PATTERNS.iter().map(|p| (*p).to_owned()))
        .collect()
}

fn secret_rules() -> &'static [SecretRule] {
    static RULES: OnceLock<Vec<SecretRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let mut rules = Vec::new();
        for (ty, pat) in SECRET_PATTERNS {
            if let Ok(re) = Regex::new(pat) {
                rules.push(SecretRule { ty, re });
            }
        }
        rules
    })
}

/// `key = value` / `key: value` pairs whose key names a credential. The value
/// span (group 1), not the label, is redacted.
fn labelled_secret_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| structured_rule(CREDENTIAL_PATTERNS[0]))
}

/// A `scheme://user:password@host` URL credential. The password span (group 1).
fn url_credential_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| structured_rule(CREDENTIAL_PATTERNS[1]))
}

/// Detect credentials: known-vendor patterns, labelled `key=value` secrets,
/// URL-embedded passwords, and a high-entropy backstop over bare tokens.
#[must_use]
pub fn detect_secrets(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for rule in secret_rules() {
        for m in rule.re.find_iter(text) {
            spans.push(Span::new(m.start(), m.end(), rule.ty, 0.99));
        }
    }
    for caps in labelled_secret_rule().captures_iter(text) {
        if let Some(v) = caps.get(1) {
            spans.push(Span::new(v.start(), v.end(), "SECRET", 0.9));
        }
    }
    for caps in url_credential_rule().captures_iter(text) {
        if let Some(v) = caps.get(1) {
            spans.push(Span::new(v.start(), v.end(), "SECRET", 0.9));
        }
    }
    spans.extend(entropy_backstop(text));
    spans
}

/// Shannon entropy (bits per char) of a byte string.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = f64::from(u32::try_from(s.len()).unwrap_or(u32::MAX));
    let mut entropy = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn is_base64ish(s: &str) -> bool {
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'_'
    })
}

fn is_hexish(s: &str) -> bool {
    s.len() >= 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// High-entropy token backstop: flags whitespace-delimited tokens that look
/// like opaque credentials. base64 ≥4.5 bits/char, hex ≥3.0. Catches the
/// bespoke internal token that matches no vendor pattern.
fn entropy_backstop(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for (start, tok) in split_with_offsets(text) {
        let len = tok.len();
        // Test the cheap character-class predicates before computing entropy: a
        // long prose word is neither hex nor base64, so it never pays for the
        // entropy scan.
        if len >= 20 && (is_hexish(tok) || is_base64ish(tok)) {
            let ent = shannon_entropy(tok);
            let hit = (is_hexish(tok) && ent >= 3.0) || (is_base64ish(tok) && ent >= 4.5);
            if hit {
                spans.push(Span::new(start, start + len, "SECRET", 0.7));
            }
        }
    }
    spans
}

/// Split on ASCII whitespace, yielding `(byte_start, token)`.
fn split_with_offsets(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split_ascii_whitespace().map(move |tok| {
        // `split_ascii_whitespace` drops offsets; recover via the substring
        // pointer arithmetic against the parent allocation.
        let start = tok.as_ptr() as usize - text.as_ptr() as usize;
        (start, tok)
    })
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
    fn shannon_entropy_of_uniform_is_high() {
        assert!(shannon_entropy("abcdefghijklmnop") > 3.0);
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 0.1);
    }

    #[test]
    fn luhn_accepts_valid_card_rejects_random() {
        assert!(luhn_ok("4111 1111 1111 1111"));
        assert!(!luhn_ok("4111 1111 1111 1112"));
        assert!(!luhn_ok("1234 5678 9012 3456"));
    }

    #[test]
    fn ipv4_validation_rejects_out_of_range() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(!is_valid_ipv4("999.1.1.1"));
    }

    #[test]
    fn detects_email_and_ssn() {
        let spans = detect_structured("mail me at a@b.com or use 123-45-6789");
        assert!(spans.iter().any(|s| s.ty == "EMAIL"));
        assert!(spans.iter().any(|s| s.ty == "US_SSN"));
    }

    #[test]
    fn detects_aws_key_and_private_key_header() {
        let spans =
            detect_secrets("creds AKIAIOSFODNN7EXAMPLE and -----BEGIN RSA PRIVATE KEY-----");
        assert!(spans.iter().any(|s| s.ty == "AWS_ACCESS_KEY"));
        assert!(spans.iter().any(|s| s.ty == "PRIVATE_KEY"));
    }

    #[test]
    fn higher_confidence_span_wins_overlap() {
        let kept = resolve_overlaps(vec![
            Span::new(0, 16, "PHONE", 0.5),
            Span::new(0, 16, "CREDIT_CARD", 0.95),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].ty, "CREDIT_CARD");
    }

    /// A wider, lower-confidence span must not be discarded in favour of a
    /// narrow, higher-confidence span nested inside it — that would leave the
    /// wider span's uncovered bytes unredacted (a leak). The whole detected
    /// region stays masked.
    #[test]
    fn nested_high_confidence_does_not_uncover_wider_region() {
        let kept = resolve_overlaps(vec![
            Span::new(0, 20, "WIDE", 0.5),
            Span::new(5, 10, "NARROW", 0.95),
            Span::new(12, 18, "TRAIL", 0.9),
        ]);
        // The wide span survives and covers [0, 20); no later span re-opens a
        // hole inside it.
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].start, 0);
        assert_eq!(kept[0].end, 20);
        assert_eq!(kept[0].ty, "WIDE");
    }

    /// A span that starts inside a kept region but runs past it is clipped to the
    /// uncovered tail so the union of both spans stays masked end to end.
    #[test]
    fn partial_overlap_clips_to_cover_the_union() {
        let kept = resolve_overlaps(vec![Span::new(0, 10, "A", 0.9), Span::new(6, 16, "B", 0.9)]);
        assert_eq!(kept.len(), 2);
        assert_eq!((kept[0].start, kept[0].end), (0, 10));
        // B is clipped to start where A ended; together they cover [0, 16).
        assert_eq!((kept[1].start, kept[1].end), (10, 16));
    }

    /// Coverage invariant over arbitrary span sets: every byte any input span
    /// flagged is covered by exactly one kept span, and kept spans never overlap.
    #[test]
    fn kept_spans_cover_every_flagged_byte_without_overlap() {
        let input = vec![
            Span::new(2, 9, "X", 0.4),
            Span::new(0, 5, "Y", 0.8),
            Span::new(20, 25, "Z", 0.6),
            Span::new(7, 22, "W", 0.5),
        ];
        let flagged: std::collections::BTreeSet<usize> =
            input.iter().flat_map(|s| s.start..s.end).collect();
        let kept = resolve_overlaps(input);
        for win in kept.windows(2) {
            assert!(win[0].end <= win[1].start, "kept spans overlap: {kept:?}");
        }
        let covered: std::collections::BTreeSet<usize> =
            kept.iter().flat_map(|s| s.start..s.end).collect();
        assert_eq!(flagged, covered, "a flagged byte was left uncovered");
    }
}
