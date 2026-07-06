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
const STRUCTURED_PATTERNS: [&str; 6] = [
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
    // Candidate IBANs (ISO 13616): 2-letter country + 2 check digits + up to 30
    // BBAN alphanumerics, optionally single-spaced (the human-readable grouping
    // varies by country). The match is deliberately greedy and may overrun into
    // the following word; `iban_ok` strips spaces, checks the country-specific
    // length, then mod-97, trimming trailing groups until a valid IBAN is found
    // or the candidate is rejected — so an overrun never produces a redaction.
    r"\b[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,32}\b",
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
    iban: Regex,
}

fn structured_rules() -> &'static StructuredRules {
    static RULES: OnceLock<StructuredRules> = OnceLock::new();
    RULES.get_or_init(|| StructuredRules {
        email: structured_rule(STRUCTURED_PATTERNS[0]),
        phone: structured_rule(STRUCTURED_PATTERNS[1]),
        ssn: structured_rule(STRUCTURED_PATTERNS[2]),
        ip: structured_rule(STRUCTURED_PATTERNS[3]),
        digits: structured_rule(STRUCTURED_PATTERNS[4]),
        iban: structured_rule(STRUCTURED_PATTERNS[5]),
    })
}

/// Detect structured PII: `EMAIL`, `PHONE`, `US_SSN`, `IP_ADDRESS`,
/// `CREDIT_CARD` (issuer-prefix + Luhn-checked), `IBAN` (mod-97-checked).
/// Checksums and issuer prefixes gate the candidates that would otherwise
/// over-match (a random 18-digit Discord snowflake is not a card even if it
/// happens to pass Luhn; a random `GB00…` string is not an IBAN).
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
        if card_number_ok(m.as_str()) {
            spans.push(Span::new(m.start(), m.end(), "CREDIT_CARD", 0.95));
        }
    }
    for m in r.iban.find_iter(text) {
        for (offset, len) in valid_ibans_in(m.as_str()) {
            let start = m.start() + offset;
            spans.push(Span::new(start, start + len, "IBAN", 0.95));
        }
    }
    spans
}

fn is_valid_ipv4(s: &str) -> bool {
    let octets: Vec<&str> = s.split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok())
}

/// A credit-card candidate must be both Luhn-valid and in a reasonably precise
/// issuer range. Luhn alone is too weak for machine identifiers: Discord
/// snowflakes, order IDs, and chain metadata are often 17-19 bare digits, and
/// about one in ten such numbers pass Luhn by chance.
fn card_number_ok(s: &str) -> bool {
    let digits = digit_string(s);
    issuer_prefix_ok(&digits) && luhn_digits_ok(digits.as_bytes())
}

fn digit_string(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

fn issuer_prefix_ok(digits: &str) -> bool {
    let len = digits.len();
    let prefix2 = prefix(digits, 2);
    let prefix3 = prefix(digits, 3);
    let prefix4 = prefix(digits, 4);
    let prefix6 = prefix(digits, 6);

    (digits.starts_with('4') && matches!(len, 13 | 16 | 19))
        || (matches!(prefix2, Some(51..=55)) && len == 16)
        || (matches!(prefix4, Some(2221..=2720)) && len == 16)
        || (matches!(prefix2, Some(34 | 37)) && len == 15)
        || (matches!(prefix4, Some(6011)) && matches!(len, 16 | 19))
        || (matches!(prefix2, Some(65)) && matches!(len, 16 | 19))
        || (matches!(prefix3, Some(644..=649)) && matches!(len, 16 | 19))
        || (matches!(prefix6, Some(622126..=622925)) && matches!(len, 16 | 19))
        || (matches!(prefix3, Some(300..=305)) && len == 14)
        || (matches!(prefix2, Some(36 | 38 | 39)) && len == 14)
        || (matches!(prefix4, Some(3528..=3589)) && matches!(len, 16..=19))
}

fn prefix(s: &str, len: usize) -> Option<u32> {
    s.get(..len)?.parse().ok()
}

/// Luhn mod-10 checksum over a possibly-spaced/hyphenated digit string.
#[cfg(test)]
fn luhn_ok(s: &str) -> bool {
    let digits = digit_string(s);
    luhn_digits_ok(digits.as_bytes())
}

fn luhn_digits_ok(digits: &[u8]) -> bool {
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut d = u32::from(d - b'0');
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

/// The registered total IBAN length per ISO 13616 country code. Length is
/// fixed per country, so it gates candidates that mod-97 alone would accept (a
/// 23-char `GB…` with recomputed check digits is not a real IBAN — GB is 22).
const IBAN_LENGTHS: &[(&[u8; 2], usize)] = &[
    (b"AD", 24),
    (b"AE", 23),
    (b"AL", 28),
    (b"AT", 20),
    (b"AZ", 28),
    (b"BA", 20),
    (b"BE", 16),
    (b"BG", 22),
    (b"BH", 22),
    (b"BI", 27),
    (b"BR", 29),
    (b"BY", 28),
    (b"CH", 21),
    (b"CR", 22),
    (b"CY", 28),
    (b"CZ", 24),
    (b"DE", 22),
    (b"DJ", 27),
    (b"DK", 18),
    (b"DO", 28),
    (b"EE", 20),
    (b"EG", 29),
    (b"ES", 24),
    (b"FI", 18),
    (b"FK", 18),
    (b"FO", 18),
    (b"FR", 27),
    (b"GB", 22),
    (b"GE", 22),
    (b"GI", 23),
    (b"GL", 18),
    (b"GR", 27),
    (b"GT", 28),
    (b"HN", 28),
    (b"HR", 21),
    (b"HU", 28),
    (b"IE", 22),
    (b"IL", 23),
    (b"IQ", 23),
    (b"IS", 26),
    (b"IT", 27),
    (b"JO", 30),
    (b"KW", 30),
    (b"KZ", 20),
    (b"LB", 28),
    (b"LC", 32),
    (b"LI", 21),
    (b"LT", 20),
    (b"LU", 20),
    (b"LV", 21),
    (b"LY", 25),
    (b"MC", 27),
    (b"MD", 24),
    (b"ME", 22),
    (b"MK", 19),
    (b"MN", 20),
    (b"MR", 27),
    (b"MT", 31),
    (b"MU", 30),
    (b"NI", 28),
    (b"NL", 18),
    (b"NO", 15),
    (b"OM", 23),
    (b"PK", 24),
    (b"PL", 28),
    (b"PS", 29),
    (b"PT", 25),
    (b"QA", 29),
    (b"RO", 24),
    (b"RS", 22),
    (b"RU", 33),
    (b"SA", 24),
    (b"SC", 31),
    (b"SD", 18),
    (b"SE", 24),
    (b"SI", 19),
    (b"SK", 24),
    (b"SM", 27),
    (b"SO", 23),
    (b"ST", 25),
    (b"SV", 28),
    (b"TL", 23),
    (b"TN", 24),
    (b"TR", 26),
    (b"UA", 29),
    (b"VA", 22),
    (b"VG", 24),
    (b"XK", 20),
    (b"YE", 30),
];

/// The registered IBAN length for `country` (uppercased), or `None` for an
/// unknown country code.
fn iban_length(country: [u8; 2]) -> Option<usize> {
    let country = [
        country[0].to_ascii_uppercase(),
        country[1].to_ascii_uppercase(),
    ];
    IBAN_LENGTHS
        .iter()
        .find(|(cc, _)| **cc == country)
        .map(|(_, len)| *len)
}

/// Every non-overlapping valid IBAN inside `candidate` as `(start_offset, len)`
/// byte indices.
///
/// One greedy regex match can span an IBAN-shaped run that is not itself valid
/// (`AA00 GB82 …`), overrun into the following word, *and* hold more than one
/// real IBAN. `find_iter` is non-overlapping, so each candidate must be mined in
/// full. Scan each `[A-Za-z]{2}\d{2}` start; on a hit, emit it and resume past
/// its end so adjacent IBANs are each found and none is double-counted.
fn valid_ibans_in(candidate: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut next = 0;
    for start in iban_starts(candidate) {
        if start < next {
            continue;
        }
        if let Some(len) = valid_iban_prefix_len(&candidate[start..]) {
            found.push((start, len));
            next = start + len;
        }
    }
    found
}

/// Byte offsets in `candidate` where an IBAN can begin: a 2-letter country code
/// and 2 check digits at a word boundary (start of string or after a space).
fn iban_starts(candidate: &str) -> impl Iterator<Item = usize> + '_ {
    let bytes = candidate.as_bytes();
    (0..bytes.len()).filter(move |&i| {
        let after_boundary = i == 0 || bytes[i - 1] == b' ';
        let anchor = bytes.get(i..i + 4).is_some_and(|w| {
            w[0].is_ascii_alphabetic()
                && w[1].is_ascii_alphabetic()
                && w[2].is_ascii_digit()
                && w[3].is_ascii_digit()
        });
        after_boundary && anchor
    })
}

/// The byte length of the valid IBAN at the start of `candidate`, or `None`.
/// Trims one trailing space-separated group at a time and accepts the first
/// prefix that validates; the length counts spaces so the caller can place the
/// span without re-walking.
fn valid_iban_prefix_len(candidate: &str) -> Option<usize> {
    let mut end = candidate.len();
    loop {
        if iban_ok(&candidate[..end]) {
            return Some(end);
        }
        // Drop the last whitespace-separated group and retry; stop once the
        // remaining prefix is too short to hold the shortest IBAN (15 chars).
        let space = candidate[..end].rfind(' ')?;
        end = candidate[..space].trim_end().len();
        if end < 15 {
            return None;
        }
    }
}

/// ISO 13616 IBAN check on a single candidate: strip spaces, require the
/// country-specific length, then validate the mod-97 checksum. The checksum
/// moves the first four characters to the end, maps each letter to two digits
/// (`A`=10 … `Z`=35), and reads the result as one integer that must be
/// `1 mod 97`. The running remainder is folded character-by-character to stay
/// within `u32` without bignum.
fn iban_ok(s: &str) -> bool {
    let compact: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let Some(&[c0, c1]) = compact.get(..2) else {
        return false;
    };
    if iban_length([c0, c1]) != Some(compact.len()) {
        return false;
    }
    let (head, tail) = compact.split_at(4);
    let mut remainder = 0u32;
    for &b in tail.iter().chain(head) {
        let value = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'A'..=b'Z' => u32::from(b - b'A') + 10,
            b'a'..=b'z' => u32::from(b - b'a') + 10,
            // The regex only admits ASCII alphanumerics, so this is unreachable;
            // reject defensively rather than panic on the detection path.
            _ => return false,
        };
        // A letter contributes two decimal digits, a digit one — shift the
        // remainder by the matching power of ten before folding the value in.
        remainder = if value >= 10 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    remainder == 1
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
    fn card_detector_requires_plausible_issuer_not_just_luhn() {
        // Discord snowflake from Graham's baked team list. It is Luhn-valid, but
        // it is not a plausible payment-card number and must not inflate the
        // dashboard's credit-card redaction count on every Graham request.
        let snowflake = "689802468376313879";
        assert!(luhn_ok(snowflake));
        assert!(!card_number_ok(snowflake));
        assert!(!detect_structured(snowflake)
            .iter()
            .any(|s| s.ty == "CREDIT_CARD"));

        for card in [
            "4111 1111 1111 1111",
            "5555 5555 5555 4444",
            "3782 822463 10005",
            "6011-1111-1111-1117",
            "3530 1113 3330 0000",
        ] {
            assert!(card_number_ok(card), "missed card: {card}");
            assert!(
                detect_structured(card).iter().any(|s| s.ty == "CREDIT_CARD"),
                "missed card span: {card}"
            );
        }
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
    fn iban_accepts_valid_rejects_bad_checksum() {
        // Published ISO 13616 test IBANs across countries, spaced and contiguous.
        assert!(iban_ok("GB82 WEST 1234 5698 7654 32"));
        assert!(iban_ok("DE89 3704 0044 0532 0130 00"));
        assert!(iban_ok("FR14 2004 1010 0505 0001 3M02 606"));
        assert!(iban_ok("NL91ABNA0417164300"));
        // Norway — the shortest IBAN at 15 characters.
        assert!(iban_ok("NO9386011117947"));
        // A single transposed digit fails the mod-97 checksum.
        assert!(!iban_ok("GB82 WEST 1234 5698 7654 33"));
        // Too short to be any IBAN.
        assert!(!iban_ok("GB82 WEST"));
    }

    #[test]
    fn iban_rejects_wrong_length_for_country() {
        // mod-97 alone would pass this recomputed-check 23-char `GB…`, but GB
        // IBANs are fixed length 22 — the country-length gate rejects it.
        assert!(!iban_ok("GB49 WEST 1234 5698 7654 321"));
        // An unknown country code has no registered length.
        assert!(!iban_ok("ZZ00 0000 0000 0000 0000 00"));
    }

    #[test]
    fn detects_iban_across_countries() {
        for iban in [
            "pay to GB82 WEST 1234 5698 7654 32 today",
            "send DE89 3704 0044 0532 0130 00 now",
            "ref NL91ABNA0417164300 please",
            // Burundi prints in non-four-char groups; the trimming validator
            // accepts it where a four-group regex would not.
            "to BI13 20001 10001 00001234567 89 ok",
        ] {
            let spans = detect_structured(iban);
            assert!(spans.iter().any(|s| s.ty == "IBAN"), "missed: {iban}");
        }
    }

    #[test]
    fn iban_span_excludes_trailing_prose() {
        // A greedy regex match runs into the following digits, but the validated
        // span ends exactly at the IBAN — trailing text is not redacted.
        let text = "iban GB82 WEST 1234 5698 7654 32 99999 done";
        let span = detect_structured(text)
            .into_iter()
            .find(|s| s.ty == "IBAN")
            .expect("IBAN detected");
        assert_eq!(&text[span.start..span.end], "GB82 WEST 1234 5698 7654 32");
    }

    #[test]
    fn iban_found_behind_iban_shaped_prefix() {
        // A bogus `AA00 …` run is itself IBAN-shaped and would consume the whole
        // candidate; the scan must still recover the real IBAN that follows it.
        let text = "note AA00 GB82 WEST 1234 5698 7654 32 end";
        let span = detect_structured(text)
            .into_iter()
            .find(|s| s.ty == "IBAN")
            .expect("IBAN behind junk prefix");
        assert_eq!(&text[span.start..span.end], "GB82 WEST 1234 5698 7654 32");
    }

    #[test]
    fn detects_two_adjacent_ibans_in_one_candidate() {
        // Two valid IBANs back-to-back fall inside a single greedy regex match;
        // both must be detected, not just the first.
        let text = "pay BE68 5390 0754 7034 and NO9386011117947 now";
        let ibans: Vec<_> = detect_structured(text)
            .into_iter()
            .filter(|s| s.ty == "IBAN")
            .map(|s| text[s.start..s.end].to_owned())
            .collect();
        assert_eq!(ibans, ["BE68 5390 0754 7034", "NO9386011117947"]);
    }

    #[test]
    fn iban_bad_checksum_not_flagged() {
        let spans = detect_structured("ref GB82 WEST 1234 5698 7654 33 here");
        assert!(!spans.iter().any(|s| s.ty == "IBAN"));
    }

    /// The card detector also matches the digit run inside an IBAN; overlap
    /// resolution must keep the single wider IBAN span, never fragment it.
    #[test]
    fn iban_not_fragmented_by_overlapping_card_match() {
        let kept = resolve_overlaps(detect_structured("iban GB82 WEST 1234 5698 7654 32 end"));
        let ibans: Vec<_> = kept.iter().filter(|s| s.ty == "IBAN").collect();
        assert_eq!(ibans.len(), 1);
        assert!(!kept.iter().any(|s| s.ty == "CREDIT_CARD"));
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
