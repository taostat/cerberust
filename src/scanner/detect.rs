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

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

use blake2::Blake2b512;
use regex::Regex;
use sha2::{Digest, Sha256};

use super::{bip39, gitleaks};

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

/// The structured-PII source patterns. `structured_boundary_pattern` expands
/// their boundary markers for both detection and streaming hold-back. Order
/// matches the fields of [`StructuredRules`].
const STRUCTURED_PATTERNS: [&str; 6] = [
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    r"(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}(?-u:\b)",
    r"(?-u:\b)\d{3}-\d{2}-\d{4}(?-u:\b)",
    r"(?-u:\b)(?:\d{1,3}\.){3}\d{1,3}(?-u:\b)",
    // Candidate card numbers: 13–19 digits, optionally space/hyphen grouped.
    // The separator sits *between* digits (`\d(?:[ \-]?\d){12,18}`), never after
    // the last one, so a trailing space before the next word is not swallowed
    // into the match (which would redact `4111 1111 1111 1111 ` and corrupt the
    // following text).
    r"(?-u:\b)\d(?:[ \-]?\d){12,18}(?-u:\b)",
    // Candidate IBANs (ISO 13616): 2-letter country + 2 check digits + up to 30
    // BBAN alphanumerics, optionally single-spaced (the human-readable grouping
    // varies by country). The match is deliberately greedy and may overrun into
    // the following word; `iban_ok` strips spaces, checks the country-specific
    // length, then mod-97, trimming trailing groups until a valid IBAN is found
    // or the candidate is rejected — so an overrun never produces a redaction.
    r"(?-u:\b)[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,32}(?-u:\b)",
];

/// Consume boundary context instead of a Unicode look assertion, which makes
/// the regex fall back from its lazy DFA on non-ASCII input. Non-ASCII letters
/// now delimit values; other Unicode word characters retain their old meaning.
/// In particular, `\d` still admits Unicode digits, so an ASCII `\b` alone
/// would miss phones ending in one and truncate mixed-digit card candidates.
fn structured_boundary_pattern(pattern: &str) -> String {
    const BOUNDARY: &str = r"(?-u:\b)";
    const DELIMITER: &str = r"[\W[\p{L}&&[^\p{ASCII}]]]";
    let Some(body) = pattern.strip_suffix(BOUNDARY) else {
        return pattern.to_owned();
    };
    let (left, body) = match body.strip_prefix(BOUNDARY) {
        Some(body) => (format!(r"(?:\A|{DELIMITER})"), body),
        None => (String::new(), body),
    };
    format!(r"{left}(?P<value>{body})(?:\z|{DELIMITER})")
}

/// Only the captured value is PII. Resume at its end so adjacent candidates
/// can share the consumed delimiter, as zero-width boundaries previously did.
fn structured_matches<'a>(
    rule: &'a Regex,
    text: &'a str,
) -> impl Iterator<Item = regex::Match<'a>> + 'a {
    let mut next = 0;
    std::iter::from_fn(move || {
        let value = rule.captures_at(text, next)?.name("value")?;
        next = value.end();
        Some(value)
    })
}

/// Candidate international phone numbers: `+` then an ASCII digit run in any
/// grouping the country uses (`+44 7700 900123`, `+33 1 23 45 67 89`). The run
/// is unbounded so the whole grouped value is one candidate; `e164_digits_ok`
/// then requires 7–15 digits across all of it, so an over-long grouped
/// identifier is rejected rather than redacted by prefix. Separators sit between
/// digits and exclude newlines, so the match never swallows trailing whitespace
/// or a number on the next line.
const INTL_PHONE_PATTERN: &str = r"\+[0-9](?:[ .\-]?[0-9])*";

/// The streaming hold-back form of [`INTL_PHONE_PATTERN`], capped at 16 digits:
/// one past the E.164 maximum decides rejection, so an endless run is flushed in
/// pieces — none of which starts with `+`, so none is a candidate — rather than
/// held whole. The runner never splits a completed match, so the flushed piece
/// carries all 16 digits and is rejected, as the unary scan rejects the run.
const INTL_PHONE_HOLD_PATTERN: &str = r"\+[0-9](?:[ .\-]?[0-9]){0,15}";

/// The structured-PII detector patterns as DFA hold-back source strings.
#[must_use]
pub fn structured_pattern_sources() -> Vec<String> {
    let mut sources: Vec<String> = STRUCTURED_PATTERNS
        .iter()
        .map(|p| structured_boundary_pattern(p))
        .collect();
    sources.push(INTL_PHONE_HOLD_PATTERN.to_owned());
    sources
}

struct StructuredRules {
    email: Regex,
    phone: Regex,
    intl_phone: Regex,
    ssn: Regex,
    ip: Regex,
    digits: Regex,
    iban: Regex,
}

fn structured_rules() -> &'static StructuredRules {
    static RULES: OnceLock<StructuredRules> = OnceLock::new();
    RULES.get_or_init(|| StructuredRules {
        email: structured_rule(STRUCTURED_PATTERNS[0]),
        phone: structured_rule(&structured_boundary_pattern(STRUCTURED_PATTERNS[1])),
        ssn: structured_rule(&structured_boundary_pattern(STRUCTURED_PATTERNS[2])),
        ip: structured_rule(&structured_boundary_pattern(STRUCTURED_PATTERNS[3])),
        digits: structured_rule(&structured_boundary_pattern(STRUCTURED_PATTERNS[4])),
        iban: structured_rule(&structured_boundary_pattern(STRUCTURED_PATTERNS[5])),
        intl_phone: structured_rule(INTL_PHONE_PATTERN),
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
    for m in structured_matches(&r.phone, text) {
        spans.push(Span::new(m.start(), m.end(), "PHONE", 0.85));
    }
    for m in r.intl_phone.find_iter(text) {
        if e164_digits_ok(m.as_str()) {
            spans.push(Span::new(m.start(), m.end(), "PHONE", 0.85));
        }
    }
    for m in structured_matches(&r.ssn, text) {
        if valid_us_ssn(m.as_str()) {
            spans.push(Span::new(m.start(), m.end(), "US_SSN", 0.9));
        }
    }
    for m in structured_matches(&r.ip, text) {
        if is_valid_ipv4(m.as_str()) {
            spans.push(Span::new(m.start(), m.end(), "IP_ADDRESS", 0.85));
        }
    }
    for m in structured_matches(&r.digits, text) {
        if card_number_ok(m.as_str()) {
            spans.push(Span::new(m.start(), m.end(), "CREDIT_CARD", 0.95));
        }
    }
    for m in structured_matches(&r.iban, text) {
        for (offset, len) in valid_ibans_in(m.as_str()) {
            let start = m.start() + offset;
            spans.push(Span::new(start, start + len, "IBAN", 0.95));
        }
    }
    spans
}

/// Keep completed candidates whole even when two of them share boundary
/// context. The hold-back regex's ordinary `find_iter` cannot reuse that byte.
/// Include rejected candidates too: a fragment could pass validation on its own.
pub(crate) fn structured_match_ranges(buf: &[u8]) -> Vec<std::ops::Range<usize>> {
    let Ok(text) = std::str::from_utf8(buf) else {
        return Vec::new();
    };
    let r = structured_rules();
    [&r.phone, &r.ssn, &r.ip, &r.digits, &r.iban]
        .into_iter()
        .flat_map(|rule| structured_matches(rule, text).map(|m| m.range()))
        .collect()
}

// SSA excludes these unassigned ranges; see its SSN fact sheet:
// https://www.ssa.gov/kc/SSAFactSheet--IssuingSSNs.pdf
fn valid_us_ssn(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 11 || bytes[3] != b'-' || bytes[6] != b'-' {
        return false;
    }
    let area = value[..3].parse::<u16>().unwrap_or(0);
    let group = value[4..6].parse::<u8>().unwrap_or(0);
    let serial = value[7..].parse::<u16>().unwrap_or(0);
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// E.164 allows at most 15 digits including the country code; fewer than 7
/// is too short to be a dialable international number.
fn e164_digits_ok(candidate: &str) -> bool {
    let digits = candidate.bytes().filter(u8::is_ascii_digit).count();
    (7..=15).contains(&digits)
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
        || (matches!(prefix6, Some(622_126..=622_925)) && matches!(len, 16 | 19))
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
    sum.is_multiple_of(10)
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

struct ValidatedSecretRule {
    ty: &'static str,
    re: Regex,
    keywords: &'static [&'static str],
    validator: fn(&str) -> bool,
    confidence: f32,
}

type SecretPattern = (
    &'static str,
    &'static str,
    &'static [&'static str],
    fn(&str) -> bool,
    f32,
);

const ADDITIONAL_SECRET_PATTERNS: &[SecretPattern] = &[
    // Bittensor keyfile fields follow this source:
    // https://raw.githubusercontent.com/opentensor/btwallet/main/src/keyfile.rs
    (
        "BITTENSOR_SEED",
        concat!(
            r"(?i)(?:--seed\b|\bsecret[_ ]?seed\b|\bseed\b)",
            r"\s*(?:[:=]\s*|\s+)(?P<secret>0x[0-9a-f]{64})\b"
        ),
        &["--seed", "seed", "secret seed", "secretseed", "secret_seed"],
        valid_prefixed_seed,
        0.995,
    ),
    (
        "BITTENSOR_SEED",
        r#"(?i)"secret[_ ]?seed"\s*:\s*"(?P<secret>0x[0-9a-f]{64})""#,
        &["secretseed", "secret_seed", "secret seed"],
        valid_prefixed_seed,
        0.995,
    ),
    (
        "BITTENSOR_PRIVATE_KEY",
        concat!(
            r#"(?i)"privatekey"\s*:\s*"(?P<secret>(?:0x)?"#,
            r"(?:[0-9a-f]{64}|[0-9a-f]{128})\b)"
        ),
        &["privatekey"],
        valid_bittensor_private_key,
        0.999,
    ),
    (
        "BITTENSOR_SECRET_PHRASE",
        r#"(?i)"secretphrase"\s*:\s*"(?P<secret>[^"\r\n]{1,512})""#,
        &["secretphrase"],
        is_private_phrase_value,
        0.999,
    ),
    // Substrate SecretUri syntax follows this format reference:
    // https://docs.rs/sp-core/latest/sp_core/crypto/struct.SecretUri.html
    (
        "SUBSTRATE_SECRET_URI",
        concat!(
            r"(?-u:\b)(?P<secret>0x[0-9a-fA-F]{64}",
            r"(?:/{1,2}[A-Za-z0-9_.-]+)+(?:///[A-Za-z0-9_.-]+)?)(?-u:\b)"
        ),
        &[],
        valid_substrate_uri,
        0.999,
    ),
    (
        "SUBSTRATE_SECRET_URI",
        concat!(
            r"(?i)(?P<secret>[a-z]+(?:\s+[a-z]+){11,23}",
            r"(?:/{1,2}[A-Za-z0-9_.-]+)+(?:///[A-Za-z0-9_.-]+)?)\b"
        ),
        &[],
        valid_substrate_uri,
        0.999,
    ),
    // Ethereum account key shape: https://ethereum.org/developers/docs/accounts
    (
        "ETHEREUM_PRIVATE_KEY",
        concat!(
            r"(?:\bprivate_key\b|\bprivateKey\b|\bPRIVATE_KEY\b|",
            r"\bpriv_key\b|\bETH_PRIVATE_KEY\b|\bDEPLOYER_PRIVATE_KEY\b|",
            r#"\bsecret_key\b)['"]?\s*(?:=\s*|:\s*)['"]?"#,
            r"(?P<secret>(?:0x)?[0-9a-fA-F]{64})\b"
        ),
        &[
            "private_key",
            "privatekey",
            "priv_key",
            "eth_private_key",
            "deployer_private_key",
            "secret_key",
        ],
        valid_ethereum_private_key,
        0.995,
    ),
    // WIF payload and checksum: https://en.bitcoin.it/wiki/Wallet_import_format
    (
        "BITCOIN_WIF",
        r"(?-u:\b)(?P<secret>[5KL9c][1-9A-HJ-NP-Za-km-z]{50,51})(?-u:\b)",
        &[],
        valid_wif,
        0.999,
    ),
    // BIP32 and SLIP-132 private versions: https://bitcoin.org/bip/32/
    // https://github.com/satoshilabs/slips/blob/master/slip-0132.md
    (
        "BIP32_EXTENDED_PRIVATE_KEY",
        concat!(
            r"(?-u:\b)(?P<secret>(?:xprv|yprv|zprv|uprv|vprv|Yprv|Zprv|",
            r"Uprv|Vprv|tprv)[1-9A-HJ-NP-Za-km-z]{107})(?-u:\b)"
        ),
        &[],
        valid_extended_private_key,
        0.999,
    ),
    // Solana keypair encodings: https://solana.com/developers/cookbook/wallets/restore-keypair
    (
        "SOLANA_KEYPAIR",
        concat!(
            r#"(?i)\b(?:secretkey|keypair|solana)\b\s*(?:['"]?\s*:\s*|=\s*)"#,
            r"(?P<secret>\[(?:\s*\d{1,3}\s*,){63}\s*\d{1,3}\s*\])"
        ),
        &["secretkey", "keypair", "solana"],
        valid_solana_array,
        0.999,
    ),
    (
        "SOLANA_KEYPAIR",
        concat!(
            r#"(?i)\b(?:secretkey|keypair|solana)\b\s*(?:['"]?\s*:\s*|=\s*)['"]?"#,
            r"(?P<secret>[1-9A-HJ-NP-Za-km-z]{1,90})\b"
        ),
        &["secretkey", "keypair", "solana"],
        valid_solana_base58,
        0.999,
    ),
];

/// The vendor secret `(type, pattern)` source list — the single source both the
/// compiled detector regexes and the streaming hold-back DFA read.
const SECRET_PATTERNS: [(&str, &str); 14] = [
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    // These live and test keys carry 64 lowercase hex characters, which do not
    // reach the entropy backstop.
    ("GM_API_KEY", r"(?-u:\b)gm_live_[0-9a-f]{64}(?-u:\b)"),
    (
        "BLOCKMACHINE_API_KEY",
        r"(?-u:\b)bm_live_[0-9a-f]{64}(?-u:\b)",
    ),
    // Taostats API keys: `tao-<uuid>:<8 hex>`, and `ts_live_` keys.
    (
        "TAOSTATS_API_KEY",
        concat!(
            r"(?-u:\b)(?:tao-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-",
            r"[0-9a-f]{4}-[0-9a-f]{12}:[0-9a-f]{8}|ts_live_[0-9a-f]{64})(?-u:\b)"
        ),
    ),
    ("GM_API_KEY", r"(?-u:\b)gm_test_[0-9a-f]{64}(?-u:\b)"),
    (
        "BLOCKMACHINE_API_KEY",
        r"(?-u:\b)bm_test_[0-9a-f]{64}(?-u:\b)",
    ),
    ("TAOSTATS_API_KEY", r"(?-u:\b)ts_test_[0-9a-f]{64}(?-u:\b)"),
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

/// The credential label words shared by the prose, JSON-key and placeholder
/// rules. A bare `key` is deliberately absent: `primary_key`, `cache_key` and
/// `public_key` name ordinary values.
macro_rules! credential_words {
    () => {
        concat!(
            "password|passwd|pwd|passphrase|credentials?|secret|",
            "(?:private|secret|signing|encryption)[_-]?key|",
            "api[_-]?key|apikey|access[_-]?key|token"
        )
    };
}

/// A credential label at a word start or after a `_`, `.` or `-` separator, so
/// `password`, `db_password`, `DB_PASSWORD` and `smtp.password` all match. Only
/// the separator is consumed, keeping the label words as the match's literal
/// anchor; [`label_identifier_start`] recovers the full name.
const CREDENTIAL_LABEL: &str = concat!(r"(?i)(?:\b|[_.-])(?:", credential_words!(), r")\b");
const CREDENTIAL_ASSIGNMENT: &str = r"\s*(?:(?P<colon>:)|=)\s*";
// A type needs recognizable syntax, or whitespace before '='. An arbitrary
// alphanumeric value ending in '=' may be a Base64 secret.
const CREDENTIAL_TYPE: &str = concat!(
    r"[ \t]*:[ \t]*(?:",
    r"[a-z_][a-z0-9_.<>\[\], |?:]*[ \t]+",
    r"|(?:str|string|int|integer|float|bool|boolean|bytes)",
    r"|[a-z_][a-z0-9_.]*(?:\[[a-z0-9_. ,|\[\]]+\]|<[a-z0-9_:<> ,]+>)",
    r")[ \t]*=[ \t]*"
);
const CREDENTIAL_VALUE: &str = concat!(
    r#"(?:(?:os\.getenv|os\.environ\.get|getenv)\s*\(\s*(?:"#,
    r#""(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:\\[^\r\n]|[^'\\\r\n])*')"#,
    r"\s*,\s*(?:default\s*=\s*)?)?",
    r#"(?:"(?P<double>(?:\\[^\r\n]|[^"\\\r\n])*\\?)(?:"|[\r\n]|$)"#,
    r"|'(?P<single>(?:\\[^\r\n]|[^'\\\r\n])*\\?)(?:'|[\r\n]|$)",
    r#"|(?P<template>(?:\{\{[ \t]*[a-z_][a-z0-9_.]*[ \t]*\}\}|<[A-Za-z _-]+>)[^\s"'&]*)"#,
    // Balanced expression bounds are indexed separately.
    r#"|(?P<bare>[a-z_][a-z0-9_.:]*[ \t]*[\[(<]|[^\s"'&]+))"#,
);
const URL_CREDENTIAL_PATTERN: &str = r"[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s/@]+)@";
/// A double-quoted object key that ends in a credential label, followed by a
/// double-quoted string value: `"password": "..."`, `"db_password":"..."`.
const JSON_CREDENTIAL_PATTERN: &str = concat!(
    r#""(?P<key>[A-Za-z0-9_.-]*?"#,
    r"(?i:",
    credential_words!(),
    "))",
    r#""[ \t\r\n]*:[ \t\r\n]*"(?P<value>(?:\\\S|[^"\\\s])*(?:\\$)?)(?:"|$)"#,
);

fn credential_pattern(typed: bool) -> String {
    let assignment = if typed {
        format!("(?:{CREDENTIAL_TYPE}|{CREDENTIAL_ASSIGNMENT})")
    } else {
        CREDENTIAL_ASSIGNMENT.to_owned()
    };
    format!("{CREDENTIAL_LABEL}{assignment}{CREDENTIAL_VALUE}")
}

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
        .chain(
            ADDITIONAL_SECRET_PATTERNS
                .iter()
                .map(|(_, pattern, _, _, _)| {
                    // The DFA uses ASCII boundaries; Unicode-aware rules need
                    // a conservative hold-back source without those assertions.
                    if pattern.starts_with("(?i)") {
                        pattern.replace(r"\b", "")
                    } else {
                        (*pattern).to_owned()
                    }
                }),
        )
        .chain([
            credential_pattern(true).replace(r"\b", ""),
            URL_CREDENTIAL_PATTERN.to_owned(),
            JSON_CREDENTIAL_PATTERN.to_owned(),
        ])
        .chain(gitleaks::pattern_sources())
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

fn validated_secret_rules() -> &'static [ValidatedSecretRule] {
    static RULES: OnceLock<Vec<ValidatedSecretRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        ADDITIONAL_SECRET_PATTERNS
            .iter()
            .map(
                |(ty, pattern, keywords, validator, confidence)| ValidatedSecretRule {
                    ty,
                    re: structured_rule(pattern),
                    keywords,
                    validator: *validator,
                    confidence: *confidence,
                },
            )
            .collect()
    })
}

/// `key = value` / `key: value` pairs whose key names a credential. The value
/// span (named quoted/bare groups), not the label or type, is redacted.
fn labelled_secret_rule(typed: bool) -> &'static Regex {
    static TYPED: OnceLock<Regex> = OnceLock::new();
    static UNTYPED: OnceLock<Regex> = OnceLock::new();
    let re = if typed { &TYPED } else { &UNTYPED };
    re.get_or_init(|| structured_rule(&credential_pattern(typed)))
}

fn credential_head_rule(anchored: bool) -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    static ANCHORED: OnceLock<Regex> = OnceLock::new();
    let re = if anchored { &ANCHORED } else { &RE };
    re.get_or_init(|| {
        let anchor = if anchored { r"\A[A-Za-z0-9_.-]*?" } else { "" };
        structured_rule(&format!(
            "{anchor}{CREDENTIAL_LABEL}{CREDENTIAL_ASSIGNMENT}"
        ))
    })
}

fn typed_credential_head_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| structured_rule(&format!("{CREDENTIAL_LABEL}{CREDENTIAL_TYPE}")))
}

/// A `scheme://user:password@host` URL credential. The password span (group 1).
fn url_credential_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| structured_rule(URL_CREDENTIAL_PATTERN))
}

/// The streaming hold point for seed phrases: see `bip39::hold_floor`.
#[must_use]
pub fn seed_phrase_hold_floor(buf: &[u8]) -> usize {
    bip39::hold_floor(buf)
}

pub(crate) fn secret_match_ranges(buf: &[u8]) -> Vec<std::ops::Range<usize>> {
    let Ok(text) = std::str::from_utf8(buf) else {
        return Vec::new();
    };
    bip39::detect(text)
        .into_iter()
        .map(|span| span.start..span.end)
        .chain(
            labelled_expression_bounds(text)
                .into_iter()
                .map(|(start, end, _)| start..end),
        )
        .collect()
}

pub(crate) fn expression_hold_floor(buf: &[u8]) -> usize {
    let Ok(text) = std::str::from_utf8(buf) else {
        return 0;
    };
    labelled_expression_bounds(text)
        .into_iter()
        .filter(|(_, _, unfinished)| *unfinished)
        .map(|(start, _, _)| start)
        .min()
        .unwrap_or(buf.len())
}

fn following_credential_head(value: &str, chained: bool) -> Option<usize> {
    let head = credential_head_rule(true).find(value)?;
    let short = value
        .char_indices()
        .take_while(|(offset, _)| *offset < 6)
        .any(|(_, ch)| ch.is_whitespace() || matches!(ch, '\'' | '"' | '&'));
    let spaced = head
        .as_str()
        .split_once([':', '='])
        .is_some_and(|(label, _)| label.ends_with(char::is_whitespace));
    if !chained && !short && !spaced {
        return None;
    }
    credential_head_rule(false)
        .find(head.as_str())
        .map(|label| label.start())
}

fn labelled_expression_bounds(text: &str) -> Vec<(usize, usize, bool)> {
    let mut syntax = None;
    let mut cursor = 0;
    let mut chained = None;
    let mut chain_start = None;
    let mut typed_chain = false;
    let mut bounds = Vec::new();
    while let Some(head) = credential_head_rule(false).find_at(text, cursor) {
        if chained != Some(head.start()) {
            chain_start = None;
            typed_chain = false;
        }
        let index = syntax.get_or_insert_with(|| AssignmentSyntax::new(text));
        let typed_end = index.typed_head_end(head.start());
        let value_start = typed_end.unwrap_or(head.end());
        let in_chain = typed_end.is_some() || typed_chain;
        if let Some(offset) = following_credential_head(&text[value_start..], in_chain) {
            chain_start.get_or_insert(head.start());
            cursor = value_start + offset;
            chained = Some(cursor);
            typed_chain = in_chain;
            continue;
        }
        chained = None;
        let start = chain_start.take().unwrap_or(head.start());
        let Some(caps) = labelled_secret_rule(typed_end.is_some()).captures_at(text, head.start())
        else {
            if start < head.start() && head.end() == text.len() {
                bounds.push((start, text.len(), true));
            }
            break;
        };
        let Some(matched) = caps.get(0) else {
            break;
        };
        if matched.start() != head.start() {
            cursor = matched.start();
            continue;
        }
        cursor = caps
            .name("double")
            .or_else(|| caps.name("single"))
            .map(|value| (value, true))
            .or_else(|| {
                caps.name("bare")
                    .or_else(|| caps.name("template"))
                    .map(|value| (value, false))
            })
            .map_or(matched.end(), |(value, quoted)| {
                value.start()
                    + credential_value_resume(&text[value.start()..], value.as_str(), quoted)
            });
        let Some(value) = caps
            .name("bare")
            .filter(|v| v.as_str().ends_with(['(', '[', '<']))
        else {
            bounds.push((start, matched.end(), false));
            continue;
        };
        let limit = index.boundary(value.start(), text.len());
        let annotation = caps.name("colon").is_some();
        let limit = index.value_end(text, value.start(), limit, annotation, None);
        let expression = index.expression(text, value.start(), limit, annotation);
        let (end, unfinished) = expression
            .as_ref()
            .map_or((limit, limit == text.len()), |(_, consumed)| {
                (value.start() + consumed, false)
            });
        bounds.push((start, end, unfinished));
        cursor = if expression.is_none() && !unfinished {
            value.start()
                + credential_value_resume(&text[value.start()..], &text[value.start()..end], false)
        } else {
            end
        };
    }
    bounds
}

/// Detect credentials in `text`, the value of the structured field `field` (a
/// JSON object key or tool-call argument name). The field name is applied as
/// the value's label: the result is what [`detect_secrets`] finds in `text`
/// plus what it finds within the value of `"field": "text"` and
/// `field: "text"`. Span offsets are into `text`.
#[must_use]
pub fn detect_field_secrets(field: &str, text: &str) -> Vec<Span> {
    let mut spans = detect_secrets(text);
    if field.is_empty() {
        return spans;
    }
    let value = QuotedValue::new(text);
    let quoted_field = QuotedValue::new(field).escaped;
    for prefix in [format!("\"{quoted_field}\": \""), format!("{field}: \"")] {
        let labelled = format!("{prefix}{}\"", value.escaped);
        for span in detect_secrets(&labelled) {
            if let Some((start, end)) = value.original_range(
                span.start.saturating_sub(prefix.len()),
                span.end.saturating_sub(prefix.len()),
            ) {
                spans.push(Span::new(start, end, &span.ty, span.confidence));
            }
        }
    }
    spans
}

/// A value escaped for a double-quoted string, with a map from each escaped
/// byte back to the original character it came from.
struct QuotedValue {
    escaped: String,
    /// For each escaped byte, the original character's byte range.
    origin: Vec<(usize, usize)>,
}

impl QuotedValue {
    fn new(text: &str) -> Self {
        let mut escaped = String::with_capacity(text.len());
        let mut origin = Vec::with_capacity(text.len());
        for (start, ch) in text.char_indices() {
            let before = escaped.len();
            match ch {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                _ => escaped.push(ch),
            }
            let range = (start, start + ch.len_utf8());
            origin.extend(std::iter::repeat_n(range, escaped.len() - before));
        }
        Self { escaped, origin }
    }

    /// The original byte range covered by escaped bytes `start..end`, clipped
    /// to the value. `None` when nothing of the value is covered.
    fn original_range(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        let end = end.min(self.origin.len());
        if start >= end {
            return None;
        }
        Some((self.origin[start].0, self.origin[end - 1].1))
    }
}

/// Detect credentials: known-vendor patterns (the crate's own plus the ported
/// gitleaks rules), BIP39 seed phrases, labelled `key=value` secrets,
/// URL-embedded passwords, and a high-entropy backstop over bare tokens.
#[must_use]
pub fn detect_secrets(text: &str) -> Vec<Span> {
    let mut validated_hits = vec![false; ADDITIONAL_SECRET_PATTERNS.len()];
    let mut spans = gitleaks::detect(text, &mut validated_hits);
    spans.extend(bip39::detect(text));
    for rule in secret_rules() {
        for m in rule.re.find_iter(text) {
            spans.push(Span::new(m.start(), m.end(), rule.ty, 0.99));
        }
    }
    detect_validated_secrets(text, &validated_hits, &mut spans);
    detect_labelled_secrets(text, &mut spans);
    detect_json_labelled_secrets(text, &mut spans);
    for caps in url_credential_rule().captures_iter(text) {
        if let Some(v) = caps.get(1) {
            spans.push(Span::new(v.start(), v.end(), "SECRET", 0.9));
        }
    }
    spans.extend(entropy_backstop(text));
    spans
}

fn json_credential_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| structured_rule(JSON_CREDENTIAL_PATTERN))
}

/// Quoted JSON keys naming a credential, with a quoted string value. Only
/// single-token values that do not look like a placeholder, a schema or type
/// word, a masked value or a reference are reported.
fn detect_json_labelled_secrets(text: &str, spans: &mut Vec<Span>) {
    for caps in json_credential_rule().captures_iter(text) {
        let (Some(key), Some(value)) = (caps.name("key"), caps.name("value")) else {
            continue;
        };
        if is_json_credential(key.as_str(), value.as_str()) {
            spans.push(Span::new(value.start(), value.end(), "SECRET", 0.9));
        }
    }
}

fn is_json_credential(key: &str, value: &str) -> bool {
    let key = key.to_ascii_lowercase();
    let value = decode_json_string(value);
    if is_pagination_token_key(&key) || is_path_label_value(&key, &value) {
        return false;
    }
    value.len() >= 6
        && !value.eq_ignore_ascii_case(&key)
        && !value.contains(char::is_whitespace)
        && !is_non_secret_assignment_value(&value, true, false)
        && !is_public_hardhat_dev_key(&value)
        && !is_json_placeholder_value(&value)
        && !is_placeholder_shape(&value)
        && !is_fetch_credentials_mode(&key, &value)
        && !is_json_type_hint(&value)
        && !is_json_reference(&value)
}

/// Decode only for classification; reported spans still cover the source bytes.
fn decode_json_string(value: &str) -> Cow<'_, str> {
    if !value.contains('\\') {
        return Cow::Borrowed(value);
    }
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }
        let mut escaped = chars.clone();
        if let Some(decoded_char) = decode_json_escape(&mut escaped) {
            decoded.push(decoded_char);
            chars = escaped;
        } else {
            decoded.push('\\');
        }
    }
    Cow::Owned(decoded)
}

fn decode_json_escape(chars: &mut std::str::Chars<'_>) -> Option<char> {
    Some(match chars.next()? {
        '"' => '"',
        '\\' => '\\',
        '/' => '/',
        'b' => '\u{0008}',
        'f' => '\u{000c}',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'u' => {
            let mut code = json_hex_quad(chars)?;
            if (0xd800..=0xdbff).contains(&code) {
                if chars.next()? != '\\' || chars.next()? != 'u' {
                    return None;
                }
                let low = json_hex_quad(chars)?;
                if !(0xdc00..=0xdfff).contains(&low) {
                    return None;
                }
                code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
            }
            char::from_u32(code)?
        }
        _ => return None,
    })
}

fn json_hex_quad(chars: &mut std::str::Chars<'_>) -> Option<u32> {
    (0..4).try_fold(0, |code, _| Some(code * 16 + chars.next()?.to_digit(16)?))
}

/// `<your-private-key>`, `<api key>`, `YOUR_SECRET`, `0xYOUR_KEY`: letters-only
/// placeholder words. Values with digits are treated as literals.
fn is_placeholder_shape(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| structured_rule(r"^(?:<[A-Za-z _-]+>|(?:0[xX])?YOUR_[A-Z_]+)$"))
        .is_match(value)
}

/// Start of the identifier that ends in the label matched at `head_start`:
/// `db_password` for a match of `_password`.
fn label_identifier_start(text: &str, head_start: usize) -> usize {
    text[..head_start]
        .bytes()
        .rposition(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')))
        .map_or(0, |index| index + 1)
}

/// A label directly after `${` or `:` names a variable inside a reference
/// (`${DB_PASSWORD:-default}`, `%env(default:db.credential:NAME)%`), not an
/// assignment.
fn is_reference_name(before: &str) -> bool {
    before.ends_with("${") || before.ends_with(':')
}

/// A path under a label that conventionally names a file or directory:
/// `PWD=/home/user`, `GOOGLE_APPLICATION_CREDENTIALS=/etc/key.json`,
/// `private_key: ./certs/server.pem`.
fn is_path_label_value(label: &str, value: &str) -> bool {
    let label = label.to_ascii_lowercase();
    (label == "pwd"
        || label.ends_with("key")
        || label.ends_with("credential")
        || label.ends_with("credentials"))
        && is_directory_path(value)
}

fn is_fetch_credentials_mode(label: &str, value: &str) -> bool {
    label
        .rsplit('.')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("credentials"))
        && matches!(value, "include" | "omit" | "same-origin")
}

fn is_tokenizer_special_token(label: &str, value: &str) -> bool {
    let label = label.to_ascii_lowercase();
    matches!(
        label.rsplit('.').next(),
        Some(
            "bos_token"
                | "eos_token"
                | "unk_token"
                | "sep_token"
                | "pad_token"
                | "cls_token"
                | "mask_token"
        )
    ) && (value.starts_with('<') && value.ends_with('>')
        || value.starts_with('[') && value.ends_with(']'))
}

fn is_directory_path(value: &str) -> bool {
    value.starts_with(['/', '\\'])
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
        || matches!(value.as_bytes(), [drive, b':', b'/' | b'\\', ..] if drive.is_ascii_alphabetic())
}

fn is_json_type_hint(value: &str) -> bool {
    let mut rest = value;
    loop {
        rest = rest.trim_start_matches('&');
        while let Some(tail) = rest.strip_prefix("[]") {
            rest = tail;
        }
        let head_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_alphabetic() || b"_.:".contains(byte))
            .count();
        let head = &rest[..head_len];
        rest = &rest[head_len..];
        let generic = rest.starts_with(['[', '<']);
        if !(is_json_type_words(head)
            || generic && matches!(head, "Vec" | "std::vec::Vec" | "Map" | "Record" | "Promise"))
        {
            return false;
        }
        if generic {
            let Some(end) = json_type_argument_end(rest) else {
                return false;
            };
            rest = &rest[end..];
        }
        rest = rest.strip_prefix('?').unwrap_or(rest);
        while let Some(tail) = rest.strip_prefix("[]") {
            rest = tail.strip_prefix('?').unwrap_or(tail);
        }
        if rest.is_empty() || matches!(rest, "&" | "&&") {
            return true;
        }
        let Some(tail) = rest.strip_prefix(['|', '&']) else {
            return false;
        };
        rest = tail;
    }
}

fn json_type_argument_end(value: &str) -> Option<usize> {
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    for (offset, ch) in value.char_indices() {
        if let Some(delimiter) = quote {
            if !escaped && ch == delimiter {
                quote = None;
            }
            escaped = !escaped && ch == '\\';
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '<' => stack.push('>'),
            '[' => stack.push(']'),
            '(' => stack.push(')'),
            '{' => stack.push('}'),
            '>' | ']' | ')' | '}' => {
                if stack.pop() != Some(ch) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(offset + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

fn is_json_type_words(value: &str) -> bool {
    let value = value.strip_prefix("java.lang.").unwrap_or(value);
    value.split("::").all(|path| {
        path.split('.').all(|part| {
            is_type_annotation(part)
                || matches!(
                    part.to_ascii_lowercase().as_str(),
                    "typing"
                        | "typing_extensions"
                        | "builtins"
                        | "union"
                        | "any"
                        | "none"
                        | "null"
                        | "undefined"
                        | "number"
                        | "object"
                        | "secretstr"
                        | "secretbytes"
                        | "anystr"
                        | "literal"
                        | "annotated"
                        | "std"
                        | "pydantic"
                        | "array"
                        | "byte"
                        | "system"
                        | "types"
                )
        })
    })
}

fn is_json_reference(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    is_json_braced_reference(value)
        || is_json_secret_reference(value)
        || RE
            .get_or_init(|| {
                structured_rule(concat!(
                    r"^(?:(?:process\.env\.|\$?(?i:env):)[A-Za-z_][A-Za-z0-9_]*",
                    r"|env\.[A-Za-z_][A-Za-z0-9_]*",
                    r#"|(?:os\.environ|process\.env)\[(?:'[A-Za-z_][A-Za-z0-9_]*'|"[A-Za-z_][A-Za-z0-9_]*")\]"#,
                    r#"|(?:os\.getenv|os\.environ\.get)\((?:'[A-Za-z_][A-Za-z0-9_]*'|"[A-Za-z_][A-Za-z0-9_]*")\)"#,
                    r"|\$ENV\{[A-Za-z_][A-Za-z0-9_]*\}",
                    r"|\$\([A-Za-z_][A-Za-z0-9_.]*\)",
                    r"|\$\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})",
                    r"|%env\((?:[A-Za-z_][A-Za-z0-9_.-]*:)*[A-Za-z_][A-Za-z0-9_]*\)%",
                    r"|%[A-Za-z_][A-Za-z0-9_]*%",
                    r"|@Microsoft\.KeyVault\((?:SecretUri=https://[^\s()]+",
                    r"|VaultName=[A-Za-z0-9-]+;SecretName=[A-Za-z0-9-]+(?:;SecretVersion=[A-Za-z0-9-]+)?)\)",
                    r"|#/[^\s]+)$"
                ))
            })
            .is_match(value)
}

fn is_json_braced_reference(value: &str) -> bool {
    if !(value.starts_with("${") || value.starts_with("#{")) {
        return false;
    }
    for quoted in [true, false] {
        let mut depth = 0usize;
        let mut quote = None;
        let mut escaped = false;
        for (offset, ch) in value.char_indices().skip(1) {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
            } else if let Some(delimiter) = quote {
                if ch == delimiter {
                    quote = None;
                }
            } else {
                match ch {
                    '\'' | '"' if quoted => quote = Some(ch),
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return offset + 1 == value.len();
                        }
                    }
                    _ => {}
                }
            }
        }
        if quote.is_none() {
            break;
        }
    }
    false
}

fn is_json_secret_reference(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let part = concat!(
            r"(?:[A-Za-z0-9_.-]|\$[A-Za-z_][A-Za-z0-9_]*|",
            r"\$\{[A-Za-z_][A-Za-z0-9_]*\})+"
        );
        structured_rule(&format!(
            r"^(?i:op)://{part}(?:/{part}){{2,3}}(?:\?(?:attribute|attr|ssh-format)=[A-Za-z0-9_-]+)?$"
        ))
    })
    .is_match(value)
}

/// `next_token`, `nextPageToken`, `continuation_token`: opaque paging cursors.
fn is_pagination_token_key(key: &str) -> bool {
    const CURSORS: [&str; 10] = [
        "next",
        "prev",
        "previous",
        "page",
        "pagination",
        "continuation",
        "sync",
        "cursor",
        "starting",
        "resume",
    ];
    let Some(prefix) = key.strip_suffix("token") else {
        return false;
    };
    let prefix = prefix.trim_end_matches(['_', '-', '.']);
    CURSORS.iter().any(|cursor| prefix.ends_with(cursor))
}

/// Schema and type words, masked values and bracketed placeholders.
fn is_json_placeholder_value(value: &str) -> bool {
    const WORDS: [&str; 27] = [
        "string",
        "secret",
        "bearer",
        "password",
        "required",
        "optional",
        "hidden",
        "redacted",
        "sensitive",
        "masked",
        "boolean",
        "integer",
        "number",
        "object",
        "secretstr",
        "undefined",
        "invalid",
        "incorrect",
        "mismatch",
        "passwort",
        "zurücksetzen",
        "mot_de_passe",
        "contraseña",
        "senha",
        "пароль",
        "パスワード",
        "密码",
    ];
    let lower = value.to_lowercase();
    let template = lower
        .strip_suffix("_here")
        .or_else(|| lower.strip_suffix("-here"))
        .unwrap_or(&lower);
    let template = template
        .strip_prefix("replace_with_")
        .or_else(|| template.strip_prefix("replace-with-"))
        .unwrap_or(template);
    let name = template
        .strip_prefix("your_")
        .or_else(|| template.strip_prefix("your-"))
        .or_else(|| template.strip_prefix("insert_"))
        .or_else(|| template.strip_prefix("insert-"))
        .unwrap_or(template);
    if WORDS.contains(&lower.trim_end_matches([':', '*', '?', '？']))
        || name.len() != lower.len()
            && (is_non_secret_assignment_value(template, true, false)
                || is_json_placeholder_name(name))
    {
        return true;
    }
    if ["[redacted]", "<redacted>", "[masked]", "<masked>"]
        .iter()
        .any(|mask| lower.contains(mask))
        || contains_json_redaction_sentinel(&lower)
    {
        return true;
    }
    if ["***", "•••", "...", "…", "xxxx", "XXXX", "###"]
        .iter()
        .any(|mask| value.contains(mask))
    {
        return true;
    }
    if value
        .chars()
        .all(|ch| matches!(ch, '*' | '\u{2022}' | 'x' | 'X' | '.' | '#' | '-'))
    {
        return true;
    }
    let bytes = value.as_bytes();
    matches!(
        (bytes.first(), bytes.last()),
        (Some(b'<'), Some(b'>'))
            | (Some(b'['), Some(b']'))
            | (Some(b'{'), Some(b'}'))
            | (Some(b'('), Some(b')'))
    )
}

fn contains_json_redaction_sentinel(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| structured_rule(r"\[redacted_[a-z0-9_]+_[0-9]+_[a-f0-9]{8}\]"))
        .is_match(value)
}

fn is_json_placeholder_name(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| structured_rule(concat!(r"^[a-z0-9_.-]*?(?:", credential_words!(), ")$")))
        .is_match(value)
}

/// Each validated rule's keywords, in rule order, for the shared keyword pass
/// in [`gitleaks::detect`]. A rule with no keywords always runs.
pub(super) fn validated_secret_keywords() -> impl Iterator<Item = &'static [&'static str]> {
    ADDITIONAL_SECRET_PATTERNS
        .iter()
        .map(|(_, _, keywords, _, _)| *keywords)
}

fn detect_validated_secrets(text: &str, keyword_hits: &[bool], spans: &mut Vec<Span>) {
    for (rule, &hit) in validated_secret_rules().iter().zip(keyword_hits) {
        if !rule.keywords.is_empty() && !hit {
            continue;
        }
        for caps in rule.re.captures_iter(text) {
            let Some(value) = caps.name("secret") else {
                continue;
            };
            if let Some(offset) = validated_secret_start(rule, value.as_str()) {
                spans.push(Span::new(
                    value.start() + offset,
                    value.end(),
                    rule.ty,
                    rule.confidence,
                ));
            }
        }
    }
}

fn validated_secret_start(rule: &ValidatedSecretRule, value: &str) -> Option<usize> {
    if (rule.validator)(value) {
        return Some(0);
    }
    if rule.ty != "SUBSTRATE_SECRET_URI" {
        return None;
    }
    // A mnemonic URI candidate can include prose before the actual seed.
    let path = value.find('/')?;
    value[..path].char_indices().find_map(|(offset, ch)| {
        let next = offset + ch.len_utf8();
        (ch.is_ascii_whitespace()
            && value
                .as_bytes()
                .get(next)
                .is_some_and(u8::is_ascii_alphabetic)
            && valid_substrate_uri(&value[next..]))
        .then_some(next)
    })
}

fn valid_prefixed_seed(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_bittensor_private_key(value: &str) -> bool {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    matches!(hex.len(), 64 | 128)
        && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !is_public_hardhat_dev_key(value)
}

fn is_private_phrase_value(value: &str) -> bool {
    !is_public_substrate_dev_phrase(value) && !is_non_secret_assignment_value(value, true, false)
}

fn valid_substrate_uri(value: &str) -> bool {
    let Some(path_start) = value.find('/') else {
        return false;
    };
    let seed = value[..path_start].trim_end();
    if seed.starts_with("0x") || seed.starts_with("0X") {
        return valid_prefixed_seed(seed);
    }
    bip39::is_valid_mnemonic(seed) && !is_public_substrate_dev_phrase(seed)
}

fn is_public_substrate_dev_phrase(value: &str) -> bool {
    const PHRASE: [&str; 12] = [
        "bottom", "drive", "obey", "lake", "curtain", "smoke", "basket", "hold", "race", "lonely",
        "fit", "walk",
    ];
    let words = value.split_ascii_whitespace();
    words.count() == PHRASE.len()
        && value
            .split_ascii_whitespace()
            .zip(PHRASE)
            .all(|(word, expected)| word.eq_ignore_ascii_case(expected))
}

fn valid_ethereum_private_key(value: &str) -> bool {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    hex.len() == 64
        && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !is_public_hardhat_dev_key(value)
}

fn is_public_hardhat_dev_key(value: &str) -> bool {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    HARDHAT_PUBLIC_DEV_KEYS
        .iter()
        .any(|key| hex.eq_ignore_ascii_case(key))
}

fn valid_solana_array(value: &str) -> bool {
    let Some(items) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) else {
        return false;
    };
    let values: Vec<_> = items.split(',').map(str::trim).collect();
    values.len() == 64 && values.iter().all(|item| item.parse::<u8>().is_ok())
}

fn valid_solana_base58(value: &str) -> bool {
    bs58::decode(value)
        .into_vec()
        .is_ok_and(|bytes| bytes.len() == 64)
}

fn valid_wif(value: &str) -> bool {
    let Some(payload) = decode_base58check_payload(value) else {
        return false;
    };
    matches!(payload.as_slice(), [0x80 | 0xef, ..])
        && (payload.len() == 33 || (payload.len() == 34 && payload[33] == 1))
}

fn valid_extended_private_key(value: &str) -> bool {
    let Some(payload) = decode_base58check_payload(value) else {
        return false;
    };
    payload.len() == 78
        && payload.get(45) == Some(&0)
        && BIP32_PRIVATE_VERSIONS.iter().any(|(prefix, version)| {
            value.starts_with(prefix) && payload.get(..4) == Some(&version[..])
        })
}

fn decode_base58check_payload(value: &str) -> Option<Vec<u8>> {
    // The largest supported payload is a 78-byte extended key plus checksum.
    if value.len() > 112 {
        return None;
    }
    let mut decoded = bs58::decode(value).into_vec().ok()?;
    if decoded.len() < 5 {
        return None;
    }
    let checksum_start = decoded.len() - 4;
    let first = Sha256::digest(&decoded[..checksum_start]);
    let second = Sha256::digest(first);
    if decoded[checksum_start..] != second[..4] {
        return None;
    }
    decoded.truncate(checksum_start);
    Some(decoded)
}

fn valid_extended_public_key(value: &str) -> bool {
    let Some(payload) = decode_base58check_payload(value) else {
        return false;
    };
    payload.len() == 78
        && matches!(payload.get(45), Some(2 | 3))
        && BIP32_PUBLIC_VERSIONS.iter().any(|(prefix, version)| {
            value.starts_with(prefix) && payload.get(..4) == Some(&version[..])
        })
}

const BIP32_PRIVATE_VERSIONS: &[(&str, [u8; 4])] = &[
    ("xprv", [0x04, 0x88, 0xad, 0xe4]),
    ("yprv", [0x04, 0x9d, 0x78, 0x78]),
    ("zprv", [0x04, 0xb2, 0x43, 0x0c]),
    ("Yprv", [0x02, 0x95, 0xb0, 0x05]),
    ("Zprv", [0x02, 0xaa, 0x7a, 0x99]),
    ("tprv", [0x04, 0x35, 0x83, 0x94]),
    ("uprv", [0x04, 0x4a, 0x4e, 0x28]),
    ("vprv", [0x04, 0x5f, 0x18, 0xbc]),
    ("Uprv", [0x02, 0x42, 0x85, 0xb5]),
    ("Vprv", [0x02, 0x57, 0x50, 0x48]),
];

const BIP32_PUBLIC_VERSIONS: &[(&str, [u8; 4])] = &[
    ("xpub", [0x04, 0x88, 0xb2, 0x1e]),
    ("ypub", [0x04, 0x9d, 0x7c, 0xb2]),
    ("zpub", [0x04, 0xb2, 0x47, 0x46]),
    ("Ypub", [0x02, 0x95, 0xb4, 0x3f]),
    ("Zpub", [0x02, 0xaa, 0x7e, 0xd3]),
    ("tpub", [0x04, 0x35, 0x87, 0xcf]),
    ("upub", [0x04, 0x4a, 0x52, 0x62]),
    ("vpub", [0x04, 0x5f, 0x1c, 0xf6]),
    ("Upub", [0x02, 0x42, 0x89, 0xef]),
    ("Vpub", [0x02, 0x57, 0x54, 0x83]),
];

// Public local-only keys derived from Hardhat's documented development
// mnemonic: https://v2.hardhat.org/hardhat-network/docs/reference
const HARDHAT_PUBLIC_DEV_KEYS: &[&str] = &[
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
    "f214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897",
    "701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82",
    "a267530f49f8280200edf313ee7af6b827f2a8bce2897751d06a843f644967b1",
    "47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd",
    "c526ee95bf44d8fc405a158bb884d9d1238d99f0612e9f33d006bb0789009aaa",
    "8166f546bab6da521a8369cab06c5d2b9e46670292d85c875ee9ec20e84ffb61",
    "ea6c44ac03bff858b476bba40716402b03e41b8e97e276d1baec7c37d42484a0",
    "689af8efa8c651a91ad287602527f3af2fe9f6501a7ac4b061667b5a93e037fd",
    "de9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0",
    "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
];

fn detect_labelled_secrets(text: &str, spans: &mut Vec<Span>) {
    let mut syntax = None;
    let mut arguments = Vec::new();
    let mut cursor = 0;
    let mut chained = None;
    while let Some(head) = credential_head_rule(false).find_at(text, cursor) {
        let label_start = label_identifier_start(text, head.start());
        let label = text[label_start..head.end()]
            .trim_end_matches(|ch: char| ch.is_whitespace() || ch == ':' || ch == '=');
        if is_pagination_token_key(&label.to_ascii_lowercase())
            || is_reference_name(&text[..label_start])
        {
            cursor = head.end();
            continue;
        }
        let index = syntax.get_or_insert_with(|| AssignmentSyntax::new(text));
        let typed_end = index.typed_head_end(head.start());
        let value_start = typed_end.unwrap_or(head.end());
        let in_chain = typed_end.is_some() || chained == Some(head.start());
        if let Some(offset) = following_credential_head(&text[value_start..], in_chain) {
            cursor = value_start + offset;
            chained = in_chain.then_some(cursor);
            continue;
        }
        chained = None;
        let Some(caps) = labelled_secret_rule(typed_end.is_some()).captures_at(text, head.start())
        else {
            break;
        };
        if let Some(matched) = caps
            .get(0)
            .filter(|matched| matched.start() != head.start())
        {
            cursor = matched.start();
            continue;
        }
        let quoted = caps.name("double").or_else(|| caps.name("single"));
        let template = caps.name("template");
        let Some(v) = quoted.or(template).or_else(|| caps.name("bare")) else {
            break;
        };
        let start = v.start();
        let annotation = caps.name("colon").is_some();
        while arguments.last().is_some_and(|&end| end <= start) {
            arguments.pop();
        }
        let mut end = v.end();
        let mut expression = None;
        if quoted.is_none() {
            if template.is_none() && v.as_str().ends_with(['(', '[', '<']) {
                end = index.boundary(start, text.len());
            }
            end = index.value_end(text, start, end, annotation, arguments.last().copied());
            if template.is_none() {
                expression = index.expression(text, start, end, annotation);
            }
        }
        if let Some((contents, consumed)) = expression {
            if annotation && text.as_bytes()[start + contents.start - 1] == b'<' {
                cursor = start + consumed;
            } else {
                cursor = start + contents.start;
                arguments.push(start + contents.end);
            }
            continue;
        }
        let candidate = &text[start..end];
        let value = if quoted.is_some() {
            candidate
        } else if template.is_some() {
            candidate.trim_end_matches([',', ';'])
        } else {
            candidate
                .split(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '\'' | '"' | '&'))
                .next()
                .unwrap_or_default()
                .trim_end_matches([',', ';'])
        };
        if value.len() >= 6
            && !is_non_secret_assignment_value(value, quoted.is_some(), annotation)
            && !is_public_hardhat_dev_key(value)
            && !is_path_label_value(label, value)
            && !is_placeholder_shape(value)
            && !is_fetch_credentials_mode(label, value)
            && !is_tokenizer_special_token(label, value)
        {
            spans.push(Span::new(start, start + value.len(), "SECRET", 0.9));
        }
        cursor = start + credential_value_resume(&text[start..], candidate, quoted.is_some());
    }
}

fn credential_value_resume(remaining: &str, value: &str, quoted: bool) -> usize {
    static LABEL: OnceLock<Regex> = OnceLock::new();
    let token = value
        .split(|ch: char| {
            ch.is_ascii_whitespace()
                || quoted && ch.is_whitespace()
                || matches!(ch, '\'' | '"' | '&')
        })
        .next()
        .unwrap_or_default();
    if quoted && token.chars().take(6).count() < 6 {
        return 0;
    }
    LABEL
        .get_or_init(|| structured_rule(CREDENTIAL_LABEL))
        .find_iter(token)
        .last()
        .filter(|label| {
            credential_head_rule(true)
                .find(&remaining[label.start()..])
                .is_some_and(|head| label.start() + head.end() >= token.len())
        })
        .map_or(token.len(), |label| label.start())
}

struct AssignmentSyntax {
    closes: HashMap<usize, usize>,
    generic_closes: HashMap<usize, usize>,
    suffixes: HashMap<usize, [usize; 2]>,
    boundaries: Vec<usize>,
    next_boundary: usize,
    // Find typed assignments once, without retrying the type look-ahead at
    // every nested label in an annotation that has no assignment.
    typed_heads: Vec<(usize, usize)>,
    next_typed: usize,
}

impl AssignmentSyntax {
    fn new(text: &str) -> Self {
        let generic_closes = generic_closes(text);
        let typed_heads = typed_credential_heads(text, &generic_closes);
        Self {
            closes: expression_closes(text),
            suffixes: expression_suffix_ends(text),
            boundaries: text
                .bytes()
                .enumerate()
                .filter(|(_, byte)| matches!(byte, b'\r' | b'\n'))
                .map(|(offset, _)| offset)
                .collect(),
            generic_closes,
            next_boundary: 0,
            typed_heads,
            next_typed: 0,
        }
    }

    fn typed_head_end(&mut self, start: usize) -> Option<usize> {
        while self
            .typed_heads
            .get(self.next_typed)
            .is_some_and(|&(offset, _)| offset < start)
        {
            self.next_typed += 1;
        }
        self.typed_heads
            .get(self.next_typed)
            .filter(|&&(offset, _)| offset == start)
            .map(|&(_, end)| end)
    }

    fn boundary(&mut self, start: usize, fallback: usize) -> usize {
        while self
            .boundaries
            .get(self.next_boundary)
            .is_some_and(|&end| end < start)
        {
            self.next_boundary += 1;
        }
        self.boundaries
            .get(self.next_boundary)
            .copied()
            .unwrap_or(fallback)
    }

    fn argument_end(&self, text: &str, start: usize, end: usize, annotation: bool) -> usize {
        let mut cursor = start;
        while cursor < end {
            match text.as_bytes()[cursor] {
                b',' | b')' | b']' | b'}' => return cursor,
                b'(' | b'[' | b'{' => match self.closes.get(&cursor) {
                    Some(&close) if close <= end => cursor = close,
                    _ => return end,
                },
                b'<' if annotation => match self.generic_closes.get(&cursor) {
                    Some(&close) if close <= end => cursor = close,
                    _ => return end,
                },
                _ => cursor += 1,
            }
        }
        end
    }

    fn value_end(
        &self,
        text: &str,
        start: usize,
        end: usize,
        annotation: bool,
        limit: Option<usize>,
    ) -> usize {
        let next = self.argument_end(text, start, limit.map_or(end, |n| end.min(n)), annotation);
        if limit.is_some() {
            return next;
        }
        let Some(rest) = text[next..].strip_prefix(',') else {
            return end;
        };
        let rest = rest.trim_start();
        let name_len = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            .count();
        if is_identifier(&rest[..name_len])
            && rest[name_len..].trim_start().starts_with(['=', ':'])
            && (is_non_secret_assignment_value(text[start..next].trim_end(), false, annotation)
                || self.expression(text, start, next, annotation).is_some())
        {
            next
        } else {
            end
        }
    }

    fn expression(
        &self,
        text: &str,
        start: usize,
        end: usize,
        annotation: bool,
    ) -> Option<(std::ops::Range<usize>, usize)> {
        let value = &text[start..end];
        let open = value.find(['(', '[', '<'])?;
        let generic = value.as_bytes()[open] == b'<';
        if generic && !annotation {
            return None;
        }
        if !value[..open]
            .trim_end()
            .split("::")
            .all(|part| is_identifier(part) || is_dotted_identifier(part))
        {
            return None;
        }
        let closes = if generic {
            &self.generic_closes
        } else {
            &self.closes
        };
        let mut close = *closes.get(&(start + open))?;
        if !generic {
            close = self.expression_end(text, close, end)?;
        }
        if close > end {
            return None;
        }
        let suffix_end = self
            .suffixes
            .get(&close)
            .map_or(close, |ends| ends[usize::from(annotation)])
            .min(end);
        let complete = text[close..end].starts_with(char::is_whitespace)
            || suffix_end == end
            || text.as_bytes()[suffix_end].is_ascii_whitespace();
        complete.then_some((open + 1..close - start - 1, close - start))
    }

    fn expression_end(&self, text: &str, mut end: usize, limit: usize) -> Option<usize> {
        while end < limit {
            match text.as_bytes()[end] {
                b'.' => {
                    let name_start = end + 1;
                    end = name_start;
                    while end < limit
                        && (text.as_bytes()[end].is_ascii_alphanumeric()
                            || text.as_bytes()[end] == b'_')
                    {
                        end += 1;
                    }
                    if !is_identifier(&text[name_start..end]) {
                        return None;
                    }
                }
                b'(' | b'[' => end = *self.closes.get(&end)?,
                b'?' => end += 1,
                _ => break,
            }
        }
        (end <= limit).then_some(end)
    }
}

fn expression_suffix_ends(text: &str) -> HashMap<usize, [usize; 2]> {
    let mut suffixes = HashMap::new();
    let mut ends = [text.len(); 2];
    let mut punctuation_end = text.len();
    for (offset, byte) in text.bytes().enumerate().rev() {
        match byte {
            b')' => punctuation_end = offset,
            b':' => {
                ends[0] = offset;
                punctuation_end = offset;
            }
            b',' | b';' => ends = [punctuation_end; 2],
            _ => {
                ends = [offset; 2];
                punctuation_end = offset;
                continue;
            }
        }
        suffixes.insert(offset, ends);
    }
    suffixes
}

fn typed_credential_heads(text: &str, closes: &HashMap<usize, usize>) -> Vec<(usize, usize)> {
    credential_head_rule(false)
        .find_iter(text)
        .filter(|head| head.as_str().contains(':'))
        .filter_map(|head| {
            let end = type_assignment_end(text, head.end(), closes)?;
            let candidate = &text[head.start()..end];
            let typed = typed_credential_head_rule().find(candidate)?;
            (typed.start() == 0 && typed.end() == candidate.len()).then_some((head.start(), end))
        })
        .collect()
}

fn type_assignment_end(
    text: &str,
    mut cursor: usize,
    closes: &HashMap<usize, usize>,
) -> Option<usize> {
    static NAME: OnceLock<Regex> = OnceLock::new();
    let name =
        NAME.get_or_init(|| structured_rule(r"(?i)\A[a-z_][a-z0-9_.]*(?:::[a-z_][a-z0-9_.]*)*"));
    loop {
        cursor += name.find(&text[cursor..])?.end();
        loop {
            let rest = text[cursor..].trim_start_matches([' ', '\t']);
            cursor = text.len() - rest.len();
            match rest.as_bytes().first()? {
                b'<' | b'[' => cursor = *closes.get(&cursor)?,
                b'?' => cursor += 1,
                b'|' => {
                    cursor += 1;
                    cursor = text.len() - text[cursor..].trim_start_matches([' ', '\t']).len();
                    break;
                }
                b'=' => {
                    cursor += 1;
                    return Some(text.len() - text[cursor..].trim_start_matches([' ', '\t']).len());
                }
                _ => return None,
            }
        }
    }
}

// Index each possible expression independently of surrounding prose. A suffix
// link skips a balanced group or quoted string in constant time.
fn expression_closes(text: &str) -> HashMap<usize, usize> {
    let mut tokens = Vec::new();
    let mut escaped = false;
    for (offset, byte) in text.bytes().enumerate() {
        if matches!(
            byte,
            b'(' | b'[' | b'{' | b')' | b']' | b'}' | b'\r' | b'\n'
        ) || !escaped && matches!(byte, b'\'' | b'"')
        {
            tokens.push((offset, byte));
        }
        escaped = byte == b'\\' && !escaped;
    }
    let mut closes = HashMap::new();
    let mut next: Vec<Option<usize>> = vec![None; tokens.len() + 1];
    let mut quotes = [None, None];
    for (i, &(offset, byte)) in tokens.iter().enumerate().rev() {
        match byte {
            b'\r' | b'\n' => quotes = [None, None],
            b'\'' | b'"' => {
                let quote = usize::from(byte == b'"');
                next[i] = quotes[quote].and_then(|end: usize| next[end + 1]);
                quotes[quote] = Some(i);
            }
            b'(' | b'[' | b'{' => {
                let expected = match byte {
                    b'(' => b')',
                    b'[' => b']',
                    _ => b'}',
                };
                if let Some(end) = next[i + 1].filter(|&end| tokens[end].1 == expected) {
                    closes.insert(offset, tokens[end].0 + 1);
                    next[i] = next[end + 1];
                }
            }
            _ => next[i] = Some(i),
        }
    }
    closes
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

/// Whether a candidate has enough character-class diversity for an opaque
/// credential. Lowercase/alphanumeric identifiers have at most two classes,
/// so they do not reach the entropy check. Hex is excluded separately because
/// mixed-case hex identifiers can contain three classes.
fn has_character_class_diversity(s: &str) -> bool {
    let mut classes = [false; 4];
    for byte in s.bytes() {
        let class = if byte.is_ascii_lowercase() {
            0
        } else if byte.is_ascii_uppercase() {
            1
        } else if byte.is_ascii_digit() {
            2
        } else {
            3
        };
        classes[class] = true;
    }
    classes.into_iter().filter(|present| *present).count() >= 3
}

/// Validate SS58 network prefixes, payload lengths and the Blake2b-512
/// checksum. Account indices have 1/2/4/8 payload bytes and up to that many
/// checksum bytes; 32/33-byte public keys always use a two-byte checksum.
fn is_ss58_address(s: &str) -> bool {
    // Bound decoding work, but allow leading zero bytes (Base58 '1's).
    if !(3..=51).contains(&s.len()) {
        return false;
    }
    let Ok(decoded) = bs58::decode(s).into_vec() else {
        return false;
    };
    let (prefix_len, network) = match decoded.as_slice() {
        [first @ 0..=63, ..] => (1, u16::from(*first)),
        [first @ 64..=127, second, ..] => {
            let network = (u16::from(first & 0x3f) << 2)
                | u16::from(second >> 6)
                | (u16::from(second & 0x3f) << 8);
            if network < 64 {
                return false;
            }
            (2, network)
        }
        _ => return false,
    };
    if matches!(network, 46 | 47) {
        return false;
    }
    let body_len = decoded.len() - prefix_len;
    let checksum_len = match body_len {
        2 => 1,
        3..=4 => body_len - 2,
        5..=8 => body_len - 4,
        9..=16 => body_len - 8,
        34..=35 => 2,
        _ => return false,
    };
    let end = decoded.len() - checksum_len;
    let mut hasher = Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(&decoded[..end]);
    let checksum = hasher.finalize();
    decoded[end..] == checksum[..checksum_len]
}

/// Whether a candidate is a Bitcoin-style `Base58Check` public address. Restrict
/// to the standard 20-byte P2PKH/P2SH payloads and network version bytes, then
/// verify the four-byte double-SHA-256 checksum.
fn is_base58check_address(s: &str) -> bool {
    if !(26..=35).contains(&s.len()) {
        return false;
    }
    let Ok(decoded) = bs58::decode(s).into_vec() else {
        return false;
    };
    if decoded.len() != 25 || !matches!(decoded[0], 0 | 5 | 111 | 196) {
        return false;
    }
    let first_hash = Sha256::digest(&decoded[..21]);
    let second_hash = Sha256::digest(first_hash);
    decoded[21..] == second_hash[..4]
}

/// Recognize standard SRI strings by algorithm prefix and exact Base64 digest
/// length, including canonical padding bits.
fn is_sri_hash(s: &str) -> bool {
    let Some((algorithm, encoded)) = s.split_once('-') else {
        return false;
    };
    let (data_chars, padding) = match algorithm {
        "sha256" => (43, 1),
        "sha384" => (64, 0),
        "sha512" => (86, 2),
        _ => return false,
    };
    if encoded.len() != data_chars + padding {
        return false;
    }
    let (data, pad) = encoded.as_bytes().split_at(data_chars);
    if !data.iter().copied().all(is_base64_char)
        || !pad.iter().all(|&byte| byte == b'=')
        || pad.len() != padding
    {
        return false;
    }
    let Some(last) = data.last().copied().and_then(base64_value) else {
        return false;
    };
    match padding {
        1 => last.trailing_zeros() >= 2,
        2 => last.trailing_zeros() >= 4,
        _ => true,
    }
}

fn is_base64_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The entropy input is sometimes a URL path or wrapped code literal. Ignore
/// common punctuation around a complete public address, and recognize an
/// address as the final component of an otherwise ordinary ASCII path.
fn is_public_identifier_candidate(s: &str) -> bool {
    if is_sri_hash(s) {
        return true;
    }
    // Never strip characters in the opaque-token alphabet: '_<address>_'
    // can itself be a credential. Only strip surrounding prose punctuation.
    let bare = s.trim_matches(['"', '\'', '`', '(', ')', '[', ']', '{', '}', ',', ';']);
    if is_ss58_address(bare) || is_base58check_address(bare) || valid_extended_public_key(bare) {
        return true;
    }
    if !s
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._~-".contains(&byte))
    {
        return false;
    }
    let Some((prefix, address)) = s.rsplit_once('/') else {
        return false;
    };
    let simple_path = s.starts_with('/')
        && prefix
            .split('/')
            .filter(|part| !part.is_empty())
            .all(|part| part.len() <= 16);
    simple_path
        && (is_ss58_address(address)
            || is_base58check_address(address)
            || valid_extended_public_key(address))
}

fn is_entropy_exempt_token(value: &str) -> bool {
    is_public_identifier_candidate(value)
        || valid_wif(value)
        || valid_extended_private_key(value)
        || is_public_hardhat_dev_key(value)
}

/// Keyword values that are code expressions, type annotations, indirections,
/// or conventional placeholders rather than literal credentials.
fn is_non_secret_assignment_value(value: &str, quoted: bool, annotation: bool) -> bool {
    // A bare reference or placeholder may be the final argument of a call.
    // Keep quoted punctuation literal, and retain brackets/braces belonging to
    // environment references and templates.
    let reference = if quoted {
        value
    } else {
        value.trim_end_matches(')')
    };
    // Exact placeholders only: prefixes like `example_` and suffixes like
    // `_token` can also be part of a real credential.
    let lower = reference.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "changeme"
            | "change_me"
            | "example"
            | "example_key"
            | "sample"
            | "dummy"
            | "placeholder"
            | "todo"
            | "xxx"
            | "your_token"
            | "your_password"
            | "your_secret"
            | "your_api_key"
            | "replace_me"
            | "insert_token"
            | "insert_password"
            | "insert_secret"
            | "insert_api_key"
            | "your-token"
            | "your-password"
            | "your-secret"
            | "your-api-key"
            | "<your_token>"
            | "<your_password>"
            | "<your_secret>"
            | "<your_api_key>"
            | "<your-password>"
            | "<your-token>"
            | "<your-secret>"
            | "<your-api-key>"
            | "<your password>"
            | "<your token>"
            | "<your secret>"
            | "<your api key>"
    ) || assignment_reference_rule().is_match(reference)
    {
        return true;
    }
    // A quoted string is a literal, even when its contents resemble code or a
    // type. Do not exempt passwords such as "Optional[str]" or "client.secret".
    if quoted {
        return false;
    }
    matches!(
        lower.trim_end_matches([')', ']', '}', ':']),
        "none" | "null" | "undefined" | "true" | "false"
    ) || annotation && is_type_annotation(value.trim_end_matches([')', ':']))
        || is_dotted_identifier(reference)
}

fn assignment_reference_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        structured_rule(concat!(
            r"^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|",
            r"%[A-Z_][A-Z0-9_]*%|\{\{[ \t]*[A-Za-z_][A-Za-z0-9_.]*",
            r"[ \t]*\}\})$"
        ))
    })
}

fn is_type_annotation(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "str"
            | "string"
            | "int"
            | "integer"
            | "float"
            | "bool"
            | "boolean"
            | "bytes"
            | "optional"
            | "option"
            | "list"
            | "dict"
            | "set"
            | "tuple"
            | "sequence"
            | "mapping"
    )
}

// Index balanced generic delimiters once, including for malformed annotations.
fn generic_closes(text: &str) -> HashMap<usize, usize> {
    let mut closes = HashMap::new();
    let mut stack = Vec::new();
    for (offset, byte) in text.bytes().enumerate() {
        match byte {
            b'<' => stack.push((offset, b'>')),
            b'[' => stack.push((offset, b']')),
            b'>' | b']' => {
                if let Some((open, expected)) = stack.pop() {
                    if byte == expected {
                        closes.insert(open, offset + 1);
                    } else {
                        stack.clear();
                    }
                }
            }
            byte if byte.is_ascii_alphanumeric() || b"_., |?:".contains(&byte) => {}
            _ => stack.clear(),
        }
    }
    closes
}

fn is_dotted_identifier(value: &str) -> bool {
    let mut parts = value.split('.');
    parts.next().is_some_and(is_identifier)
        && parts.next().is_some_and(is_identifier)
        && parts.all(is_identifier)
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// High-entropy token backstop: flags diverse whitespace-delimited tokens that
/// look like opaque credentials: non-hex base64 ≥4.5 bits/char. Catches a bespoke
/// mixed-class token that matches no vendor pattern.
fn entropy_backstop(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for (start, tok) in split_with_offsets(text) {
        let len = tok.len();
        // Test the cheap character-class predicates before computing entropy: a
        // long prose word lacks diversity, so it never pays for the entropy scan.
        if len >= 20
            && is_base64ish(tok)
            && !is_hexish(tok)
            && has_character_class_diversity(tok)
            && !is_entropy_exempt_token(tok)
            && shannon_entropy(tok) >= 4.5
        {
            spans.push(Span::new(start, start + len, "SECRET", 0.7));
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
    fn structured_patterns_have_no_unicode_word_boundaries() {
        // A Unicode word boundary forces the regex crate off its lazy DFA for
        // any haystack containing a non-ASCII byte.
        for pattern in structured_pattern_sources()
            .into_iter()
            .chain([INTL_PHONE_PATTERN.to_owned()])
        {
            let hir = regex_automata::util::syntax::parse(&pattern).unwrap();
            let looks = hir.properties().look_set();
            assert!(
                !looks.contains_word_unicode(),
                "Unicode word boundary in {pattern}"
            );
            let re = regex_automata::hybrid::regex::Regex::new(&pattern).unwrap();
            let mut cache = re.create_cache();
            let input = regex_automata::Input::new(
                "é ٤١٥-٥٥٥-٠١٣٢ — 4111 1111 1111 1111 — GB82 WEST 1234 5698 7654 32",
            );
            re.try_search(&mut cache, &input).unwrap();
        }
    }

    #[test]
    fn detects_taostats_api_keys() {
        // Synthetic keys in each issued format; never real credentials.
        let hex64 = "7c0e9b4a1d2f3e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c";
        for (key, ty) in [
            (format!("gm_live_{hex64}"), "GM_API_KEY"),
            (format!("bm_live_{hex64}"), "BLOCKMACHINE_API_KEY"),
            (format!("ts_live_{hex64}"), "TAOSTATS_API_KEY"),
            (
                "tao-3f2b8c1e-9d4a-4e6b-8a7c-5d1e2f3a4b5c:9a8b7c6d".to_owned(),
                "TAOSTATS_API_KEY",
            ),
        ] {
            let text = format!("Authorization: {key}\n");
            let spans = resolve_overlaps(detect_secrets(&text));
            assert!(
                spans
                    .iter()
                    .any(|s| s.ty == ty && text[s.start..s.end] == key),
                "{ty} not detected in {text:?}: {spans:?}"
            );
        }
        // A prefix without the full body is not a key.
        assert!(!detect_secrets("gm_live_1234")
            .iter()
            .any(|s| s.ty == "GM_API_KEY"));
    }

    #[test]
    fn shannon_entropy_of_uniform_is_high() {
        assert!(shannon_entropy("abcdefghijklmnop") > 3.0);
        assert!(shannon_entropy("aaaaaaaaaaaaaaaa") < 0.1);
    }

    #[test]
    fn validated_keyword_gate_covers_unicode_case_folded_matches() {
        let hex = "a7".repeat(32);
        let array = format!(
            "[{}]",
            (0..64).map(|n| n.to_string()).collect::<Vec<_>>().join(",")
        );
        for text in [
            format!("ſeed=0x{hex}"),
            format!(r#"{{"ſecretſeed":"0x{hex}"}}"#),
            format!(r#"{{"privateKey":"{hex}"}}"#),
            r#"{"ſecretphraſe":"private words for testing"}"#.to_owned(),
            format!("Keypair={array}"),
            format!("ſolana={}", bs58::encode([7; 64]).into_string()),
        ] {
            let mut hits = vec![false; ADDITIONAL_SECRET_PATTERNS.len()];
            let _ = gitleaks::detect(&text, &mut hits);
            let mut expected = Vec::new();
            detect_validated_secrets(&text, &vec![true; hits.len()], &mut expected);
            assert!(
                !expected.is_empty(),
                "fixture must match a validated regex: {text}"
            );
            let mut actual = Vec::new();
            detect_validated_secrets(&text, &hits, &mut actual);
            assert_eq!(actual, expected, "{text}");
        }
    }

    #[test]
    fn every_validated_regex_sample_reaches_its_keyword_gate() {
        use proptest::strategy::{Strategy, ValueTree};
        use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

        let mut runner = TestRunner::new_with_rng(
            Config::default(),
            TestRng::from_seed(RngAlgorithm::ChaCha, &[11; 32]),
        );
        for (index, rule) in validated_secret_rules().iter().enumerate() {
            if rule.keywords.is_empty() {
                continue;
            }
            let sampling_form = rule.re.as_str().replace(r"\b", "");
            let strategy = proptest::string::string_regex(&sampling_form).unwrap();
            for _ in 0..32 {
                let sample = strategy.new_tree(&mut runner).unwrap().current();
                assert!(rule.re.is_match(&sample), "invalid sample: {sample:?}");
                let mut hits = vec![false; ADDITIONAL_SECRET_PATTERNS.len()];
                let _ = gitleaks::detect(&sample, &mut hits);
                assert!(hits[index], "rule {} missed sample {sample:?}", rule.ty);
            }
        }
    }

    #[test]
    fn opaque_tokens_are_not_exempt_by_private_key_shape_or_substring() {
        let alphabet =
            "Q7wE2r9T4y1U8i3O6p0A5sDf3Gh8Jk1Lz4Xc7Vb2Nm6Qa9Ws5Ed0Rf3Tg7Yh1Uj4Ik8Ol2Pz6Xm";
        for token in [
            format!("5{}", &alphabet[..50]),
            format!(
                "xprv{}",
                alphabet.chars().cycle().take(107).collect::<String>()
            ),
            format!("{}{}", HARDHAT_PUBLIC_DEV_KEYS[0], alphabet.repeat(4)),
        ] {
            assert!(shannon_entropy(&token) >= 4.5);
            assert!(entropy_backstop(&token)
                .iter()
                .any(|span| span.end == token.len()));
        }
    }

    #[test]
    fn base58check_payload_is_bounded_to_supported_formats() {
        let mut bytes = vec![42; 128];
        let checksum = Sha256::digest(Sha256::digest(&bytes));
        bytes.extend_from_slice(&checksum[..4]);
        let encoded = bs58::encode(bytes).into_string();
        assert!(decode_base58check_payload(&encoded).is_none());
    }

    #[test]
    fn ss58_checksum_accepts_valid_address_and_rejects_bad_checksum() {
        let valid = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let invalid = "5FHBJCMkqnBzGh6s8hx1LNUyycVTdWfjzgQQs7XZNmbDzXJR";
        assert!(is_ss58_address(valid));
        assert!(!is_ss58_address(invalid));
    }

    #[test]
    fn base58check_and_sri_validators_require_exact_encodings() {
        let bitcoin = "14YomMWKx4jzD34ESv7HzpNhU6wojtLFGW";
        assert!(is_base58check_address(bitcoin));
        let mut corrupted = bitcoin.as_bytes().to_vec();
        corrupted[10] = if corrupted[10] == b'1' { b'2' } else { b'1' };
        let corrupted = std::str::from_utf8(&corrupted).unwrap();
        assert!(!is_base58check_address(corrupted));

        assert!(is_sri_hash(
            "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        ));
        assert!(!is_sri_hash("sha384-not-a-valid-integrity-value"));
    }

    fn ss58_fixture(prefix: &[u8], payload: &[u8], checksum_len: usize) -> String {
        let mut data = [prefix, payload].concat();
        let digest = Blake2b512::digest([b"SS58PRE".as_slice(), &data].concat());
        data.extend_from_slice(&digest[..checksum_len]);
        bs58::encode(data).into_string()
    }

    #[test]
    fn ss58_accepts_all_payload_lengths_and_network_prefix_widths() {
        // Prefix 42 is also used by Bittensor; [0x50, 0x00] encodes network 64.
        // Include leading zero bytes, which Base58 represents as leading '1's.
        for prefix in [&[0][..], &[42], &[63], &[0x50, 0x00], &[0x7f, 0xff]] {
            for (payload_len, max_checksum) in [(1, 1), (2, 2), (4, 4), (8, 8), (32, 2), (33, 2)] {
                let checksums = if payload_len >= 32 {
                    2..=2
                } else {
                    1..=max_checksum
                };
                for checksum_len in checksums {
                    for byte in [0, 0xa7] {
                        let address = ss58_fixture(prefix, &vec![byte; payload_len], checksum_len);
                        assert!(
                            is_ss58_address(&address),
                            concat!("prefix={:?} payload={} ", "checksum={}: {}"),
                            prefix,
                            payload_len,
                            checksum_len,
                            address
                        );
                        assert_eq!(entropy_backstop(&address), []);
                        let mut decoded = bs58::decode(&address).into_vec().unwrap();
                        *decoded.last_mut().unwrap() ^= 1;
                        assert!(!is_ss58_address(&bs58::encode(decoded).into_string()));
                    }
                }
            }
        }
        assert!(is_ss58_address(
            "5Hq3PNMU3AJnw4HwTPCQ2yFUAjX19MFFWENW9bfNfH3CURcx"
        ));
    }

    #[test]
    fn ss58_rejects_reserved_prefixes_and_invalid_lengths() {
        for prefix in [&[46][..], &[47], &[128], &[255], &[0x40, 0]] {
            assert!(!is_ss58_address(&ss58_fixture(prefix, &[0xa7; 32], 2)));
        }
        for payload_len in [0, 17, 31, 34, 64] {
            assert!(!is_ss58_address(&ss58_fixture(
                &[42],
                &vec![0xa7; payload_len],
                2
            )));
        }
    }

    #[test]
    fn base58check_preserves_leading_zeros_and_rejects_private_keys() {
        for version in [0, 5, 111, 196] {
            for zeros in 0..=20 {
                let mut data = vec![version];
                data.extend(vec![0; zeros]);
                data.extend(vec![0xa7; 20 - zeros]);
                let checksum = Sha256::digest(Sha256::digest(&data));
                data.extend_from_slice(&checksum[..4]);
                let address = bs58::encode(&data).into_string();
                assert!(is_base58check_address(&address), "{address}");
                assert!(!is_base58check_address(&format!("1{address}")));
                for invalid in ['0', 'O', 'I', 'l', 'é'] {
                    let malformed = format!("{}{invalid}{}", &address[..10], &address[11..]);
                    assert!(!is_base58check_address(&malformed));
                }
            }
        }
        // WIF is Base58Check too, but is a private key, never a public exemption.
        let mut data = vec![128];
        data.extend(Sha256::digest(b"test-only WIF private key"));
        let checksum = Sha256::digest(Sha256::digest(&data));
        data.extend_from_slice(&checksum[..4]);
        let wif = bs58::encode(data).into_string();
        assert!(!is_base58check_address(&wif));
        assert!(!is_public_identifier_candidate(&wif));
        assert_ne!(detect_secrets(&wif), []);
    }

    #[test]
    fn sri_rejects_wrong_lengths_padding_and_non_ascii_without_panicking() {
        for (algorithm, chars, padding) in [("sha256", 43, 1), ("sha384", 64, 0), ("sha512", 86, 2)]
        {
            let data = "A".repeat(chars);
            let digest = format!("{algorithm}-{data}{}", "=".repeat(padding));
            assert!(is_sri_hash(&digest));
            assert!(!is_sri_hash(&format!("{digest}=")));
            assert!(!is_sri_hash(&digest[..digest.len() - 1]));
            if padding > 0 {
                assert!(!is_sri_hash(&format!(
                    "{algorithm}-{}B{}",
                    "A".repeat(chars - 1),
                    "=".repeat(padding)
                )));
                let unicode = format!(
                    "{algorithm}-{}é{}",
                    "A".repeat(chars - 1),
                    "=".repeat(padding - 1)
                );
                assert!(!is_sri_hash(&unicode));
            }
            for bad in ['-', '_', '=', ' ', 'é'] {
                assert!(!is_sri_hash(&format!(
                    "{algorithm}-{bad}{}{}",
                    "A".repeat(chars - 1),
                    "=".repeat(padding)
                )));
            }
        }
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
                detect_structured(card)
                    .iter()
                    .any(|s| s.ty == "CREDIT_CARD"),
                "missed card span: {card}"
            );
        }
    }

    #[test]
    fn ipv4_validation_rejects_out_of_range() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(!is_valid_ipv4("999.1.1.1"));
    }

    fn phones(text: &str) -> Vec<&str> {
        let mut found = Vec::new();
        for s in resolve_overlaps(detect_structured(text)) {
            if s.ty == "PHONE" {
                found.push(&text[s.start..s.end]);
            }
        }
        found
    }

    #[test]
    fn detects_international_phone_numbers() {
        assert_eq!(phones("call +44 7700 900123 today"), ["+44 7700 900123"]);
        assert_eq!(phones("tel:+447700900123."), ["+447700900123"]);
        assert_eq!(phones("Paris +33 1 23 45 67 89"), ["+33 1 23 45 67 89"]);
        assert_eq!(phones("Berlin +49-30-1234567"), ["+49-30-1234567"]);
        assert_eq!(phones("US +1 555 123 4567"), ["+1 555 123 4567"]);
    }

    #[test]
    fn international_phone_counts_only_ascii_digits() {
        // Full-width digits are not part of the candidate, so they neither pad
        // a short run past the limit nor form a number on their own.
        assert_eq!(phones("+1234567８９０"), ["+1234567"]);
        assert_eq!(phones("+４４７７００９００１２３"), Vec::<&str>::new());
    }

    #[test]
    fn international_phone_stops_at_line_end() {
        assert_eq!(phones("+44 7700 900123\n2024"), ["+44 7700 900123"]);
    }

    #[test]
    fn international_phone_rejects_wrong_digit_count_whole_candidate() {
        assert_eq!(phones("score +123456"), Vec::<&str>::new());
        assert_eq!(phones("id +1234567890123456"), Vec::<&str>::new());
        // 16 digits in groups: no 15-digit prefix is redacted either.
        assert_eq!(phones("id +1234 5678 9012 3456"), Vec::<&str>::new());
    }

    #[test]
    fn international_candidate_does_not_hide_a_us_number() {
        // The `+` run is rejected (23 digits) but must not stop the NANP rule
        // from covering the US number it overlaps, as it did before.
        let text = "+447700900123 555-123-4567";
        let us_start = text.len() - "555-123-4567".len();
        let spans = resolve_overlaps(detect_structured(text));
        for byte in us_start..text.len() {
            assert!(
                spans.iter().any(|s| s.start <= byte && byte < s.end),
                "byte {byte}"
            );
        }
    }

    #[test]
    fn detects_email_and_ssn() {
        let spans = detect_structured("mail me at a@b.com or use 123-45-6789");
        assert!(spans.iter().any(|s| s.ty == "EMAIL"));
        assert!(spans.iter().any(|s| s.ty == "US_SSN"));
    }

    #[test]
    fn ssn_rejects_unassigned_areas_groups_and_serials() {
        for ssn in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "999-12-3456",
            "123-00-6789",
            "123-45-0000",
        ] {
            assert!(
                !detect_structured(ssn)
                    .iter()
                    .any(|span| span.ty == "US_SSN"),
                "invalid SSN accepted: {ssn}"
            );
        }
        assert!(detect_structured("123-45-6789")
            .iter()
            .any(|span| span.ty == "US_SSN"));
    }

    #[test]
    fn keyword_seed_pattern_captures_after_flag() {
        let value = format!("0x{}", "a7".repeat(32));
        let text = format!("btcli wallet create --seed {value}");
        let rule = validated_secret_rules()
            .iter()
            .find(|rule| rule.ty == "BITTENSOR_SEED")
            .unwrap();
        let capture = rule.re.captures(&text).unwrap();
        assert_eq!(capture.name("secret").unwrap().as_str(), value);
        assert!((rule.validator)(capture.name("secret").unwrap().as_str()));
        let text = format!(r#"{{"secretSeed":"{value}"}}"#);
        let rule = validated_secret_rules()
            .iter()
            .find(|rule| rule.re.as_str().starts_with("(?i)\"secret[_ ]?seed\""))
            .unwrap();
        let capture = rule.re.captures(&text).unwrap();
        assert_eq!(capture.name("secret").unwrap().as_str(), value);
    }

    #[test]
    fn additional_secret_patterns_compile_with_secret_captures() {
        for (_, pattern, _, _, _) in ADDITIONAL_SECRET_PATTERNS {
            let regex = Regex::new(pattern).unwrap();
            assert!(regex.capture_names().flatten().any(|name| name == "secret"));
        }
    }

    #[test]
    fn extended_public_test_vector_is_valid_and_remains_public() {
        let xpub = concat!(
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8i",
            "doc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        );
        assert!(valid_extended_public_key(xpub));
        assert!(is_public_identifier_candidate(&format!("/wallet/{xpub}")));
        assert_eq!(detect_secrets(xpub), Vec::<Span>::new());
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
