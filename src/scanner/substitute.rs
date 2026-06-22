//! The single sentinel→original substitution used by the output-restore path.
//!
//! Restore scans **raw text** for sentinels and splices each original back.
//! Sentinels live in a JSON-escape-free alphabet (`[`, `]`, `_`, `0-9`,
//! `A-F`/`a-f`, `A-Z`), so a sentinel appears identically in a raw frame and in
//! decoded content; matching on raw bytes therefore needs no JSON parse.
//!
//! Matching is exact plus ASCII-case-insensitive (a model that echoes
//! `[redacted_email_1_ab12cd34]` still restores). There is deliberately **no**
//! fuzzy/edit-distance pass: a hallucinated counter or nonce is edit-distance 1
//! from a real sentinel, and restoring it would splice a *different* value's
//! original into the response.
//!
//! `longest_sentinel` and `is_sentinel_prefix` exist for the streaming runner
//! follow-up: a per-chunk restorer holds back the longest trailing run that
//! could still complete a sentinel and flushes it at EOF. The whole-text
//! [`Substituter::substitute`] is the unary path the [`ScannerStack`] uses
//! today.

/// A request's sentinel→original table, pre-sorted longest-sentinel first so a
/// complete sentinel is matched before any shorter sentinel that prefixes it.
#[derive(Debug, Clone)]
pub struct Substituter {
    subs: Vec<Sub>,
    /// The longest sentinel byte length — the streaming hold-back bound.
    longest: usize,
}

#[derive(Debug, Clone)]
struct Sub {
    sentinel: Vec<u8>,
    sentinel_lower: Vec<u8>,
    original: Vec<u8>,
}

impl Substituter {
    /// Build from `(sentinel, original)` pairs.
    #[must_use]
    pub fn from_pairs<'a>(pairs: impl Iterator<Item = (&'a str, &'a str)>) -> Self {
        let mut subs: Vec<Sub> = pairs
            .map(|(sentinel, original)| Sub {
                sentinel: sentinel.as_bytes().to_vec(),
                sentinel_lower: sentinel.to_ascii_lowercase().into_bytes(),
                original: original.as_bytes().to_vec(),
            })
            .collect();
        subs.sort_by_key(|s| std::cmp::Reverse(s.sentinel.len()));
        let longest = subs.first().map_or(0, |s| s.sentinel.len());
        Self { subs, longest }
    }

    /// The longest sentinel byte length — the maximum trailing run a streaming
    /// runner must hold back as a possible incomplete sentinel.
    #[must_use]
    pub fn longest_sentinel(&self) -> usize {
        self.longest
    }

    /// Whether the table is empty (nothing to substitute).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.subs.is_empty()
    }

    /// Replace every complete sentinel in `text` (exact or ASCII-case-
    /// insensitive) with its original. Sentinels open on `[`, are pure ASCII,
    /// and self-delimiting, so a left-to-right scan with the pre-sorted
    /// longest-first table is unambiguous.
    #[must_use]
    pub fn substitute(&self, text: &str) -> String {
        self.substitute_counting(text).0
    }

    /// Like [`Substituter::substitute`], but also returns `(sentinel, count)`
    /// pairs for every sentinel actually spliced back, so a metrics consumer can
    /// attribute restores per entity type. The pairs carry sentinel **labels**
    /// and counts only — never the restored originals.
    #[must_use]
    pub fn substitute_counting(&self, text: &str) -> (String, Vec<(String, u32)>) {
        let bytes = text.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut counts: Vec<u32> = vec![0; self.subs.len()];
        let mut i = 0;
        'scan: while i < bytes.len() {
            if bytes[i] == b'[' {
                for (idx, sub) in self.subs.iter().enumerate() {
                    if matches_at(bytes, i, sub) {
                        out.extend_from_slice(&sub.original);
                        i += sub.sentinel.len();
                        counts[idx] += 1;
                        continue 'scan;
                    }
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        // The originals were valid UTF-8 strings and the surrounding text is
        // UTF-8; splicing whole-byte sentinels for whole-byte originals on
        // char-aligned boundaries (sentinels are ASCII) preserves UTF-8.
        let text = String::from_utf8(out)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        let restored = self
            .subs
            .iter()
            .zip(counts)
            .filter(|(_, n)| *n > 0)
            .map(|(sub, n)| (String::from_utf8_lossy(&sub.sentinel).into_owned(), n))
            .collect();
        (text, restored)
    }

    /// Whether `tail` is a non-empty strict prefix of some sentinel (exact or
    /// case-insensitive) — a run that could still complete once more bytes
    /// arrive. For the streaming runner follow-up.
    #[must_use]
    pub fn is_sentinel_prefix(&self, tail: &[u8]) -> bool {
        self.subs
            .iter()
            .any(|sub| tail.len() < sub.sentinel.len() && ci_starts_with(&sub.sentinel_lower, tail))
    }
}

/// Whether `sub`'s sentinel matches `bytes` at `i`, ASCII-case-insensitively.
fn matches_at(bytes: &[u8], i: usize, sub: &Sub) -> bool {
    let end = i + sub.sentinel.len();
    end <= bytes.len() && ci_eq(&bytes[i..end], &sub.sentinel_lower)
}

/// Whether `bytes` equals `lowered` ignoring ASCII case (`lowered` is already
/// lowercased; `bytes` is lowercased per element on the fly).
fn ci_eq(bytes: &[u8], lowered: &[u8]) -> bool {
    bytes.len() == lowered.len()
        && bytes
            .iter()
            .zip(lowered)
            .all(|(b, l)| b.to_ascii_lowercase() == *l)
}

/// Whether `lowered` starts with `prefix` ignoring ASCII case.
fn ci_starts_with(lowered: &[u8], prefix: &[u8]) -> bool {
    prefix.len() <= lowered.len()
        && prefix
            .iter()
            .zip(lowered)
            .all(|(p, l)| p.to_ascii_lowercase() == *l)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use super::*;

    fn subber(pairs: &[(&str, &str)]) -> Substituter {
        Substituter::from_pairs(pairs.iter().map(|(s, o)| (*s, *o)))
    }

    #[test]
    fn exact_substitution() {
        let s = subber(&[("[REDACTED_EMAIL_1_abcd1234]", "alice@x.com")]);
        assert_eq!(
            s.substitute("see [REDACTED_EMAIL_1_abcd1234] now"),
            "see alice@x.com now"
        );
    }

    #[test]
    fn case_insensitive_substitution() {
        let s = subber(&[("[REDACTED_EMAIL_1_ABCD1234]", "alice@x.com")]);
        assert_eq!(
            s.substitute("see [redacted_email_1_abcd1234] now"),
            "see alice@x.com now"
        );
    }

    #[test]
    fn longest_first_avoids_shadowing() {
        let s = subber(&[
            ("[REDACTED_EMAIL_1_aa]", "short"),
            ("[REDACTED_EMAIL_1_aa_X]", "long"),
        ]);
        assert_eq!(s.substitute("[REDACTED_EMAIL_1_aa_X]"), "long");
    }

    #[test]
    fn mangled_sentinel_is_left_alone() {
        let s = subber(&[("[REDACTED_EMAIL_1_abcd1234]", "alice@x.com")]);
        let mangled = "[REDACTED_EMAL_1_abcd1234]";
        assert_eq!(s.substitute(mangled), mangled);
    }

    #[test]
    fn prefix_detection_for_holdback() {
        let s = subber(&[("[REDACTED_EMAIL_1_abcd1234]", "alice@x.com")]);
        assert!(s.is_sentinel_prefix(b"[REDACTED_EM"));
        assert!(s.is_sentinel_prefix(b"[redacted_em"));
        assert!(!s.is_sentinel_prefix(b"[REDACTED_EMAIL_1_abcd1234]"));
        assert!(!s.is_sentinel_prefix(b"[50]"));
    }

    #[test]
    fn substitute_counting_reports_per_sentinel_counts() {
        let s = subber(&[
            ("[REDACTED_EMAIL_1_abcd1234]", "alice@x.com"),
            ("[REDACTED_PHONE_1_abcd1234]", "555-1234"),
        ]);
        let (text, counts) = s.substitute_counting(
            "mail [REDACTED_EMAIL_1_abcd1234] twice [REDACTED_EMAIL_1_abcd1234] phone [REDACTED_PHONE_1_abcd1234]",
        );
        assert!(text.contains("alice@x.com"));
        assert!(text.contains("555-1234"));
        let map: std::collections::BTreeMap<_, _> = counts.into_iter().collect();
        assert_eq!(map.get("[REDACTED_EMAIL_1_abcd1234]"), Some(&2));
        assert_eq!(map.get("[REDACTED_PHONE_1_abcd1234]"), Some(&1));
    }

    #[test]
    fn substitute_counting_omits_unmatched_sentinels() {
        let s = subber(&[("[REDACTED_EMAIL_1_abcd1234]", "alice@x.com")]);
        let (_text, counts) = s.substitute_counting("no sentinel here");
        assert!(counts.is_empty());
    }

    #[test]
    fn unrelated_bracket_run_untouched() {
        let s = subber(&[("[REDACTED_EMAIL_1_abcd1234]", "alice@x.com")]);
        assert_eq!(s.substitute("price [50] then text"), "price [50] then text");
    }
}
