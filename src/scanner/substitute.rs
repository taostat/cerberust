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

/// The shared closure behind a [`RestoreEncoder`]: maps a restored original to
/// its encoded form. `Arc` so the encoder is cheap to `Clone` onto the context.
type EncodeFn = std::sync::Arc<dyn Fn(&str) -> String + Send + Sync>;

/// A caller-supplied transform applied to each restored original before it is
/// spliced back into the output, e.g. JSON-escaping a value being placed inside
/// a JSON string in an SSE/JSON stream. It sees only the rehydrated original —
/// never the surrounding model text — so the caller escapes exactly the bytes
/// it is introducing and nothing the upstream already encoded.
///
/// The default is [`RestoreEncoder::identity`]: the original is emitted
/// verbatim, so restore is byte-for-byte unchanged unless a hook is installed.
#[derive(Clone)]
pub struct RestoreEncoder {
    /// `None` is identity — a hot-path marker that splices the original's raw
    /// bytes with no allocation. `Some(f)` maps an original to its encoded form.
    encode: Option<EncodeFn>,
}

impl RestoreEncoder {
    /// The identity encoder: restored originals are emitted unchanged.
    #[must_use]
    pub fn identity() -> Self {
        Self { encode: None }
    }

    /// An encoder from a closure mapping each original to its encoded form.
    #[must_use]
    pub fn new(encode: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        Self {
            encode: Some(std::sync::Arc::new(encode)),
        }
    }

    /// Encode `original` and append the result to `out`. Identity appends the raw
    /// bytes with no allocation; otherwise the closure's `String` is appended.
    fn encode_into(&self, original: &[u8], out: &mut Vec<u8>) {
        match &self.encode {
            None => out.extend_from_slice(original),
            Some(f) => {
                // Originals are interned from `&str`, so they are valid UTF-8.
                let original = String::from_utf8_lossy(original);
                out.extend_from_slice(f(&original).as_bytes());
            }
        }
    }
}

impl Default for RestoreEncoder {
    fn default() -> Self {
        Self::identity()
    }
}

impl std::fmt::Debug for RestoreEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = if self.encode.is_some() {
            "custom"
        } else {
            "identity"
        };
        f.debug_struct("RestoreEncoder")
            .field("kind", &kind)
            .finish()
    }
}

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
        self.substitute_with_counting(text, &RestoreEncoder::identity())
            .0
    }

    /// The core restore: replace every complete sentinel with its original,
    /// passing each restored original through `encoder` first, and return
    /// `(output, (sentinel, count) pairs)` for every sentinel actually spliced
    /// back. The encoder lets a caller JSON-escape a rehydrated value placed
    /// inside a JSON/SSE stream (surrounding bytes untouched); the pairs carry
    /// sentinel **labels** and counts only — never the restored originals. With
    /// [`RestoreEncoder::identity`] the output is byte-identical to
    /// [`Self::substitute`].
    #[must_use]
    pub fn substitute_with_counting(
        &self,
        text: &str,
        encoder: &RestoreEncoder,
    ) -> (String, Vec<(String, u32)>) {
        let bytes = text.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut counts: Vec<u32> = vec![0; self.subs.len()];
        let mut i = 0;
        'scan: while i < bytes.len() {
            if bytes[i] == b'[' {
                for (idx, sub) in self.subs.iter().enumerate() {
                    if matches_at(bytes, i, sub) {
                        encoder.encode_into(&sub.original, &mut out);
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

    /// Like [`Self::substitute`], applying `encoder` to each restored original
    /// before splicing. Output encoding only — no restore counts.
    #[must_use]
    pub fn substitute_with(&self, text: &str, encoder: &RestoreEncoder) -> String {
        self.substitute_with_counting(text, encoder).0
    }

    /// Like [`Self::substitute`], also returning per-sentinel restore counts
    /// (sentinel labels + counts only, never originals). Identity encoding.
    #[must_use]
    pub fn substitute_counting(&self, text: &str) -> (String, Vec<(String, u32)>) {
        self.substitute_with_counting(text, &RestoreEncoder::identity())
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

    #[test]
    fn identity_encoder_matches_plain_substitute() {
        let s = subber(&[("[REDACTED_EMAIL_1_abcd1234]", "a\"b\nc")]);
        let text = "x [REDACTED_EMAIL_1_abcd1234] y";
        // The default substitute and an explicit identity encoder agree, and
        // neither touches the surrounding bytes.
        assert_eq!(
            s.substitute(text),
            s.substitute_with(text, &RestoreEncoder::identity()),
        );
        assert_eq!(s.substitute(text), "x a\"b\nc y");
    }

    #[test]
    fn encoder_transforms_only_the_restored_original() {
        let s = subber(&[("[REDACTED_EMAIL_1_abcd1234]", "a\"b")]);
        // A JSON-string escaper applied to the original; the surrounding `"` is
        // model text and must be left untouched.
        let enc = RestoreEncoder::new(|o| o.replace('"', "\\\""));
        assert_eq!(
            s.substitute_with("say \"[REDACTED_EMAIL_1_abcd1234]\"", &enc),
            "say \"a\\\"b\"",
        );
    }
}
