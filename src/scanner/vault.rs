//! The request-scoped vault: a placeholder↔original map with a per-type
//! counter and a per-request nonce, zeroized on drop.
//!
//! The vault holds the one piece of request state that must never leave the
//! host — the map from each `[REDACTED_<TYPE>_<N>_<nonce>]` sentinel back
//! to the original plaintext. Any scanner may intern into it (PII, secrets);
//! restore reads it on the output path. It is a *stack capability* threaded on
//! [`ScanCtx`](crate::ScanCtx), not the private field of one scanner.
//!
//! Each request mints a fresh nonce baked into every sentinel it emits. The
//! nonce namespaces the request's sentinels so a caller cannot pre-image one
//! (embed a guessed sentinel in their own prompt and have the restore pass
//! splice a *different* request's original into the response): without the
//! per-request nonce the sentinel is guessable, with it the caller would have
//! to predict the request's random token.

use std::collections::HashMap;

use rand::Rng;
use zeroize::Zeroize;

/// Hex characters one request's sentinel nonce carries. Kept in a JSON-escape-
/// free alphabet (hex digits) so a sentinel is byte-identical inside a JSON
/// string and a raw byte scan needs no JSON parse.
const NONCE_HEX_LEN: usize = 8;

/// Maps a redaction sentinel to the original plaintext it stands in for, and
/// allocates a stable per-type counter so two distinct values of the same type
/// stay distinct (`[REDACTED_EMAIL_1_<nonce>]` vs `[REDACTED_EMAIL_2_<nonce>]`).
#[derive(Debug)]
pub struct Vault {
    /// sentinel → original plaintext.
    by_placeholder: HashMap<String, String>,
    /// original plaintext → sentinel, so the same value within one request maps
    /// to the same sentinel (dedupe-by-value).
    by_value: HashMap<String, String>,
    /// Sentinels eligible for restore — those interned by a `RoundTrip` input
    /// scanner. A model-emitted value masked on the output path interns its own
    /// sentinel of the *same entity type* but is absent here, so the restore pass
    /// rehydrates only the input values and never echoes model-generated PII
    /// back. Restore eligibility is therefore per-sentinel, not per-type.
    restorable: std::collections::HashSet<String>,
    /// Next counter to allocate per entity type.
    counters: HashMap<String, u32>,
    /// Per-request random suffix every sentinel carries.
    nonce: String,
}

impl Vault {
    /// Build a vault with a freshly-minted per-request nonce, derived from the
    /// thread RNG so two concurrent requests never share a sentinel namespace.
    #[must_use]
    pub fn new() -> Self {
        Self::with_nonce(random_nonce())
    }

    /// Build a vault with an explicit nonce. Test-only escape hatch so a test
    /// can assert against a fixed sentinel; production always mints a random
    /// one via [`Self::new`].
    #[must_use]
    pub fn with_nonce(nonce: String) -> Self {
        Self {
            by_placeholder: HashMap::new(),
            by_value: HashMap::new(),
            restorable: std::collections::HashSet::new(),
            counters: HashMap::new(),
            nonce,
        }
    }

    /// The request's sentinel nonce. For audit and tests only.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Whether the vault holds any redaction. An empty vault is the
    /// byte-identical-passthrough signal on the response path.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_placeholder.is_empty()
    }

    /// Number of distinct values interned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_placeholder.len()
    }

    /// Intern `original` under entity type `ty`, returning its sentinel. The
    /// same original value seen twice in one request returns the same sentinel;
    /// a new value allocates the next per-type counter.
    ///
    /// `restorable` marks the sentinel for the restore pass: `true` for a
    /// `RoundTrip` input redaction (the caller's own PII, echoed back), `false`
    /// for a `OneWay` redaction (a secret, or model-emitted PII masked on
    /// output). Restorability is sticky-`true`: if a value is interned restorable
    /// once, a later `OneWay` intern of the *same* value (the model echoing the
    /// caller's literal input) keeps it restorable, because it is still the
    /// caller's value.
    pub fn intern(&mut self, ty: &str, original: &str, restorable: bool) -> String {
        if let Some(existing) = self.by_value.get(original) {
            if restorable {
                self.restorable.insert(existing.clone());
            }
            return existing.clone();
        }
        let counter = self.counters.entry(ty.to_owned()).or_insert(0);
        *counter += 1;
        let placeholder = format!("[REDACTED_{ty}_{counter}_{}]", self.nonce);
        self.by_placeholder
            .insert(placeholder.clone(), original.to_owned());
        self.by_value
            .insert(original.to_owned(), placeholder.clone());
        if restorable {
            self.restorable.insert(placeholder.clone());
        }
        placeholder
    }

    /// Whether `placeholder` was interned as restorable (a `RoundTrip` input
    /// redaction). The restore pass consults this so it never rehydrates a
    /// `OneWay` sentinel — a secret, or model-emitted PII masked on output — even
    /// when that sentinel shares an entity type with a restored input value.
    #[must_use]
    pub fn is_restorable(&self, placeholder: &str) -> bool {
        self.restorable.contains(placeholder)
    }

    /// Look up the original for a sentinel (exact match). The detokenize half
    /// of the round-trip; the proptest pins `intern` then `original_for` as an
    /// identity.
    #[must_use]
    pub fn original_for(&self, placeholder: &str) -> Option<&str> {
        self.by_placeholder.get(placeholder).map(String::as_str)
    }

    /// Iterate `(sentinel, original)` pairs for the restore pass.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.by_placeholder
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

impl Default for Vault {
    /// Mints a fresh random nonce, same as [`Self::new`] — there is no
    /// nonce-less vault, so `default()` is never a footgun.
    fn default() -> Self {
        Self::new()
    }
}

/// An 8-hex-char random nonce from the thread RNG.
fn random_nonce() -> String {
    let bytes: [u8; NONCE_HEX_LEN / 2] = rand::thread_rng().gen();
    hex::encode(bytes)
}

impl Drop for Vault {
    fn drop(&mut self) {
        // Drain both maps into owned buffers and zeroize each: a HashMap key
        // cannot be mutated in place, so the originals are wiped by taking
        // ownership of them out of the map before they are freed.
        for (_, mut original) in self.by_placeholder.drain() {
            original.zeroize();
        }
        for (mut original, _) in self.by_value.drain() {
            original.zeroize();
        }
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
    fn interns_and_numbers_per_type() {
        let mut v = Vault::with_nonce("deadbeef".to_owned());
        let a = v.intern("EMAIL", "alice@x.com", true);
        let b = v.intern("EMAIL", "bob@y.com", true);
        assert_eq!(a, "[REDACTED_EMAIL_1_deadbeef]");
        assert_eq!(b, "[REDACTED_EMAIL_2_deadbeef]");
    }

    #[test]
    fn same_value_dedupes_to_same_sentinel() {
        let mut v = Vault::new();
        let a = v.intern("EMAIL", "alice@x.com", true);
        let a2 = v.intern("EMAIL", "alice@x.com", true);
        assert_eq!(a, a2);
    }

    #[test]
    fn distinct_types_number_independently() {
        let mut v = Vault::with_nonce("deadbeef".to_owned());
        assert_eq!(
            v.intern("EMAIL", "a@b.com", true),
            "[REDACTED_EMAIL_1_deadbeef]"
        );
        assert_eq!(
            v.intern("PHONE", "555-1234", true),
            "[REDACTED_PHONE_1_deadbeef]"
        );
    }

    #[test]
    fn original_for_round_trips_the_sentinel() {
        let mut v = Vault::new();
        let p = v.intern("EMAIL", "alice@x.com", true);
        assert_eq!(v.original_for(&p), Some("alice@x.com"));
        assert_eq!(v.original_for("[REDACTED_EMAIL_9_zzzz]"), None);
    }

    #[test]
    fn nonce_is_eight_hex_chars() {
        let v = Vault::new();
        assert_eq!(v.nonce().len(), NONCE_HEX_LEN);
        assert!(v.nonce().bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn distinct_vaults_get_distinct_nonces() {
        let a = Vault::new();
        let b = Vault::new();
        assert_ne!(a.nonce(), b.nonce());
    }

    #[test]
    fn empty_vault_reports_empty() {
        let v = Vault::new();
        assert!(v.is_empty());
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn drop_zeroizes_originals() {
        let mut v = Vault::new();
        let _ = v.intern("EMAIL", "secret@example.com", true);
        assert!(!v.is_empty());
        drop(v);
    }
}
