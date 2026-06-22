//! The request-scoped vault: a placeholder↔original map with a per-type
//! counter and a per-value sentinel suffix, zeroized on drop.
//!
//! The vault holds the one piece of request state that must never leave the
//! host — the map from each `[REDACTED_<TYPE>_<N>_<suffix>]` sentinel back
//! to the original plaintext. Any scanner may intern into it (PII, secrets);
//! restore reads it on the output path. It is a *stack capability* threaded on
//! [`ScanCtx`](crate::ScanCtx), not the private field of one scanner.
//!
//! The sentinel suffix namespaces a request's sentinels so a caller cannot
//! pre-image one (embed a guessed sentinel in their own prompt and have the
//! restore pass splice a *different* request's original into the response).
//! Two strategies mint that suffix, selected by [`NonceStrategy`]:
//!
//! - [`NonceStrategy::Random`] (default): one random nonce per request, shared
//!   by every sentinel it emits. Unguessable, but the same value redacts to a
//!   different sentinel on each request.
//! - [`NonceStrategy::Deterministic`]: the suffix is `HMAC(key, value)[:n]`, a
//!   pure function of `(key, value)` — the same value under the same key always
//!   yields the same suffix. A replayed conversation prefix therefore redacts
//!   byte-identically turn after turn (it interns the same values in the same
//!   order, so the per-type counter matches too), preserving upstream prompt
//!   caching, while the sentinel stays unguessable. It is a *keyed* HMAC, never
//!   a bare hash: low-entropy PII (emails, phones, SSNs) would otherwise be
//!   brute-forceable out of its placeholder. The counter prefix is retained:
//!   it keeps the `[REDACTED_<TYPE>_<counter>_<suffix>]` shape the restore
//!   parser expects and disambiguates the rare truncated-HMAC collision between
//!   two distinct values of one type.

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Hex characters a sentinel suffix carries. Kept in a JSON-escape-free
/// alphabet (hex digits) so a sentinel is byte-identical inside a JSON string
/// and a raw byte scan needs no JSON parse.
const SUFFIX_HEX_LEN: usize = 8;

/// How the vault mints the per-value suffix baked into every sentinel. The
/// caller selects this; [`NonceStrategy::Random`] is the default and the only
/// behaviour unless deterministic mode is opted in.
pub enum NonceStrategy {
    /// One random nonce per request, shared by every sentinel. The same value
    /// redacts to a different sentinel on each request.
    Random,
    /// `HMAC(key, value)[:n]` per value: the same value under the same key
    /// always yields the same suffix (cache-stable across requests). `key` is
    /// caller-owned secret bytes; cerberust is agnostic to its scope and where
    /// it comes from. The key is zeroized on drop.
    ///
    /// The key MUST be a non-empty high-entropy secret: an empty or guessable
    /// key collapses the HMAC to an effectively unkeyed hash, which is
    /// brute-forceable for low-entropy PII. cerberust does not police this —
    /// supplying the key well is the caller's responsibility.
    Deterministic { key: Zeroizing<Vec<u8>> },
}

impl NonceStrategy {
    /// Deterministic mode keyed by caller-owned secret `key`. See
    /// [`NonceStrategy::Deterministic`] for the non-empty-key requirement.
    #[must_use]
    pub fn deterministic(key: &[u8]) -> Self {
        Self::Deterministic {
            key: Zeroizing::new(key.to_vec()),
        }
    }
}

/// The vault's resolved per-request suffix source — a [`NonceStrategy`] with its
/// random nonce already minted, so there is no "Random-but-no-nonce" state.
enum Suffix {
    /// One nonce reused by every sentinel this request.
    Fixed(String),
    /// `HMAC(key, value)` per value; the key is zeroized on drop.
    Keyed(Zeroizing<Vec<u8>>),
}

impl Suffix {
    /// The `SUFFIX_HEX_LEN`-hex suffix for `value`. Fixed reuses the per-request
    /// nonce; Keyed derives `HMAC(key, value)[:n]` so the same value under the
    /// same key is byte-identical across vaults.
    fn for_value(&self, value: &str) -> String {
        match self {
            Suffix::Fixed(nonce) => nonce.clone(),
            Suffix::Keyed(key) => keyed_suffix(key, value),
        }
    }
}

/// Maps a redaction sentinel to the original plaintext it stands in for, and
/// allocates a stable per-type counter so two distinct values of the same type
/// stay distinct (`[REDACTED_EMAIL_1_<suffix>]` vs `[REDACTED_EMAIL_2_<suffix>]`).
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
    /// Next counter to allocate per entity type. Because a new distinct value
    /// bumps its type's counter and a deduped value does not, the final counter
    /// per type is exactly the number of distinct values interned under it — the
    /// content-free `by_entity_type` redaction tally.
    counters: HashMap<String, u32>,
    /// Per-entity-type tally of restores performed against this vault, recorded
    /// by the restore pass via [`Vault::note_restored`]. Counts only — never the
    /// restored values — so it is safe to surface in a report.
    restored: HashMap<String, u32>,
    /// How each sentinel's suffix is derived (random nonce already minted).
    suffix: Suffix,
}

impl Vault {
    /// Build a vault with a freshly-minted per-request random nonce, derived
    /// from the thread RNG so two concurrent requests never share a sentinel
    /// namespace.
    #[must_use]
    pub fn new() -> Self {
        Self::with_nonce(random_nonce())
    }

    /// Build a deterministic vault keyed by caller-owned secret `key`: every
    /// sentinel suffix is `HMAC(key, value)[:n]`, so the same value under the
    /// same key redacts byte-identically across independent vaults. The key is
    /// copied into the vault and zeroized on drop.
    #[must_use]
    pub fn deterministic(key: &[u8]) -> Self {
        Self::with_strategy(NonceStrategy::deterministic(key))
    }

    /// Build a vault under an explicit [`NonceStrategy`] — the general entry
    /// point behind [`Self::new`] (Random) and [`Self::deterministic`].
    #[must_use]
    pub fn with_strategy(strategy: NonceStrategy) -> Self {
        let suffix = match strategy {
            NonceStrategy::Random => Suffix::Fixed(random_nonce()),
            NonceStrategy::Deterministic { key } => Suffix::Keyed(key),
        };
        Self::with_suffix(suffix)
    }

    /// Build a vault with an explicit nonce. Test-only escape hatch so a test
    /// can assert against a fixed sentinel; production always mints a random
    /// one via [`Self::new`].
    #[must_use]
    pub fn with_nonce(nonce: String) -> Self {
        Self::with_suffix(Suffix::Fixed(nonce))
    }

    fn with_suffix(suffix: Suffix) -> Self {
        Self {
            by_placeholder: HashMap::new(),
            by_value: HashMap::new(),
            restorable: std::collections::HashSet::new(),
            counters: HashMap::new(),
            restored: HashMap::new(),
            suffix,
        }
    }

    /// The request's random nonce, or `None` in deterministic mode (where the
    /// suffix is per-value, not per-request). For audit and tests only.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        match &self.suffix {
            Suffix::Fixed(nonce) => Some(nonce),
            Suffix::Keyed(_) => None,
        }
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
        let suffix = self.suffix.for_value(original);
        let counter = self.counters.entry(ty.to_owned()).or_insert(0);
        *counter += 1;
        let placeholder = format!("[REDACTED_{ty}_{counter}_{suffix}]");
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

    /// Iterate `(entity_type, count)` for every type interned so far, where the
    /// count is the number of distinct values redacted under that type. The keys
    /// are entity **type** labels (`EMAIL`, `AWS_ACCESS_KEY`…), never values — so
    /// a metrics consumer can diff this snapshot across a scanner run to attribute
    /// redactions per type without ever touching plaintext.
    pub fn interned_counts(&self) -> impl Iterator<Item = (&str, u32)> {
        self.counters.iter().map(|(ty, n)| (ty.as_str(), *n))
    }

    /// Record that `n` sentinels of entity type `ty` were restored against this
    /// vault. The restore pass calls this so a metrics consumer can read the
    /// restored tally; it stores counts and the type label only.
    pub fn note_restored(&mut self, ty: &str, n: u32) {
        if n == 0 {
            return;
        }
        *self.restored.entry(ty.to_owned()).or_insert(0) += n;
    }

    /// Iterate `(entity_type, count)` of restores recorded via
    /// [`Vault::note_restored`]. Type labels and counts only.
    pub fn restored_counts(&self) -> impl Iterator<Item = (&str, u32)> {
        self.restored.iter().map(|(ty, n)| (ty.as_str(), *n))
    }
}

impl Default for Vault {
    /// Mints a fresh random nonce, same as [`Self::new`] — there is no
    /// suffix-less vault, so `default()` is never a footgun.
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Vault {
    /// Reports only counts and mode — never the originals, nonce, or key, which
    /// are the host-side secret this type exists to hold.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match self.suffix {
            Suffix::Fixed(_) => "Random",
            Suffix::Keyed(_) => "Deterministic",
        };
        f.debug_struct("Vault")
            .field("entries", &self.by_placeholder.len())
            .field("mode", &mode)
            .finish_non_exhaustive()
    }
}

/// `HMAC-SHA256(key, value)` truncated to `SUFFIX_HEX_LEN` hex chars.
fn keyed_suffix(key: &[u8], value: &str) -> String {
    // `new_from_slice` never errors for HMAC — any key length is valid — so the
    // `let...else` arm is unreachable.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        unreachable!("HMAC accepts any key length")
    };
    mac.update(value.as_bytes());
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..SUFFIX_HEX_LEN / 2])
}

/// An 8-hex-char random nonce from the thread RNG.
fn random_nonce() -> String {
    let bytes: [u8; SUFFIX_HEX_LEN / 2] = rand::thread_rng().gen();
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
        let nonce = v.nonce().unwrap();
        assert_eq!(nonce.len(), SUFFIX_HEX_LEN);
        assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()));
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

    /// The suffix slug of a `[REDACTED_<TYPE>_<counter>_<suffix>]` sentinel.
    fn suffix_of(sentinel: &str) -> &str {
        sentinel
            .strip_suffix(']')
            .and_then(|s| s.rsplit_once('_'))
            .map_or("", |(_, suffix)| suffix)
    }

    #[test]
    fn deterministic_same_key_same_sentinel_in_replay_order() {
        // A replayed prefix interns the same values in the same order, so the
        // counter matches too and the full sentinel is byte-identical.
        let key = b"conversation-key";
        let mut a = Vault::deterministic(key);
        let mut b = Vault::deterministic(key);
        let sa = a.intern("EMAIL", "alice@x.com", true);
        let sb = b.intern("EMAIL", "alice@x.com", true);
        assert_eq!(sa, sb, "same value + same key + same order must match");
    }

    #[test]
    fn deterministic_suffix_is_value_keyed_independent_of_order() {
        // The suffix is `HMAC(key, value)` — a pure function of the value — so
        // it is identical even when the counter differs across interning orders.
        let key = b"conversation-key";
        let mut a = Vault::deterministic(key);
        let mut b = Vault::deterministic(key);
        a.intern("EMAIL", "bob@y.com", true); // shift `a`'s counter
        let sa = a.intern("EMAIL", "alice@x.com", true);
        let sb = b.intern("EMAIL", "alice@x.com", true);
        assert_eq!(suffix_of(&sa), suffix_of(&sb));
    }

    #[test]
    fn deterministic_different_keys_different_sentinels() {
        let mut a = Vault::deterministic(b"key-one");
        let mut b = Vault::deterministic(b"key-two");
        let sa = a.intern("EMAIL", "alice@x.com", true);
        let sb = b.intern("EMAIL", "alice@x.com", true);
        assert_ne!(sa, sb, "different keys must diverge for the same value");
    }

    #[test]
    fn deterministic_suffix_is_eight_hex_chars() {
        let mut v = Vault::deterministic(b"k");
        let s = v.intern("EMAIL", "alice@x.com", true);
        let suffix = s
            .strip_prefix("[REDACTED_EMAIL_1_")
            .and_then(|s| s.strip_suffix(']'))
            .unwrap();
        assert_eq!(suffix.len(), SUFFIX_HEX_LEN);
        assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn deterministic_nonce_accessor_is_none() {
        let v = Vault::deterministic(b"k");
        assert_eq!(v.nonce(), None);
    }

    #[test]
    fn deterministic_round_trips_the_sentinel() {
        let mut v = Vault::deterministic(b"conversation-key");
        let p = v.intern("EMAIL", "alice@x.com", true);
        assert_eq!(v.original_for(&p), Some("alice@x.com"));
        assert!(v.is_restorable(&p));
    }

    #[test]
    fn deterministic_distinct_values_distinct_suffixes() {
        let mut v = Vault::deterministic(b"k");
        let a = v.intern("EMAIL", "alice@x.com", true);
        let b = v.intern("EMAIL", "bob@y.com", true);
        assert_ne!(a, b);
    }

    #[test]
    fn interned_counts_track_distinct_values_per_type() {
        let mut v = Vault::with_nonce("deadbeef".to_owned());
        v.intern("EMAIL", "a@b.com", true);
        v.intern("EMAIL", "c@d.com", true);
        v.intern("EMAIL", "a@b.com", true); // dedupe: no new count
        v.intern("PHONE", "555-1234", true);
        let counts: std::collections::BTreeMap<_, _> = v
            .interned_counts()
            .map(|(ty, n)| (ty.to_owned(), n))
            .collect();
        assert_eq!(counts.get("EMAIL"), Some(&2));
        assert_eq!(counts.get("PHONE"), Some(&1));
    }

    #[test]
    fn restored_counts_accumulate_per_type() {
        let mut v = Vault::new();
        v.note_restored("EMAIL", 2);
        v.note_restored("EMAIL", 1);
        v.note_restored("PHONE", 0); // a zero is a no-op
        let counts: std::collections::BTreeMap<_, _> = v
            .restored_counts()
            .map(|(ty, n)| (ty.to_owned(), n))
            .collect();
        assert_eq!(counts.get("EMAIL"), Some(&3));
        assert_eq!(counts.get("PHONE"), None);
    }

    #[test]
    fn deterministic_dedupes_same_value() {
        let mut v = Vault::deterministic(b"k");
        let a = v.intern("EMAIL", "alice@x.com", true);
        let a2 = v.intern("EMAIL", "alice@x.com", true);
        assert_eq!(a, a2);
        assert_eq!(v.len(), 1);
    }
}
