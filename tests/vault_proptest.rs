//! Property test for the vault round-trip: for any sequence of (type, value)
//! interns, restoring the sentinel-replaced text reproduces the original — the
//! tokenize→detokenize identity the whole `RoundTrip` policy rests on.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::scanner::substitute::Substituter;
use cerberust::Vault;
use proptest::prelude::*;

proptest! {
    /// Intern a batch of values, splice their sentinels into a carrier string,
    /// then restore: the result must equal the carrier with originals inlined.
    #[test]
    fn tokenize_then_detokenize_is_identity(
        values in proptest::collection::vec("[a-zA-Z0-9@._+-]{1,40}", 1..12),
    ) {
        let mut vault = Vault::new();
        // Intern each value; build the redacted carrier "<s0> <s1> ...".
        let sentinels: Vec<String> =
            values.iter().map(|v| vault.intern("VAL", v, true)).collect();
        let redacted = sentinels.join(" ");

        // original_for round-trips each sentinel directly.
        for (sentinel, value) in sentinels.iter().zip(&values) {
            prop_assert_eq!(vault.original_for(sentinel), Some(value.as_str()));
        }

        // The Substituter restores the whole carrier back to the joined values.
        let pairs: Vec<(String, String)> = vault
            .entries()
            .map(|(s, o)| (s.to_owned(), o.to_owned()))
            .collect();
        let sub = Substituter::from_pairs(pairs.iter().map(|(s, o)| (s.as_str(), o.as_str())));
        let restored = sub.substitute(&redacted);

        // Dedupe-by-value means equal inputs share one sentinel; reconstruct the
        // expected restored carrier from the (deduped) sentinel→value mapping.
        let expected: Vec<&str> = sentinels
            .iter()
            .map(|s| vault.original_for(s).unwrap_or(""))
            .collect();
        prop_assert_eq!(restored, expected.join(" "));
    }

    /// Interning the same value twice always yields the same sentinel.
    #[test]
    fn same_value_is_stable(value in "[a-zA-Z0-9]{1,30}") {
        let mut vault = Vault::new();
        let a = vault.intern("VAL", &value, true);
        let b = vault.intern("VAL", &value, true);
        prop_assert_eq!(a, b);
        prop_assert_eq!(vault.len(), 1);
    }
}
