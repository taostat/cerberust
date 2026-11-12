//! Structured PII patterns use ASCII word boundaries: non-ASCII punctuation and
//! letters next to a value are boundaries, ASCII letters and digits are not.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::scanner::detect::detect_structured;

const VALUES: [(&str, &str); 6] = [
    ("CREDIT_CARD", "4111 1111 1111 1111"),
    ("PHONE", "415-555-0132"),
    ("EMAIL", "alice@example.com"),
    ("US_SSN", "536-22-1475"),
    ("IP_ADDRESS", "192.168.1.20"),
    ("IBAN", "GB82 WEST 1234 5698 7654 32"),
];

fn found(text: &str, ty: &str) -> Vec<String> {
    detect_structured(text)
        .into_iter()
        .filter(|span| span.ty == ty)
        .map(|span| text[span.start..span.end].to_owned())
        .collect()
}

#[test]
fn values_next_to_non_ascii_punctuation_keep_their_spans() {
    for (ty, value) in VALUES {
        let plain = found(&format!("see {value} now"), ty);
        assert_eq!(plain, [value], "{ty} control");
        for text in [
            format!("call\u{2014}{value}\u{2014}today"),
            format!("\u{201c}{value}\u{201d}"),
            format!("\u{1f4de}{value}\u{1f4de}"),
            format!("caf\u{e9} {value} \u{2192} na\u{ef}ve"),
        ] {
            assert_eq!(found(&text, ty), [value], "{ty} in {text:?}");
        }
    }
}

#[test]
fn non_ascii_letters_directly_next_to_digits_are_boundaries() {
    for (ty, value) in [
        ("CREDIT_CARD", "4111 1111 1111 1111"),
        ("US_SSN", "536-22-1475"),
        ("IP_ADDRESS", "192.168.1.20"),
    ] {
        for text in [format!("\u{e9}{value}"), format!("{value}\u{e9}")] {
            assert_eq!(found(&text, ty), [value], "{ty} in {text:?}");
        }
    }
}

#[test]
fn ascii_letters_and_digits_next_to_values_are_still_not_boundaries() {
    for (ty, value) in [
        ("CREDIT_CARD", "4111 1111 1111 1111"),
        ("US_SSN", "536-22-1475"),
        ("IP_ADDRESS", "192.168.1.20"),
    ] {
        for text in [format!("x{value}"), format!("{value}x")] {
            assert!(found(&text, ty).is_empty(), "{ty} in {text:?}");
        }
    }
    // A digit run continuing a card or SSN is part of a longer number.
    for (ty, value) in [
        ("CREDIT_CARD", "4111111111111111"),
        ("US_SSN", "536-22-1475"),
    ] {
        for text in [format!("7{value}"), format!("{value}7")] {
            assert!(
                !found(&text, ty).contains(&value.to_owned()),
                "{ty} in {text:?}"
            );
        }
    }
}
