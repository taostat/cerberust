//! Field-labelled scans: a structured value scanned on its own, with its field
//! name supplied as the label it would have in running text.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::scanner::detect::{detect_field_secrets, detect_secrets};
use cerberust::scanners::RestoreScanner;
use cerberust::{
    BanSubstringsScanner, Direction, Disposition, RestorePolicy, ScanCtx, ScanError, ScanResult,
    Scanner, ScannerId, ScannerStack, SecretScanner,
};
use proptest::prelude::*;

fn input_stack() -> ScannerStack {
    let scanner = SecretScanner::new().with_policy(RestorePolicy::RoundTrip);
    let restore = RestoreScanner::for_types(
        ScannerId("test:secrets-restore"),
        ["BITTENSOR_PRIVATE_KEY", "SECRET"].map(str::to_owned),
    );
    ScannerStack::new(
        vec![
            Box::new(scanner) as Box<dyn Scanner>,
            Box::new(restore) as Box<dyn Scanner>,
        ],
        false,
    )
}

#[test]
fn private_key_field_redacts_bare_hex_that_an_unlabelled_scan_leaves() {
    let key = "b3".repeat(32);
    let mut stack = input_stack();
    assert_eq!(stack.run_input(&key).unwrap(), key);

    let mut stack = input_stack();
    let forwarded = stack.run_input_field("privateKey", &key).unwrap();
    assert!(!forwarded.contains(&key), "{forwarded}");
    assert_eq!(stack.run_output(&forwarded).unwrap(), key);
}

#[test]
fn credential_label_fields_redact_their_values() {
    for (field, value) in [
        ("password", "hunter2hunter2"),
        ("api_key", "Zx81mQ0pLr7vT2"),
        ("token", "c0ffee-tok-91x7"),
        (
            "secretPhrase",
            "abandon abandon abandon abandon abandon abandon",
        ),
    ] {
        let mut stack = input_stack();
        let forwarded = stack.run_input_field(field, value).unwrap();
        assert!(!forwarded.contains(value), "{field}: {forwarded}");
    }
}

#[test]
fn unlabelled_and_ordinary_fields_are_unchanged() {
    let sha = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    for (field, value) in [
        ("description", "hello world, this is a note"),
        ("commit", sha),
        ("", "hunter2hunter2"),
    ] {
        let mut stack = input_stack();
        assert_eq!(
            stack.run_input_field(field, value).unwrap(),
            value,
            "{field}"
        );
    }
}

#[test]
fn label_exemptions_still_apply_to_field_values() {
    for value in ["${DB_PASSWORD}", "{{ secrets.token }}", "placeholder"] {
        let mut stack = input_stack();
        assert_eq!(
            stack.run_input_field("password", value).unwrap(),
            value,
            "{value}"
        );
    }
}

#[test]
fn escaped_characters_map_back_to_the_whole_original_value() {
    let value = "pa\"ss\\wo\nrd-é-91x7Qz";
    let mut stack = input_stack();
    let forwarded = stack.run_input_field("password", value).unwrap();
    for fragment in ["pa", "ss", "wo", "rd-é-91x7Qz"] {
        assert!(!forwarded.contains(fragment), "{fragment} in {forwarded}");
    }
    assert_eq!(stack.run_output(&forwarded).unwrap(), value);
}

#[test]
fn field_spans_preserve_text_around_an_embedded_secret() {
    let secret = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
    for (prefix, suffix) in [
        ("", ""),
        ("safe ", " safe suffix"),
        ("é\"\\ ", " fin\"\\\r\n\té"),
        ("é\r\n ", " fin"),
        ("🙂\t ", " fin"),
        ("", " fin\"\\\né"),
        ("é\"\\ ", ""),
    ] {
        let value = format!("{prefix}{secret}{suffix}");
        assert_eq!(detect_secrets(&value), []);
        let spans = detect_field_secrets("sourcegraph", &value);
        assert!(!spans.is_empty(), "{value:?}");
        for span in spans {
            assert_eq!(span.start, prefix.len(), "{value:?}");
            assert_eq!(span.end, prefix.len() + secret.len(), "{value:?}");
        }

        for direction in [Direction::Input, Direction::Output] {
            let scanner = SecretScanner::new().with_direction(direction);
            let mut stack = ScannerStack::new(vec![Box::new(scanner)], false);
            let redacted = match direction {
                Direction::Input => stack.run_input_field("sourcegraph", &value),
                Direction::Output => stack.run_output_field("sourcegraph", &value),
            }
            .unwrap();
            assert_eq!(stack.ctx().vault.len(), 1);
            let (placeholder, original) = stack.ctx().vault.entries().next().unwrap();
            assert_eq!(original, secret, "{value:?}, {direction:?}");
            assert_eq!(
                redacted,
                format!("{prefix}{placeholder}{suffix}"),
                "{value:?}, {direction:?}"
            );
        }
    }
}

#[test]
fn field_is_set_for_one_run_only() {
    let key = "b3".repeat(32);
    let mut stack = input_stack();
    let _ = stack.run_input_field("privateKey", &key).unwrap();
    assert!(stack.ctx().field.is_none());
    assert_eq!(stack.run_input(&key).unwrap(), key);
}

#[test]
fn field_is_cleared_after_a_block_verdict() {
    let key = "b3".repeat(32);
    for direction in [Direction::Input, Direction::Output] {
        for fail_fast in [false, true] {
            let block = BanSubstringsScanner::new(["stop".to_owned()]).with_direction(direction);
            let secret = SecretScanner::new().with_direction(direction);
            let mut scanners: Vec<Box<dyn Scanner>> = vec![Box::new(block), Box::new(secret)];
            if direction == Direction::Output {
                scanners.reverse();
            }
            let mut stack = ScannerStack::new(scanners, fail_fast);
            let result = match direction {
                Direction::Input => stack.run_input_field("privateKey", "stop"),
                Direction::Output => stack.run_output_field("privateKey", "stop"),
            };
            assert_eq!(result.is_err(), fail_fast);
            assert!(stack.ctx().field.is_none(), "{direction:?}, {fail_fast}");
            let plain = match direction {
                Direction::Input => stack.run_input(&key),
                Direction::Output => stack.run_output(&key),
            };
            assert_eq!(plain.unwrap(), key);
        }
    }
}

struct FailingScanner(Direction);

impl Scanner for FailingScanner {
    fn id(&self) -> ScannerId {
        ScannerId("test:field-error")
    }

    fn direction(&self) -> Direction {
        self.0
    }

    fn disposition(&self) -> Disposition {
        Disposition::Block
    }

    fn scan<'a>(&self, _text: &'a str, _ctx: &mut ScanCtx) -> ScanResult<'a> {
        Err(ScanError::Detector {
            scanner: self.id(),
            reason: "test detector error".to_owned(),
        })
    }
}

#[test]
fn field_survives_a_detector_error_until_the_run_finishes() {
    let key = "b3".repeat(32);
    for direction in [Direction::Input, Direction::Output] {
        for fail_fast in [false, true] {
            let secret = SecretScanner::new().with_direction(direction);
            let mut scanners: Vec<Box<dyn Scanner>> =
                vec![Box::new(FailingScanner(direction)), Box::new(secret)];
            if direction == Direction::Output {
                scanners.reverse();
            }
            let mut stack = ScannerStack::new(scanners, fail_fast);
            let redacted = match direction {
                Direction::Input => stack.run_input_field("privateKey", &key),
                Direction::Output => stack.run_output_field("privateKey", &key),
            }
            .unwrap();
            assert_eq!(
                stack.ctx().vault.original_for(&redacted),
                Some(key.as_str())
            );
            assert!(stack.ctx().field.is_none());
            let plain = match direction {
                Direction::Input => stack.run_input(&key),
                Direction::Output => stack.run_output(&key),
            };
            assert_eq!(plain.unwrap(), key);
        }
    }
}

#[test]
fn output_field_scans_use_the_label() {
    let key = "b3".repeat(32);
    let scanner = SecretScanner::new().with_direction(Direction::Output);
    let mut stack = ScannerStack::new(vec![Box::new(scanner) as Box<dyn Scanner>], false);
    assert_eq!(stack.run_output(&key).unwrap(), key);
    let output = stack.run_output_field("privateKey", &key).unwrap();
    assert!(!output.contains(&key), "{output}");
    assert!(stack.ctx().field.is_none());
}

#[test]
fn field_names_with_quotes_are_escaped() {
    let key = "b3".repeat(32);
    let spans = detect_field_secrets("x\": \"y", &key);
    assert!(spans.iter().all(|span| span.end <= key.len()));
}

#[test]
fn unquoted_field_labels_preserve_whitespace() {
    let value = "hunter2hunter2";
    for field in ["\npassword", "password\n", "password\r\n"] {
        let prefix = format!("{field}: \"");
        let labelled = format!("{prefix}{value}\"");
        assert!(detect_secrets(&labelled)
            .iter()
            .any(|span| { span.start == prefix.len() && span.end == prefix.len() + value.len() }));

        for direction in [Direction::Input, Direction::Output] {
            let scanner = SecretScanner::new().with_direction(direction);
            let mut stack = ScannerStack::new(vec![Box::new(scanner)], false);
            let redacted = match direction {
                Direction::Input => stack.run_input_field(field, value),
                Direction::Output => stack.run_output_field(field, value),
            }
            .unwrap();
            assert_eq!(
                stack.ctx().vault.original_for(&redacted),
                Some(value),
                "{field:?}, {direction:?}: {redacted}"
            );
            assert!(stack.ctx().field.is_none());
        }
    }
}

proptest! {
    #[test]
    fn field_spans_stay_on_value_char_boundaries(
        field in prop::sample::select(vec!["password", "api_key", "token"]),
        text in "\\PC{0,48}",
    ) {
        let text = format!("pa\"ss\\wo\nrd-é-91x7Qz{text}");
        let spans = detect_field_secrets(field, &text);
        prop_assert!(spans.iter().any(|span| span.start == 0 && span.end == text.len()));
        for span in spans {
            prop_assert!(span.start < span.end && span.end <= text.len());
            prop_assert!(text.is_char_boundary(span.start));
            prop_assert!(text.is_char_boundary(span.end));
        }
    }

    #[test]
    fn field_scan_finds_everything_an_unlabelled_scan_finds(
        field in "[a-zA-Z_]{0,12}",
        text in prop_oneof![
            "\\PC{0,48}",
            Just("aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV".to_owned()),
            Just("AKIAIOSFODNN7EXAMPLE".to_owned()),
        ],
    ) {
        let labelled = detect_field_secrets(&field, &text);
        for span in detect_secrets(&text) {
            prop_assert!(labelled.contains(&span));
        }
    }
}
