//! The entropy backstop redacts only the value of an `<identifier>=<value>` or
//! `<identifier>:<value>` token and keeps the name.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::middleware::stream::StreamOutput;
use cerberust::scanner::detect::{detect_secrets, resolve_overlaps};
use cerberust::{Direction, Scanner, ScannerStack, SecretScanner};

const OPAQUE: &str = "Zx81mQ0pLr7vT2k8Vq2nLm5Rt9wXz3Ab";

fn redacted(text: &str) -> Vec<&str> {
    resolve_overlaps(detect_secrets(text))
        .into_iter()
        .map(|span| &text[span.start..span.end])
        .collect()
}

fn streamed(text: &str, chunk: usize) -> String {
    let scanner = SecretScanner::new().with_direction(Direction::Output);
    let mut stack = ScannerStack::new(vec![Box::new(scanner) as Box<dyn Scanner>], false);
    let mut runner = StreamOutput::new(&stack);
    let mut emitted = String::new();
    let mut start = 0;
    while start < text.len() {
        let end = (start + chunk).min(text.len());
        emitted.push_str(&runner.push(&mut stack, &text[start..end]).unwrap());
        start = end;
    }
    emitted.push_str(&runner.finish(&mut stack).unwrap());
    emitted
}

fn assert_name_kept(text: &str, name: &str, value: &str) {
    assert_eq!(redacted(text), [value], "{text}");
    for chunk in 1..=8 {
        let output = streamed(&format!("{text}\n"), chunk);
        assert!(output.starts_with(name), "chunk {chunk}: {output}");
        assert!(!output.contains(value), "chunk {chunk}: {output}");
    }
}

#[test]
fn credential_assignment_keeps_its_name() {
    let value = "k8Vq2nLm5Rt9wXz3";
    assert_name_kept(&format!("DB_PASSWORD={value}"), "DB_PASSWORD=", value);
}

#[test]
fn any_identifier_assignment_keeps_its_name() {
    for name in ["FOO=", "app.build-id=", "_X:", "SESSION_TOKEN_2="] {
        assert_name_kept(&format!("{name}{OPAQUE}"), name, OPAQUE);
    }
}

#[test]
fn tokens_without_an_identifier_name_are_redacted_whole() {
    for text in [
        OPAQUE.to_owned(),
        format!("{OPAQUE}=="),
        format!("9x={OPAQUE}"),
        format!("={OPAQUE}"),
        format!("x=={OPAQUE}"),
    ] {
        assert_eq!(redacted(&text), [text.as_str()], "{text}");
    }
}

#[test]
fn urls_and_userinfo_are_not_split_at_their_colon() {
    for text in [
        format!("https://{OPAQUE}"),
        format!("ftp://{OPAQUE}/x"),
        format!("admin:{OPAQUE}@db"),
    ] {
        let spans = redacted(&text);
        assert!(
            spans
                .iter()
                .all(|span| !span.starts_with("//") && !span.ends_with("@db")),
            "{text}: {spans:?}"
        );
        assert!(
            !spans.contains(&format!("//{OPAQUE}").as_str()),
            "{text}: {spans:?}"
        );
    }
}
