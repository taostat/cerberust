//! The entropy backstop decides on the whole whitespace-delimited token, as
//! before, but a flagged `<identifier>=<value>` token keeps its name.

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
    for name in ["FOO=", "build-id=", "_X=", "SESSION_TOKEN_2="] {
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
fn colon_tokens_urls_and_fingerprints_are_not_redacted() {
    for text in [
        format!("https://{OPAQUE}"),
        format!("admin:{OPAQUE}@db"),
        format!("_X:{OPAQUE}"),
        "1024 SHA256:b3lzpq447byDomGBD+aw2XgY2AWDMYGrIVTk3tncYa8 no comment (RSA)".to_owned(),
        "2048 MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48 user@host (RSA)".to_owned(),
    ] {
        assert!(redacted(&text).is_empty(), "{text}: {:?}", redacted(&text));
    }
}
