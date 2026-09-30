//! Streaming no-leak tests for the vendor secret formats.
//!
//! Every token below is built at test time from a fixed alphabet, so no
//! credential-shaped literal is committed. Each is streamed inside prose at
//! chunk sizes 1..=8; the emitted output must contain no 12-byte fragment of the
//! secret at any point, and the final output must redact it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::middleware::stream::StreamOutput;
use cerberust::scanner::detect::detect_secrets;
use cerberust::{Direction, Scanner, ScannerStack, SecretScanner};

const HEX: &str = "7c0e9b4a1d2f3e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c";
const ALNUM: &str = "Q7wE2r9T4y1U8i3O6p0A5sDf3Gh8Jk1Lz4Xc7Vb2Nm6Qa9Ws5Ed0Rf3Tg7Yh1Uj4Ik8Ol2Pz6Xm";

fn take(alphabet: &str, n: usize) -> String {
    alphabet.chars().cycle().take(n).collect()
}

/// `(expected type, secret)` for each Taostats format and a sample of ported
/// gitleaks rules with distinct shapes (fixed prefix, prefix + separator,
/// keyword outside the token, JWT).
fn secrets() -> Vec<(&'static str, String)> {
    vec![
        ("GM_API_KEY", format!("gm_live_{HEX}")),
        ("BLOCKMACHINE_API_KEY", format!("bm_live_{HEX}")),
        ("TAOSTATS_API_KEY", format!("ts_live_{HEX}")),
        (
            "TAOSTATS_API_KEY",
            format!(
                "tao-{}-{}-{}-{}-{}:{}",
                &HEX[..8],
                &HEX[8..12],
                &HEX[12..16],
                &HEX[16..20],
                &HEX[20..32],
                &HEX[32..40]
            ),
        ),
        (
            "GITHUB_FINE_GRAINED_PAT",
            format!("github_pat_{}", take(ALNUM, 82)),
        ),
        ("GITLAB_PAT", format!("glpat-{}", take(ALNUM, 20))),
        (
            "NPM_ACCESS_TOKEN",
            format!("npm_{}", take(&ALNUM.to_lowercase(), 36)),
        ),
        (
            "SLACK_BOT_TOKEN",
            format!("xoxb-1234567890123-1234567890123-{}", take(ALNUM, 24)),
        ),
        (
            "ANTHROPIC_API_KEY",
            format!("sk-ant-api03-{}AA", take(ALNUM, 93)),
        ),
    ]
}

fn stack() -> ScannerStack {
    let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(
        SecretScanner::new().with_direction(Direction::Output),
    )];
    ScannerStack::new(scanners, true)
}

fn fragments(secret: &str) -> Vec<&str> {
    (0..=secret.len().saturating_sub(12))
        .map(|i| &secret[i..i + 12])
        .collect()
}

fn stream(response: &str, chunk_len: usize, secret: &str) -> String {
    let mut stack = stack();
    let mut runner = StreamOutput::new(&stack);
    let frags = fragments(secret);
    let mut emitted = String::new();
    let bytes = response.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + chunk_len).min(bytes.len());
        emitted.push_str(&runner.push(&mut stack, &response[i..end]).unwrap());
        for f in &frags {
            assert!(
                !emitted.contains(f),
                "leaked {f:?} (chunk_len {chunk_len}) in {emitted:?}"
            );
        }
        i = end;
    }
    emitted.push_str(&runner.finish(&mut stack).unwrap());
    emitted
}

#[test]
fn samples_are_detected_unary() {
    for (ty, secret) in secrets() {
        let text = format!("value {secret} end");
        assert!(
            detect_secrets(&text).iter().any(|s| s.ty == ty),
            "{ty} not detected unary"
        );
    }
}

#[test]
fn vendor_secrets_never_leak_at_any_chunk_size() {
    for (ty, secret) in secrets() {
        let response = format!("here is the key {secret} ok\n");
        for chunk_len in 1..=8 {
            let emitted = stream(&response, chunk_len, &secret);
            for f in fragments(&secret) {
                assert!(
                    !emitted.contains(f),
                    "{ty} leaked at chunk_len {chunk_len}: {emitted:?}"
                );
            }
            assert!(
                emitted.contains("[REDACTED_"),
                "{ty} not redacted at {chunk_len}"
            );
        }
    }
}
