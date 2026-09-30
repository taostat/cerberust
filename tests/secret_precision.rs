//! Precision check for the secret detectors added with the gitleaks port.
//!
//! `tests/fixtures/secret-negative-corpus/` holds ordinary prompt content with
//! no real credentials (see its README). `SecretScanner` redacts one-way, so a
//! false positive permanently damages a prompt: the ported vendor rules, the
//! Taostats key patterns and the seed-phrase detector must find nothing here.
//! The pre-existing detectors (the original vendor patterns, labelled secrets
//! and the entropy backstop) are out of scope for this check.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::scanner::detect::detect_secrets;

/// Entity types the detector emitted before the gitleaks port.
const PRE_EXISTING: &[&str] = &[
    "AWS_ACCESS_KEY",
    "GITHUB_TOKEN",
    "STRIPE_KEY",
    "OPENAI_KEY",
    "GOOGLE_API_KEY",
    "SLACK_WEBHOOK",
    "PRIVATE_KEY",
    "SECRET",
];

fn corpus() -> Vec<(String, String)> {
    let dir = std::path::Path::new("tests/fixtures/secret-negative-corpus");
    let mut files: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().is_some_and(|n| n != "README.md"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn corpus_is_present() {
    assert!(corpus().len() >= 10);
}

#[test]
fn new_detectors_find_nothing_in_ordinary_prompts() {
    let mut hits = Vec::new();
    for (name, text) in corpus() {
        for span in detect_secrets(&text) {
            if !PRE_EXISTING.contains(&span.ty.as_str()) {
                hits.push(format!(
                    "{name}: {} {:?}",
                    span.ty,
                    &text[span.start..span.end]
                ));
            }
        }
    }
    assert!(hits.is_empty(), "false positives: {hits:#?}");
}
