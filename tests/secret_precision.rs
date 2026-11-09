//! Precision check for secret detection in ordinary developer prompts.
//!
//! `tests/fixtures/secret-negative-corpus/` holds ordinary prompt content with
//! no real credentials (see its README). `SecretScanner` redacts one-way, so a
//! false positive permanently damages a prompt. This check includes the generic
//! `SECRET` findings as well as the ported rules and seed-phrase detector. The
//! original, format-specific vendor patterns remain outside this check.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::scanner::detect::detect_secrets;
use cerberust::{ScanCtx, Scanner, SecretScanner};
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Original format-specific entity types that predate the gitleaks port.
const PRE_EXISTING: &[&str] = &[
    "AWS_ACCESS_KEY",
    "GITHUB_TOKEN",
    "STRIPE_KEY",
    "OPENAI_KEY",
    "GOOGLE_API_KEY",
    "SLACK_WEBHOOK",
    "PRIVATE_KEY",
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

fn assert_redacted(text: &str, secret: &str, entity: &str) {
    let mut ctx = ScanCtx::new();
    let verdict = SecretScanner::new().scan(text, &mut ctx).unwrap();
    assert!(
        verdict.text.contains(&format!("[REDACTED_{entity}_")),
        "{entity} was not redacted: {text:?}"
    );
    assert!(
        !verdict.text.contains(secret),
        "{entity} leaked in redacted output: {:?}",
        verdict.text
    );
}

#[test]
fn provider_keys_and_secret_formats_still_redact() {
    // Synthetic values exercise the existing vendored provider rules.
    let github_body: String = "Q7wE2r9T4y1U8i3O6p0A5sD".chars().cycle().take(82).collect();
    let github = format!("github_pat_{github_body}");
    assert_redacted(
        &format!("token {github}"),
        &github,
        "GITHUB_FINE_GRAINED_PAT",
    );

    let anthropic_body: String = "Q7wE2r9T4y1U8i3O6p0A5sD".chars().cycle().take(93).collect();
    let anthropic = format!("sk-ant-api03-{anthropic_body}AA");
    assert_redacted(
        &format!("token {anthropic}"),
        &anthropic,
        "ANTHROPIC_API_KEY",
    );

    let mut rng = StdRng::seed_from_u64(0x5ec7_2026);
    let mixed_token = Alphanumeric.sample_string(&mut rng, 48);
    let text = format!("api_key={mixed_token}");
    assert_redacted(&text, &mixed_token, "SECRET");
    assert_redacted(
        &format!("opaque candidate {mixed_token}"),
        &mixed_token,
        "SECRET",
    );

    let pem = std::fs::read_to_string(
        "tests/fixtures/secret-positive-corpus/test-only-rsa-private-key.pem",
    )
    .unwrap();
    assert_redacted(&pem, &pem, "PRIVATE_KEY");

    // A test-only JWT with realistic structure and a generated signature.
    let jwt_signature = Alphanumeric.sample_string(&mut rng, 43);
    let jwt = format!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.{jwt_signature}"
    );
    assert_redacted(&format!("Authorization: Bearer {jwt}"), &jwt, "JWT");

    let mnemonic = std::iter::repeat_n("abandon", 11)
        .chain(["about"])
        .collect::<Vec<_>>()
        .join(" ");
    assert_redacted(
        &format!("wallet seed: {mnemonic}"),
        &mnemonic,
        "SEED_PHRASE",
    );
}

#[test]
fn literal_assignments_are_not_exempted_by_punctuation_or_placeholder_fragments() {
    let values = [
        "p@ss$word9",
        "value(with)punctuation",
        "value[with]brackets",
        "unusual,",
        "example_9x7k2m",
        "sample_private9",
        "replace_me9x7",
        "insert_9x7key",
        "your-9x7key",
        "private9_token",
        "private9_password",
        "private9_secret",
        "private9_api_key",
        "client.secret",
        "Optional[str]",
        "self.tokenizer(text)",
        "secret}}",
        "<private9>",
        "%private9%",
    ];
    let mut missed = Vec::new();
    for value in values {
        let text = format!("password = \"{value}\"");
        let spans = detect_secrets(&text);
        let start = text.find(value).unwrap();
        if !spans
            .iter()
            .any(|s| s.start <= start && s.end >= start + value.len())
        {
            missed.push(text);
        }
    }
    assert!(missed.is_empty(), "literal secrets missed: {missed:#?}");
}

#[test]
fn unquoted_literals_keep_punctuation_and_do_not_use_broad_placeholder_exemptions() {
    for value in [
        "p@ss$word9",
        "abc(def)123",
        "abc[def]123",
        "example_9x7k2m",
        "private9_token",
    ] {
        assert_redacted(&format!("password={value}"), value, "SECRET");
    }
    assert_redacted("password=hunter2,", "hunter2", "SECRET");
}

#[test]
fn typed_assignments_redact_the_literal_value() {
    for annotation in [
        "str",
        "String",
        "Optional[str]",
        "Optional[ str ]",
        "str | None",
        "Option<String>",
    ] {
        let text = format!("password: {annotation} = 'hunter2'");
        assert_redacted(&text, "hunter2", "SECRET");
        let start = text.find("hunter2").unwrap();
        assert!(detect_secrets(&text)
            .iter()
            .any(|s| s.start == start && s.end == start + 7));
    }
}

#[test]
fn environment_defaults_redact_literals_but_preserve_lookup_names() {
    for call in ["os.getenv", "os.environ.get"] {
        for args in [
            "'X', 'hunter2'",
            "'X', default='hunter2'",
            "'X', 'sk-live-9x7k2m'",
        ] {
            let text = format!("password = {call}({args})");
            let value = if args.contains("sk-live") {
                "sk-live-9x7k2m"
            } else {
                "hunter2"
            };
            assert_redacted(&text, value, "SECRET");
            let start = text.find(value).unwrap();
            assert!(detect_secrets(&text)
                .iter()
                .any(|s| s.start == start && s.end == start + value.len()));
        }
    }
}

#[test]
fn public_address_wrappers_do_not_exempt_opaque_secrets() {
    let address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    for secret in [
        format!("_{address}_"),
        format!("+{address}="),
        format!("-{address}-"),
    ] {
        assert_redacted(&format!("opaque {secret}"), &secret, "SECRET");
    }
}

#[test]
fn unicode_assignment_values_keep_valid_span_boundaries() {
    for value in ["pässwörd$9", "密碼(秘密)123", "é_private9_token"] {
        assert_redacted(&format!("🦀 password = '{value}'"), value, "SECRET");
    }
}

#[test]
fn public_identifier_exemptions_do_not_override_labelled_credentials() {
    for value in [
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        "14YomMWKx4jzD34ESv7HzpNhU6wojtLFGW",
        "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC",
    ] {
        assert_redacted(&format!("password = '{value}'"), value, "SECRET");
    }
}

#[test]
fn padded_literal_is_not_misread_as_a_type_annotation() {
    for value in ["aBcDeF9x7k2m==", "Optional9x7k2m=", "string9x7k2m="] {
        assert_redacted(&format!("password:{value}"), value, "SECRET");
    }
}
