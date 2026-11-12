//! Credential labels with an identifier prefix (`db_password`, `DB_PASSWORD`,
//! `smtp.password`) and the passphrase/credentials/`*_key` label words, in
//! prose, `.env` lines and JSON keys.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::middleware::stream::StreamOutput;
use cerberust::scanner::detect::{detect_secrets, resolve_overlaps};
use cerberust::{Direction, Scanner, ScannerStack, SecretScanner};

const VALUE: &str = "Tr0ub4dor-x7Zq";

fn secret_values(text: &str) -> Vec<&str> {
    resolve_overlaps(detect_secrets(text))
        .into_iter()
        .map(|span| &text[span.start..span.end])
        .collect()
}

#[test]
fn prefixed_labels_redact_their_values() {
    for text in [
        format!("db_password: '{VALUE}'"),
        format!("db_password = '{VALUE}'"),
        format!("DB_PASSWORD={VALUE}"),
        format!("export DB_PASSWORD=\"{VALUE}\""),
        format!("smtp.password = '{VALUE}'"),
        format!("admin-pwd: {VALUE}"),
        format!("stripe_api_key={VALUE}"),
        format!("my_apikey={VALUE}"),
        format!("SMTP_AUTH_TOKEN = {VALUE}"),
        format!("client_secret: \"{VALUE}\""),
    ] {
        assert_eq!(secret_values(&text), [VALUE], "{text}");
    }
}

#[test]
fn new_label_words_redact_their_values() {
    for label in [
        "passphrase",
        "credential",
        "credentials",
        "private_key",
        "privateKey",
        "secret_key",
        "secret-key",
        "signing_key",
        "encryption_key",
        "auth_token",
    ] {
        for text in [
            format!("{label}: '{VALUE}'"),
            format!("{label}={VALUE}"),
            format!("{{\"{label}\": \"{VALUE}\"}}"),
        ] {
            if label == "privateKey" && !text.starts_with('{') {
                continue;
            }
            assert_eq!(secret_values(&text), [VALUE], "{text}");
        }
    }
    for text in [
        format!("APP_PASSPHRASE={VALUE}"),
        format!("{{\"jwt_signing_key\": \"{VALUE}\"}}"),
    ] {
        assert_eq!(secret_values(&text), [VALUE], "{text}");
    }
}

#[test]
fn ordinary_key_names_and_non_credential_values_are_unchanged() {
    for text in [
        "primary_key = user_42",
        "cache_key: orders-2024-11",
        "sort_key=created_at",
        "partition_key = tenant_7",
        "idempotency_key: order-5521",
        "public_key: ssh-ed25519",
        "token_type=bearer",
        "next_token: abc123def",
        "page_token = cursor_9921",
        "NEXT_PAGE_TOKEN=offset_100",
        "db_password: Optional[str] = None",
        "password_hash = argon2id",
        "db_password_file=passwords.txt",
        "DB_PASSWORD=${DB_PASSWORD}",
        "url=${DB_PASSWORD:-changeme}",
        "GOOGLE_APPLICATION_CREDENTIALS=/etc/gcp/service-account.json",
        "private_key: ./certs/server.pem",
        "SSL_PRIVATE_KEY=C:\\certs\\server.key",
        "private_key = \"<your-private-key>\"",
        "SIGNING_KEY=YOUR_SIGNING_KEY",
        r#"{"primary_key": "user_42abc"}"#,
        r#"{"public_key": "ssh-ed25519"}"#,
        r#"{"token_type": "bearer"}"#,
        r#"{"credentials": "/etc/gcp/service-account.json"}"#,
    ] {
        assert!(
            secret_values(text).is_empty(),
            "{text}: {:?}",
            secret_values(text)
        );
    }
}

#[test]
fn streamed_prefixed_labels_never_flush_part_of_the_value() {
    let response = format!("Set these:\nDB_HOST=db\nDB_PASSWORD={VALUE}\nDB_PORT=5432\n");
    for chunk in 1..=8 {
        let scanner = SecretScanner::new().with_direction(Direction::Output);
        let mut stack = ScannerStack::new(vec![Box::new(scanner) as Box<dyn Scanner>], false);
        let mut runner = StreamOutput::new(&stack);
        let mut emitted = String::new();
        let mut start = 0;
        while start < response.len() {
            let end = (start + chunk).min(response.len());
            emitted.push_str(&runner.push(&mut stack, &response[start..end]).unwrap());
            for fragment in VALUE.as_bytes().windows(6) {
                let fragment = std::str::from_utf8(fragment).unwrap();
                assert!(!emitted.contains(fragment), "chunk {chunk}: {emitted}");
            }
            start = end;
        }
        emitted.push_str(&runner.finish(&mut stack).unwrap());
        assert!(!emitted.contains(VALUE), "chunk {chunk}: {emitted}");
        assert!(emitted.contains("DB_PASSWORD="), "chunk {chunk}: {emitted}");
        assert!(
            emitted.ends_with("\nDB_PORT=5432\n"),
            "chunk {chunk}: {emitted}"
        );
    }
}
