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
            format!("{label}: Optional[str] = '{VALUE}'"),
            format!("{{\"{label}\": \"{VALUE}\"}}"),
        ] {
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
fn prefixed_chains_preserve_labels_and_redact_only_the_final_value() {
    for text in [
        format!("db_password: str = smtp_password = '{VALUE}'"),
        format!("db_password: str = smtp_password={VALUE}"),
        format!("db_password = smtp_password = '{VALUE}'"),
        format!("app_passphrase: str = app_credential = auth_token = '{VALUE}'"),
    ] {
        assert_eq!(secret_values(&text), [VALUE], "{text}");
        assert_streamed_values(&text, &[VALUE]);
    }
    let text = "db_password: str = smtp_password = None";
    assert!(secret_values(text).is_empty(), "{text}");
    assert_streamed_values(text, &[]);
}

#[test]
fn compact_prefixed_chains_preserve_assignment_heads() {
    for assignment in [
        format!("smtp_password='{VALUE}'"),
        format!("smtp_password=\"{VALUE}\""),
        format!("smtp_password= {VALUE}"),
        format!("smtp_password= auth_token='{VALUE}'"),
        format!("app_passphrase='{VALUE}'"),
    ] {
        let text = format!("db_password = {assignment}\nfinished!\n");
        assert_eq!(secret_values(&text), [VALUE], "{text}");
        assert_streamed_values(&text, &[VALUE]);
    }
    let value = format!("smtp_password={VALUE}");
    let text = format!("db_password = {value}\nfinished!\n");
    assert_eq!(secret_values(&text), [value.as_str()]);
    assert_streamed_values(&text, &[&value]);
}

#[test]
fn deeply_prefixed_chains_preserve_value_spans() {
    let text = format!(
        "app_password: str = {}'{VALUE}'",
        "db_password=".repeat(16_384)
    );
    assert_eq!(secret_values(&text), [VALUE]);
}

#[test]
fn path_exemptions_use_the_credential_label_suffix() {
    for label in [
        "credential_password",
        "credentials_token",
        "credential_secret",
    ] {
        for text in [
            format!("{label}: '/private9'"),
            format!(r#"{{"{label}":"/private9"}}"#),
        ] {
            assert_eq!(secret_values(&text), ["/private9"], "{text}");
        }
    }
}

#[test]
fn relative_credential_file_paths_are_preserved() {
    for label in [
        "private_key",
        "APP_CREDENTIALS",
        "credential",
        "SIGNING_KEY",
    ] {
        for path in [
            "certs/server.pem",
            "config/google-credentials.json",
            r"keys\signing.key",
        ] {
            for text in [
                format!("{label}={path}\nfinished!\n"),
                format!("{label} = '{path}'\nfinished!\n"),
                format!(r#"{{"{label}":"{}"}}"#, path.replace('\\', r"\\")),
            ] {
                assert!(secret_values(&text).is_empty(), "{text}");
                assert_streamed_values(&text, &[]);
            }
        }
    }
    for value in ["some/base64/12345", "a.b/cD1234==", "Abc.de9"] {
        let text = format!("private_key = '{value}'\nfinished!\n");
        assert_eq!(secret_values(&text), [value], "{text}");
        assert_streamed_values(&text, &[value]);
    }
    let text = "db_password = 'certs/server.pem'";
    assert_eq!(secret_values(text), ["certs/server.pem"]);
}

#[test]
fn placeholders_keep_their_complete_values_in_prose_and_json() {
    for text in [
        "private_key: <private key>",
        "passphrase = <enter phrase>",
        r#"{"passphrase":"YOUR_VALUE"}"#,
        r#"{"credentials":"0xYOUR_VALUE"}"#,
    ] {
        assert!(secret_values(text).is_empty(), "{text}");
        assert_streamed_values(text, &[]);
    }
    for value in ["<private key>9", "YOUR_VALUE9", "0xYOUR_VALUE9"] {
        let text = format!("passphrase = '{value}'");
        assert_eq!(secret_values(&text), [value], "{text}");
    }
}

#[test]
fn placeholder_arguments_preserve_call_delimiters() {
    for value in ["YOUR_PASSPHRASE", "0xYOUR_VALUE", "<private key>"] {
        for closing in [")", "))"] {
            let text = format!("connect(passphrase={value}{closing}");
            assert!(secret_values(&text).is_empty(), "{text}");
            assert_streamed_values(&text, &[]);
        }
        let text = format!("connect(passphrase={value},timeout=30)");
        assert!(secret_values(&text).is_empty(), "{text}");
        assert_streamed_values(&text, &[]);
        let text = format!("connect(passphrase={value},password='hunter2')");
        assert_eq!(secret_values(&text), ["hunter2"], "{text}");
        assert_streamed_values(&text, &["hunter2"]);
        for literal in [format!("{value})"), format!("{value})9")] {
            let text = format!("connect(passphrase='{literal}')");
            assert_eq!(secret_values(&text), [literal.as_str()], "{text}");
            assert_streamed_values(&text, &[&literal]);
        }
    }
}

#[test]
fn fetch_credentials_modes_are_not_secrets() {
    for mode in ["include", "omit", "same-origin"] {
        for text in [
            format!("fetch(url, {{credentials: '{mode}'}})"),
            format!("options.credentials = '{mode}'"),
            format!(r#"{{"credentials":"{mode}"}}"#),
        ] {
            assert!(secret_values(&text).is_empty(), "{text}");
            assert_streamed_values(&text, &[]);
        }
    }
    for text in [
        "password = 'include'",
        "credentials = 'include9'",
        r#"{"credentials":"same-origin9"}"#,
    ] {
        assert_eq!(secret_values(text).len(), 1, "{text}");
    }
}

#[test]
fn credential_objects_preserve_properties_and_scan_nested_values() {
    for label in ["credentials", "app_credentials", "credential"] {
        for object in [
            "{username: 'alice', password: 'hunter2'}",
            "{username : 'alice', password: 'hunter2'}",
            r#"{"username":"alice","password":"hunter2"}"#,
            "{username: 'alice', password: 'hunter2'",
        ] {
            let text = format!("{label} = {object}\nfinished!\n");
            assert_eq!(secret_values(&text), ["hunter2"], "{text}");
            assert_streamed_values(&text, &["hunter2"]);
        }
        let text = format!("{label} = {{username: 'alice'}}\n");
        assert!(secret_values(&text).is_empty(), "{text}");
        assert_streamed_values(&text, &[]);
    }
    for (assignment, value) in [
        ("{private9}", "{private9}"),
        ("'{username: hunter2}'", "{username: hunter2}"),
    ] {
        let text = format!("credentials = {assignment}\nfinished!\n");
        assert_eq!(secret_values(&text), [value], "{text}");
        assert_streamed_values(&text, &[value]);
    }
}

#[test]
fn credential_objects_preserve_shorthand_properties() {
    for label in ["credentials", "app_credentials", "credential"] {
        for (object, expected) in [
            ("{accessKeyId, secretAccessKey}", vec![]),
            ("{username,password}", vec![]),
            ("{username, password: 'hunter2'}", vec!["hunter2"]),
            ("{username,db_password: 'hunter2'}", vec!["hunter2"]),
        ] {
            let text = format!("{label} = {object}\nfinished!\n");
            assert_eq!(secret_values(&text), expected, "{text}");
            assert_streamed_values(&text, &expected);
        }
    }
    let value = "{username,password}";
    let text = format!("credentials = '{value}'\nfinished!\n");
    assert_eq!(secret_values(&text), [value]);
    assert_streamed_values(&text, &[value]);
}

#[test]
fn credential_mappings_preserve_properties_and_scan_nested_values() {
    for label in ["credentials", "app_credentials", "credential"] {
        for property in ["username:", "username :", "'username':", "\"username\":"] {
            for newline in ["\n", "\r\n"] {
                let text = format!(
                    "{label}:{newline}  {property} alice{newline}  password: '{VALUE}'{newline}finished!{newline}"
                );
                assert_eq!(secret_values(&text), [VALUE], "{text}");
                assert_streamed_values(&text, &[VALUE]);
            }
        }
        let text = format!("{label}:\n  username: alice\nfinished!\n");
        assert!(secret_values(&text).is_empty(), "{text}");
        assert_streamed_values(&text, &[]);
    }
    for value in ["hunter2", "abc:def", "'username: alice'"] {
        let text = format!("credentials:\n  {value}\nfinished!\n");
        let expected = value.trim_matches('\'');
        assert_eq!(secret_values(&text), [expected], "{text}");
        assert_streamed_values(&text, &[expected]);
    }
}

#[test]
fn tokenizer_special_tokens_are_not_credentials() {
    for (label, value) in [
        ("pad_token", "<|endoftext|>"),
        ("eos_token", "<|eot_id|>"),
        ("bos_token", "<|begin_of_text|>"),
        ("unk_token", "[UNK]"),
        ("sep_token", "[SEP]"),
        ("cls_token", "[CLS]"),
        ("mask_token", "[MASK]"),
        ("tokenizer.pad_token", "<|endoftext|>"),
    ] {
        let text = format!("{label} = '{value}'");
        assert!(secret_values(&text).is_empty(), "{text}");
        assert_streamed_values(&text, &[]);
    }
    for text in [
        "client_token = '<|private9|>'",
        "pad_token = 'private9'",
        "pad_token = '<|private9|>suffix'",
    ] {
        assert_eq!(secret_values(text).len(), 1, "{text}");
    }
}

fn assert_streamed_values(text: &str, values: &[&str]) {
    for chunk in 1..=8 {
        let scanner = SecretScanner::new().with_direction(Direction::Output);
        let mut stack = ScannerStack::new(vec![Box::new(scanner) as Box<dyn Scanner>], false);
        let mut runner = StreamOutput::new(&stack);
        let mut emitted = String::new();
        for part in text.as_bytes().chunks(chunk) {
            emitted.push_str(
                &runner
                    .push(&mut stack, std::str::from_utf8(part).unwrap())
                    .unwrap(),
            );
        }
        emitted.push_str(&runner.finish(&mut stack).unwrap());
        let mut expected = text.to_owned();
        let mut originals = Vec::new();
        for (sentinel, original) in stack.ctx().vault.entries() {
            expected = expected.replace(original, sentinel);
            originals.push(original);
        }
        originals.sort_unstable();
        assert_eq!(originals, values, "chunk {chunk}: {text}");
        assert_eq!(emitted, expected, "chunk {chunk}: {text}");
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
