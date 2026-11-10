//! Credential values under double-quoted JSON keys in running text: JSON pasted
//! into a message, or tool-call arguments that are not valid JSON.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::middleware::stream::StreamOutput;
use cerberust::scanner::detect::{detect_secrets, resolve_overlaps};
use cerberust::{Direction, Scanner, ScannerStack, SecretScanner};

fn secret_values(text: &str) -> Vec<&str> {
    resolve_overlaps(detect_secrets(text))
        .into_iter()
        .filter(|span| span.ty == "SECRET")
        .map(|span| &text[span.start..span.end])
        .collect()
}

#[test]
fn quoted_credential_keys_redact_their_string_values() {
    for (text, value) in [
        (r#"{"password":"mysecretvalue"}"#, "mysecretvalue"),
        (
            r#"config: {"api_key": "Zx81mQ0pLr7vT2"} thanks"#,
            "Zx81mQ0pLr7vT2",
        ),
        (
            r#"{"user": "ann", "db_password" : "hunter2hunter2"}"#,
            "hunter2hunter2",
        ),
        (r#"{"dbPassword":"c0rrect-h0rse"}"#, "c0rrect-h0rse"),
        (r#"{"ACCESS_TOKEN":"Ab12Cd34Ef56"}"#, "Ab12Cd34Ef56"),
        (r#"{"refresh_token":"rt_9f8e7d6c5b"}"#, "rt_9f8e7d6c5b"),
        (r#"{"client_secret":"s3cr3t.v4lue"}"#, "s3cr3t.v4lue"),
        (r#"{"apiKey":"k-77aa88bb99"}"#, "k-77aa88bb99"),
        (r#"{"access-key":"AK00zz11yy"}"#, "AK00zz11yy"),
        (r#"{"passwd":"pa\"ss\\word9"}"#, r#"pa\"ss\\word9"#),
    ] {
        assert_eq!(secret_values(text), [value], "{text}");
    }
}

#[test]
fn malformed_tool_arguments_still_redact_credential_values() {
    let text = r#"{"host": "db.internal", "password": "mysecretvalue", "port": 54"#;
    assert_eq!(secret_values(text), ["mysecretvalue"]);
}

#[test]
fn non_credential_json_is_unchanged() {
    for text in [
        r#"{"password": null}"#,
        r#"{"password": true}"#,
        r#"{"password": 123456789}"#,
        r#"{"password": {"type": "string", "description": "The user's password"}}"#,
        r#"{"token_type": "bearer"}"#,
        r#"{"token": "bearer"}"#,
        r#"{"password": "string"}"#,
        r#"{"secret": "Optional"}"#,
        r#"{"password": "The account password"}"#,
        r#"{"password": "********"}"#,
        r#"{"password": "<password>"}"#,
        r#"{"password": "{password}"}"#,
        r#"{"password": "[REDACTED]"}"#,
        r#"{"password": "${DB_PASSWORD}"}"#,
        r#"{"api_key": "{{ secrets.api_key }}"}"#,
        r#"{"password": "changeme"}"#,
        r#"{"password": "short"}"#,
        r#"{"next_token": "eyJvZmZzZXQiOjEwMH0"}"#,
        r#"{"nextPageToken": "CiAKGjBpNDd2Nmp2Zml2cXRwYjBpOXA"}"#,
        r#"{"continuation-token": "c1d2e3f4a5b6"}"#,
        r#"{"PWD": "/home/user/project"}"#,
        r#"{"max_tokens": "4096000"}"#,
        r#"{"password_hint": "first pet"}"#,
        r#"{"description": "password reset token"}"#,
        r#"{\"password\":\"mysecretvalue\"}"#,
    ] {
        assert!(
            secret_values(text).is_empty(),
            "{text}: {:?}",
            secret_values(text)
        );
    }
}

#[test]
fn streamed_json_credentials_never_flush_part_of_the_value() {
    let value = "mysecretvalue";
    let response = format!(r#"Use {{"host": "db", "password": "{value}"}} to connect.\n"#);
    for chunk in 1..=8 {
        let scanner = SecretScanner::new().with_direction(Direction::Output);
        let mut stack = ScannerStack::new(vec![Box::new(scanner) as Box<dyn Scanner>], false);
        let mut runner = StreamOutput::new(&stack);
        let mut emitted = String::new();
        let mut start = 0;
        while start < response.len() {
            let end = (start + chunk).min(response.len());
            emitted.push_str(&runner.push(&mut stack, &response[start..end]).unwrap());
            for fragment in value.as_bytes().windows(6) {
                let fragment = std::str::from_utf8(fragment).unwrap();
                assert!(!emitted.contains(fragment), "chunk {chunk}: {emitted}");
            }
            start = end;
        }
        emitted.push_str(&runner.finish(&mut stack).unwrap());
        assert!(!emitted.contains(value), "chunk {chunk}: {emitted}");
        assert!(emitted.starts_with(r#"Use {"host": "db", "password": ""#));
        assert!(emitted.ends_with(r#""} to connect.\n"#));
    }
}
