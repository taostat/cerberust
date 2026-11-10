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

#[test]
fn json_whitespace_around_the_colon_preserves_value_spans() {
    for gap in ["\n", "\r\n", " \t\n "] {
        for (before, after) in [(gap, ""), ("", gap), (gap, gap)] {
            let text = format!("前 {{\"password\"{before}:{after}\"mysecretvalue\"}} 後");
            assert_eq!(secret_values(&text), ["mysecretvalue"], "{text:?}");
        }
    }
}

#[test]
fn json_exemptions_use_decoded_string_contents() {
    for text in [
        r#"{"password":"The\naccount\npassword"}"#,
        r#"{"password":"The\taccount\tpassword"}"#,
        r#"{"password":"The\u0020account\u0020password"}"#,
        r#"{"password":"\u0073tring"}"#,
        r#"{"password":"\u2022\u2022\u2022\u2022"}"#,
        r#"{"password":"\u003cpassword\u003e"}"#,
        r#"{"password":"\u0024{DB_PASSWORD}"}"#,
        r#"{"password":"ab\u0063"}"#,
    ] {
        assert!(detect_secrets(text).is_empty(), "{text}");
    }
}

#[test]
fn json_type_hints_are_not_credentials() {
    for value in [
        "Optional[str]",
        "Option<String>",
        "typing.Optional[str]",
        "builtins.str",
        "List[str]",
        "Sequence",
        "Mapping",
        "Union[str,None]",
    ] {
        let text = format!(r#"{{"password":"{value}"}}"#);
        assert!(detect_secrets(&text).is_empty(), "{text}");
    }
}

#[test]
fn json_references_are_not_credentials() {
    for value in [
        "process.env.DB_PASSWORD",
        "env:DB_PASSWORD",
        "#/components/schemas/Password",
        "${DB_PASSWORD:-changeme}",
        "${{secrets.DB_PASSWORD}}",
    ] {
        let text = format!(r#"{{"password":"{value}"}}"#);
        assert!(detect_secrets(&text).is_empty(), "{text}");
    }
}

#[test]
fn json_partially_masked_values_are_not_credentials() {
    for value in ["********1234", "••••1234", "abcd********", "abcd...wxyz"] {
        let text = format!(r#"{{"password":"{value}"}}"#);
        assert!(detect_secrets(&text).is_empty(), "{text}");
    }
}

#[test]
fn json_display_labels_are_not_credentials() {
    for value in [
        "Password:",
        "Passwort",
        "Mot_de_passe",
        "Contraseña",
        "パスワード",
        "密码",
    ] {
        let text = format!(r#"{{"password":"{value}"}}"#);
        assert!(detect_secrets(&text).is_empty(), "{text}");
    }
}

#[test]
fn backward_pagination_tokens_are_not_credentials() {
    for key in ["prev_token", "prevToken", "previous_token", "previousToken"] {
        let text = format!(r#"{{"{key}":"cursor_1234567"}}"#);
        assert!(detect_secrets(&text).is_empty(), "{text}");
    }
}

#[test]
fn pwd_credentials_are_distinct_from_working_directories() {
    for key in ["pwd", "PWD", "db_pwd"] {
        let text = format!(r#"{{"{key}":"mysecretvalue"}}"#);
        assert_eq!(secret_values(&text), ["mysecretvalue"], "{text}");
    }
    for value in [
        "/home/user/project",
        "./project",
        "../project",
        "~/project",
        r"C:\\Users\\ann",
    ] {
        let text = format!(r#"{{"PWD":"{value}"}}"#);
        assert!(detect_secrets(&text).is_empty(), "{text}");
    }
}

#[test]
fn escaped_and_unicode_credentials_keep_their_complete_source_spans() {
    for value in [
        r"my\u0073ecretvalue",
        r#"pa\"ss\\word9"#,
        r"abc\ud83d\udd11def",
        "clé-secrète-91x7",
        r"abc\uD800def",
        r"abc\uDC00def",
        r"abc\u00",
        r"abc\qdef",
        "Optional9x7k2m=",
        "secretstr9x7k2m",
        "process.env.KEY-suffix",
        "${DB_PASSWORD}-suffix",
        "::::::",
    ] {
        let text = format!(r#"前 {{"password":"{value}"}} 後"#);
        assert_eq!(secret_values(&text), [value], "{text}");
    }
}

fn output_stack() -> ScannerStack {
    ScannerStack::new(
        vec![Box::new(
            SecretScanner::new().with_direction(Direction::Output),
        )],
        false,
    )
}

fn assert_complete_redactions(stack: &ScannerStack, source: &str, emitted: &str, values: &[&str]) {
    assert_eq!(stack.ctx().vault.len(), values.len(), "{emitted}");
    let mut expected = source.to_owned();
    for (placeholder, original) in stack.ctx().vault.entries() {
        assert!(values.contains(&original), "unexpected span: {original:?}");
        expected = expected.replace(original, placeholder);
    }
    assert_eq!(emitted, expected);
}

#[test]
fn streamed_multiline_and_escaped_json_preserves_exact_spans() {
    let source = concat!(
        "前 {\"password\"\r\n:\n\"mysecretvalue\", ",
        r#""api_key":"pa\"ss\\word9", "client_secret":"abc\ud83d\udd11def"} 後 "#,
    );
    let values = ["mysecretvalue", r#"pa\"ss\\word9"#, r"abc\ud83d\udd11def"];
    let mut unary = output_stack();
    let output = unary.run_output(source).unwrap();
    assert_complete_redactions(&unary, source, &output, &values);
    let boundaries: Vec<_> = source.char_indices().map(|(offset, _)| offset).collect();
    for split in boundaries {
        let mut stack = output_stack();
        let mut runner = StreamOutput::new(&stack);
        let mut emitted = runner.push(&mut stack, &source[..split]).unwrap();
        emitted.push_str(&runner.push(&mut stack, &source[split..]).unwrap());
        emitted.push_str(&runner.finish(&mut stack).unwrap());
        assert_complete_redactions(&stack, source, &emitted, &values);
    }
    let mut stack = output_stack();
    let mut runner = StreamOutput::new(&stack);
    let mut emitted = String::new();
    for ch in source.chars() {
        emitted.push_str(
            &runner
                .push(&mut stack, ch.encode_utf8(&mut [0; 4]))
                .unwrap(),
        );
    }
    emitted.push_str(&runner.finish(&mut stack).unwrap());
    assert_complete_redactions(&stack, source, &emitted, &values);
}

#[test]
fn json_vendor_credentials_are_redacted_once_without_changing_their_type() {
    let value = format!("gm_live_{}", "a1b2".repeat(16));
    let source = format!(r#"{{"api_key":"{value}"}}"#);
    let mut stack = output_stack();
    let output = stack.run_output(&source).unwrap();
    assert_complete_redactions(&stack, &source, &output, &[&value]);
    assert!(output.contains("[REDACTED_GM_API_KEY_"), "{output}");
}

#[test]
fn ordinary_json_responses_schemas_and_logs_are_unchanged_when_streamed() {
    let source = concat!(
        r#"{"token_type":"bearer","expires_in":3600,"total_tokens":100,"max_tokens":200,"pwd":"/home/user"} "#,
        r##"{"password":{"type":"string","description":"The user's password"},"api_key":{"$ref":"#/definitions/ApiKey"}} "##,
        r#"{"password":"The\naccount\npassword","prev_token":"cursor_1234567","password_hint":"first pet"} "#,
        r#"{"password":"Password:","db_password":"env:DB_PASSWORD","token":"****1234"} "#,
    );
    assert_eq!(detect_secrets(source), []);
    let mut stack = output_stack();
    let mut runner = StreamOutput::new(&stack);
    let mut emitted = String::new();
    for chunk in source.as_bytes().chunks(7) {
        emitted.push_str(
            &runner
                .push(&mut stack, std::str::from_utf8(chunk).unwrap())
                .unwrap(),
        );
    }
    emitted.push_str(&runner.finish(&mut stack).unwrap());
    assert_eq!(emitted, source);
    assert!(stack.ctx().vault.is_empty());
}

#[test]
fn truncated_json_credentials_keep_the_complete_value() {
    for value in [
        "mysecretvalue",
        r"my\u0073ecretvalue",
        r"mysecretvalue\",
        r#"my\"secretvalue"#,
        "clé-secrète-91x7",
    ] {
        let source = format!(r#"tool arguments: {{"password": "{value}"#);
        assert_eq!(secret_values(&source), [value], "{source}");
        let mut stack = output_stack();
        let mut runner = StreamOutput::new(&stack);
        let mut emitted = String::new();
        for ch in source.chars() {
            emitted.push_str(
                &runner
                    .push(&mut stack, ch.encode_utf8(&mut [0; 4]))
                    .unwrap(),
            );
            assert!(source[..source.find(value).unwrap()].starts_with(&emitted));
        }
        emitted.push_str(&runner.finish(&mut stack).unwrap());
        assert_complete_redactions(&stack, &source, &emitted, &[value]);
    }
}

fn assert_unchanged_json(source: &str) {
    assert!(detect_secrets(source).is_empty(), "{source}");
    let mut stack = output_stack();
    let mut runner = StreamOutput::new(&stack);
    let mut emitted = String::new();
    for ch in source.chars() {
        emitted.push_str(
            &runner
                .push(&mut stack, ch.encode_utf8(&mut [0; 4]))
                .unwrap(),
        );
    }
    emitted.push_str(&runner.finish(&mut stack).unwrap());
    assert_eq!(emitted, source);
    assert!(stack.ctx().vault.is_empty());
}

#[test]
fn json_field_names_used_as_placeholders_are_not_credentials() {
    for (key, value) in [
        ("api_key", "api_key"),
        ("apiKey", "ApiKey"),
        ("access_token", "ACCESS_TOKEN"),
        ("db_password", "db_password"),
        ("api_key", r"api\u005fkey"),
    ] {
        let source = format!(r#"{{"{key}":"{value}"}}"#);
        assert_unchanged_json(&source);
    }
}

#[test]
fn json_hash_masked_values_are_not_credentials() {
    for value in ["######1234", "abcd########", r"\u0023\u0023\u00231234"] {
        let source = format!(r#"{{"password":"{value}"}}"#);
        assert_unchanged_json(&source);
    }
}

#[test]
fn json_qualified_type_hints_are_not_credentials() {
    for value in [
        "std::string::String",
        "std::option::Option<String>",
        "Option<&str>",
        "pydantic.SecretStr",
    ] {
        let source = format!(r#"{{"password":"{value}"}}"#);
        assert_unchanged_json(&source);
    }
}

#[test]
fn json_windows_environment_references_are_not_credentials() {
    for value in ["%Db_Password%", "%db_password%"] {
        let source = format!(r#"{{"password":"{value}"}}"#);
        assert_unchanged_json(&source);
    }
}

#[test]
fn json_starting_and_resume_tokens_are_not_credentials() {
    for key in [
        "StartingToken",
        "starting_token",
        "resume_token",
        "resumeToken",
    ] {
        let source = format!(r#"{{"{key}":"cursor_1234567"}}"#);
        assert_unchanged_json(&source);
    }
}

#[test]
fn streamed_json_descriptions_release_text_before_the_closing_quote() {
    let mut stack = output_stack();
    let mut runner = StreamOutput::new(&stack);
    let mut source = r#"{"password":"The account password "#.to_owned();
    let mut emitted = runner.push(&mut stack, &source).unwrap();
    for _ in 0..100 {
        let chunk = "validation instructions; ".repeat(4);
        source.push_str(&chunk);
        emitted.push_str(&runner.push(&mut stack, &chunk).unwrap());
        assert!(source.len() - emitted.len() < 256);
    }
    source.push_str(r#""}"#);
    emitted.push_str(&runner.push(&mut stack, r#""}"#).unwrap());
    emitted.push_str(&runner.finish(&mut stack).unwrap());
    assert_eq!(emitted, source);
    assert!(stack.ctx().vault.is_empty());
}

#[test]
fn json_exemptions_preserve_distinct_credential_literals() {
    for (key, value) in [
        ("api_key", "api_key9x7"),
        ("password", "pydantic.SecretStr9x7"),
        ("password", "std::string::String9x7"),
        ("password", "%Db_Password%-suffix"),
        ("password", "ab#cd#12"),
        ("starting_access_token", "mysecretvalue"),
        ("api_key", "YOUR_API_KEY_HERE9x7"),
        ("api_key", "mysecretvalue_here"),
        ("api_key", "replace_with_mysecretvalue"),
        ("password", "Array<string>9x7"),
        ("password", "System.String9x7"),
        ("password", "$env:DB_PASSWORD-suffix"),
    ] {
        let source = format!(r#"{{"{key}":"{value}"}}"#);
        assert_eq!(secret_values(&source), [value], "{source}");
        let mut stack = output_stack();
        let output = stack.run_output(&source).unwrap();
        assert_complete_redactions(&stack, &source, &output, &[value]);
    }
}

#[test]
fn json_escaped_quotes_do_not_end_description_values() {
    for source in [
        r#"{"password":"Account\" password"}"#,
        r#"{"password":"Account\"\npassword"}"#,
        r#"{"password":"Account\" password","api_key":"placeholder"}"#,
        r#"前 {"password":"Account\" password"} 後"#,
    ] {
        assert_unchanged_json(source);
    }
}

#[test]
fn json_config_template_placeholders_are_not_credentials() {
    for value in [
        "YOUR_API_KEY_HERE",
        "your-password-here",
        "INSERT_TOKEN_HERE",
        "REPLACE_WITH_YOUR_SECRET",
    ] {
        assert_unchanged_json(&format!(r#"{{"api_key":"{value}"}}"#));
    }
}

#[test]
fn json_array_and_qualified_string_types_are_not_credentials() {
    for value in [
        "Array<string>",
        "[]byte",
        "System.String",
        "pydantic.types.SecretStr",
    ] {
        assert_unchanged_json(&format!(r#"{{"password":"{value}"}}"#));
    }
}

#[test]
fn json_powershell_environment_references_are_not_credentials() {
    for value in [
        "$env:DB_PASSWORD",
        "$Env:DB_PASSWORD",
        "$ENV:Db_Password",
        "${env:DB_PASSWORD}",
    ] {
        assert_unchanged_json(&format!(r#"{{"password":"{value}"}}"#));
    }
}

#[test]
fn json_compound_credential_placeholders_are_not_credentials() {
    for (key, value) in [
        ("client_secret", "YOUR_CLIENT_SECRET"),
        ("access_token", "YOUR_ACCESS_TOKEN_HERE"),
        ("db_password", "REPLACE_WITH_YOUR_DB_PASSWORD"),
        ("api_key", "INSERT_ACCESS_TOKEN_HERE"),
        ("api_key", "your-client-secret-here"),
    ] {
        assert_unchanged_json(&format!(r#"{{"{key}":"{value}"}}"#));
    }
}

#[test]
fn json_environment_accessors_are_not_credentials() {
    for value in [
        "os.environ['DB_PASSWORD']",
        r#"os.getenv(\"DB_PASSWORD\")"#,
        "os.environ.get('DB_PASSWORD')",
        "process.env['DB_PASSWORD']",
        r#"process.env[\"DB_PASSWORD\"]"#,
        "env.DB_PASSWORD",
        "$ENV{DB_PASSWORD}",
        "%env(DB_PASSWORD)%",
    ] {
        assert_unchanged_json(&format!(r#"{{"password":"{value}"}}"#));
    }
}

#[test]
fn json_invalid_escapes_preserve_decoded_whitespace_exemptions() {
    for value in [
        r"Enter\u0020your\u0020password\u",
        r"Please\nenter\q",
        r"Please\tenter\ud800",
        r"Please\qenter\npassword",
        r"Please\nenter\",
    ] {
        let source = format!(r#"{{"password":"{value}"#);
        assert_unchanged_json(&source);
        assert_unchanged_json(&format!(r#"{source}"}}"#));
    }
}

#[test]
fn json_generic_and_secret_types_are_not_credentials() {
    for value in [
        "SecretBytes",
        "typing.AnyStr",
        "pydantic.SecretBytes",
        "Literal['redacted']",
        r#"typing.Literal[\"redacted\",\"hidden\"]"#,
        "typing_extensions.Annotated[str,Field(repr=False)]",
        "Optional[Credential]",
        "Option<Credential>",
        "List[Literal['redacted']]",
    ] {
        assert_unchanged_json(&format!(r#"{{"password":"{value}"}}"#));
    }
}

#[test]
fn json_named_partial_masks_are_not_credentials() {
    for value in [
        "[redacted]1234",
        "abcd[REDACTED]",
        "<masked>1234",
        r"\u005bredacted\u005d1234",
    ] {
        assert_unchanged_json(&format!(r#"{{"password":"{value}"}}"#));
    }
}

#[test]
fn json_validation_messages_are_not_credentials() {
    for source in [
        r#"{"errors":{"password":"invalid"}}"#,
        r#"{"password":"required","confirm_password":"mismatch"}"#,
        r#"{"password":"incorrect"}"#,
    ] {
        assert_unchanged_json(source);
    }
}

#[test]
fn json_localized_display_questions_are_not_credentials() {
    for source in [
        r#"{"i18n":{"forgot_password":"Passwort?","reset_password":"Zurücksetzen"}}"#,
        r#"{"password":"Password?"}"#,
        r#"{"password":"パスワード？"}"#,
    ] {
        assert_unchanged_json(source);
    }
}

#[test]
fn json_exemptions_require_complete_placeholders_references_and_types() {
    for value in [
        "YOUR_CLIENT_SECRET9x7",
        "YOUR_ACCESS_TOKEN_HERE9x7",
        "os.environ['DB_PASSWORD']-suffix",
        "os.getenv('DB_PASSWORD','mysecretvalue')",
        "process.env['DB_PASSWORD']-suffix",
        "$ENV{DB_PASSWORD}-suffix",
        "%env(DB_PASSWORD)%-suffix",
        "Literal['redacted']9x7",
        "Option<Credential>9x7",
        "Optional[Credential]9x7",
        "SecretBytes9x7",
        "my[part]secret123",
        "invalid9x7",
        "Passwort?9x7",
    ] {
        let source = format!(r#"{{"password":"{value}"}}"#);
        assert_eq!(secret_values(&source), [value], "{source}");
        let mut stack = output_stack();
        let output = stack.run_output(&source).unwrap();
        assert_complete_redactions(&stack, &source, &output, &[value]);
    }
}
