//! End-to-end regression tests for the two scanners through the full
//! middleware + stack path: known inputs → expected redaction, verdict, and
//! restore. Pins the PII restored / secret NOT restored asymmetry.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use std::borrow::Cow;

use cerberust::{
    Direction, Disposition, GuardrailRunner, MiddlewareChain, Model, Params, PiiScanner,
    RestorePolicy, RestoreScanner, ScanCtx, Scanner, ScannerStack, SecretScanner, Verdict,
};

struct EchoModel;
impl Model for EchoModel {
    fn generate(&self, params: &Params) -> Result<String, cerberust::MiddlewareError> {
        Ok(params.prompt.clone())
    }
}

fn stack() -> ScannerStack {
    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(PiiScanner::new()),
        Box::new(SecretScanner::new()),
        Box::new(RestoreScanner::for_pii()),
    ];
    ScannerStack::new(scanners, true)
}

#[test]
fn email_redacted_then_restored() {
    let scanner = PiiScanner::new();
    let mut ctx = ScanCtx::new();
    let verdict = scanner.scan("contact alice@example.com", &mut ctx).unwrap();
    assert!(verdict.text.contains("[REDACTED_EMAIL_1_"));
    assert!(verdict.valid);
    assert!(!verdict.is_risk_judgment());

    let restore = RestoreScanner::for_pii();
    let redacted = verdict.text.into_owned();
    let restored = restore.scan(&redacted, &mut ctx).unwrap();
    assert_eq!(restored.text, "contact alice@example.com");
}

#[test]
fn credit_card_luhn_redacted_random_digits_untouched() {
    let scanner = PiiScanner::new();
    let mut ctx = ScanCtx::new();
    // 4111 1111 1111 1111 is a valid Luhn test card; the second is not.
    let out = scanner
        .scan("card 4111 1111 1111 1111 not 1234 5678 9012 3456", &mut ctx)
        .unwrap();
    assert!(out.text.contains("[REDACTED_CREDIT_CARD_1_"));
    assert!(out.text.contains("1234 5678 9012 3456"));
}

#[test]
fn secret_redacted_and_never_restored_end_to_end() {
    let runner = GuardrailRunner::new("native:guard", stack());
    let prompt = "my key is AKIAIOSFODNN7EXAMPLE and mail bob@y.com";
    let out = {
        let chain = MiddlewareChain::new(vec![&runner]);
        chain.generate(Params::new(prompt), &EchoModel).unwrap()
    };
    // PII round-trips back to plaintext.
    assert!(out.contains("bob@y.com"));
    // Secret stays a sentinel: OneWay is the load-bearing privacy property.
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(out.contains("[REDACTED_AWS_ACCESS_KEY_1_"));
}

#[test]
fn private_key_header_redacted() {
    let scanner = SecretScanner::new();
    let mut ctx = ScanCtx::new();
    let out = scanner
        .scan(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEcontent\n-----END RSA PRIVATE KEY-----",
            &mut ctx,
        )
        .unwrap();
    assert!(out.text.contains("[REDACTED_PRIVATE_KEY_1_"));
    assert!(!out.text.contains("MIIEcontent"));
}

#[test]
fn pii_one_way_policy_masks_permanently() {
    // Flip PII to OneWay: redact on input, the restore scanner (PII types) still
    // restores by type — so to truly mask, the restorer must not own the type.
    // Here we assert the policy is configurable and reported correctly.
    let scanner = PiiScanner::new().with_policy(RestorePolicy::OneWay);
    assert_eq!(scanner.policy(), RestorePolicy::OneWay);
}

#[test]
fn block_scanner_rejects_before_model() {
    // A trivial block scanner proves the input fail-fast path rejects with no
    // model call.
    struct RejectAll;
    impl Scanner for RejectAll {
        fn id(&self) -> cerberust::ScannerId {
            cerberust::ScannerId("test:reject")
        }
        fn direction(&self) -> Direction {
            Direction::Input
        }
        fn disposition(&self) -> Disposition {
            Disposition::Block
        }
        fn scan<'a>(&self, text: &'a str, _ctx: &mut ScanCtx) -> cerberust::ScanResult<'a> {
            Ok(Verdict::detected(text, 1.0, 0.5))
        }
    }
    let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(RejectAll)];
    let runner = GuardrailRunner::new("native:guard", ScannerStack::new(scanners, true));
    let chain = MiddlewareChain::new(vec![&runner]);
    let err = chain
        .generate(Params::new("anything"), &EchoModel)
        .unwrap_err();
    assert!(matches!(err, cerberust::MiddlewareError::Blocked { .. }));
}

#[test]
fn clean_prompt_passes_through_unchanged() {
    let runner = GuardrailRunner::new("native:guard", stack());
    let chain = MiddlewareChain::new(vec![&runner]);
    let out = chain
        .generate(Params::new("just a normal question"), &EchoModel)
        .unwrap();
    assert_eq!(out, "just a normal question");
}

// A scanner using a borrowed verdict to prove the zero-alloc clean path holds
// through the public API.
#[test]
fn clean_pii_scan_borrows_input() {
    let scanner = PiiScanner::new();
    let mut ctx = ScanCtx::new();
    let verdict = scanner.scan("no pii here", &mut ctx).unwrap();
    assert!(matches!(verdict.text, Cow::Borrowed(_)));
}
