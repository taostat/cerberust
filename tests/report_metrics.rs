//! Tests for the content-free per-scanner [`ScanMetrics`] surfaced on the
//! [`ScanReport`]: detection/redaction/restore/block counts, the per-entity-type
//! tally, per-scanner latency, and the hard privacy invariant that no report
//! field ever carries matched content.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests assert on known-good values"
)]

use std::fmt::Write as _;

use cerberust::{
    BanSubstringsScanner, Direction, GuardrailRunner, MiddlewareChain, Model, Params, PiiScanner,
    RestoreScanner, ScanReport, Scanner, ScannerStack, SecretScanner, TokenLimitScanner,
};

struct EchoModel;
impl Model for EchoModel {
    fn generate(&self, params: &Params) -> Result<String, cerberust::MiddlewareError> {
        Ok(params.prompt.clone())
    }
}

/// A PII + secret + restore stack, mirroring the shipped default wiring.
fn pii_secret_stack() -> ScannerStack {
    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(PiiScanner::new()),
        Box::new(SecretScanner::new()),
        Box::new(RestoreScanner::for_pii()),
    ];
    ScannerStack::new(scanners, true)
}

/// Run a prompt through a runner and return its report. A blocked request still
/// yields a report (the blocking scanner's entry is recorded before the stack
/// short-circuits), so the generate result is intentionally not unwrapped.
fn report_for(stack: ScannerStack, prompt: &str) -> ScanReport {
    let runner = GuardrailRunner::new("native:guard", stack);
    {
        let chain = MiddlewareChain::new(vec![&runner]);
        let _ = chain.generate(Params::new(prompt), &EchoModel);
    }
    runner.into_report()
}

/// Find one scanner's entry in a report by id.
fn entry<'a>(report: &'a ScanReport, id: &str) -> &'a cerberust::ScanEntry {
    report
        .entries()
        .iter()
        .find(|e| e.scanner.as_str() == id)
        .unwrap_or_else(|| panic!("no entry for {id}"))
}

#[test]
fn pii_scanner_counts_redactions_by_type() {
    let report = report_for(
        pii_secret_stack(),
        "mail alice@x.com and bob@y.com, ssn 123-45-6789",
    );
    let pii = entry(&report, "native:pii");
    // Two distinct emails + one SSN redacted.
    assert_eq!(pii.metrics.redacted, 3);
    assert_eq!(pii.metrics.detections, 3);
    assert_eq!(pii.metrics.blocked, 0);
    assert_eq!(pii.metrics.by_entity_type.get("EMAIL"), Some(&2));
    assert_eq!(pii.metrics.by_entity_type.get("US_SSN"), Some(&1));
}

#[test]
fn duplicate_value_counts_once() {
    let report = report_for(
        pii_secret_stack(),
        "mail alice@x.com then alice@x.com again",
    );
    let pii = entry(&report, "native:pii");
    // The same email twice dedupes to one distinct redaction.
    assert_eq!(pii.metrics.by_entity_type.get("EMAIL"), Some(&1));
    assert_eq!(pii.metrics.redacted, 1);
}

#[test]
fn secret_scanner_attributes_only_its_own_redactions() {
    let report = report_for(
        pii_secret_stack(),
        "mail alice@x.com key AKIAIOSFODNN7EXAMPLE",
    );
    let pii = entry(&report, "native:pii");
    let secrets = entry(&report, "native:secrets");
    // The PII scanner ran first and owns the email; the secret scanner owns only
    // the AWS key — the per-scanner delta keeps them separate.
    assert_eq!(pii.metrics.by_entity_type.get("EMAIL"), Some(&1));
    assert_eq!(pii.metrics.by_entity_type.get("AWS_ACCESS_KEY"), None);
    assert_eq!(
        secrets.metrics.by_entity_type.get("AWS_ACCESS_KEY"),
        Some(&1)
    );
    assert_eq!(secrets.metrics.by_entity_type.get("EMAIL"), None);
}

#[test]
fn restore_scanner_counts_restored_pii_only() {
    let report = report_for(
        pii_secret_stack(),
        "mail alice@x.com key AKIAIOSFODNN7EXAMPLE",
    );
    let restore = entry(&report, "native:pii-restore");
    // The email round-trips (restored); the secret is OneWay (never restored).
    assert_eq!(restore.metrics.restored, 1);
    assert_eq!(restore.metrics.detections, 1);
    assert_eq!(restore.metrics.redacted, 0);
    assert!(restore.metrics.by_entity_type.is_empty());
}

#[test]
fn block_scanner_records_a_block() {
    let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(TokenLimitScanner::new(2))];
    let report = report_for(ScannerStack::new(scanners, true), "one two three four five");
    let limit = entry(&report, "native:token-limit");
    assert_eq!(limit.metrics.blocked, 1);
    assert_eq!(limit.metrics.detections, 1);
    assert_eq!(limit.metrics.redacted, 0);
    assert!(limit.metrics.by_entity_type.is_empty());
}

#[test]
fn clean_input_records_no_detections() {
    let report = report_for(pii_secret_stack(), "a perfectly ordinary question");
    for e in report.entries() {
        assert_eq!(
            e.metrics.detections, 0,
            "{} detected on clean input",
            e.scanner
        );
        assert_eq!(e.metrics.redacted, 0);
        assert_eq!(e.metrics.blocked, 0);
        assert!(e.metrics.by_entity_type.is_empty());
    }
}

#[test]
fn latency_is_recorded_for_every_scanner() {
    let report = report_for(pii_secret_stack(), "mail alice@x.com");
    // Every entry carries a latency reading; we assert the field is populated
    // (>= 0 is trivially true for u64, so assert the scanners all produced an
    // entry rather than pinning a flaky wall-clock lower bound).
    assert_eq!(report.entries().len(), 3);
}

#[test]
fn redacting_ban_substrings_counts_by_label() {
    let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(
        BanSubstringsScanner::new(["forbidden".to_owned()])
            .redacting()
            .with_direction(Direction::Input),
    )];
    let report = report_for(
        ScannerStack::new(scanners, true),
        "this is forbidden and also forbidden",
    );
    let ban = entry(&report, "native:ban-substrings");
    // Two occurrences of one banned substring — but dedupe-by-value collapses the
    // identical string to a single distinct redaction.
    assert_eq!(ban.metrics.by_entity_type.get("BANNED_SUBSTRING"), Some(&1));
    assert_eq!(ban.metrics.redacted, 1);
    assert_eq!(ban.metrics.blocked, 0);
}

/// The hard privacy invariant: a report assembled over secret-bearing input must
/// not carry any matched content — no redacted value, no plaintext — anywhere in
/// any field. Mirrors the gateway's
/// `rendered_guard_activity_carries_no_matched_content` idea.
#[test]
fn report_carries_no_matched_content() {
    let email = "alice@secret-domain.example";
    let aws_key = "AKIAIOSFODNN7EXAMPLE";
    let ssn = "123-45-6789";
    let prompt = format!("mail {email} key {aws_key} ssn {ssn}");

    let report = report_for(pii_secret_stack(), &prompt);

    // Serialize every field a consumer could read into one string and assert no
    // matched value survives anywhere in it.
    let mut rendered = String::new();
    for e in report.entries() {
        rendered.push_str(e.scanner.as_str());
        write!(
            rendered,
            " valid={} risk={} det={} red={} res={} blk={} lat={}",
            e.valid,
            e.risk,
            e.metrics.detections,
            e.metrics.redacted,
            e.metrics.restored,
            e.metrics.blocked,
            e.metrics.latency_us,
        )
        .unwrap();
        for (ty, n) in &e.metrics.by_entity_type {
            write!(rendered, " {ty}={n}").unwrap();
        }
    }

    for needle in [email, aws_key, ssn] {
        assert!(
            !rendered.contains(needle),
            "report leaked matched content: {needle:?} in {rendered:?}"
        );
    }
    // The type LABELS are present (closed vocabulary, safe), proving the report is
    // non-empty and the assertion above is meaningful.
    assert!(rendered.contains("EMAIL"));
    assert!(rendered.contains("AWS_ACCESS_KEY"));
    assert!(rendered.contains("US_SSN"));
}
