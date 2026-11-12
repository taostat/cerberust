//! Measure redaction cost as input and match counts grow.
//!
//! Run with `cargo bench --bench scaling`. Each result is the median of five
//! warmed scans with a fresh vault. Only `scan` is timed: scanner construction,
//! input generation, vault creation and result/vault destruction are excluded.
//!
//! Inputs are exactly 8–128 KiB. Rare cases contain one isolated match; dense
//! cases grow the number of matches with input size. Dense regex/substring
//! cases repeat a value (vault deduplication), while PII/secrets use distinct
//! values. The overlap/adjacent regex cases exercise competing/nested matches
//! and touching matches respectively. `redactions` counts emitted sentinels,
//! not unique vault entries or candidates before overlap resolution.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    reason = "standalone benchmark reports measurements to stdout"
)]

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::{Duration, Instant};

use cerberust::scanners::{BanSubstringsScanner, PiiScanner, RegexScanner, SecretScanner};
use cerberust::{ScanCtx, Scanner, ScannerStack};

const SIZES: [usize; 5] = [8, 16, 32, 64, 128];
const REPEATS: usize = 5;
const LARGE_STACK_BYTES: usize = 10 * 1024 * 1024;
type BenchmarkCase = (&'static str, Box<dyn Scanner>, fn(usize) -> String);

fn main() {
    let cases: [BenchmarkCase; 11] = [
        (
            "regex_dense",
            Box::new(RegexScanner::from_patterns([(r"\d+", "NUMBER")]).0),
            digit_runs,
        ),
        (
            "regex_rare",
            Box::new(RegexScanner::from_patterns([(r"RARE-\d{8}", "RARE")]).0),
            |size| sparse(size, "RARE-12345678"),
        ),
        (
            "regex_overlap_adjacent",
            Box::new(RegexScanner::from_patterns([(r"\d{6}", "LONG"), (r"\d{3}", "PART")]).0),
            overlap_candidates,
        ),
        ("pii_dense", Box::new(PiiScanner::new()), pii_values),
        ("pii_rare", Box::new(PiiScanner::new()), |size| {
            sparse(size, "alice@example.com")
        }),
        ("pii_rare_non_ascii", Box::new(PiiScanner::new()), |size| {
            non_ascii_sparse(size, "alice@example.com")
        }),
        (
            "secrets_dense",
            Box::new(SecretScanner::new()),
            secret_values,
        ),
        ("secrets_rare", Box::new(SecretScanner::new()), |size| {
            sparse(size, "AKIA0000000000000001")
        }),
        (
            "ban_substrings_dense",
            Box::new(BanSubstringsScanner::new(["forbidden".to_owned()]).redacting()),
            |size| repeated(size, "forbidden "),
        ),
        (
            "ban_substrings_rare",
            Box::new(BanSubstringsScanner::new(["forbidden".to_owned()]).redacting()),
            |size| sparse(size, "forbidden"),
        ),
        (
            "regex_adjacent",
            Box::new(RegexScanner::from_patterns([(r"\d{3}", "PART")]).0),
            overlap_candidates,
        ),
    ];

    println!("case,size_kib,redactions,median_us");
    for (name, scanner, make_text) in cases {
        for kib in SIZES {
            let text = make_text(kib * 1024);
            // Warm compiled scanner state before timing.
            let mut warm_ctx = ScanCtx::new();
            let warm_verdict = scanner.scan(&text, &mut warm_ctx).unwrap();
            let redactions = warm_verdict.text.matches("[REDACTED_").count();
            assert_eq!(text.len(), kib * 1024);
            if name.ends_with("_rare") {
                assert_eq!(redactions, 1, "{name} must redact exactly one match");
                assert_eq!(
                    warm_ctx
                        .vault
                        .entries()
                        .next()
                        .map(|(_, original)| original),
                    Some(text.trim()),
                    "{name} must redact only the isolated needle",
                );
            }
            black_box((&warm_verdict.text, warm_ctx.vault.len(), redactions));
            drop(warm_ctx);

            let mut samples = Vec::with_capacity(REPEATS);
            for _ in 0..REPEATS {
                let mut ctx = ScanCtx::new();
                let start = Instant::now();
                let verdict = scanner.scan(&text, &mut ctx).unwrap();
                let elapsed = start.elapsed();
                black_box((&verdict.text, ctx.vault.len()));
                samples.push(elapsed);
            }
            samples.sort_unstable();
            let median = samples[REPEATS / 2];
            println!("{name},{kib},{redactions},{:.1}", duration_micros(median));
        }
    }

    bench_large_pii_secrets_stack();
}

/// Measure the public stack path for a large clean leaf: unlike the individual
/// scanner cases above, this includes input threading, context retention and
/// per-scanner metrics snapshots.
fn bench_large_pii_secrets_stack() {
    let text = repeated(LARGE_STACK_BYTES, "safe! ");
    let mut warm_stack = pii_secrets_stack();
    let warm_output = warm_stack.run_input(&text).unwrap();
    assert_eq!(warm_output, text);
    black_box((warm_output.len(), warm_stack.ctx().vault.len()));

    let mut samples = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let mut stack = pii_secrets_stack();
        let start = Instant::now();
        let output = stack.run_input(&text).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(output.len(), text.len());
        black_box((output, stack.ctx().vault.len()));
        samples.push(elapsed);
    }
    samples.sort_unstable();
    let median = samples[REPEATS / 2];
    println!(
        "stack_pii_secrets_clean,{},0,{:.1}",
        LARGE_STACK_BYTES / 1024,
        duration_micros(median)
    );
}

fn pii_secrets_stack() -> ScannerStack {
    ScannerStack::new(
        vec![Box::new(PiiScanner::new()), Box::new(SecretScanner::new())],
        true,
    )
}

fn duration_micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn repeated(size: usize, unit: &str) -> String {
    let mut text = String::with_capacity(size);
    while text.len() < size {
        text.push_str(unit);
    }
    text.truncate(size);
    text
}

/// `sparse` with one non-ASCII character at the start, so the PII regexes scan
/// a haystack that is not pure ASCII.
fn non_ascii_sparse(size: usize, needle: &str) -> String {
    let mut text = sparse(size, needle);
    text.replace_range(..2, "\u{e9}");
    text
}

fn sparse(size: usize, needle: &str) -> String {
    // Alphanumeric padding would become part of the PII email match.
    let mut text = vec![b' '; size];
    let start = (size.saturating_sub(needle.len())) / 2;
    text[start..start + needle.len()].copy_from_slice(needle.as_bytes());
    // All benchmark cases use ASCII so this conversion is infallible.
    String::from_utf8(text).unwrap()
}

fn digit_runs(size: usize) -> String {
    repeated(size, "123 ")
}

fn overlap_candidates(size: usize) -> String {
    let mut text = String::with_capacity(size);
    let mut i = 0_u64;
    while text.len() < size {
        let _ = write!(text, "{i:06} ");
        i += 1;
    }
    text.truncate(size);
    text
}

fn pii_values(size: usize) -> String {
    let mut text = String::with_capacity(size);
    let mut i = 0_u64;
    while text.len() < size {
        let _ = write!(text, "user{i:08}@example.com ");
        i += 1;
    }
    text.truncate(size);
    text
}

fn secret_values(size: usize) -> String {
    let mut text = String::with_capacity(size);
    let mut i = 0_u64;
    while text.len() < size {
        let _ = write!(text, "AKIA{i:016X} ");
        i += 1;
    }
    text.truncate(size);
    text
}
