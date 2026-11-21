//! Scan-time benchmark on real source and prose with no redactions, used by the
//! CI perf gate (`scripts/perf-gate.sh`).
//!
//! `perf_gate clean <list>` prints each listed file that neither the PII nor
//! the secrets scanner changes. `perf_gate bench <list>` joins the listed files
//! into one corpus, repeats it to at least 1 MiB, and prints one CSV row per
//! case: `case,median_us,changed`. `changed` is 1 when the scan altered the
//! input.
//!
//! The example uses only the public API, so the CI job can copy it into the
//! base revision and time both revisions with the same code.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    reason = "standalone benchmark reports measurements to stdout"
)]

use std::hint::black_box;
use std::time::Instant;

use cerberust::scanners::{PiiScanner, SecretScanner};
use cerberust::{ScanCtx, Scanner, ScannerStack};

const SIZES_KIB: [usize; 2] = [128, 1024];

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, list] = args.as_slice() else {
        return Err("usage: perf_gate <clean|bench> <file-list>".to_owned());
    };
    let paths: Vec<String> = std::fs::read_to_string(list)
        .map_err(|err| format!("read file list {list}: {err}"))?
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    match mode.as_str() {
        "clean" => print_clean(&paths),
        "bench" => bench(&corpus(&paths)),
        other => return Err(format!("unknown mode {other:?}; expected clean or bench")),
    }
    Ok(())
}

fn changes(scanner: &dyn Scanner, text: &str) -> bool {
    scanner.scan(text, &mut ScanCtx::new()).unwrap().text != text
}

fn print_clean(paths: &[String]) {
    let (pii, secrets) = (PiiScanner::new(), SecretScanner::new());
    for path in paths {
        let text = std::fs::read_to_string(path).expect("read listed file");
        if !changes(&pii, &text) && !changes(&secrets, &text) {
            println!("{path}");
        }
    }
}

fn corpus(paths: &[String]) -> String {
    let mut text = String::new();
    for path in paths {
        text.push_str(&std::fs::read_to_string(path).expect("read listed file"));
        text.push('\n');
    }
    assert!(
        !text.trim().is_empty(),
        "file list produced an empty corpus"
    );
    let unit = text.clone();
    while text.len() < SIZES_KIB[SIZES_KIB.len() - 1] * 1024 {
        text.push_str(&unit);
    }
    text
}

fn prefix(text: &str, size: usize) -> &str {
    let mut end = size.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn median_us(iters: usize, mut run: impl FnMut() -> f64) -> f64 {
    for _ in 0..2 {
        run();
    }
    let mut samples: Vec<f64> = (0..iters).map(|_| run()).collect();
    samples.sort_by(f64::total_cmp);
    samples[iters / 2]
}

fn time_scanner(scanner: &dyn Scanner, text: &str, iters: usize) -> f64 {
    median_us(iters, || {
        let mut ctx = ScanCtx::new();
        let start = Instant::now();
        black_box(scanner.scan(text, &mut ctx).unwrap());
        start.elapsed().as_secs_f64() * 1e6
    })
}

fn time_stack(text: &str, iters: usize) -> f64 {
    median_us(iters, || {
        let mut stack = ScannerStack::new(
            vec![
                Box::new(PiiScanner::new()) as Box<dyn Scanner>,
                Box::new(SecretScanner::new()),
            ],
            false,
        );
        let start = Instant::now();
        black_box(stack.run_input(text).unwrap());
        start.elapsed().as_secs_f64() * 1e6
    })
}

fn bench(full: &str) {
    let (pii, secrets) = (PiiScanner::new(), SecretScanner::new());
    for kib in SIZES_KIB {
        let text = prefix(full, kib * 1024);
        let iters = if kib > 256 { 11 } else { 41 };
        let pii_changed = changes(&pii, text);
        let secrets_changed = changes(&secrets, text);
        let rows = [
            ("pii", time_scanner(&pii, text, iters), pii_changed),
            (
                "secrets",
                time_scanner(&secrets, text, iters),
                secrets_changed,
            ),
            (
                "stack",
                time_stack(text, iters),
                pii_changed || secrets_changed,
            ),
        ];
        for (name, median, changed) in rows {
            println!("{name}_{kib}k,{median:.1},{}", u8::from(changed));
        }
    }
}
