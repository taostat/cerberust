//! Scan-time benchmark on real source and prose with no redactions, used by the
//! CI perf gate (`scripts/perf-gate.sh`).
//!
//! `perf_gate clean <list>` prints each listed UTF-8 file that neither the PII
//! nor the secrets scanner changes; other files are reported on stderr.
//! `perf_gate bench <label> <list>` builds a corpus from the listed files and
//! prints one CSV row per case: `<label>_<scan>_<size>,median_us,changed`.
//! `changed` is 1 when the scan altered the input.
//!
//! Each file contributes at most `128 KiB / file count` bytes including its
//! separator, so every file is in the 128 KiB case and no single large file
//! decides the result. Every timed sample must contain non-ASCII text, so the
//! scanners' Unicode paths are always timed.
//!
//! The example uses only the public API, so the CI job can copy it into the
//! base revision and time both revisions with the same code.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "standalone benchmark reports measurements to stdout"
)]

use std::hint::black_box;
use std::time::Instant;

use cerberust::scanners::{PiiScanner, SecretScanner};
use cerberust::{ScanCtx, Scanner, ScannerStack};

const SIZES_KIB: [usize; 2] = [128, 1024];

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, list] if mode == "clean" => {
            print_clean(&read_list(list)?);
            Ok(())
        }
        [mode, label, list] if mode == "bench" => bench(label, &corpus(&read_list(list)?)?),
        _ => Err(
            "usage: perf_gate clean <file-list> | perf_gate bench <label> <file-list>".to_owned(),
        ),
    }
}

fn read_list(list: &str) -> Result<Vec<String>, String> {
    Ok(std::fs::read_to_string(list)
        .map_err(|err| format!("read file list {list}: {err}"))?
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

fn changes(scanner: &dyn Scanner, text: &str) -> bool {
    scanner.scan(text, &mut ScanCtx::new()).unwrap().text != text
}

fn print_clean(paths: &[String]) {
    let (pii, secrets) = (PiiScanner::new(), SecretScanner::new());
    for path in paths {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("skipping {path}: {err}");
                continue;
            }
        };
        if !changes(&pii, &text) && !changes(&secrets, &text) {
            println!("{path}");
        }
    }
}

fn corpus(paths: &[String]) -> Result<String, String> {
    if paths.is_empty() {
        return Err("file list is empty".to_owned());
    }
    let share = (SIZES_KIB[0] * 1024 / paths.len()).saturating_sub(1);
    if share == 0 {
        return Err(format!(
            "{} files leave no room per file in 128 KiB",
            paths.len()
        ));
    }
    let mut unit = String::new();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|err| format!("read {path}: {err}"))?;
        unit.push_str(prefix(&text, share));
        unit.push('\n');
    }
    if unit.trim().is_empty() {
        return Err("file list produced an empty corpus".to_owned());
    }
    let mut text = unit.clone();
    while text.len() < SIZES_KIB[SIZES_KIB.len() - 1] * 1024 {
        text.push_str(&unit);
    }
    Ok(text)
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

fn bench(label: &str, full: &str) -> Result<(), String> {
    let (pii, secrets) = (PiiScanner::new(), SecretScanner::new());
    for kib in SIZES_KIB {
        let text = prefix(full, kib * 1024);
        if text.is_ascii() {
            return Err(format!(
                "{label} {kib} KiB sample has no non-ASCII text; add files that contain some"
            ));
        }
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
            println!("{label}_{name}_{kib}k,{median:.1},{}", u8::from(changed));
        }
    }
    Ok(())
}
