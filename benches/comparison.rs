//! The cerberust side of the LLM Guard comparison.
//!
//! Reads the shared labeled corpus (`benchmarks/corpus/corpus.jsonl`), runs each
//! cerberust scanner that overlaps an LLM Guard scanner, and measures two things
//! per scanner:
//!
//! * **speed** — wall-clock throughput in samples/sec over the whole corpus,
//!   timed across repeated passes after a warm-up so per-call regex compilation
//!   (memoized in a `OnceLock`) is not charged to the measured runs.
//! * **detection** — precision/recall of the scanner's flag against the corpus
//!   ground-truth label, where "flag" means the scanner redacted at least one
//!   span (PII/secrets/regex) or returned `valid = false` (the block scanners
//!   and the ML prompt-injection scanner).
//!
//! Results are written to `benchmarks/results/cerberust.json` for the Python
//! side (`benchmarks/compare.py`) to merge into `RESULTS.md`. This is a custom
//! `harness = false` bench: a plain `main()` so it can read a corpus path, emit
//! JSON, and feature-gate the ML scanner — `criterion` cannot do those.
//!
//! Run:
//! ```sh
//! cargo bench --bench comparison                         # regex scanners only
//! CERBERUST_MODEL_DIR=… cargo bench --features prompt-injection --bench comparison
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::panic,
    clippy::cast_precision_loss,
    reason = "a standalone benchmark binary: it reports to stdout, fails loudly on a bad corpus or missing model, and the usize→f64 sample counts are far below the f64 mantissa limit so the throughput cast is exact"
)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use cerberust::scanners::{BanSubstringsScanner, PiiScanner, RegexScanner, SecretScanner};
use cerberust::{Disposition, ScanCtx, Scanner};

/// One corpus row: the text and the three ground-truth labels.
struct Sample {
    text: String,
    pii: bool,
    secret: bool,
    injection: bool,
}

/// A confusion-matrix tally and the derived precision/recall.
#[derive(Default, Clone, Copy)]
struct Metrics {
    tp: u32,
    fp: u32,
    f_n: u32,
    tn: u32,
}

impl Metrics {
    fn observe(&mut self, predicted: bool, actual: bool) {
        match (predicted, actual) {
            (true, true) => self.tp += 1,
            (true, false) => self.fp += 1,
            (false, true) => self.f_n += 1,
            (false, false) => self.tn += 1,
        }
    }

    fn precision(self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            1.0
        } else {
            f64::from(self.tp) / f64::from(denom)
        }
    }

    fn recall(self) -> f64 {
        let denom = self.tp + self.f_n;
        if denom == 0 {
            1.0
        } else {
            f64::from(self.tp) / f64::from(denom)
        }
    }
}

/// One scanner's measured numbers, serialized into the results JSON.
struct ScannerResult {
    name: String,
    samples_per_sec: f64,
    metrics: Metrics,
}

/// Parse one JSONL row by hand — the corpus is flat string/bool fields, so a
/// dependency-free reader keeps the bench off the `serde` tree the crate does
/// not otherwise carry.
fn parse_sample(line: &str) -> Option<Sample> {
    let text = json_string_field(line, "text")?;
    Some(Sample {
        text,
        pii: json_bool_field(line, "pii"),
        secret: json_bool_field(line, "secret"),
        injection: json_bool_field(line, "injection"),
    })
}

/// Extract a JSON string field's value, decoding the escapes the corpus
/// generator emits (`\"`, `\\`, `\n`, `\t`, `\/`).
fn json_string_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":");
    let start = line.find(&needle)? + needle.len();
    let rest = line[start..].trim_start();
    let mut chars = rest.char_indices();
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for (_, c) in chars {
        if escaped {
            out.push(match c {
                'n' => '\n',
                't' => '\t',
                other => other,
            });
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

/// Read a JSON boolean field, defaulting to `false` if absent.
fn json_bool_field(line: &str, key: &str) -> bool {
    let needle = format!("\"{key}\":");
    match line.find(&needle) {
        Some(idx) => line[idx + needle.len()..].trim_start().starts_with("true"),
        None => false,
    }
}

/// Load the corpus from `CERBERUST_CORPUS` or the default repo path.
fn load_corpus() -> Vec<Sample> {
    let path = std::env::var("CERBERUST_CORPUS").map_or_else(
        |_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("benchmarks")
                .join("corpus")
                .join("corpus.jsonl")
        },
        PathBuf::from,
    );
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read corpus {}: {e}", path.display()));
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(parse_sample)
        .collect()
}

/// Does this scanner flag `text`? A `Transform` scanner flags when it rewrites
/// (redacted ≥1 span); a `Block` scanner flags when it returns `valid = false`.
fn flags(scanner: &dyn Scanner, text: &str) -> bool {
    let mut ctx = ScanCtx::new();
    let verdict = scanner.scan(text, &mut ctx).unwrap();
    match scanner.disposition() {
        Disposition::Transform => verdict.text != text,
        Disposition::Block => !verdict.valid,
    }
}

/// Run one scanner across the corpus: score detection once, then time repeated
/// passes for throughput. `label` selects which ground-truth column is truth.
fn run_scanner(
    name: &str,
    scanner: &dyn Scanner,
    corpus: &[Sample],
    label: impl Fn(&Sample) -> bool,
) -> ScannerResult {
    let mut metrics = Metrics::default();
    for sample in corpus {
        metrics.observe(flags(scanner, &sample.text), label(sample));
    }

    // Warm-up pass (regex compilation memoizes in a OnceLock on first use).
    for sample in corpus {
        let _ = flags(scanner, &sample.text);
    }

    let passes = 50;
    let start = Instant::now();
    for _ in 0..passes {
        for sample in corpus {
            let _ = flags(scanner, &sample.text);
        }
    }
    let elapsed = start.elapsed();
    let total = (passes * corpus.len()) as f64;
    let samples_per_sec = total / elapsed.as_secs_f64();

    ScannerResult {
        name: name.to_owned(),
        samples_per_sec,
        metrics,
    }
}

/// Run the ML prompt-injection scanner (timed once per sample — inference
/// dominates, so a single pass is the honest throughput; no repeat loop).
#[cfg(feature = "prompt-injection")]
fn run_prompt_injection(corpus: &[Sample]) -> Option<ScannerResult> {
    use cerberust::PromptInjectionScanner;

    let dir = std::env::var("CERBERUST_MODEL_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.cache/cerberust/deberta-v3-base-prompt-injection-v2")
    });
    let scanner = match PromptInjectionScanner::from_dir(&dir) {
        Ok(s) => s,
        Err(e) => {
            println!("skipping prompt-injection (model load failed): {e}");
            return None;
        }
    };

    // One warm-up inference (ORT lazily allocates on the first run).
    if let Some(first) = corpus.first() {
        let _ = flags(&scanner, &first.text);
    }

    let mut metrics = Metrics::default();
    let start = Instant::now();
    for sample in corpus {
        metrics.observe(flags(&scanner, &sample.text), sample.injection);
    }
    let elapsed = start.elapsed();
    let samples_per_sec = corpus.len() as f64 / elapsed.as_secs_f64();

    Some(ScannerResult {
        name: "PromptInjection".to_owned(),
        samples_per_sec,
        metrics,
    })
}

/// Serialize the results to JSON by hand (no serde dependency in this crate).
fn write_json(results: &[ScannerResult]) {
    let mut body = String::from("{\n  \"engine\": \"cerberust\",\n  \"scanners\": [\n");
    for (i, r) in results.iter().enumerate() {
        let comma = if i + 1 < results.len() { "," } else { "" };
        let _ = writeln!(
            body,
            "    {{\"scanner\": \"{}\", \"samples_per_sec\": {:.2}, \
             \"precision\": {:.4}, \"recall\": {:.4}, \
             \"tp\": {}, \"fp\": {}, \"fn\": {}, \"tn\": {}}}{comma}",
            r.name,
            r.samples_per_sec,
            r.metrics.precision(),
            r.metrics.recall(),
            r.metrics.tp,
            r.metrics.fp,
            r.metrics.f_n,
            r.metrics.tn,
        );
    }
    body.push_str("  ]\n}\n");

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("benchmarks")
        .join("results")
        .join("cerberust.json");
    if let Some(parent) = out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&out, body).unwrap_or_else(|e| panic!("write {}: {e}", out.display()));
    println!("wrote {}", out.display());
}

fn report(r: &ScannerResult) {
    println!(
        "  {:<16} {:>12.0} samples/s   P={:.3} R={:.3}  (tp={} fp={} fn={} tn={})",
        r.name,
        r.samples_per_sec,
        r.metrics.precision(),
        r.metrics.recall(),
        r.metrics.tp,
        r.metrics.fp,
        r.metrics.f_n,
        r.metrics.tn,
    );
}

fn main() {
    let corpus = load_corpus();
    println!("cerberust benchmark over {} samples\n", corpus.len());

    let mut results = Vec::new();

    // PII vs LLM Guard Anonymize.
    results.push(run_scanner("PII", &PiiScanner::new(), &corpus, |s| s.pii));

    // Secrets vs LLM Guard Secrets.
    results.push(run_scanner(
        "Secrets",
        &SecretScanner::new(),
        &corpus,
        |s| s.secret,
    ));

    // Regex vs LLM Guard Regex: a caller-supplied email pattern, redacting, so
    // both sides do the same job (flag/redact a configured pattern). Scored
    // against the PII label since the pattern targets emails — the comparison is
    // matcher speed on an identical regex task.
    let (regex_scanner, errs) = RegexScanner::from_patterns([(
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
        "EMAIL",
    )]);
    assert!(errs.is_empty(), "{errs:?}");
    results.push(run_scanner("Regex", &regex_scanner, &corpus, |s| {
        s.text.contains('@') && s.pii
    }));

    // BanSubstrings vs LLM Guard BanSubstrings: block on injection trigger
    // phrases. Scored against the injection label (literal-substring detection,
    // not the ML model) — the keyword baseline both libraries expose.
    let ban = BanSubstringsScanner::new(
        [
            "ignore all previous instructions",
            "ignore previous instructions",
            "disregard the above",
            "system override",
            "you are now dan",
        ]
        .into_iter()
        .map(str::to_owned),
    )
    .case_insensitive();
    results.push(run_scanner("BanSubstrings", &ban, &corpus, |s| s.injection));

    #[cfg(feature = "prompt-injection")]
    if let Some(pi) = run_prompt_injection(&corpus) {
        results.push(pi);
    }
    #[cfg(not(feature = "prompt-injection"))]
    println!("(prompt-injection feature off — ML scanner not benched)");

    println!();
    for r in &results {
        report(r);
    }
    println!();
    write_json(&results);
}
