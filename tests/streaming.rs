//! Streaming output-runner tests. The headline is the no-leak property: a
//! secret split across chunk boundaries must be FULLY redacted — the stream
//! must never emit a non-empty prefix of it. The rest pin sentinel-across-chunks
//! restore, the `WholeStream` buffer-and-gate (block + pass), a clean stream's
//! bounded hold-back, and streaming ≡ unary `run_output`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::middleware::stream::StreamOutput;
use cerberust::{
    BanSubstringsScanner, BanTopicsScanner, Direction, MiddlewareChain, Params, PiiScanner,
    RestoreScanner, Scanner, ScannerId, ScannerStack, SecretScanner, Topic,
};

/// A valid-Luhn test card the model emits; the `Sensitive` output scanner masks
/// it `OneWay` (it has no vault entry — it originated in the response).
const MODEL_CARD: &str = "4111 1111 1111 1111";

/// An AWS key the secret scanner redacts via the `AKIA[0-9A-Z]{16}` pattern.
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// The distinctive prefixes of `secret` — every prefix from the 4-char vendor
/// marker (`AKIA`) up to one byte short of the whole key. These begin with a
/// marker that appears in neither clean prose nor the redaction sentinel, so a
/// match in the streamed output is unambiguously a leaked partial key. (Single-
/// character prefixes like "A" are not distinctive — they occur in the sentinel
/// itself — so the property is stated over distinctive prefixes.)
fn distinctive_prefixes(secret: &str) -> Vec<&str> {
    (4..secret.len()).map(|i| &secret[..i]).collect()
}

/// Replace each sentinel's 8-hex random nonce with a fixed marker so two stacks
/// (each with its own random vault nonce) compare structurally.
fn normalize_nonces(s: &str) -> String {
    let re = regex::Regex::new(r"_[0-9a-f]{8}\]").unwrap();
    re.replace_all(s, "_NONCE]").into_owned()
}

fn output_secret_stack() -> ScannerStack {
    let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(
        SecretScanner::new().with_direction(Direction::Output),
    )];
    ScannerStack::new(scanners, true)
}

/// Drive a single response string through the streaming runner one slice of
/// `chunk_len` bytes at a time, returning every emitted piece in order. After
/// each push the closure `check` sees the cumulative emitted output, so a test
/// can assert the no-leak invariant at every step.
fn run_chunked(
    stack: &mut ScannerStack,
    response: &str,
    chunk_len: usize,
    mut check: impl FnMut(&str),
) -> String {
    let mut runner = StreamOutput::new(stack);
    let mut emitted = String::new();
    let bytes = response.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Advance to a char boundary so each chunk is valid UTF-8.
        let mut end = (i + chunk_len).min(bytes.len());
        while end < bytes.len() && bytes[end] & 0xC0 == 0x80 {
            end += 1;
        }
        let chunk = std::str::from_utf8(&bytes[i..end]).unwrap();
        let safe = runner.push(chunk).unwrap();
        emitted.push_str(&safe);
        check(&emitted);
        i = end;
    }
    let tail = runner.finish().unwrap();
    emitted.push_str(&tail);
    check(&emitted);
    emitted
}

#[test]
fn split_secret_is_never_half_emitted() {
    // THE critical test: feed a secret 1 char at a time and assert the cumulative
    // emitted output never contains any non-empty prefix of the key — until the
    // full sentinel has replaced it (no prefix survives in the final output).
    let response = format!("my key is {AWS_KEY} thanks");
    let prefixes = distinctive_prefixes(AWS_KEY);
    let mut stack = output_secret_stack();
    let emitted = run_chunked(&mut stack, &response, 1, |out| {
        for p in &prefixes {
            assert!(
                !out.contains(p),
                "leaked secret prefix {p:?} in streamed output {out:?}",
            );
        }
    });
    // The key is gone, replaced by its OneWay sentinel; surrounding prose stays.
    assert!(!emitted.contains(AWS_KEY));
    assert!(emitted.contains("[REDACTED_AWS_ACCESS_KEY_1_"));
    assert!(emitted.starts_with("my key is "));
    assert!(emitted.ends_with(" thanks"));
}

#[test]
fn split_secret_never_leaks_at_any_chunk_size() {
    // The no-leak property holds for every chunking, not just 1-char chunks.
    let response = format!("prefix {AWS_KEY} suffix");
    let prefixes = distinctive_prefixes(AWS_KEY);
    for chunk_len in 1..=7 {
        let mut stack = output_secret_stack();
        let emitted = run_chunked(&mut stack, &response, chunk_len, |out| {
            for p in &prefixes {
                assert!(
                    !out.contains(p),
                    "leaked {p:?} at chunk_len {chunk_len} in {out:?}",
                );
            }
        });
        assert!(emitted.contains("[REDACTED_AWS_ACCESS_KEY_1_"));
        assert!(!emitted.contains(AWS_KEY));
    }
}

#[test]
fn sentinel_spanning_chunks_restores_fully() {
    // A PII round-trip: the input redacts an email to a sentinel, the model
    // echoes the sentinel back, and the streamed restore must rehydrate it even
    // when the sentinel straddles chunk boundaries — never emitting a partial
    // sentinel that the restorer could not match.
    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(PiiScanner::new()),
        Box::new(RestoreScanner::for_pii()),
    ];
    let mut stack = ScannerStack::new(scanners, true);
    // Input pass interns the email and gives us the sentinel to feed back.
    let redacted = stack.run_input("contact alice@example.com now").unwrap();
    assert!(redacted.contains("[REDACTED_EMAIL_1_"));

    for chunk_len in 1..=6 {
        // A fresh runner per chunk size; the same stack/vault drives restore.
        let mut runner = StreamOutput::new(&mut stack);
        let mut emitted = String::new();
        let bytes = redacted.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let end = (i + chunk_len).min(bytes.len());
            let chunk = std::str::from_utf8(&bytes[i..end]).unwrap();
            emitted.push_str(&runner.push(chunk).unwrap());
            // A partial sentinel must never escape: if any `[REDACTED…` opened,
            // it is only ever emitted complete (post-restore it is the email).
            i = end;
        }
        emitted.push_str(&runner.finish().unwrap());
        assert_eq!(
            emitted, "contact alice@example.com now",
            "restore failed at chunk_len {chunk_len}",
        );
        assert!(!emitted.contains("[REDACTED_EMAIL"));
    }
}

#[test]
fn whole_stream_scanner_buffers_then_passes_clean() {
    // A blocking ban-topics scanner declares WholeStream: the runner emits
    // nothing until finish, then passes a clean response through whole.
    let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(
        BanTopicsScanner::new([Topic::new("violence", ["weapon".to_owned()])])
            .with_direction(Direction::Output),
    )];
    let mut stack = ScannerStack::new(scanners, true);
    let mut runner = StreamOutput::new(&mut stack);
    let mut emitted = String::new();
    for chunk in ["the weather ", "is nice ", "today"] {
        let safe = runner.push(chunk).unwrap();
        // Mode B emits nothing mid-stream: first-token latency = full generation.
        assert!(safe.is_empty());
        emitted.push_str(&safe);
    }
    assert!(emitted.is_empty());
    emitted.push_str(&runner.finish().unwrap());
    assert_eq!(emitted, "the weather is nice today");
}

#[test]
fn whole_stream_scanner_blocks_on_banned_response() {
    let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(
        BanTopicsScanner::new([Topic::new("violence", ["weapon".to_owned()])])
            .with_direction(Direction::Output),
    )];
    let mut stack = ScannerStack::new(scanners, true);
    let mut runner = StreamOutput::new(&mut stack);
    for chunk in ["how to ", "build a ", "weapon"] {
        assert!(runner.push(chunk).unwrap().is_empty());
    }
    // The full buffered response trips the ban: finish blocks the whole turn.
    assert!(runner.finish().is_err());
}

#[test]
fn output_phrase_gate_blocks_phrase_split_across_chunks() {
    // A full-text OUTPUT phrase gate (Block + WholeStream) buffers the whole
    // response, so it catches a forbidden phrase even when chunked mid-phrase —
    // Mode B sees the joined buffer the incremental DFA never would.
    let phrase = "as an ai language model";
    let scanners: Vec<Box<dyn Scanner>> =
        vec![Box::new(BanSubstringsScanner::output_phrase_gate([
            phrase.to_owned()
        ]))];
    let mut stack = ScannerStack::new(scanners, true);
    let mut runner = StreamOutput::new(&mut stack);
    // Split the phrase across several chunks: no single chunk contains it whole.
    for chunk in ["Sure! As an ", "AI language ", "model, I refuse."] {
        assert!(runner.push(chunk).unwrap().is_empty());
    }
    assert!(runner.finish().is_err());
}

#[test]
fn output_phrase_gate_passes_when_phrase_absent() {
    let scanners: Vec<Box<dyn Scanner>> =
        vec![Box::new(BanSubstringsScanner::output_phrase_gate([
            "forbidden phrase".to_owned(),
        ]))];
    let mut stack = ScannerStack::new(scanners, true);
    let mut runner = StreamOutput::new(&mut stack);
    for chunk in ["a perfectly ", "ordinary ", "answer"] {
        assert!(runner.push(chunk).unwrap().is_empty());
    }
    assert_eq!(runner.finish().unwrap(), "a perfectly ordinary answer");
}

#[test]
fn coexistence_restores_input_pii_and_redacts_model_pii_one_pass() {
    // The coexistence invariant: in ONE output pass the caller's input email is
    // RESTORED from its `[EMAIL_1]` sentinel (RoundTrip), while a credit card the
    // model freshly emitted is REDACTED (OneWay, no vault entry to round-trip).
    // Output runs LIFO (last pushed runs first). Two coupled constraints make
    // both halves coexist in one pass:
    //   1. The sensitive redactor must run BEFORE restore, so it masks the
    //      model's raw card while the caller's email is still a sentinel — it
    //      never sees, and so never re-masks, the restored email.
    //   2. Restore is scoped to the entity types actually anonymized on input
    //      (here EMAIL), so it rehydrates the caller's sentinel and leaves the
    //      model's freshly-minted CREDIT_CARD sentinel masked.
    // Pushing restore first, sensitive second gives `.rev()` order
    // sensitive→restore — the redactor first, restore last.
    let restore_email_only =
        RestoreScanner::for_types(ScannerId("native:pii-restore"), ["EMAIL".to_owned()]);
    let scanners: Vec<Box<dyn Scanner>> = vec![
        // Input: redact the caller's PII into the vault for round-trip.
        Box::new(PiiScanner::new()),
        // Output, runs LAST under LIFO: rehydrate only the caller's EMAIL sentinel.
        Box::new(restore_email_only),
        // Output, runs FIRST under LIFO: mask PII the model itself emitted.
        Box::new(PiiScanner::sensitive_output()),
    ];
    let mut stack = ScannerStack::new(scanners, true);

    let redacted = stack.run_input("contact alice@example.com").unwrap();
    assert!(redacted.contains("[REDACTED_EMAIL_1_"));
    let sentinel = redacted
        .split_whitespace()
        .find(|t| t.starts_with("[REDACTED_EMAIL_1_"))
        .unwrap();

    // The model echoes the sentinel (the caller's email) and leaks a fresh card.
    let response = format!("re {sentinel}, your card {MODEL_CARD} is on file");

    let unary = stack.run_output(&response).unwrap();
    assert!(unary.contains("alice@example.com"));
    assert!(!unary.contains(MODEL_CARD));
    assert!(unary.contains("[REDACTED_CREDIT_CARD_"));

    // The same holds over the streamed runner, every chunking. The vault counter
    // persists across passes, so assert on the card label, not a fixed index.
    for chunk_len in 1..=7 {
        let mut runner = StreamOutput::new(&mut stack);
        let mut emitted = String::new();
        let bytes = response.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let mut end = (i + chunk_len).min(bytes.len());
            while end < bytes.len() && bytes[end] & 0xC0 == 0x80 {
                end += 1;
            }
            let chunk = std::str::from_utf8(&bytes[i..end]).unwrap();
            emitted.push_str(&runner.push(chunk).unwrap());
            i = end;
        }
        emitted.push_str(&runner.finish().unwrap());
        assert!(
            emitted.contains("alice@example.com"),
            "input PII not restored at chunk_len {chunk_len}: {emitted:?}",
        );
        assert!(
            !emitted.contains(MODEL_CARD),
            "model card leaked at chunk_len {chunk_len}: {emitted:?}",
        );
        assert!(
            emitted.contains("[REDACTED_CREDIT_CARD_"),
            "model card not redacted at chunk_len {chunk_len}: {emitted:?}",
        );
    }
}

#[test]
fn clean_stream_passes_with_eventually_zero_holdback() {
    // A clean stream through a secret-redacting output stack must flush all its
    // text by EOF — no bytes stuck in the carry buffer.
    let mut stack = output_secret_stack();
    let response = "the quick brown fox jumps over the lazy dog";
    let emitted = run_chunked(&mut stack, response, 3, |_| {});
    assert_eq!(emitted, response);
}

#[test]
fn streaming_equals_unary_run_output() {
    // Streaming ≡ unary: for every chunking, the concatenated streamed output
    // equals the unary `run_output` of the whole response.
    let response = format!(
        "ship {AWS_KEY} to alice@example.com and ghp_{} now",
        "a".repeat(36)
    );
    for chunk_len in 1..=9 {
        let mut unary_stack = output_secret_stack();
        let unary = unary_stack.run_output(&response).unwrap();

        let mut stream_stack = output_secret_stack();
        let streamed = run_chunked(&mut stream_stack, &response, chunk_len, |_| {});
        assert_eq!(
            normalize_nonces(&streamed),
            normalize_nonces(&unary),
            "stream != unary at chunk_len {chunk_len}",
        );
    }
}

proptest::proptest! {
    /// For any chunking of any input containing the secret and a vault sentinel,
    /// the concatenated streamed output equals the unary `run_output` (modulo the
    /// per-stack random nonce) — streaming is identical to unary.
    #[test]
    fn prop_streaming_equals_unary(
        head in "[a-z ]{0,12}",
        mid in "[a-z ]{0,12}",
        tail in "[a-z ]{0,12}",
        chunk_len in 1usize..=8,
    ) {
        let response = format!("{head}{AWS_KEY}{mid} alice@example.com {tail}");

        let mut unary_stack = output_secret_stack();
        let unary = unary_stack.run_output(&response).unwrap();

        let mut stream_stack = output_secret_stack();
        let streamed = run_chunked(&mut stream_stack, &response, chunk_len, |_| {});

        proptest::prop_assert_eq!(normalize_nonces(&streamed), normalize_nonces(&unary));
    }

    /// For any chunking, no distinctive prefix of the secret ever appears in the
    /// streamed output — the no-leak property as a property test.
    #[test]
    fn prop_secret_never_half_emitted(
        head in "[a-z ]{0,16}",
        tail in "[a-z ]{0,16}",
        chunk_len in 1usize..=6,
    ) {
        let response = format!("{head}{AWS_KEY}{tail}");
        let prefixes = distinctive_prefixes(AWS_KEY);
        let mut stack = output_secret_stack();
        let emitted = run_chunked(&mut stack, &response, chunk_len, |_| {});
        for p in &prefixes {
            proptest::prop_assert!(!emitted.contains(p), "leaked {:?}", p);
        }
    }
}

#[test]
fn runner_wires_through_the_middleware_chain() {
    use cerberust::{Chunk, GuardrailRunner, StreamModel};

    // A streamed model that emits the response one char at a time.
    struct CharModel(String);
    impl StreamModel for CharModel {
        fn stream(&self, _params: &Params) -> Box<dyn Iterator<Item = Chunk> + '_> {
            Box::new(self.0.chars().map(|c| Ok(c.to_string())))
        }
    }

    let runner = GuardrailRunner::new("native:guard", output_secret_stack());
    let chain = MiddlewareChain::new(vec![&runner]);
    let model = CharModel(format!("here {AWS_KEY} ok"));
    let chunks = chain.stream(Params::new("ignored"), &model).unwrap();
    let joined: String = chunks.concat();
    assert!(!joined.contains(AWS_KEY));
    assert!(joined.contains("[REDACTED_AWS_ACCESS_KEY_1_"));
}
