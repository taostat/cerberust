#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "tests construct known-good scanners and assert their behavior"
)]

#[cfg(any(feature = "prompt-injection", feature = "wasm"))]
use std::sync::OnceLock;

use cerberust::{
    BanSubstringsScanner, BanTopicsScanner, Direction, PiiScanner, RegexRule, RegexScanner,
    RestoreScanner, ScanCtx, Scanner, SecretScanner, TokenLimitScanner, Topic,
};
use proptest::prelude::*;

#[cfg(feature = "prompt-injection")]
use std::path::PathBuf;

#[cfg(feature = "prompt-injection")]
use cerberust::PromptInjectionScanner;

#[cfg(feature = "wasm")]
use cerberust::{Disposition, ScannerId, WasmScanner};

fn arbitrary_unicode() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![Just('é'), Just('漢'), Just('😀'), any::<char>()],
        0..48,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn scan_without_panicking(scanner: &dyn Scanner, text: &str) {
    let mut ctx = ScanCtx::new();
    match scanner.scan(text, &mut ctx) {
        Ok(_) | Err(_) => {}
    }
}

fn append_match_context(text: &mut String, values: &[String]) {
    for value in values.iter().filter(|value| !value.is_empty()) {
        // Exercise both a rejected left boundary and a later accepted match.
        text.push('x');
        text.push_str(value);
        text.push(' ');
        text.push_str(value);
        text.push(' ');
    }
}

#[cfg(feature = "wasm")]
fn wasm_scanner() -> &'static WasmScanner {
    static SCANNER: OnceLock<WasmScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        WasmScanner::from_bytes(
            include_bytes!("fixtures/redact-foo-guard.wasm"),
            ScannerId("wasm:unicode-proptest"),
            Direction::Input,
            Disposition::Block,
        )
        .expect("committed example guard loads")
    })
}

#[cfg(feature = "prompt-injection")]
fn prompt_injection_scanner() -> &'static PromptInjectionScanner {
    static SCANNER: OnceLock<PromptInjectionScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let dir = std::env::var_os("CERBERUST_MODEL_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| {
                    PathBuf::from(home).join(".cache/cerberust/deberta-v3-base-prompt-injection-v2")
                })
            })
            .expect("CERBERUST_MODEL_DIR or HOME is set");
        PromptInjectionScanner::from_dir(dir)
            .expect("model files load (run scripts/fetch-model.sh)")
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        // Keep the default gate's generated cases and runtime reproducible.
        rng_seed: proptest::test_runner::RngSeed::Fixed(1),
        ..ProptestConfig::default()
    })]

    #[test]
    fn non_ml_scanners_handle_arbitrary_unicode(
        text in arbitrary_unicode(),
        topic_name in arbitrary_unicode(),
        keywords in prop::collection::vec(arbitrary_unicode(), 0..5),
        substrings in prop::collection::vec(arbitrary_unicode(), 0..5),
        regex_literal in arbitrary_unicode(),
        max_tokens in any::<usize>(),
    ) {
        let mut probe = text;
        append_match_context(&mut probe, &keywords);
        append_match_context(&mut probe, &substrings);
        append_match_context(&mut probe, std::slice::from_ref(&regex_literal));

        scan_without_panicking(&PiiScanner::new(), &probe);
        scan_without_panicking(&PiiScanner::sensitive_output(), &probe);
        scan_without_panicking(&SecretScanner::new(), &probe);
        scan_without_panicking(
            &SecretScanner::new().with_direction(Direction::Output),
            &probe,
        );
        scan_without_panicking(&TokenLimitScanner::new(max_tokens), &probe);
        scan_without_panicking(
            &BanSubstringsScanner::new(substrings.clone()),
            &probe,
        );
        scan_without_panicking(
            &BanSubstringsScanner::new(substrings.clone())
                .case_insensitive()
                .redacting(),
            &probe,
        );
        scan_without_panicking(
            &BanSubstringsScanner::output_phrase_gate(substrings.clone()),
            &probe,
        );
        scan_without_panicking(
            &BanTopicsScanner::new([Topic::new(topic_name, keywords)]),
            &probe,
        );

        // The empty literal is also a valid caller-supplied regex; exercise its
        // zero-width matches instead of replacing it with an empty rule set.
        let escaped = regex::escape(&regex_literal);
        let regex_scanner = RegexScanner::new(vec![
            RegexRule::new(&escaped, "UNICODE_LITERAL")
                .expect("an escaped literal is a valid regex"),
        ]);
        scan_without_panicking(&regex_scanner, &probe);
        scan_without_panicking(&RestoreScanner::for_pii(), &probe);

        let mut restore_ctx = ScanCtx::new();
        if let Ok(redacted) = PiiScanner::new().scan(&probe, &mut restore_ctx) {
            match RestoreScanner::for_pii().scan(redacted.text.as_ref(), &mut restore_ctx) {
                Ok(_) | Err(_) => {}
            }
        }

        #[cfg(feature = "wasm")]
        scan_without_panicking(wasm_scanner(), &probe);
    }
}

#[cfg(feature = "prompt-injection")]
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 8,
        rng_seed: proptest::test_runner::RngSeed::Fixed(1),
        ..ProptestConfig::default()
    })]

    #[test]
    #[ignore = "loads the ~739MB DeBERTa-v3 model; run with --ignored after scripts/fetch-model.sh"]
    fn prompt_injection_handles_arbitrary_unicode(text in arbitrary_unicode()) {
        scan_without_panicking(prompt_injection_scanner(), &text);
    }
}
