//! Streaming no-leak tests for the vendor secret formats.
//!
//! Every token below is built at test time from a fixed alphabet, so no
//! credential-shaped literal is committed. Each is streamed inside prose at
//! chunk sizes 1..=8; the emitted output must contain no 12-byte fragment of the
//! secret at any point, and the final output must redact it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::middleware::stream::StreamOutput;
use cerberust::scanner::detect::detect_secrets;
use cerberust::{Direction, Scanner, ScannerStack, SecretScanner};

const HEX: &str = "7c0e9b4a1d2f3e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c";
const ALNUM: &str = "Q7wE2r9T4y1U8i3O6p0A5sDf3Gh8Jk1Lz4Xc7Vb2Nm6Qa9Ws5Ed0Rf3Tg7Yh1Uj4Ik8Ol2Pz6Xm";

fn take(alphabet: &str, n: usize) -> String {
    alphabet.chars().cycle().take(n).collect()
}

/// `(expected type, secret)` for each Taostats format and a sample of ported
/// gitleaks rules with distinct shapes (fixed prefix, prefix + separator,
/// keyword outside the token, JWT).
fn secrets() -> Vec<(&'static str, String)> {
    vec![
        ("GM_API_KEY", format!("gm_live_{HEX}")),
        ("BLOCKMACHINE_API_KEY", format!("bm_live_{HEX}")),
        ("TAOSTATS_API_KEY", format!("ts_live_{HEX}")),
        (
            "TAOSTATS_API_KEY",
            format!(
                "tao-{}-{}-{}-{}-{}:{}",
                &HEX[..8],
                &HEX[8..12],
                &HEX[12..16],
                &HEX[16..20],
                &HEX[20..32],
                &HEX[32..40]
            ),
        ),
        (
            "GITHUB_FINE_GRAINED_PAT",
            format!("github_pat_{}", take(ALNUM, 82)),
        ),
        ("GITLAB_PAT", format!("glpat-{}", take(ALNUM, 20))),
        (
            "NPM_ACCESS_TOKEN",
            format!("npm_{}", take(&ALNUM.to_lowercase(), 36)),
        ),
        (
            "SLACK_BOT_TOKEN",
            // Assembled so the source holds no token-shaped literal.
            format!(
                "{}-{n}-{n}-{}",
                "xoxb",
                take(ALNUM, 24),
                n = "1234567890123"
            ),
        ),
        (
            "ANTHROPIC_API_KEY",
            format!("sk-ant-api03-{}AA", take(ALNUM, 93)),
        ),
    ]
}

fn stack() -> ScannerStack {
    let scanners: Vec<Box<dyn Scanner>> = vec![Box::new(
        SecretScanner::new().with_direction(Direction::Output),
    )];
    ScannerStack::new(scanners, true)
}

fn fragments(secret: &str) -> Vec<&str> {
    (0..=secret.len().saturating_sub(12))
        .map(|i| &secret[i..i + 12])
        .collect()
}

fn stream(response: &str, chunk_len: usize, secret: &str) -> String {
    let mut stack = stack();
    let mut runner = StreamOutput::new(&stack);
    let frags = fragments(secret);
    let mut emitted = String::new();
    let bytes = response.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + chunk_len).min(bytes.len());
        emitted.push_str(&runner.push(&mut stack, &response[i..end]).unwrap());
        for f in &frags {
            assert!(
                !emitted.contains(f),
                "leaked {f:?} (chunk_len {chunk_len}) in {emitted:?}"
            );
        }
        i = end;
    }
    emitted.push_str(&runner.finish(&mut stack).unwrap());
    emitted
}

#[test]
fn samples_are_detected_unary() {
    for (ty, secret) in secrets() {
        let text = format!("value {secret} end");
        assert!(
            detect_secrets(&text).iter().any(|s| s.ty == ty),
            "{ty} not detected unary"
        );
    }
}

#[test]
fn vendor_secrets_never_leak_at_any_chunk_size() {
    for (ty, secret) in secrets() {
        let response = format!("here is the key {secret} ok\n");
        for chunk_len in 1..=8 {
            let emitted = stream(&response, chunk_len, &secret);
            for f in fragments(&secret) {
                assert!(
                    !emitted.contains(f),
                    "{ty} leaked at chunk_len {chunk_len}: {emitted:?}"
                );
            }
            assert!(
                emitted.contains("[REDACTED_"),
                "{ty} not redacted at {chunk_len}"
            );
        }
    }
}

#[test]
fn structural_crypto_secrets_never_leak_at_any_chunk_size() {
    let seed = format!("0x{}", "a7".repeat(32));
    let ethereum_key = format!("0x{}", "d5".repeat(32));
    let suri = format!("0x{}//hard", "91".repeat(32));
    // Public format vectors documented by Bitcoin Wiki and BIP32.
    let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ".to_owned();
    let xprv = concat!(
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8",
        "NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
    )
    .to_owned();
    let ai_key = format!("sk-ant-api03-{}AA", take(ALNUM, 93));
    let cases = [
        (
            "BITTENSOR_SEED",
            format!("btcli wallet create --seed {seed}\n"),
            seed.clone(),
        ),
        (
            "BITTENSOR_SEED",
            format!(r#"{{"secretSeed":"{seed}"}}"#),
            seed.clone(),
        ),
        (
            "ETHEREUM_PRIVATE_KEY",
            format!("PRIVATE_KEY={ethereum_key}\n"),
            ethereum_key.clone(),
        ),
        ("SUBSTRATE_SECRET_URI", format!("{suri}\n"), suri),
        ("BITCOIN_WIF", format!("{wif}\n"), wif),
        ("BIP32_EXTENDED_PRIVATE_KEY", format!("{xprv}\n"), xprv),
        (
            "ANTHROPIC_API_KEY",
            format!("Authorization: Bearer {ai_key}\n"),
            ai_key,
        ),
    ];
    for (ty, response, secret) in cases {
        assert!(
            detect_secrets(&response).iter().any(|span| span.ty == ty),
            "{ty} not detected unary"
        );
        for chunk_len in 1..=8 {
            let emitted = stream(&response, chunk_len, &secret);
            assert!(
                emitted.contains("[REDACTED_"),
                "{ty} not redacted at chunk_len {chunk_len}"
            );
        }
    }
}

/// Replace sentinel nonces so two stacks' outputs compare structurally.
fn normalize(s: &str) -> String {
    regex::Regex::new(r"_[0-9a-f]{8}\]")
        .unwrap()
        .replace_all(s, "_NONCE]")
        .into_owned()
}

/// Texts that contain secrets, including forms that need more than a regex:
/// keywords well before their token, seed phrases (valid, mistyped, JSON).
fn positive_corpus() -> Vec<String> {
    let abandon: Vec<&str> = std::iter::repeat_n("abandon", 11)
        .chain(["about"])
        .collect();
    let legal = concat!(
        "legal winner thank year wave sausage worth useful ",
        "legal winner thank year wave sausage worth useful ",
        "legal winner thank year wave sausage worth title"
    );
    let airtable = format!("pat{}.{}", take(ALNUM, 14), &HEX[..64]);
    let facebook = format!(
        "{}|{}",
        &"123456789012345"[..15],
        take(&ALNUM.to_lowercase(), 32)
    );
    let mut texts: Vec<String> = secrets()
        .into_iter()
        .map(|(_, s)| format!("Use this: {s}\nthen restart."))
        .collect();
    texts.extend([
        format!("Your airtable workspace is set up. Paste the token {airtable} into the config."),
        format!("The facebook app is live, and the page uses {facebook} for now."),
        format!(
            "My wallet seed phrase: {} please keep it safe",
            abandon.join(" ")
        ),
        format!(
            "seed = [{}]",
            abandon
                .iter()
                .map(|w| format!("'{w}'"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        format!("backup words {legal} and nothing else"),
        format!("typo version: {} end", legal.replacen("thank", "that", 1)),
    ]);
    texts
}

#[test]
fn streaming_output_equals_unary_on_positive_corpus() {
    for text in positive_corpus() {
        let mut unary_stack = stack();
        let unary = normalize(&unary_stack.run_output(&text).unwrap());
        assert!(unary.contains("[REDACTED_"), "nothing redacted: {text}");
        for chunk_len in 1..=8 {
            let mut s = stack();
            let mut runner = StreamOutput::new(&s);
            let mut streamed = String::new();
            let mut i = 0;
            while i < text.len() {
                let end = (i + chunk_len).min(text.len());
                streamed.push_str(&runner.push(&mut s, &text[i..end]).unwrap());
                i = end;
            }
            streamed.push_str(&runner.finish(&mut s).unwrap());
            assert_eq!(normalize(&streamed), unary, "chunk_len {chunk_len}: {text}");
        }
    }
}

#[test]
fn labelled_literals_and_defaults_never_leak_across_chunks() {
    let secret = "private-default-9x7k2m";
    for text in [
        format!("password: Optional[str] = '{secret}'\n"),
        format!("password: str = os.getenv('DB_PASSWORD', '{secret}')\n"),
        format!("password = os.environ.get('DB_PASSWORD', default='{secret}')\n"),
        format!("password = '{secret}(with$punctuation)'\n"),
        format!("password = os.getenv ('DB_PASSWORD', '{secret}')\n"),
        format!("token=issue(secret={secret})\n"),
        format!("token=issue(secret=derive(password={secret}))\n"),
        format!("token=issue(secret={secret},other=nested('text'))\n"),
        format!("token=issue (secret={secret}, other=nested('text'))\n"),
        format!("password=pass({secret}]9)\n"),
        format!("password='{secret}\nnext line\n"),
        format!("password=\"{secret}\\\r\nnext line\n"),
        format!("password='{secret}\\"),
    ] {
        let mut unary_stack = stack();
        let unary = normalize(&unary_stack.run_output(&text).unwrap());
        assert!(unary.contains("[REDACTED_SECRET_"));
        for chunk_len in 1..=8 {
            let emitted = stream(&text, chunk_len, secret);
            assert_eq!(
                normalize(&emitted),
                unary,
                "chunk_len={chunk_len}: {text:?}"
            );
        }
    }
}

#[test]
fn spaced_code_expressions_remain_intact_across_chunks() {
    for text in [
        "token = tokenizer(text, add_special_tokens=False)\n",
        "token = tokenizer (text)\n",
        "token = std::env::var (\"TOKEN\")\n",
        "token = cache[index + 1]\n",
        "password: Option< String >\n",
        "def f(password: Optional[str]):\n",
        "token=issue(secret=config.secret,other=nested('text'))\n",
    ] {
        for chunk_len in 1..=8 {
            let mut scanners = stack();
            let mut runner = StreamOutput::new(&scanners);
            let mut emitted = String::new();
            for chunk in text.as_bytes().chunks(chunk_len) {
                emitted.push_str(
                    &runner
                        .push(&mut scanners, std::str::from_utf8(chunk).unwrap())
                        .unwrap(),
                );
            }
            emitted.push_str(&runner.finish(&mut scanners).unwrap());
            assert_eq!(emitted, text, "chunk_len={chunk_len}");
        }
    }
}
