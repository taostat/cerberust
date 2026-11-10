//! Precision check for secret detection in ordinary developer prompts.
//!
//! `tests/fixtures/secret-negative-corpus/` holds ordinary prompt content with
//! no real credentials (see its README). `SecretScanner` redacts one-way, so a
//! false positive permanently damages a prompt. This check includes the generic
//! `SECRET` findings as well as the ported rules and seed-phrase detector. The
//! original, format-specific vendor patterns remain outside this check.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests assert on known-good values"
)]

use cerberust::scanner::detect::{detect_secrets, resolve_overlaps};
use cerberust::{ScanCtx, Scanner, SecretScanner};
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

/// Original format-specific entity types that predate the gitleaks port.
const PRE_EXISTING: &[&str] = &[
    "AWS_ACCESS_KEY",
    "GITHUB_TOKEN",
    "STRIPE_KEY",
    "OPENAI_KEY",
    "GOOGLE_API_KEY",
    "SLACK_WEBHOOK",
    "PRIVATE_KEY",
];

fn corpus() -> Vec<(String, String)> {
    let dir = std::path::Path::new("tests/fixtures/secret-negative-corpus");
    let mut files: Vec<(String, String)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().is_some_and(|n| n != "README.md"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn corpus_is_present() {
    assert!(corpus().len() >= 10);
}

#[test]
fn new_detectors_find_nothing_in_ordinary_prompts() {
    let mut hits = Vec::new();
    for (name, text) in corpus() {
        for span in detect_secrets(&text) {
            if !PRE_EXISTING.contains(&span.ty.as_str()) {
                hits.push(format!(
                    "{name}: {} {:?}",
                    span.ty,
                    &text[span.start..span.end]
                ));
            }
        }
    }
    assert!(hits.is_empty(), "false positives: {hits:#?}");
}

fn assert_redacted(text: &str, secret: &str, entity: &str) {
    let mut ctx = ScanCtx::new();
    let verdict = SecretScanner::new().scan(text, &mut ctx).unwrap();
    assert!(
        verdict.text.contains(&format!("[REDACTED_{entity}_")),
        "{entity} was not redacted: {text:?}"
    );
    assert!(
        !verdict.text.contains(secret),
        "{entity} leaked in redacted output: {:?}",
        verdict.text
    );
}

#[test]
fn provider_keys_and_secret_formats_still_redact() {
    // Synthetic values exercise the existing vendored provider rules.
    let github_body: String = "Q7wE2r9T4y1U8i3O6p0A5sD".chars().cycle().take(82).collect();
    let github = format!("github_pat_{github_body}");
    assert_redacted(
        &format!("token {github}"),
        &github,
        "GITHUB_FINE_GRAINED_PAT",
    );

    let anthropic_body: String = "Q7wE2r9T4y1U8i3O6p0A5sD".chars().cycle().take(93).collect();
    let anthropic = format!("sk-ant-api03-{anthropic_body}AA");
    assert_redacted(
        &format!("token {anthropic}"),
        &anthropic,
        "ANTHROPIC_API_KEY",
    );

    let mut rng = StdRng::seed_from_u64(0x5ec7_2026);
    let mixed_token = Alphanumeric.sample_string(&mut rng, 48);
    let text = format!("api_key={mixed_token}");
    assert_redacted(&text, &mixed_token, "SECRET");
    assert_redacted(
        &format!("opaque candidate {mixed_token}"),
        &mixed_token,
        "SECRET",
    );

    let pem = std::fs::read_to_string(
        "tests/fixtures/secret-positive-corpus/test-only-rsa-private-key.pem",
    )
    .unwrap();
    assert_redacted(&pem, &pem, "PRIVATE_KEY");

    // A test-only JWT with realistic structure and a generated signature.
    let jwt_signature = Alphanumeric.sample_string(&mut rng, 43);
    let jwt = format!(
        "{}.{}.{}",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        concat!(
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2",
            "MjM5MDIyfQ"
        ),
        jwt_signature
    );
    assert_redacted(&format!("Authorization: Bearer {jwt}"), &jwt, "JWT");

    let mnemonic = std::iter::repeat_n("abandon", 11)
        .chain(["about"])
        .collect::<Vec<_>>()
        .join(" ");
    assert_redacted(
        &format!("wallet seed: {mnemonic}"),
        &mnemonic,
        "SEED_PHRASE",
    );
}

fn assert_type(text: &str, secret: &str, entity: &str) {
    let spans = resolve_overlaps(detect_secrets(text));
    assert!(
        spans
            .iter()
            .any(|s| s.ty == entity && &text[s.start..s.end] == secret),
        "{entity} did not match {secret:?}: {spans:?}"
    );
}

fn assert_no_new_crypto_type(text: &str) {
    const TYPES: &[&str] = &[
        "BITTENSOR_SEED",
        "BITTENSOR_PRIVATE_KEY",
        "BITTENSOR_SECRET_PHRASE",
        "SUBSTRATE_SECRET_URI",
        "ETHEREUM_PRIVATE_KEY",
        "BITCOIN_WIF",
        "BIP32_EXTENDED_PRIVATE_KEY",
        "SOLANA_KEYPAIR",
    ];
    let found: Vec<_> = detect_secrets(text)
        .into_iter()
        .filter(|span| TYPES.contains(&span.ty.as_str()))
        .collect();
    assert!(found.is_empty(), "unexpected crypto spans: {found:?}");
}

#[test]
fn bittensor_seed_and_keyfile_fields_are_structural() {
    let seed = format!("0x{}", "a7".repeat(32));
    assert_type(
        &format!("btcli wallet create --seed {seed}"),
        &seed,
        "BITTENSOR_SEED",
    );
    for field in ["secretSeed", "secret_seed"] {
        assert_type(
            &format!(r#"{{"{field}":"{seed}"}}"#),
            &seed,
            "BITTENSOR_SEED",
        );
    }

    let private64 = "b3".repeat(32);
    let private128 = "c4".repeat(64);
    for private_key in [&private64, &private128] {
        let value = format!("0x{private_key}");
        assert_type(
            &format!(r#"{{"privateKey":"{value}"}}"#),
            &value,
            "BITTENSOR_PRIVATE_KEY",
        );
    }
    assert_type(
        &format!(r#"{{"privateKey":"{private64}"}}"#),
        &private64,
        "BITTENSOR_PRIVATE_KEY",
    );

    let phrase = std::iter::repeat_n("abandon", 11)
        .chain(["about"])
        .collect::<Vec<_>>()
        .join(" ");
    assert_type(
        &format!(r#"{{"secretPhrase":"{phrase}"}}"#),
        &phrase,
        "BITTENSOR_SECRET_PHRASE",
    );

    for text in [
        "--seed 42",
        "seed = 1234",
        "rng.seed(0x123456789abc)",
        "seed = 0x123456789abc",
        &format!("block hash 0x{}", "d1".repeat(32)),
        "{\"secretSeed\":\"0x1234\"}",
        &format!("--seed 0x{}g", "a7".repeat(31)),
        &format!(r#"{{"privateKey":"0x{}g"}}"#, "b3".repeat(31)),
    ] {
        assert_no_new_crypto_type(text);
    }

    assert_no_new_crypto_type(&format!("privateKey {private64}"));
}

#[test]
fn ethereum_private_keys_require_named_assignments() {
    let key = format!("0x{}", "d5".repeat(32));
    for name in [
        "private_key",
        "privateKey",
        "PRIVATE_KEY",
        "priv_key",
        "ETH_PRIVATE_KEY",
        "DEPLOYER_PRIVATE_KEY",
        "secret_key",
    ] {
        let text = format!("export {name}='{key}'");
        assert_type(&text, &key, "ETHEREUM_PRIVATE_KEY");
    }
    assert_type(
        &format!(r#"{{"PRIVATE_KEY":"{key}"}}"#),
        &key,
        "ETHEREUM_PRIVATE_KEY",
    );

    let bare = format!("0x{}", "e6".repeat(32));
    assert_no_new_crypto_type(&bare);
    assert_no_new_crypto_type(&format!("pk={bare}"));
    assert_no_new_crypto_type(&format!("PRIVATE_KEY=0x{}", "aa".repeat(31)));
    let bad_charset = format!("PRIVATE_KEY=0x{}g", "aa".repeat(31));
    assert_no_new_crypto_type(&bad_charset);

    for key in hardhat_dev_keys() {
        for text in [
            format!("PRIVATE_KEY=0x{key}"),
            format!("secret=0x{key}"),
            format!("api_key=0x{key}"),
            format!("0x{key}"),
            format!(r#"{{"privateKey":"{key}"}}"#),
            format!(r#"{{"privateKey":"0x{key}"}}"#),
            format!(r#"{{"privateKey":"0x{}"}}"#, key.to_ascii_uppercase()),
        ] {
            assert_no_new_crypto_type(&text);
            assert!(
                detect_secrets(&text).is_empty(),
                "public dev key flagged: {text}"
            );
        }
    }
}

/// Public deterministic local development keys from the documented default
/// mnemonic. These keys must remain unredacted in local config examples.
fn hardhat_dev_keys() -> [&'static str; 20] {
    [
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
        "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
        "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
        "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
        "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
        "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
        "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
        "f214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897",
        "701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82",
        "a267530f49f8280200edf313ee7af6b827f2a8bce2897751d06a843f644967b1",
        "47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd",
        "c526ee95bf44d8fc405a158bb884d9d1238d99f0612e9f33d006bb0789009aaa",
        "8166f546bab6da521a8369cab06c5d2b9e46670292d85c875ee9ec20e84ffb61",
        "ea6c44ac03bff858b476bba40716402b03e41b8e97e276d1baec7c37d42484a0",
        "689af8efa8c651a91ad287602527f3af2fe9f6501a7ac4b061667b5a93e037fd",
        "de9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0",
        "df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
    ]
}

#[test]
fn substrate_secret_uris_validate_the_secret_phrase() {
    let raw = format!("0x{}", "91".repeat(32));
    let suri = format!("{raw}//hard/soft///password");
    assert_type(&suri, &suri, "SUBSTRATE_SECRET_URI");

    let phrase = std::iter::repeat_n("abandon", 11)
        .chain(["about"])
        .collect::<Vec<_>>()
        .join(" ");
    let mnemonic_uri = format!("{phrase}//account/0");
    assert_type(&mnemonic_uri, &mnemonic_uri, "SUBSTRATE_SECRET_URI");

    let invalid = std::iter::repeat_n("abandon", 12)
        .collect::<Vec<_>>()
        .join(" ");
    assert_no_new_crypto_type(&format!("{invalid}//account"));
    assert_no_new_crypto_type("//Alice");
    assert_no_new_crypto_type("//Bob//stash");
    assert_no_new_crypto_type("//Ferdie");
    assert_no_new_crypto_type(
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk",
    );
    assert_no_new_crypto_type(
        "bottom drive obey lake curtain smoke basket hold race lonely fit walk//Alice",
    );
    assert_no_new_crypto_type(&raw);
}

#[test]
fn substrate_mnemonic_uris_redact_the_complete_value_after_prose() {
    let phrase = std::iter::repeat_n("abandon", 11)
        .chain(["about"])
        .collect::<Vec<_>>()
        .join(" ");
    let uri = format!("{phrase}//account/0///private9x7");
    for prefix in ["Use ", "Here is my URI ", "🦀 Example\n"] {
        assert_type(&format!("{prefix}{uri}"), &uri, "SUBSTRATE_SECRET_URI");
    }
}

#[test]
fn unquoted_template_references_preserve_internal_whitespace() {
    for value in [
        "{{DB_PASSWORD }}",
        "{{ DB_PASSWORD}}",
        "{{\tprocess.env.PASSWORD\t}}",
    ] {
        let text = format!("password={value}\n");
        assert_eq!(detect_secrets(&text), [], "template reference: {text}");
        let text = format!("token=issue(password={value},secret=hunter2)");
        let spans = detect_secrets(&text);
        assert_eq!(spans.len(), 1, "{text}");
        assert_eq!(&text[spans[0].start..spans[0].end], "hunter2");
    }
    for value in ["{{DB_PASSWORD }}private9x7", "{{private9x7"] {
        assert_redacted(&format!("password={value}"), value, "SECRET");
    }
}

#[test]
fn bitcoin_private_keys_require_base58check_and_private_versions() {
    // Public WIF test vector from the Bitcoin Wiki format example.
    let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    assert_type(wif, wif, "BITCOIN_WIF");

    let xprv = concat!(
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8",
        "NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
    );
    assert_type(xprv, xprv, "BIP32_EXTENDED_PRIVATE_KEY");

    for (prefix, version) in [
        ("xprv", [0x04, 0x88, 0xad, 0xe4]),
        ("yprv", [0x04, 0x9d, 0x78, 0x78]),
        ("zprv", [0x04, 0xb2, 0x43, 0x0c]),
        ("Yprv", [0x02, 0x95, 0xb0, 0x05]),
        ("Zprv", [0x02, 0xaa, 0x7a, 0x99]),
        ("tprv", [0x04, 0x35, 0x83, 0x94]),
        ("uprv", [0x04, 0x4a, 0x4e, 0x28]),
        ("vprv", [0x04, 0x5f, 0x18, 0xbc]),
        ("Uprv", [0x02, 0x42, 0x85, 0xb5]),
        ("Vprv", [0x02, 0x57, 0x50, 0x48]),
    ] {
        let encoded = extended_key_with_version(xprv, version);
        assert!(encoded.starts_with(prefix), "{prefix}: {encoded}");
        assert_type(&encoded, &encoded, "BIP32_EXTENDED_PRIVATE_KEY");
    }

    for public in [
        concat!(
            "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8i",
            "doc4a6mr8",
            "BDzTJY47LJhkJ8UB7WEGuduB"
        ),
        concat!(
            "tpubD6NzVbkrYhZ4XJDrzRvuxHEyQaPd1mwwdDofEJwekX18tAdsqeKfxss79AJzg1431FybXg5rfpTrJF4i",
            "Ahy",
            "R7RubberdzEQXiRmXGADH2eA"
        ),
    ] {
        assert_no_new_crypto_type(public);
        assert!(
            detect_secrets(public).is_empty(),
            "public key flagged: {public}"
        );
    }

    let mut bad_wif = wif.as_bytes().to_vec();
    let last = bad_wif.len() - 1;
    bad_wif[last] = if bad_wif[last] == b"1"[0] {
        b"2"[0]
    } else {
        b"1"[0]
    };
    let bad_wif = String::from_utf8(bad_wif).unwrap();
    assert_no_new_crypto_type(&bad_wif);
    assert_redacted(&bad_wif, &bad_wif, "SECRET");
    assert_redacted(&wif[..wif.len() - 1], &wif[..wif.len() - 1], "SECRET");
    let bad_wif_char = format!("{}0{}", &wif[..10], &wif[11..]);
    assert_no_new_crypto_type(&bad_wif_char);
    assert_redacted(&bad_wif_char, &bad_wif_char, "SECRET");

    for bad_xprv in [
        xprv[..xprv.len() - 1].to_owned(),
        format!("{}0{}", &xprv[..10], &xprv[11..]),
        corrupt_base58_checksum(xprv),
    ] {
        assert_no_new_crypto_type(&bad_xprv);
        assert_redacted(&bad_xprv, &bad_xprv, "SECRET");
    }
}

fn extended_key_with_version(key: &str, version: [u8; 4]) -> String {
    let mut payload = bs58::decode(key).into_vec().unwrap();
    payload.truncate(payload.len() - 4);
    payload[..4].copy_from_slice(&version);
    base58check_encode(&payload)
}

fn corrupt_base58_checksum(key: &str) -> String {
    let mut bytes = key.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'1' { b'2' } else { b'1' };
    String::from_utf8(bytes).unwrap()
}

fn base58check_encode(payload: &[u8]) -> String {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    let mut data = payload.to_vec();
    data.extend_from_slice(&second[..4]);
    bs58::encode(data).into_string()
}

#[test]
fn solana_keypair_values_need_a_keyword_and_exact_byte_shape() {
    let values: Vec<String> = (0..64).map(|n| n.to_string()).collect();
    let array = format!("[{}]", values.join(","));
    let json = format!(r#"{{"secretKey":{array}}}"#);
    assert_type(&json, &array, "SOLANA_KEYPAIR");

    let bytes: Vec<u8> = (0..64).collect();
    let encoded = bs58::encode(bytes).into_string();
    let json = format!(r#"{{"secretKey":"{encoded}"}}"#);
    assert_type(&json, &encoded, "SOLANA_KEYPAIR");

    let short: Vec<String> = (0..63).map(|n| n.to_string()).collect();
    assert_no_new_crypto_type(&format!(r#"{{"secretKey":[{}]}}"#, short.join(",")));
    let too_large = format!(r#"{{"secretKey":[{},999]}}"#, values[..63].join(","));
    assert_no_new_crypto_type(&too_large);
    assert_no_new_crypto_type(&format!(r#"{{"secretKey":"{encoded}0"}}"#));
    let too_long = bs58::encode((0..65).collect::<Vec<u8>>()).into_string();
    assert_no_new_crypto_type(&format!(r#"{{"secretKey":"{too_long}"}}"#));
    assert_no_new_crypto_type(&array);
}

#[test]
fn gm_and_partner_keys_accept_test_environment_prefixes() {
    let body = "9a".repeat(32);
    for (prefix, ty) in [
        ("gm_test_", "GM_API_KEY"),
        ("bm_test_", "BLOCKMACHINE_API_KEY"),
        ("ts_test_", "TAOSTATS_API_KEY"),
    ] {
        let key = format!("{prefix}{body}");
        assert_type(&format!("token {key}"), &key, ty);
        let near_miss = format!("{prefix}{}g", &body[..63]);
        assert_no_new_crypto_type(&near_miss);
        assert!(!detect_secrets(&near_miss).iter().any(|span| span.ty == ty));
    }
}

#[test]
fn literal_assignments_are_not_exempted_by_punctuation_or_placeholder_fragments() {
    let values = [
        "p@ss$word9",
        "value(with)punctuation",
        "value[with]brackets",
        "unusual,",
        "example_9x7k2m",
        "sample_private9",
        "replace_me9x7",
        "insert_9x7key",
        "your-9x7key",
        "private9_token",
        "private9_password",
        "private9_secret",
        "private9_api_key",
        "client.secret",
        "Optional[str]",
        "Option<String>",
        "self.tokenizer(text)",
        "secret}}",
        "<private9>",
        "%private9%",
    ];
    let mut missed = Vec::new();
    for value in values {
        let text = format!("password = \"{value}\"");
        let spans = detect_secrets(&text);
        let start = text.find(value).unwrap();
        if !spans
            .iter()
            .any(|s| s.start <= start && s.end >= start + value.len())
        {
            missed.push(text);
        }
    }
    assert!(missed.is_empty(), "literal secrets missed: {missed:#?}");
}

#[test]
fn unquoted_literals_keep_punctuation_and_do_not_use_broad_placeholder_exemptions() {
    for value in [
        "p@ss$word9",
        "abc(def)123",
        "abc[def]123",
        "example_9x7k2m",
        "private9_token",
        "token=changeme",
        "secret=private9x7",
        "password=config.password",
    ] {
        assert_redacted(&format!("password={value}"), value, "SECRET");
    }
    assert_redacted("password=hunter2,", "hunter2", "SECRET");
}

#[test]
fn typed_assignments_redact_the_literal_value() {
    for annotation in [
        "str",
        "String",
        "Optional[str]",
        "Optional[ str ]",
        "str | None",
        "Option<String>",
    ] {
        let text = format!("password: {annotation} = 'hunter2'");
        assert_redacted(&text, "hunter2", "SECRET");
        let start = text.find("hunter2").unwrap();
        assert!(detect_secrets(&text)
            .iter()
            .any(|s| s.start == start && s.end == start + 7));
    }
}

#[test]
fn colon_labelled_literals_are_not_types_for_later_assignments() {
    for text in [
        "password: hunter2, timeout = 30",
        "password: hunter2, token = None",
        "password: hunter2 token = None",
        "password: hunter2, description = 'ordinary text'",
    ] {
        assert_redacted(text, "hunter2", "SECRET");
        let spans = detect_secrets(text);
        assert_eq!(spans.len(), 1, "{text}: {spans:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], "hunter2");
    }
}

#[test]
fn typed_assignment_heads_preserve_generics_unions_and_separate_parameters() {
    for text in [
        "password: tuple[str, str] = 'hunter2'",
        "password: Dict[str, List[str | None]] = 'hunter2'",
        "password: Option<String> | None = 'hunter2'",
        "password: Wrapper<token: Credentials> = 'hunter2'",
        "def f(password: str, token: Option<String> = 'hunter2'):",
        "def f(password: str, token: str='hunter2'):",
    ] {
        let spans = detect_secrets(text);
        assert_eq!(spans.len(), 1, "{text}: {spans:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], "hunter2");
    }
}

#[test]
fn typed_chained_assignments_redact_the_literal_value() {
    for assignment in [
        "password = 'private9x7'",
        "password=\"private9x7\"",
        "api_key = private9x7",
        "password = token = 'private9x7'",
    ] {
        let text = format!("let token: string = {assignment};");
        let spans = detect_secrets(&text);
        assert_eq!(spans.len(), 1, "{text}: {spans:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], "private9x7");
        assert_redacted(&text, "private9x7", "SECRET");
    }
}

#[test]
fn deeply_chained_assignments_preserve_literal_detection() {
    let text = format!(
        "let token: string = {}'private9x7'",
        "password=".repeat(16_384)
    );
    let spans = detect_secrets(&text);
    assert_eq!(spans.len(), 1);
    assert_eq!(&text[spans[0].start..spans[0].end], "private9x7");
}

#[test]
fn incomplete_labels_do_not_skip_typed_assignments() {
    let text = format!(
        "{}password: Optional[str] = 'hunter2'",
        "password=& ".repeat(1_024)
    );
    assert_redacted(&text, "hunter2", "SECRET");
}

#[test]
fn environment_defaults_redact_literals_but_preserve_lookup_names() {
    for call in ["os.getenv", "os.environ.get"] {
        for args in [
            "'X', 'hunter2'",
            "'X', default='hunter2'",
            "'X', 'sk-live-9x7k2m'",
        ] {
            let text = format!("password = {call}({args})");
            let value = if args.contains("sk-live") {
                "sk-live-9x7k2m"
            } else {
                "hunter2"
            };
            assert_redacted(&text, value, "SECRET");
            let start = text.find(value).unwrap();
            assert!(detect_secrets(&text)
                .iter()
                .any(|s| s.start == start && s.end == start + value.len()));
        }
    }
}

#[test]
fn public_address_wrappers_do_not_exempt_opaque_secrets() {
    let address = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    for secret in [
        format!("_{address}_"),
        format!("+{address}="),
        format!("-{address}-"),
    ] {
        assert_redacted(&format!("opaque {secret}"), &secret, "SECRET");
    }
}

#[test]
fn unicode_assignment_values_keep_valid_span_boundaries() {
    for value in ["pässwörd$9", "密碼(秘密)123", "é_private9_token"] {
        assert_redacted(&format!("🦀 password = '{value}'"), value, "SECRET");
    }
}

#[test]
fn public_identifier_exemptions_do_not_override_labelled_credentials() {
    for value in [
        "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        "14YomMWKx4jzD34ESv7HzpNhU6wojtLFGW",
        "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC",
    ] {
        assert_redacted(&format!("password = '{value}'"), value, "SECRET");
    }
}

#[test]
fn padded_literal_is_not_misread_as_a_type_annotation() {
    for value in ["aBcDeF9x7k2m==", "Optional9x7k2m=", "string9x7k2m="] {
        assert_redacted(&format!("password:{value}"), value, "SECRET");
    }
}

#[test]
fn mixed_case_hex_identifiers_are_not_secrets() {
    for value in [
        "616670c245D44b2C80f0272cdF1d2629",
        "3e4035A3febe3E91f4319a5D1e93D6787d4fbb6d",
        "e163e53B9e7E8a8511e77271e2B323ed057759542a6D988258afe3a1fa329caf",
    ] {
        assert_eq!(detect_secrets(value), [], "hex identifier: {value}");
        assert_redacted(&format!("password={value}"), value, "SECRET");
    }
}

#[test]
fn truncated_quoted_assignments_still_redact() {
    for quote in ['\'', '"'] {
        for suffix in ["\n", "\r\n", "\\\n", "\\"] {
            let text = format!("password={quote}hunter2{suffix}");
            assert_redacted(&text, "hunter2", "SECRET");
        }
    }
}

#[test]
fn exempt_calls_do_not_hide_nested_secret_assignments() {
    for text in [
        "token=issue(secret=hunter2)",
        "token=issue(secret='hunter2')",
        "token=issue(secret=\"hunter2\")",
        "token=issue(secret=derive(password=hunter2))",
        "token=issue(secret=hunter2,other=nested('text'))",
    ] {
        assert_redacted(text, "hunter2", "SECRET");
    }
    for text in [
        "token=issue(secret=config.secret)",
        "token=issue(secret=derive(password=os.getenv('DB_PASSWORD')))",
        "token=self.tokenizer(text,add_special_tokens=False)",
        "token=issue(secret=config.secret,other=nested('text'))",
        "token=issue(secret=config.secret,other=nested(text))",
    ] {
        assert_eq!(detect_secrets(text), [], "code expression: {text}");
    }
}

#[test]
fn nested_assignments_redact_each_argument() {
    for separator in [",", ", "] {
        let text = format!("token=issue(secret=hunter2{separator}password=private9x7)");
        assert_redacted(&text, "hunter2", "SECRET");
        assert_redacted(&text, "private9x7", "SECRET");
    }
}

#[test]
fn environment_defaults_allow_space_before_parentheses() {
    for call in ["os.getenv", "os.environ.get", "getenv"] {
        let text = format!("password = {call} ('DB_PASSWORD', 'hunter2')");
        assert_redacted(&text, "hunter2", "SECRET");
    }
}

#[test]
fn environment_defaults_accept_double_quoted_lookup_names() {
    for call in ["os.getenv", "os.environ.get", "getenv"] {
        for value in ["'hunter2'", "\"hunter2\"", "default=\"hunter2\""] {
            let text = format!("password = {call}(\"DB_PASSWORD\", {value})");
            assert_redacted(&text, "hunter2", "SECRET");
        }
    }
}

#[test]
fn deeply_nested_assignments_preserve_literals_and_code_references() {
    let prefix = "token=f(".repeat(16_384);
    let suffix = ")".repeat(16_384);
    let literal = format!("{prefix}password=hunter2{suffix}");
    assert_redacted(&literal, "hunter2", "SECRET");
    let reference = format!("{prefix}password=config.password{suffix}");
    assert_eq!(detect_secrets(&reference), []);
}

#[test]
fn angle_bracket_type_annotations_are_not_secrets() {
    for text in [
        "password: Option<String>",
        "struct Config { secret: Option<String>, }",
        "interface Config { token: Promise<string>; }",
    ] {
        assert_eq!(detect_secrets(text), [], "type annotation: {text}");
    }
    assert_redacted("password=Option<String>", "Option<String>", "SECRET");
}

#[test]
fn generic_type_contents_are_not_scanned_as_assignments() {
    let text = "password: Wrapper<token: Credentials>";
    assert_eq!(detect_secrets(text), []);

    let text = format!(
        "{}{}\npassword=hunter2",
        "password: Wrapper<".repeat(16_384),
        ">".repeat(16_384)
    );
    let spans = detect_secrets(&text);
    assert_eq!(spans.len(), 1);
    assert_eq!(&text[spans[0].start..spans[0].end], "hunter2");
}

#[test]
fn malformed_nested_annotations_keep_literal_detection() {
    for opening in ['<', '['] {
        for suffix in ["", "=", "]="] {
            let text = format!(
                "{}{suffix}\npassword=hunter2",
                format!("password: Wrapper{opening}").repeat(16_384)
            );
            let spans = detect_secrets(&text);
            assert!(spans.len() > 1);
            let last = spans.last().unwrap();
            assert_eq!(&text[last.start..last.end], "hunter2");
        }
    }
}

#[test]
fn spaced_expressions_and_generic_annotations_are_not_secrets() {
    let mut hits = Vec::new();
    for text in [
        "token = tokenizer(text, add_special_tokens=False)",
        "token = tokenizer (text)",
        "token = std::env::var (\"TOKEN\")",
        "token = cache[index + 1]",
        "password: Option< String >",
        "token: Promise< string >;",
        "def f(password: Optional[str]):",
    ] {
        if !detect_secrets(text).is_empty() {
            hits.push(text);
        }
    }
    assert!(hits.is_empty(), "code redacted: {hits:#?}");
}

#[test]
fn malformed_expression_shaped_passwords_are_not_exempted() {
    let mut missed = Vec::new();
    for value in [
        "pass(word]9)",
        "pass[wor)d]",
        "pass(word)tail(",
        "pass(word\n",
    ] {
        let text = format!("password={value}");
        if detect_secrets(&text).is_empty() {
            missed.push(text);
        }
    }
    assert!(missed.is_empty(), "literal passwords missed: {missed:#?}");
    assert_redacted(
        "token=tokenizer(text) password=pass,word",
        "pass,word",
        "SECRET",
    );
}

#[test]
fn malformed_quoted_calls_keep_literal_detection() {
    for text in [
        "password=pass(word'9)",
        "password=pass(word\"9)",
        "password=pass(word'9'",
        "password=pass(word\"9\"",
    ] {
        assert_redacted(text, "pass(word", "SECRET");
    }
}

#[test]
fn quoted_arguments_preserve_following_credential_references() {
    for text in [
        "token=issue('scope',secret=config.secret,other=value)",
        "token=issue(\"scope\",secret=config.secret,other='text')",
        "token=issue(')',secret=config.secret,other=value)",
        "token=issue('\\\'',secret=config.secret,other=value)",
        "token=issue('a&b',secret=config.secret,other=value)",
        "Here's token=issue('scope',secret=config.secret,other=value)",
        "token=issue(\"scope\").with_secret(secret=config.secret)",
    ] {
        assert_eq!(detect_secrets(text), [], "code expression: {text}");
    }
    assert_redacted(
        "token=issue('scope',secret=config.secret,password=hunter2)",
        "hunter2",
        "SECRET",
    );
}

#[test]
fn ordinary_calls_preserve_credential_reference_arguments() {
    for text in [
        "issue(secret=config.secret,other=value)",
        "issue( secret=config.secret,other='text')",
        "issue(secret=config.lookup('name'),other=value)",
        "issue(secret={{ DB_SECRET }},other=value)",
        "issue(secret=${DB_SECRET},other=value)",
    ] {
        assert_eq!(detect_secrets(text), [], "code expression: {text}");
    }
    assert_redacted(
        "issue( secret=config.secret,password=hunter2)",
        "hunter2",
        "SECRET",
    );
}

#[test]
fn deeply_nested_quoted_calls_preserve_references_and_detect_literals() {
    let prefix = "token=f('scope',".repeat(16_384);
    let suffix = ")".repeat(16_384);
    assert_eq!(
        detect_secrets(&format!("{prefix}password=config.password{suffix}")),
        []
    );
    for closing in [&suffix, ""] {
        assert_redacted(
            &format!("{prefix}password=hunter2{closing}"),
            "hunter2",
            "SECRET",
        );
    }
}
