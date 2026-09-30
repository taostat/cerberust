//! Generator and drift check for `src/scanner/gitleaks_rules.rs`.
//!
//! The secret rules are generated from the vendored upstream gitleaks config
//! (`data/gitleaks/gitleaks.toml`), never copied by hand. This test renders the
//! Rust table from that file and asserts the checked-in module matches, so a
//! hand edit or a stale vendored config fails CI.
//!
//! Regenerate after bumping the vendored config:
//!
//! ```sh
//! CERBERUST_REGENERATE_GITLEAKS=1 cargo test --test gitleaks_rules
//! ```
//!
//! Go RE2 and the Rust `regex` crate share a dialect, but Go's `\w`, `\d`,
//! `\s` and `\b` are ASCII-only while Rust's are Unicode. Each pattern is
//! rewritten to explicit ASCII classes so the port keeps gitleaks' semantics,
//! then compiled; a pattern that does not compile is excluded with its error.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a generator test fails loudly on malformed vendored input"
)]

use std::fmt::Write as _;
use std::path::Path;

use sha2::{Digest, Sha256};

const UPSTREAM_VERSION: &str = "v8.30.1";
const UPSTREAM_SHA256: &str = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf";
const GENERATED: &str = "src/scanner/gitleaks_rules.rs";

/// Rules left out of the port, with the reason. `SecretScanner` redacts one-way,
/// so a false positive permanently damages a prompt: identifiers, public keys
/// and context-free generic rules are excluded, as are rules gitleaks scopes to
/// file paths (a prompt has no path, so gitleaks itself would never fire them).
const EXCLUDED: &[(&str, &str)] = &[
    ("generic-api-key", "generic keyword/assignment rule; too many false positives for one-way redaction (the entropy backstop covers opaque tokens)"),
    ("adobe-client-id", "OAuth client identifier, not a secret"),
    ("asana-client-id", "OAuth client identifier, not a secret"),
    ("bitbucket-client-id", "OAuth client identifier, not a secret"),
    ("discord-client-id", "OAuth client identifier, not a secret"),
    ("linkedin-client-id", "OAuth client identifier, not a secret"),
    ("looker-client-id", "OAuth client identifier, not a secret"),
    ("messagebird-client-id", "OAuth client identifier, not a secret"),
    ("plaid-client-id", "client identifier, not a secret"),
    ("new-relic-user-api-id", "account identifier, not a secret"),
    ("sumologic-access-id", "access identifier (paired with a secret that has its own rule)"),
    ("sendbird-access-id", "application identifier, not a secret"),
    ("flutterwave-public-key", "public key, designed to be embedded in clients"),
    ("lob-pub-api-key", "publishable key, designed to be embedded in clients"),
    ("mailgun-pub-key", "public validation key, designed to be embedded in clients"),
    ("new-relic-browser-api-token", "browser ingest key, embedded in public web pages"),
    ("gitlab-feature-flag-client-token", "client-side feature-flag token, embedded in clients"),
    ("freemius-secret-key", "gitleaks applies it only to *.php paths"),
    ("hashicorp-tf-password", "gitleaks applies it only to *.tf/*.hcl paths"),
    ("kubernetes-secret-yaml", "gitleaks applies it only to *.yaml paths"),
    ("nuget-config-password", "gitleaks applies it only to nuget.config paths"),
    ("pkcs12-file", "path-only rule (matches file names, has no content regex)"),
];

/// Rules kept keyword-gated even though a keyword can sit outside the match,
/// because the ungated regex is not specific enough to run on every text.
/// `sourcegraph-access-token` includes a bare `[a-fA-F0-9]{40}` alternative
/// that would match every git SHA. On a stream, a token whose keyword was
/// flushed in an earlier chunk is missed.
const ALWAYS_GATED: &[&str] = &["sourcegraph-access-token"];

#[test]
fn vendored_config_is_the_pinned_upstream_release() {
    let bytes = std::fs::read("data/gitleaks/gitleaks.toml").unwrap();
    let digest = hex::encode(Sha256::digest(&bytes));
    assert_eq!(
        digest, UPSTREAM_SHA256,
        "data/gitleaks/gitleaks.toml is not gitleaks {UPSTREAM_VERSION}; update UPSTREAM_* and regenerate"
    );
}

#[test]
fn generated_rules_match_vendored_config() {
    let rendered = render();
    if std::env::var_os("CERBERUST_REGENERATE_GITLEAKS").is_some() {
        std::fs::write(GENERATED, &rendered).unwrap();
        return;
    }
    let current = std::fs::read_to_string(GENERATED).unwrap_or_default();
    assert!(
        current == rendered,
        "{GENERATED} is out of date with data/gitleaks/gitleaks.toml; run \
         CERBERUST_REGENERATE_GITLEAKS=1 cargo test --test gitleaks_rules"
    );
}

#[test]
fn every_exclusion_names_a_real_rule() {
    let config = load();
    let ids: Vec<&str> = rules(&config)
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    for (id, _) in EXCLUDED {
        assert!(
            ids.contains(id),
            "excluded rule {id} is not in the vendored config"
        );
    }
}

#[test]
fn go_classes_become_ascii() {
    assert_eq!(go_to_rust(r"\w+").unwrap(), "[0-9A-Za-z_]+");
    assert_eq!(go_to_rust(r"[\w.-]{0,5}").unwrap(), "[0-9A-Za-z_.-]{0,5}");
    assert_eq!(
        go_to_rust(r"\b\d\s\S").unwrap(),
        r"(?-u:\b)[0-9][\t\n\f\r ][^\t\n\f\r ]"
    );
    assert_eq!(go_to_rust(r"\\w").unwrap(), r"\\w");
    assert_eq!(go_to_rust(r"[^\s]").unwrap(), r"[^\t\n\f\r ]");
    assert_eq!(go_to_rust(r"[\s\S-]").unwrap(), r"[\t\n\f\r [^\t\n\f\r ]-]");
    assert_eq!(
        go_to_rust(r"^(?:[0-9]+|{[0-9]+})$").unwrap(),
        r"^(?:[0-9]+|\{[0-9]+})$"
    );
    assert_eq!(go_to_rust(r"a{2,3}").unwrap(), "a{2,3}");
}

fn load() -> toml::Table {
    let text = std::fs::read_to_string("data/gitleaks/gitleaks.toml").unwrap();
    text.parse::<toml::Table>().unwrap()
}

fn rules(config: &toml::Table) -> &Vec<toml::Value> {
    config["rules"].as_array().unwrap()
}

/// Rewrite Go RE2 ASCII shorthand classes and word boundaries as explicit
/// ASCII forms the Rust `regex` crate reads with the same meaning.
fn go_to_rust(pattern: &str) -> Result<String, String> {
    let mut out = String::with_capacity(pattern.len() + 32);
    let mut chars = pattern.chars();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let Some(e) = chars.next() else {
                    return Err("trailing backslash".to_owned());
                };
                out.push_str(&shorthand(e, in_class));
            }
            '[' if !in_class => {
                in_class = true;
                out.push('[');
                // A leading `^` and a leading `]` are literal parts of the class.
                let mut peek = chars.clone();
                if peek.next() == Some('^') {
                    out.push('^');
                    chars.next();
                }
                if chars.clone().next() == Some(']') {
                    out.push(']');
                    chars.next();
                }
            }
            '[' if in_class && chars.clone().next() == Some(':') => {
                // POSIX class `[:alnum:]` inside a bracket: copy through `:]`.
                out.push('[');
                for p in chars.by_ref() {
                    out.push(p);
                    if p == ']' {
                        break;
                    }
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(']');
            }
            // Go reads a `{` that cannot start a repetition as a literal; Rust
            // rejects it, so escape it.
            '{' if !in_class && !starts_repetition(&out, chars.as_str()) => out.push_str(r"\{"),
            _ => out.push(c),
        }
    }
    Ok(out)
}

/// Whether a `{` (with `rest` following it) is a `{n}`, `{n,}` or `{n,m}`
/// repetition applied to a preceding atom.
fn starts_repetition(before: &str, rest: &str) -> bool {
    let has_atom = !before.is_empty() && !before.ends_with('(') && !before.ends_with('|');
    let Some(close) = rest.find('}') else {
        return false;
    };
    let inner = &rest[..close];
    let (min, max) = inner.split_once(',').unwrap_or((inner, ""));
    has_atom
        && !min.is_empty()
        && min.bytes().all(|b| b.is_ascii_digit())
        && max.bytes().all(|b| b.is_ascii_digit())
}

fn shorthand(e: char, in_class: bool) -> String {
    const WORD: &str = "0-9A-Za-z_";
    const DIGIT: &str = "0-9";
    const SPACE: &str = r"\t\n\f\r ";
    let (set, negated) = match e {
        'w' => (WORD, false),
        'W' => (WORD, true),
        'd' => (DIGIT, false),
        'D' => (DIGIT, true),
        's' => (SPACE, false),
        'S' => (SPACE, true),
        'b' | 'B' if !in_class => return format!(r"(?-u:\{e})"),
        other => return format!(r"\{other}"),
    };
    match (in_class, negated) {
        (true, false) => set.to_owned(),
        (false, false) => format!("[{set}]"),
        // Negated shorthand is a negated class; inside a bracket Rust nests it:
        // `[a[^b]]` is "a, or anything but b".
        (_, true) => format!("[^{set}]"),
    }
}

/// The regex as a pattern `proptest::string_regex` can sample: context
/// anchors and the optional identifier prefix are dropped.
fn sampling_form(regex: &str) -> String {
    regex
        .replace("(?-u:\\b)", "")
        .replace("(?-u:\\B)", "")
        .replace("[0-9A-Za-z_.-]{0,50}?", "")
        .replace("(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|$)", "(?:[ ;])")
        .replace("(?:[\\x60'\"\\t\\n\\f\\r ;,]|\\\\[nr]|$)", "(?:[ ;])")
        .replace("(?:[^0-9A-Za-z_-]|\\z)", "(?: )")
        .replace("(?:[^a-zA-Z0-9+/]|\\z)", "(?: )")
        .replace('$', "")
        .replace("(?:^|", "(?:")
        .replace('^', "")
}

/// Whether every match of `regex` contains one of `keywords` (sampled, fixed
/// seed). If not, a keyword can sit outside the match (`airtable` before an
/// Airtable token), and gating the regex on a keyword in the same text would
/// make a streaming flush that holds the token but not the keyword miss it.
fn keywords_always_in_match(regex: &str, keywords: &[String]) -> bool {
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    // Sample case-sensitively: `(?i)` sampling mostly emits Unicode case
    // variants (`ſ` for `s`, the Kelvin sign for `k`). Keywords are compared
    // lower-cased, so the literal-case sample is enough.
    let case_sensitive = sampling_form(regex)
        .replace("(?i)", "")
        .replace("(?i:", "(?:");
    let Ok(strategy) = proptest::string::string_regex(&case_sensitive) else {
        // Unsamplable patterns (lazy multi-line curl rules) name their keyword
        // at the start of the match.
        return true;
    };
    let mut runner = TestRunner::new_with_rng(
        Config::default(),
        TestRng::from_seed(RngAlgorithm::ChaCha, &[11; 32]),
    );
    (0..64).all(|_| {
        let sample = strategy
            .new_tree(&mut runner)
            .unwrap()
            .current()
            .to_ascii_lowercase();
        keywords.iter().any(|k| sample.contains(k.as_str()))
    })
}

/// A Rust raw string literal for `s`, with only as many `#`s as needed.
fn raw(s: &str) -> String {
    let mut hashes = 0;
    while s.contains(&format!("\"{}", "#".repeat(hashes))) {
        hashes += 1;
    }
    let h = "#".repeat(hashes);
    format!("r{h}\"{s}\"{h}")
}

fn type_name(id: &str) -> String {
    id.to_ascii_uppercase().replace('-', "_")
}

fn strings(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

fn compiled(pattern: &str) -> Result<String, String> {
    let converted = go_to_rust(pattern)?;
    regex::Regex::new(&converted)
        .map(|_| converted)
        .map_err(|e| {
            let detail = e.to_string();
            format!(
                "does not compile with the Rust regex crate: {}",
                detail.lines().last().unwrap_or("").trim()
            )
        })
}

fn render_allowlist(out: &mut String, list: &toml::Value) -> Result<(), String> {
    match list.get("regexTarget").and_then(toml::Value::as_str) {
        None | Some("secret") => {}
        Some(other) => {
            return Err(format!(
                "allowlist targets the {other}; only secret-targeted allowlists are ported"
            ))
        }
    }
    let all = list.get("condition").and_then(toml::Value::as_str) == Some("AND");
    let contextual = list.get("paths").is_some() || list.get("commits").is_some();
    let regexes = strings(list.get("regexes"))
        .iter()
        .map(|p| compiled(p))
        .collect::<Result<Vec<_>, _>>()?;
    let stopwords = strings(list.get("stopwords"));
    writeln!(out, "            Allowlist {{").unwrap();
    writeln!(out, "                all: {all},").unwrap();
    writeln!(out, "                path_or_commit: {contextual},").unwrap();
    render_list(out, "                regexes", &regexes);
    render_list(out, "                stopwords", &stopwords);
    writeln!(out, "            }},").unwrap();
    Ok(())
}

fn render_list(out: &mut String, label: &str, items: &[String]) {
    if items.is_empty() {
        writeln!(out, "{label}: &[],").unwrap();
        return;
    }
    writeln!(out, "{label}: &[").unwrap();
    for item in items {
        writeln!(
            out,
            "{}    {},",
            " ".repeat(label.find(|c: char| c != ' ').unwrap_or(0)),
            raw(item)
        )
        .unwrap();
    }
    writeln!(
        out,
        "{}],",
        " ".repeat(label.find(|c: char| c != ' ').unwrap_or(0))
    )
    .unwrap();
}

fn render_rule(out: &mut String, rule: &toml::Value) -> Result<(), String> {
    let id = rule["id"].as_str().unwrap();
    let regex = compiled(rule["regex"].as_str().unwrap())?;
    let keywords: Vec<String> = strings(rule.get("keywords"))
        .iter()
        .map(|k| k.to_ascii_lowercase())
        .collect();
    let entropy = rule
        .get("entropy")
        .and_then(toml::Value::as_float)
        .unwrap_or(0.0);
    let group = rule
        .get("secretGroup")
        .and_then(toml::Value::as_integer)
        .unwrap_or(0);
    let gated = ALWAYS_GATED.contains(&id) || keywords_always_in_match(&regex, &keywords);
    let mut lists = String::new();
    for list in rule
        .get("allowlists")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        render_allowlist(&mut lists, list)?;
    }
    writeln!(out, "    Rule {{").unwrap();
    writeln!(out, "        id: {},", raw(id)).unwrap();
    writeln!(out, "        ty: {},", raw(&type_name(id))).unwrap();
    writeln!(out, "        regex: {},", raw(&regex)).unwrap();
    writeln!(out, "        secret_group: {group},").unwrap();
    render_list(out, "        keywords", &keywords);
    writeln!(out, "        gated: {gated},").unwrap();
    writeln!(out, "        entropy: {entropy:?},").unwrap();
    if lists.is_empty() {
        writeln!(out, "        allowlists: &[],").unwrap();
    } else {
        writeln!(out, "        allowlists: &[").unwrap();
        out.push_str(&lists);
        writeln!(out, "        ],").unwrap();
    }
    writeln!(out, "    }},").unwrap();
    Ok(())
}

fn render() -> String {
    let config = load();
    let mut body = String::new();
    let mut excluded: Vec<(String, String)> = EXCLUDED
        .iter()
        .map(|(id, why)| ((*id).to_owned(), (*why).to_owned()))
        .collect();
    let mut included = 0usize;
    for rule in rules(&config) {
        let id = rule["id"].as_str().unwrap();
        if EXCLUDED.iter().any(|(x, _)| *x == id) {
            continue;
        }
        if rule.get("path").is_some() || rule.get("regex").is_none() {
            excluded.push((
                id.to_owned(),
                "path-scoped rule without an explicit exclusion".to_owned(),
            ));
            continue;
        }
        match render_rule(&mut body, rule) {
            Ok(()) => included += 1,
            Err(e) => excluded.push((id.to_owned(), format!("not ported: {e}"))),
        }
    }
    let global = config["allowlist"].as_table().unwrap();
    let global_regexes = strings(global.get("regexes"))
        .iter()
        .map(|p| compiled(p).unwrap())
        .collect::<Vec<_>>();
    let global_stopwords = strings(global.get("stopwords"));

    let mut out = String::new();
    writeln!(
        out,
        "//! GENERATED from `data/gitleaks/gitleaks.toml` (gitleaks {UPSTREAM_VERSION}, MIT)."
    )
    .unwrap();
    writeln!(out, "//! Do not edit. Regenerate with").unwrap();
    writeln!(
        out,
        "//! `CERBERUST_REGENERATE_GITLEAKS=1 cargo test --test gitleaks_rules`."
    )
    .unwrap();
    writeln!(out, "//!").unwrap();
    writeln!(
        out,
        "//! {included} rules included; {} excluded (see [`EXCLUDED`]).",
        excluded.len()
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(out, "use super::gitleaks::{{Allowlist, Rule}};").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "/// The ported gitleaks rules, in upstream order.").unwrap();
    writeln!(out, "pub(crate) const RULES: &[Rule] = &[").unwrap();
    out.push_str(&body);
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "/// Upstream global allowlist regexes, checked against every secret."
    )
    .unwrap();
    writeln!(out, "pub(crate) const GLOBAL_REGEXES: &[&str] = &[").unwrap();
    for r in &global_regexes {
        writeln!(out, "    {},", raw(r)).unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "/// Upstream global stopwords: a secret containing one is not a finding."
    )
    .unwrap();
    writeln!(out, "pub(crate) const GLOBAL_STOPWORDS: &[&str] = &[").unwrap();
    for s in &global_stopwords {
        writeln!(out, "    {},", raw(s)).unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "/// Upstream rules left out of the port, with the reason."
    )
    .unwrap();
    writeln!(out, "#[cfg_attr(not(test), expect(dead_code, reason = \"documentation table, read by tests\"))]").unwrap();
    writeln!(out, "pub(crate) const EXCLUDED: &[(&str, &str)] = &[").unwrap();
    for (id, why) in &excluded {
        writeln!(out, "    ({}, {}),", raw(id), raw(why)).unwrap();
    }
    writeln!(out, "];").unwrap();
    out
}

#[test]
fn generated_file_path_exists_relative_to_crate_root() {
    assert!(Path::new("data/gitleaks/gitleaks.toml").is_file());
}
