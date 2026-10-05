//! Vendor secret rules ported from gitleaks, matched with gitleaks' semantics.
//!
//! The rule table ([`super::gitleaks_rules`]) is generated from the vendored
//! upstream config by `tests/gitleaks_rules.rs`. This module compiles it once
//! and applies it the way gitleaks does:
//!
//! 1. **Keyword prefilter.** A rule's regex runs only when one of its keywords
//!    occurs in the text (ASCII case-insensitive), found in one Aho-Corasick pass.
//! 2. **Secret group.** The redacted span is the rule's `secretGroup`, else the
//!    first non-empty capture group, else the whole match.
//! 3. **Entropy.** A rule with an entropy minimum drops a secret whose Shannon
//!    entropy is at or below it.
//! 4. **Allowlists.** The rule's allowlists and the global allowlist drop a
//!    secret matched by an allowlist regex or containing a stopword. A prompt
//!    has no file path or commit, so path/commit criteria never match: under
//!    `OR` they are ignored, and an `AND` allowlist that needs one never
//!    applies. Only secret-targeted allowlist regexes are ported; the generator
//!    excludes a rule whose allowlist targets the match or the line.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};
use regex::Regex;
use regex_automata::meta;
use regex_automata::util::captures::Captures;
use regex_automata::Input;

use super::detect::Span;
use super::gitleaks_rules::{GLOBAL_REGEXES, GLOBAL_STOPWORDS, RULES};

/// Confidence of a ported-rule span. Below the crate's hand-written vendor
/// patterns (0.99), so an identical span keeps its established type name.
const CONFIDENCE: f32 = 0.95;

/// One ported gitleaks rule (generated data).
#[derive(Debug)]
pub(crate) struct Rule {
    /// Upstream rule id.
    #[cfg_attr(not(test), expect(dead_code, reason = "rule identity, read by tests"))]
    pub id: &'static str,
    /// Sentinel entity type (the id upper-cased, `-` → `_`).
    pub ty: &'static str,
    /// The regex, rewritten to Rust with gitleaks' ASCII class semantics.
    pub regex: &'static str,
    /// Capture group holding the secret; `0` = unset.
    pub secret_group: usize,
    /// Lower-case keywords; the rule runs only if one occurs in the text.
    pub keywords: &'static [&'static str],
    /// Whether every match contains a keyword. An ungated rule (its keyword can
    /// sit before the token, as with Airtable and Facebook) always runs, so a
    /// streaming flush that holds the token but not the keyword still sees it.
    pub gated: bool,
    /// Minimum Shannon entropy; `0.0` = no minimum.
    pub entropy: f64,
    /// Rule-level allowlists.
    pub allowlists: &'static [Allowlist],
}

/// A rule-level allowlist (generated data).
#[derive(Debug)]
pub(crate) struct Allowlist {
    /// `true` for `condition = "AND"`.
    pub all: bool,
    /// The allowlist also names paths or commits, which a prompt never has.
    pub path_or_commit: bool,
    /// Allowlist regexes, matched against the secret.
    pub regexes: &'static [&'static str],
    /// Stopwords, matched case-insensitively as substrings of the secret.
    pub stopwords: &'static [&'static str],
}

struct CompiledAllowlist {
    all: bool,
    path_or_commit: bool,
    regexes: Vec<Regex>,
    stopwords: &'static [&'static str],
}

struct CompiledRule {
    rule: &'static Rule,
    re: meta::Regex,
    /// Longest possible match in bytes; `None` when unbounded.
    max_len: Option<usize>,
    allowlists: Vec<CompiledAllowlist>,
}

struct Compiled {
    rules: Vec<CompiledRule>,
    /// Keyword automaton; pattern `i` is `keyword_rules[i]`'s keyword.
    keywords: Option<AhoCorasick>,
    /// For each keyword pattern, the indices (into `rules`) that carry it.
    keyword_rules: Vec<Vec<usize>>,
    global_regexes: Vec<Regex>,
}

fn compile_all(patterns: &[&str]) -> Vec<Regex> {
    patterns.iter().filter_map(|p| Regex::new(p).ok()).collect()
}

fn compiled() -> &'static Compiled {
    static COMPILED: OnceLock<Compiled> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let mut rules = Vec::with_capacity(RULES.len());
        let mut keyword_list: Vec<&'static str> = Vec::new();
        let mut keyword_rules: Vec<Vec<usize>> = Vec::new();
        for rule in RULES {
            // Every generated regex compiles (the generator checks); a failure
            // here would drop that one rule rather than panic.
            let Ok(re) = meta::Regex::new(rule.regex) else {
                continue;
            };
            let max_len = regex_automata::util::syntax::parse(rule.regex)
                .ok()
                .and_then(|hir| hir.properties().maximum_len());
            let index = rules.len();
            for kw in rule.keywords {
                if let Some(pos) = keyword_list.iter().position(|k| *k == *kw) {
                    keyword_rules[pos].push(index);
                } else {
                    keyword_list.push(*kw);
                    keyword_rules.push(vec![index]);
                }
            }
            let allowlists = rule
                .allowlists
                .iter()
                .map(|a| CompiledAllowlist {
                    all: a.all,
                    path_or_commit: a.path_or_commit,
                    regexes: compile_all(a.regexes),
                    stopwords: a.stopwords,
                })
                .collect();
            rules.push(CompiledRule {
                rule,
                re,
                max_len,
                allowlists,
            });
        }
        let keywords = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .kind(Some(AhoCorasickKind::DFA))
            .build(&keyword_list)
            .ok();
        Compiled {
            rules,
            keywords,
            keyword_rules,
            global_regexes: compile_all(GLOBAL_REGEXES),
        }
    })
}

/// The optional context prefix gitleaks' semi-generic rules open with: up to
/// 50 identifier characters before the vendor keyword (`MY_HEROKU_KEY=`).
const OPTIONAL_PREFIX: &str = "[0-9A-Za-z_.-]{0,50}?";

/// The ported rules' regex sources, for the streaming hold-back DFA.
///
/// The optional identifier prefix of the semi-generic rules is dropped: it can
/// match empty, so any match of the full rule also matches, without it, from the
/// keyword onward — holding back from the keyword is enough for the unary scan
/// to see the whole match, and the prefix is never part of the redacted secret.
/// Keeping it would make every identifier character a live match start and
/// multiply the DFA's states across ~100 rules.
pub(crate) fn pattern_sources() -> impl Iterator<Item = String> {
    RULES.iter().map(|r| hold_back_source(r.regex))
}

fn hold_back_source(regex: &str) -> String {
    let (flag, rest) = regex
        .strip_prefix("(?i)")
        .map_or(("", regex), |rest| ("(?i)", rest));
    let rest = rest.strip_prefix(OPTIONAL_PREFIX).unwrap_or(rest);
    // A few rules repeat the prefix inside a case-insensitive group:
    // `…{0,50}?(?i:…{0,50}?(?:okta)…)`.
    match rest
        .strip_prefix("(?i:")
        .and_then(|inner| inner.strip_prefix(OPTIONAL_PREFIX))
    {
        Some(inner) => format!("{flag}(?i:{inner}"),
        None => format!("{flag}{rest}"),
    }
}

/// Detect secrets with the ported gitleaks rules.
///
/// A gated rule's match always contains one of its keywords, so its regex runs
/// only over windows around the keyword hits, each widened by the rule's
/// longest possible match (the whole text when unbounded). Look-around at a
/// window's edge still sees the surrounding bytes.
#[must_use]
pub(crate) fn detect(text: &str) -> Vec<Span> {
    let c = compiled();
    let Some(keywords) = &c.keywords else {
        return Vec::new();
    };
    // Per rule: keyword hit spans, or `None` if the rule does not run.
    let mut hits: Vec<Option<Vec<(usize, usize)>>> = c
        .rules
        .iter()
        .map(|r| (!r.rule.gated).then(Vec::new))
        .collect();
    for m in keywords.find_overlapping_iter(text) {
        for &i in &c.keyword_rules[m.pattern().as_usize()] {
            hits[i]
                .get_or_insert_with(Vec::new)
                .push((m.start(), m.end()));
        }
    }
    let mut spans = Vec::new();
    for (rule, rule_hits) in c.rules.iter().zip(hits) {
        let Some(rule_hits) = rule_hits else {
            continue;
        };
        let windows = match (rule.rule.gated, rule.max_len) {
            (true, Some(max_len)) => windows(&rule_hits, max_len, text.len()),
            _ => vec![(0, text.len())],
        };
        let mut caps = rule.re.create_captures();
        for (from, to) in windows {
            let mut input = Input::new(text).span(from..to);
            while let Some(m) = {
                rule.re.search_captures(&input, &mut caps);
                caps.get_match()
            } {
                if let Some(span) = finding(c, rule, text, &caps) {
                    spans.push(span);
                }
                // An empty match must still advance.
                let next = if m.is_empty() { m.end() + 1 } else { m.end() };
                if next > to {
                    break;
                }
                input.set_start(next);
            }
        }
    }
    spans
}

/// Merge keyword hits into search windows: a match containing the hit at
/// `start..end` begins no earlier than `end - max_len` and ends no later than
/// `start + max_len`.
fn windows(hits: &[(usize, usize)], max_len: usize, len: usize) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for &(start, end) in hits {
        let from = end.saturating_sub(max_len);
        let to = (start + max_len).min(len);
        match out.last_mut() {
            Some(last) if from <= last.1 => last.1 = last.1.max(to),
            _ => out.push((from, to)),
        }
    }
    out
}

fn finding(c: &Compiled, rule: &CompiledRule, text: &str, caps: &Captures) -> Option<Span> {
    let secret = secret_match(rule.rule.secret_group, caps)?;
    let value = &text[secret.0..secret.1];
    if rule.rule.entropy > 0.0 && shannon_entropy(value) <= rule.rule.entropy {
        return None;
    }
    if globally_allowed(c, value) {
        return None;
    }
    if rule.allowlists.iter().any(|a| allowed(a, value)) {
        return None;
    }
    Some(Span::new(secret.0, secret.1, rule.rule.ty, CONFIDENCE))
}

/// gitleaks' secret selection: the configured group, else the first non-empty
/// capture group, else the whole match. A configured group that did not
/// participate yields no finding.
fn secret_match(group: usize, caps: &Captures) -> Option<(usize, usize)> {
    let groups = caps.group_len();
    let span = |i: usize| caps.get_group(i).map(|s| (s.start, s.end));
    if groups < 2 {
        return span(0);
    }
    if group > 0 {
        return span(group);
    }
    (1..groups)
        .filter_map(span)
        .find(|(start, end)| end > start)
        .or_else(|| span(0))
}

fn contains_stopword(secret: &str, stopwords: &[&str]) -> bool {
    let lower = secret.to_ascii_lowercase();
    stopwords
        .iter()
        .any(|w| lower.contains(&w.to_ascii_lowercase()))
}

fn globally_allowed(c: &Compiled, secret: &str) -> bool {
    c.global_regexes.iter().any(|re| re.is_match(secret))
        || contains_stopword(secret, GLOBAL_STOPWORDS)
}

fn allowed(list: &CompiledAllowlist, secret: &str) -> bool {
    let regex_hit =
        (!list.regexes.is_empty()).then(|| list.regexes.iter().any(|re| re.is_match(secret)));
    let stop_hit = (!list.stopwords.is_empty()).then(|| contains_stopword(secret, list.stopwords));
    let checks = [regex_hit, stop_hit];
    if list.all {
        // Every specified criterion must match; a path/commit criterion cannot.
        !list.path_or_commit
            && checks.iter().flatten().all(|&hit| hit)
            && checks.iter().any(Option::is_some)
    } else {
        checks.iter().flatten().any(|&hit| hit)
    }
}

/// Shannon entropy in bits per character, over `char`s as gitleaks computes it.
fn shannon_entropy(s: &str) -> f64 {
    let mut counts: Vec<(char, u32)> = Vec::new();
    let mut total = 0u32;
    for ch in s.chars() {
        total += 1;
        match counts.iter_mut().find(|(c, _)| *c == ch) {
            Some((_, n)) => *n += 1,
            None => counts.push((ch, 1)),
        }
    }
    if total == 0 {
        return 0.0;
    }
    let len = f64::from(total);
    counts
        .iter()
        .map(|&(_, n)| {
            let p = f64::from(n) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use super::super::gitleaks_rules::EXCLUDED;
    use super::*;

    fn types(text: &str) -> Vec<String> {
        detect(text).into_iter().map(|s| s.ty).collect()
    }

    #[test]
    fn every_rule_compiles() {
        assert_eq!(compiled().rules.len(), RULES.len());
        assert!(RULES.len() > 150, "unexpectedly few rules: {}", RULES.len());
    }

    #[test]
    fn every_rule_match_consumes_at_least_one_byte() {
        for rule in RULES {
            let hir = regex_automata::util::syntax::parse(rule.regex).expect("rule regex parses");
            assert!(
                hir.properties().minimum_len().is_some_and(|len| len > 0),
                "{} can match the empty string",
                rule.id
            );
        }
    }

    #[test]
    fn every_allowlist_regex_compiles() {
        // `compile_all` drops a regex that fails to compile; none may.
        for rule in RULES {
            for list in rule.allowlists {
                for re in list.regexes {
                    assert!(Regex::new(re).is_ok(), "{}: {re}", rule.id);
                }
            }
        }
        for re in GLOBAL_REGEXES {
            assert!(Regex::new(re).is_ok(), "global: {re}");
        }
    }

    #[test]
    fn excluded_rules_are_not_ported() {
        for (id, _) in EXCLUDED {
            assert!(
                RULES.iter().all(|r| r.id != *id),
                "{id} is excluded but ported"
            );
        }
    }

    #[test]
    fn windows_cover_every_match_containing_a_hit_and_merge() {
        // Hit at 50..54, max match 10: a match holding it lies within 44..60.
        assert_eq!(windows(&[(50, 54)], 10, 100), vec![(44, 60)]);
        // Overlapping windows merge; the start clamps at 0 and the end at len.
        assert_eq!(windows(&[(2, 4), (8, 10)], 6, 12), vec![(0, 12)]);
        assert_eq!(
            windows(&[(0, 4), (80, 84)], 10, 100),
            vec![(0, 10), (74, 90)]
        );
    }

    #[test]
    fn windowed_search_keeps_word_boundary_context() {
        // `\b` before a Datadog-style hex token must see the byte before the
        // window: a token glued to a preceding word is not a match.
        let key = "0123456789abcdef".repeat(2) + "01234567";
        let glued = format!("datadog x{key}");
        let spaced = format!("datadog {key}");
        let ty = "DATADOG_ACCESS_TOKEN";
        assert_eq!(
            detect(&glued).iter().any(|s| s.ty == ty),
            Regex::new(RULES.iter().find(|r| r.ty == ty).unwrap().regex)
                .unwrap()
                .is_match(&glued)
        );
        assert!(detect(&spaced)
            .iter()
            .all(|s| s.start >= "datadog ".len() || s.ty != ty));
    }

    #[test]
    fn keyword_prefilter_gates_the_regex() {
        // `github_pat_` + 82 token characters is a fine-grained PAT; the same
        // body without the keyword prefix is not.
        let body: String = "Q7w_E2r9T4y1U8i3O6p0A5sD"
            .chars()
            .cycle()
            .take(82)
            .collect();
        assert!(!types(&body).iter().any(|t| t == "GITHUB_FINE_GRAINED_PAT"));
        let token = format!("github_pat_{body}");
        assert!(types(&token).iter().any(|t| t == "GITHUB_FINE_GRAINED_PAT"));
    }

    #[test]
    fn secret_group_limits_the_span_to_the_secret() {
        // Built at runtime so no key-shaped literal sits in the source.
        let key = format!("SK{}", "0123456789abcdef".repeat(2));
        let text = format!("export TWILIO_KEY={key}");
        let spans = detect(&text);
        let twilio = spans.iter().find(|s| s.ty == "TWILIO_API_KEY").unwrap();
        assert_eq!(&text[twilio.start..twilio.end], key);
    }

    #[test]
    fn global_stopword_drops_a_placeholder() {
        assert!(contains_stopword(
            "xxabcdefghijklmnopqrstuvwxyzxx",
            GLOBAL_STOPWORDS
        ));
        let placeholder: String = "abcdefghijklmnopqrstuvwxyz0123456789"
            .chars()
            .cycle()
            .take(82)
            .collect();
        assert!(!types(&format!("github_pat_{placeholder}"))
            .iter()
            .any(|t| t == "GITHUB_FINE_GRAINED_PAT"));
    }

    #[test]
    fn low_entropy_value_is_dropped() {
        // Artifactory API keys carry a 4.5-bit entropy minimum.
        let varied: String = "Zq8Xw3Rt6Yp1Lk9Mn2Bv5Cx7Hj4Gf0Ds"
            .chars()
            .cycle()
            .take(69)
            .collect();
        let flat = "a".repeat(69);
        assert!(types(&format!("AKCp{varied}"))
            .iter()
            .any(|t| t == "ARTIFACTORY_API_KEY"));
        assert!(!types(&format!("AKCp{flat}"))
            .iter()
            .any(|t| t == "ARTIFACTORY_API_KEY"));
    }

    #[test]
    fn allowlist_and_needs_every_criterion() {
        let list = CompiledAllowlist {
            all: true,
            path_or_commit: true,
            regexes: vec![Regex::new("x").unwrap()],
            stopwords: &[],
        };
        assert!(!allowed(&list, "x"));
        let or_list = CompiledAllowlist { all: false, ..list };
        assert!(allowed(&or_list, "x"));
    }

    #[test]
    fn hold_back_source_drops_only_the_optional_prefix() {
        assert_eq!(
            hold_back_source("(?i)[0-9A-Za-z_.-]{0,50}?(?:heroku)x"),
            "(?i)(?:heroku)x"
        );
        assert_eq!(hold_back_source("ghp_[0-9]{36}"), "ghp_[0-9]{36}");
        assert_eq!(
            hold_back_source("[0-9A-Za-z_.-]{0,50}?(?i:[0-9A-Za-z_.-]{0,50}?(?:okta)x)"),
            "(?i:(?:okta)x)"
        );
        let leading = pattern_sources()
            .filter(|p| {
                p.trim_start_matches("(?i)")
                    .trim_start_matches("(?i:")
                    .starts_with(OPTIONAL_PREFIX)
            })
            .count();
        assert_eq!(leading, 0, "an optional leading prefix survived");
    }

    #[test]
    fn stripped_source_still_matches_the_full_rules_match_from_the_keyword() {
        let text = "export MY_HEROKU_API_KEY=\"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\"";
        let full = Regex::new(
            RULES
                .iter()
                .find(|r| r.id == "heroku-api-key")
                .unwrap()
                .regex,
        )
        .unwrap();
        let short = Regex::new(&hold_back_source(
            RULES
                .iter()
                .find(|r| r.id == "heroku-api-key")
                .unwrap()
                .regex,
        ))
        .unwrap();
        let full_secret = full.captures(text).unwrap().get(1).unwrap();
        let short_caps = short
            .captures(&text[text.find("HEROKU").unwrap()..])
            .unwrap();
        assert_eq!(full_secret.as_str(), short_caps.get(1).unwrap().as_str());
    }

    #[test]
    fn entropy_matches_uniform_expectation() {
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
        assert!(shannon_entropy("").abs() < f64::EPSILON);
    }

    #[test]
    fn empty_text_has_no_findings() {
        assert_eq!(detect(""), []);
    }
}

#[cfg(test)]
mod recall {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

    use super::*;

    /// Rewrite a rule regex into the subset `proptest::string_regex` can
    /// sample: drop word boundaries and anchors (they constrain context, not
    /// the token), and pin the optional identifier prefix to empty.
    fn sampling_form(regex: &str) -> String {
        regex
            .replace("(?-u:\\b)", "")
            .replace("(?-u:\\B)", "")
            .replace("[0-9A-Za-z_.-]{0,50}?", "")
            .replace("(?:[\\x60'\"\\t\\n\\f\\r ;]|\\\\[nr]|$)", "(?:[ ;])")
            .replace("(?:[^0-9A-Za-z_-]|\\z)", "(?: )")
            .replace("(?:[^a-zA-Z0-9+/]|\\z)", "(?: )")
            .replace("(?:[\\x60'\"\\t\\n\\f\\r ;,]|\\\\[nr]|$)", "(?:[ ;])")
            .replace('$', "")
            .replace("(?:^|", "(?:")
            .replace('^', "")
    }

    /// Examples for rules whose lazy multi-line regexes `string_regex` cannot
    /// sample. Credentials are drawn at test time.
    fn handwritten(id: &str, runner: &mut TestRunner) -> Option<Vec<String>> {
        let token = proptest::string::string_regex("[A-Za-z0-9]{24}")
            .unwrap()
            .new_tree(runner)
            .unwrap()
            .current();
        match id {
            "curl-auth-header" => Some(vec![format!(
                "curl -X POST https://api.example.com/v1 -H \"Authorization: Bearer {token}\""
            )]),
            "curl-auth-user" => Some(vec![format!(
                "curl --{} 'deploy:{token}' https://registry.example.com/v2/",
                "user"
            )]),
            _ => None,
        }
    }

    /// Every ported rule fires on tokens sampled from its own regex. Samples are
    /// generated at test time from a fixed seed, so no example token is
    /// committed. A rule passes if any of its samples is detected (entropy
    /// minimums reject some random draws by design).
    #[test]
    fn every_rule_fires_on_samples_of_its_own_regex() {
        let mut runner = TestRunner::new_with_rng(
            Config::default(),
            TestRng::from_seed(RngAlgorithm::ChaCha, &[7; 32]),
        );
        let mut silent = Vec::new();
        for rule in RULES {
            let fired = if let Some(texts) = handwritten(rule.id, &mut runner) {
                texts
                    .iter()
                    .any(|t| detect(t).iter().any(|s| s.ty == rule.ty))
            } else {
                let Ok(strategy) = proptest::string::string_regex(&sampling_form(rule.regex))
                else {
                    silent.push(format!("{} (unsamplable)", rule.id));
                    continue;
                };
                // gitleaks runs a rule only when a keyword occurs somewhere in
                // the text; some keywords sit outside the token itself.
                let context = rule.keywords.join(" ");
                (0..40).any(|_| {
                    let sample = strategy.new_tree(&mut runner).unwrap().current();
                    let text = format!("{context}\n{sample} \n");
                    detect(&text).iter().any(|s| s.ty == rule.ty)
                })
            };
            if !fired {
                silent.push(rule.id.to_owned());
            }
        }
        assert!(silent.is_empty(), "rules that never fired: {silent:?}");
    }
}
