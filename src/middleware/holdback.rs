//! The DFA that bounds how much of a streamed buffer is provably safe to flush.
//!
//! A streamed match can straddle a chunk boundary: emitting `AKIA` because the
//! chunk ended there, before the remaining 16 characters of the key arrive,
//! leaks the first half of a secret. The hold-back DFA decides, for the bytes
//! buffered so far, the longest prefix that **cannot** be the start of a match
//! still forming — that prefix is safe to flush; the rest is held until more
//! bytes arrive or the stream ends.
//!
//! # How the DFA bounds the hold-back
//!
//! The union of every active output scanner's [`stream_patterns`] compiles to
//! one anchored lazy DFA. For a candidate start offset `s` in the buffer, feed
//! `buffer[s..]` into the DFA from its start state and watch the match state:
//!
//! - **dead** before end-of-buffer — no match begins at `s`; `s` is safe.
//! - **alive at end-of-buffer** (accepting or mid-match, never having died) — a
//!   longer match *could* still form once more bytes arrive; `s` is **live**.
//!
//! The earliest live `s` is the hold point: everything before it is flushed,
//! `buffer[s..]` is held. A match that both starts and ends inside the flushed
//! prefix is fine — the unary scan redacts it; only a match that could extend
//! past the buffer is dangerous, and that is exactly the "alive at EOF" case.
//! When uncertain the DFA holds: an unbounded tail (`sk-[A-Za-z0-9]{20,}`, the
//! PEM `[\s\S]*?` body) keeps every interior start live, so the runner holds
//! from the secret's first byte until the match provably completes or dies.
//!
//! [`stream_patterns`]: crate::Scanner::stream_patterns

use regex_automata::{
    hybrid::dfa::{Cache, DFA},
    util::start::Config as StartConfig,
    Anchored, MatchKind,
};

/// A compiled hold-back DFA over the union of the active output scanners'
/// stream patterns.
#[derive(Debug)]
pub struct HoldBackDfa {
    dfa: DFA,
    /// `true` when no scanner contributed a pattern: there is nothing to hold
    /// back for matches (sentinel hold-back is handled separately), so every
    /// buffer flushes whole.
    empty: bool,
}

impl HoldBackDfa {
    /// Build a DFA recognising any of `patterns` (the union). Patterns that fail
    /// to compile into the combined DFA are dropped — the same defensive stance
    /// the unary detectors take — leaving a DFA over whatever compiled. An empty
    /// or all-failing pattern set yields a DFA that holds nothing back.
    #[must_use]
    pub fn new(patterns: &[String]) -> Self {
        if patterns.is_empty() {
            return Self::nothing();
        }
        let patterns: Vec<String> = patterns.iter().map(|p| ascii_word_boundaries(p)).collect();
        // `All` match semantics keep every alive thread rather than reporting the
        // leftmost-first match and stopping — the hold-back needs to know a
        // thread is *still alive*, not merely that one match already finished.
        let built = DFA::builder()
            .configure(DFA::config().match_kind(MatchKind::All))
            .build_many(&patterns);
        match built {
            Ok(dfa) => Self { dfa, empty: false },
            Err(_) => Self::compile_individually(&patterns),
        }
    }

    /// A DFA over no pattern: nothing is ever held back for a match. The build
    /// of an empty pattern set is total — but rather than `expect`, fall back to
    /// the same DFA over a never-matching pattern if it somehow fails, keeping
    /// the constructor panic-free.
    fn nothing() -> Self {
        let dfa = DFA::builder()
            .configure(DFA::config().match_kind(MatchKind::All))
            .build_many::<&str>(&[])
            .unwrap_or_else(|_| never_match_dfa());
        Self { dfa, empty: true }
    }

    // The `nothing()` DFA is never consulted (an `empty` runner returns the full
    // buffer before touching it), so this value only needs to exist.

    /// Build from only the patterns that compile when the combined build failed
    /// (one bad caller regex must not disable hold-back for the good ones).
    fn compile_individually(patterns: &[String]) -> Self {
        let good: Vec<String> = patterns
            .iter()
            .filter(|p| {
                DFA::builder()
                    .configure(DFA::config().match_kind(MatchKind::All))
                    .build(p)
                    .is_ok()
            })
            .cloned()
            .collect();
        if good.is_empty() {
            return Self::nothing();
        }
        match DFA::builder()
            .configure(DFA::config().match_kind(MatchKind::All))
            .build_many(&good)
        {
            Ok(dfa) => Self { dfa, empty: false },
            Err(_) => Self::nothing(),
        }
    }

    /// The byte offset in `buf` up to which it is safe to flush: the earliest
    /// start offset from which a match could still be forming at end-of-buffer.
    /// Returns `buf.len()` when nothing is live (flush everything) and `0` when a
    /// match could begin at the very first byte (hold everything).
    ///
    /// `at_eof` collapses the hold-back: at the true end of the stream no more
    /// bytes will arrive, so a "still could extend" thread can never complete —
    /// everything flushes (the final unary scan redacts any complete match).
    #[must_use]
    pub fn safe_flush_len(&self, buf: &[u8], at_eof: bool) -> usize {
        if self.empty || at_eof {
            return buf.len();
        }
        let mut cache = self.dfa.create_cache();
        for s in 0..buf.len() {
            if self.alive_at_eof(&mut cache, &buf[s..]) {
                return s;
            }
        }
        buf.len()
    }

    /// Whether feeding `tail` into the anchored DFA from the start state leaves
    /// it alive (never dead) all the way to the end — i.e. more bytes could
    /// extend or complete a match that began at `tail`'s first byte.
    fn alive_at_eof(&self, cache: &mut Cache, tail: &[u8]) -> bool {
        // Cannot prove dead ⇒ hold (conservative).
        let Ok(start) = self
            .dfa
            .start_state(cache, &StartConfig::new().anchored(Anchored::Yes))
        else {
            return true;
        };
        let mut state = start;
        for &b in tail {
            state = match self.dfa.next_state(cache, state, b) {
                Ok(s) => s,
                Err(_) => return true,
            };
            if state.is_dead() {
                return false;
            }
        }
        // Reached end-of-buffer without dying: still a viable (live) start.
        !state.is_dead()
    }
}

/// Rewrite Unicode word boundaries (`\b`, `\B`) to their ASCII forms
/// (`(?-u:\b)`, `(?-u:\B)`) so the lazy DFA can build the pattern.
///
/// `regex-automata`'s lazy DFA rejects Unicode word boundaries outright; the
/// structured-PII patterns (phone, SSN, IP, card) all anchor on `\b`, so without
/// this rewrite they fail to compile and are silently dropped from the hold-back
/// DFA — a spaced card or SSN split across chunks then flushes group-by-group and
/// leaks. These patterns match ASCII digits and email bytes only, so an ASCII
/// boundary is semantically identical here. The unary detector regexes (the
/// high-level `regex` crate, which handles Unicode `\b`) are untouched: this
/// rewrite is hold-back-only. Already-ASCII `(?-u:\b)` is left as-is because the
/// scan walks character by character and only converts a `\b`/`\B` not already
/// preceded by the `-u:` scope opener.
fn ascii_word_boundaries(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // Consume the escaped char as a pair so a literal `\\` is never
            // misread, and the following char is never re-scanned as a boundary.
            match chars.next() {
                Some(esc @ ('b' | 'B')) => {
                    out.push_str("(?-u:\\");
                    out.push(esc);
                    out.push(')');
                }
                Some(esc) => {
                    out.push('\\');
                    out.push(esc);
                }
                None => out.push('\\'),
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// A DFA that matches nothing — the total fallback when the empty-pattern build
/// somehow fails. `[^\s\S]` matches no character and is a fixed valid pattern;
/// if even it fails to build, recurse rather than panic (unreachable in
/// practice, total by construction).
fn never_match_dfa() -> DFA {
    match DFA::builder()
        .configure(DFA::config().match_kind(MatchKind::All))
        .build(r"[^\s\S]")
    {
        Ok(dfa) => dfa,
        Err(_) => never_match_dfa(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use super::*;

    fn dfa(pats: &[&str]) -> HoldBackDfa {
        HoldBackDfa::new(&pats.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn empty_pattern_set_flushes_everything() {
        let d = dfa(&[]);
        assert_eq!(d.safe_flush_len(b"anything at all", false), 15);
    }

    #[test]
    fn holds_from_a_forming_match() {
        // AWS key prefix: AKIA then 16 [0-9A-Z]. "AKIAABC" is a live prefix, so
        // the hold point is at the 'A' of AKIA — flush nothing after it.
        let d = dfa(&[r"AKIA[0-9A-Z]{16}"]);
        let buf = b"see AKIAABC";
        let flush = d.safe_flush_len(buf, false);
        assert_eq!(&buf[..flush], b"see ");
    }

    #[test]
    fn flushes_when_match_dies() {
        // "AKIA!" cannot extend to a key ('!' is not [0-9A-Z]); the whole buffer
        // is dead-from-every-start, so it all flushes.
        let d = dfa(&[r"AKIA[0-9A-Z]{16}"]);
        let buf = b"AKIA!rest";
        assert_eq!(d.safe_flush_len(buf, false), buf.len());
    }

    #[test]
    fn eof_collapses_holdback() {
        // At true end-of-stream a forming match can never complete; flush all.
        let d = dfa(&[r"AKIA[0-9A-Z]{16}"]);
        let buf = b"see AKIAABC";
        assert_eq!(d.safe_flush_len(buf, true), buf.len());
    }

    #[test]
    fn unbounded_tail_holds_from_match_start() {
        // sk- then 20+ chars: every interior position keeps a thread alive, so
        // the hold point is the 's' of "sk-".
        let d = dfa(&[r"sk-[A-Za-z0-9]{20,}"]);
        let buf = b"key sk-aaaaaaaaaaaaaaaaaaaaaa";
        let flush = d.safe_flush_len(buf, false);
        assert_eq!(&buf[..flush], b"key ");
    }

    #[test]
    fn clean_buffer_with_patterns_flushes_whole() {
        let d = dfa(&[r"AKIA[0-9A-Z]{16}"]);
        let buf = b"the quick brown fox";
        assert_eq!(d.safe_flush_len(buf, false), buf.len());
    }

    #[test]
    fn one_bad_pattern_does_not_disable_others() {
        // An unparseable pattern is dropped; the good one still holds back.
        let d = dfa(&[r"AKIA[0-9A-Z]{16}", r"(unclosed"]);
        let buf = b"AKIAABC";
        assert_eq!(d.safe_flush_len(buf, false), 0);
    }

    #[test]
    fn rewrites_unicode_word_boundaries_to_ascii() {
        assert_eq!(
            ascii_word_boundaries(r"\b\d{3}\b"),
            r"(?-u:\b)\d{3}(?-u:\b)"
        );
        // A non-boundary escape is left untouched.
        assert_eq!(ascii_word_boundaries(r"\d{3}\."), r"\d{3}\.");
        assert_eq!(ascii_word_boundaries(r"\B"), r"(?-u:\B)");
    }

    #[test]
    fn word_boundary_pattern_builds_and_holds() {
        // The card pattern's Unicode `\b` would reject the lazy-DFA build; the
        // ASCII rewrite lets it compile and hold a forming spaced card so a card
        // split across chunks never flushes group-by-group.
        let d = dfa(&[r"\b(?:\d[ \-]?){13,19}\b"]);
        let buf = b"card 4111 1111 1111 ";
        let flush = d.safe_flush_len(buf, false);
        // Hold from the first card digit: the buffered prefix is still a live,
        // incomplete card, so only the text before it flushes.
        assert_eq!(&buf[..flush], b"card ");
    }
}
