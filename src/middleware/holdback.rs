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
//! # Completed matches are flushed whole
//!
//! A match that has already completed is not live, but the hold point another
//! pattern sets (or the last whitespace) can still fall inside it: a spaced
//! card followed by `\n5` leaves a phone pattern live from the card's last
//! group. Flushing there hands the unary scan a fragment it does not recognise,
//! and the card leaks. [`HoldScan::straddling_start`] finds such a
//! match so the runner moves the split back to its start. It follows each
//! pattern's own non-overlapping matches, as each unary detector's `find_iter`
//! does — overlapping candidates of one pattern (a card candidate at every digit
//! of a long run) would otherwise chain the split back to the buffer start.
//!
//! [`stream_patterns`]: crate::Scanner::stream_patterns

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use regex_automata::{
    hybrid::{
        dfa::{Cache, DFA},
        LazyStateID,
    },
    util::start::Config as StartConfig,
    Anchored, MatchKind,
};

/// Distinct pattern sets whose compiled DFA is kept for reuse. Beyond this the
/// memo is cleared: caller-supplied regex scanners can vary per tenant, and the
/// memo must not grow without bound.
const MEMO_LIMIT: usize = 64;

/// A compiled hold-back DFA over the union of the active output scanners'
/// stream patterns.
#[derive(Debug)]
pub struct HoldBackDfa {
    dfa: Arc<DFA>,
    /// The lazy DFA's state cache, kept across calls so states built for one
    /// buffer are reused for the next instead of being recomputed per push.
    cache: Mutex<Cache>,
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
    ///
    /// Compiling the union is the expensive step (hundreds of vendor secret
    /// patterns), and every stream builds one, so the compiled DFA is memoised
    /// per distinct pattern set; each call still gets its own per-use cache.
    #[must_use]
    pub fn new(patterns: &[String]) -> Self {
        static MEMO: OnceLock<Mutex<HashMap<Vec<String>, Arc<DFA>>>> = OnceLock::new();
        if patterns.is_empty() {
            return Self::nothing();
        }
        let memo = MEMO.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(dfa) = memo.lock().ok().and_then(|m| m.get(patterns).cloned()) {
            return Self::with_dfa(dfa, false);
        }
        let built = Self::build(patterns);
        if !built.empty {
            if let Ok(mut m) = memo.lock() {
                if m.len() >= MEMO_LIMIT {
                    m.clear();
                }
                m.insert(patterns.to_vec(), Arc::clone(&built.dfa));
            }
        }
        built
    }

    fn with_dfa(dfa: Arc<DFA>, empty: bool) -> Self {
        let cache = Mutex::new(dfa.create_cache());
        Self { dfa, cache, empty }
    }

    fn build(patterns: &[String]) -> Self {
        let patterns: Vec<String> = patterns.iter().map(|p| ascii_word_boundaries(p)).collect();
        // `All` match semantics keep every alive thread rather than reporting the
        // leftmost-first match and stopping — the hold-back needs to know a
        // thread is *still alive*, not merely that one match already finished.
        let built = DFA::builder()
            .configure(DFA::config().match_kind(MatchKind::All))
            .build_many(&patterns);
        match built {
            Ok(dfa) => Self::with_dfa(Arc::new(dfa), false),
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
        Self::with_dfa(Arc::new(dfa), true)
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
            Ok(dfa) => Self::with_dfa(Arc::new(dfa), false),
            Err(_) => Self::nothing(),
        }
    }

    /// One pass over `buf`: the flush length and the completed matches before it.
    ///
    /// The flush length is the earliest start offset from which a match could
    /// still be forming at end-of-buffer, snapped to its token start — `buf.len()`
    /// when nothing is live, `0` when a match could begin at the first byte.
    ///
    /// The same anchored run from each start also yields the matches completed
    /// before that point, followed per pattern, left to right and non-overlapping
    /// — a pattern's candidate that starts inside its own earlier candidate is
    /// skipped, as the unary `find_iter` skips it. Where the lazy DFA cannot
    /// decide (a cache failure) the start counts as live — hold.
    #[must_use]
    pub fn scan(&self, buf: &[u8]) -> HoldScan {
        let mut hold = HoldScan {
            flush_len: buf.len(),
            matches: Vec::new(),
        };
        if self.empty {
            return hold;
        }
        let mut guard = self.cache.lock().unwrap_or_else(|poisoned| {
            // An earlier call panicked mid-scan; its cache may be half-updated,
            // so start from a fresh one rather than trust it.
            let mut guard = poisoned.into_inner();
            *guard = self.dfa.create_cache();
            guard
        });
        // `(pattern, end)` of each pattern's previous match. Few patterns match
        // in any one buffer, so this stays short; a dense per-pattern table
        // would be zeroed on every push.
        let mut last_end: Vec<(usize, usize)> = Vec::new();
        let mut ends = Vec::new();
        for s in 0..buf.len() {
            let before = s.checked_sub(1).map(|i| buf[i]);
            if !self.dies_from(&mut guard, buf, s, before, &mut ends) {
                hold.flush_len = token_start(buf, s);
                break;
            }
            for &(pattern, end) in &ends {
                match last_end.iter_mut().find(|(p, _)| *p == pattern) {
                    Some((_, prev)) if s < *prev => {}
                    Some((_, prev)) => {
                        *prev = end;
                        hold.matches.push((s, end));
                    }
                    None => {
                        last_end.push((pattern, end));
                        hold.matches.push((s, end));
                    }
                }
            }
        }
        hold
    }

    /// Feed `buf[start..]` into the anchored DFA. Returns `true` when it dies
    /// before end-of-buffer, filling `ends` with `(pattern index, longest match
    /// end)` for each pattern matched on the way; `false` when it is still alive
    /// at end-of-buffer (a match could still be forming) or cannot decide.
    ///
    /// Only matches containing ASCII whitespace are recorded: the runner splits
    /// only at 0, end-of-buffer, or just after whitespace, so no other match can
    /// cross a split. Leaving out a pattern's whitespace-free match can only make
    /// a later candidate of it look non-overlapping — more holding, never less.
    ///
    /// `before` is the byte preceding `start` (`None` at the buffer start), so a
    /// pattern opening with `\b` is not treated as live in the middle of a word.
    #[inline]
    fn dies_from(
        &self,
        cache: &mut Cache,
        buf: &[u8],
        start: usize,
        before: Option<u8>,
        ends: &mut Vec<(usize, usize)>,
    ) -> bool {
        ends.clear();
        let config = StartConfig::new()
            .anchored(Anchored::Yes)
            .look_behind(before);
        let Ok(mut state) = self.dfa.start_state(cache, &config) else {
            return false;
        };
        // Lazy-DFA matches are reported one byte late: a match state reached
        // after feeding `tail[i]` is a match over `tail[..i]`. Dead and match
        // states are both tagged, so the common path is a single check.
        let tail = &buf[start..];
        for (i, &b) in tail.iter().enumerate() {
            let Ok(next) = self.dfa.next_state(cache, state, b) else {
                return false;
            };
            state = next;
            if !state.is_tagged() {
                continue;
            }
            if state.is_dead() {
                return true;
            }
            if state.is_match() && tail[..i].iter().any(u8::is_ascii_whitespace) {
                self.record_match(cache, state, start + i, ends);
            }
        }
        false
    }

    /// Record `end` for every pattern `state` matches; later (longer) ends
    /// overwrite earlier ones.
    fn record_match(
        &self,
        cache: &Cache,
        state: LazyStateID,
        end: usize,
        ends: &mut Vec<(usize, usize)>,
    ) {
        if !state.is_match() {
            return;
        }
        for i in 0..self.dfa.match_len(cache, state) {
            let pattern = self.dfa.match_pattern(cache, state, i).as_usize();
            match ends.iter_mut().find(|(p, _)| *p == pattern) {
                Some(slot) => slot.1 = end,
                None => ends.push((pattern, end)),
            }
        }
    }
}

/// The result of [`HoldBackDfa::scan`] over one buffer.
#[derive(Debug)]
pub struct HoldScan {
    flush_len: usize,
    /// `(start, end)` of each completed match before the live point, ordered by
    /// start.
    matches: Vec<(usize, usize)>,
}

impl HoldScan {
    /// The byte offset up to which no match can still be forming.
    #[must_use]
    pub fn flush_len(&self) -> usize {
        self.flush_len
    }

    /// The start of the earliest completed match that begins before `split` and
    /// ends after it, if any; the runner moves its split back to it.
    #[must_use]
    pub fn straddling_start(&self, split: usize) -> Option<usize> {
        self.matches
            .iter()
            .find(|&&(start, end)| start < split && split < end)
            .map(|&(start, _)| start)
    }
}

/// Snap a hold point down to the start of the whitespace-delimited token that
/// contains it, so a flush never splits a token: a match starting mid-token
/// (a shorter pattern alive inside a longer key) must not strand the key's
/// prefix in the flushed output, where the unary scan no longer sees a whole
/// key.
fn token_start(buf: &[u8], hold: usize) -> usize {
    buf[..hold]
        .iter()
        .rposition(u8::is_ascii_whitespace)
        .map_or(0, |pos| pos + 1)
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
    fn word_boundary_pattern_is_not_live_mid_word() {
        let d = dfa(&[r"\b[0-9]{40}"]);
        // Inside a word, `\b` cannot hold: not a live start.
        assert_eq!(d.scan(b"a0123").flush_len(), 5);
        // After a space it can.
        assert_eq!(d.scan(b" 0123").flush_len(), 1);
    }

    #[test]
    fn hold_point_snaps_to_the_token_start() {
        assert_eq!(token_start(b"key gm_live_0123", 12), 4);
        assert_eq!(token_start(b"abc", 2), 0);
        assert_eq!(token_start(b"a\nbcd", 3), 2);
        // A shorter pattern alive inside a longer token holds the whole token.
        let d = dfa(&["[0-9a-f]{40}"]);
        assert_eq!(d.scan(b"key gm_live_0123").flush_len(), 4);
    }

    #[test]
    fn empty_pattern_set_flushes_everything() {
        let d = dfa(&[]);
        assert_eq!(d.scan(b"anything at all").flush_len(), 15);
    }

    #[test]
    fn holds_from_a_forming_match() {
        // AWS key prefix: AKIA then 16 [0-9A-Z]. "AKIAABC" is a live prefix, so
        // the hold point is at the 'A' of AKIA — flush nothing after it.
        let d = dfa(&[r"AKIA[0-9A-Z]{16}"]);
        let buf = b"see AKIAABC";
        let flush = d.scan(buf).flush_len();
        assert_eq!(&buf[..flush], b"see ");
    }

    #[test]
    fn flushes_when_match_dies() {
        // "AKIA!" cannot extend to a key ('!' is not [0-9A-Z]); the whole buffer
        // is dead-from-every-start, so it all flushes.
        let d = dfa(&[r"AKIA[0-9A-Z]{16}"]);
        let buf = b"AKIA!rest";
        assert_eq!(d.scan(buf).flush_len(), buf.len());
    }

    #[test]
    fn unbounded_tail_holds_from_match_start() {
        // sk- then 20+ chars: every interior position keeps a thread alive, so
        // the hold point is the 's' of "sk-".
        let d = dfa(&[r"sk-[A-Za-z0-9]{20,}"]);
        let buf = b"key sk-aaaaaaaaaaaaaaaaaaaaaa";
        let flush = d.scan(buf).flush_len();
        assert_eq!(&buf[..flush], b"key ");
    }

    #[test]
    fn clean_buffer_with_patterns_flushes_whole() {
        let d = dfa(&[r"AKIA[0-9A-Z]{16}"]);
        let buf = b"the quick brown fox";
        assert_eq!(d.scan(buf).flush_len(), buf.len());
    }

    #[test]
    fn one_bad_pattern_does_not_disable_others() {
        // An unparseable pattern is dropped; the good one still holds back.
        let d = dfa(&[r"AKIA[0-9A-Z]{16}", r"(unclosed"]);
        let buf = b"AKIAABC";
        assert_eq!(d.scan(buf).flush_len(), 0);
    }

    #[test]
    fn finds_a_completed_match_crossing_the_split() {
        let d = dfa(&[r"[0-9]{4} [0-9]{4}"]);
        let scan = d.scan(b"pay 1234 5678 now");
        assert_eq!(scan.flush_len(), 17);
        assert_eq!(scan.straddling_start(9), Some(4));
        assert_eq!(scan.straddling_start(4), None);
        assert_eq!(scan.straddling_start(14), None);
    }

    #[test]
    fn straddle_follows_each_patterns_non_overlapping_matches() {
        // A candidate starting inside the pattern's previous candidate is not a
        // match `find_iter` would report, so it cannot pull the split back.
        let d = dfa(&[r"[0-9]{4} [0-9]{4}"]);
        let scan = d.scan(b"1111 2222 3333 4444 x");
        assert_eq!(scan.straddling_start(15), Some(10));
        assert_eq!(scan.straddling_start(10), None);
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
        let flush = d.scan(buf).flush_len();
        // Hold from the first card digit: the buffered prefix is still a live,
        // incomplete card, so only the text before it flushes.
        assert_eq!(&buf[..flush], b"card ");
    }
}
