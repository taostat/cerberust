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
//! and the card leaks. `HoldScan::straddling_start` finds such a
//! match so the runner moves the split back to its start. It follows each
//! pattern's own non-overlapping matches, as each unary detector's `find_iter`
//! does — overlapping candidates of one pattern (a card candidate at every digit
//! of a long run) would otherwise chain the split back to the buffer start.
//!
//! [`stream_patterns`]: crate::Scanner::stream_patterns

use std::cell::OnceCell;
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

/// The compiled form of one pattern set, shared by every stream that uses it.
#[derive(Debug)]
struct Compiled {
    dfa: DFA,
    /// Each DFA pattern's source, by pattern index, with its leftmost-first
    /// regex compiled on first use — the semantics the unary detectors match
    /// with, which the `All`-semantics DFA cannot report.
    sources: Vec<(String, OnceLock<Option<regex::bytes::Regex>>)>,
}

impl Compiled {
    fn new(dfa: DFA, sources: Vec<String>) -> Self {
        let sources = sources.into_iter().map(|s| (s, OnceLock::new())).collect();
        Self { dfa, sources }
    }

    fn regex(&self, pattern: usize) -> Option<&regex::bytes::Regex> {
        let (source, re) = self.sources.get(pattern)?;
        re.get_or_init(|| regex::bytes::Regex::new(source).ok())
            .as_ref()
    }
}

/// A compiled hold-back DFA over the union of the active output scanners'
/// stream patterns.
#[derive(Debug)]
pub struct HoldBackDfa {
    compiled: Arc<Compiled>,
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
        static MEMO: OnceLock<Mutex<HashMap<Vec<String>, Arc<Compiled>>>> = OnceLock::new();
        if patterns.is_empty() {
            return Self::nothing();
        }
        let memo = MEMO.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(compiled) = memo.lock().ok().and_then(|m| m.get(patterns).cloned()) {
            return Self::with_compiled(compiled, false);
        }
        let built = Self::build(patterns);
        if !built.empty {
            if let Ok(mut m) = memo.lock() {
                if m.len() >= MEMO_LIMIT {
                    m.clear();
                }
                m.insert(patterns.to_vec(), Arc::clone(&built.compiled));
            }
        }
        built
    }

    fn with_compiled(compiled: Arc<Compiled>, empty: bool) -> Self {
        let cache = Mutex::new(compiled.dfa.create_cache());
        Self {
            compiled,
            cache,
            empty,
        }
    }

    fn build(patterns: &[String]) -> Self {
        let rewritten: Vec<String> = patterns.iter().map(|p| ascii_word_boundaries(p)).collect();
        // `All` match semantics keep every alive thread rather than reporting the
        // leftmost-first match and stopping — the hold-back needs to know a
        // thread is *still alive*, not merely that one match already finished.
        match all_matches_dfa().build_many(&rewritten) {
            Ok(dfa) => Self::with_compiled(Arc::new(Compiled::new(dfa, patterns.to_vec())), false),
            Err(_) => Self::compile_individually(patterns, &rewritten),
        }
    }

    /// A DFA over no pattern: nothing is ever held back for a match. The build
    /// of an empty pattern set is total — but rather than `expect`, fall back to
    /// the same DFA over a never-matching pattern if it somehow fails, keeping
    /// the constructor panic-free.
    fn nothing() -> Self {
        let dfa = all_matches_dfa()
            .build_many::<&str>(&[])
            .unwrap_or_else(|_| never_match_dfa());
        Self::with_compiled(Arc::new(Compiled::new(dfa, Vec::new())), true)
    }

    // The `nothing()` DFA is never consulted (an `empty` runner returns the full
    // buffer before touching it), so this value only needs to exist.

    /// Build from only the patterns that compile when the combined build failed
    /// (one bad caller regex must not disable hold-back for the good ones).
    fn compile_individually(patterns: &[String], rewritten: &[String]) -> Self {
        let mut sources = Vec::new();
        let mut good = Vec::new();
        for (source, pattern) in patterns.iter().zip(rewritten) {
            if all_matches_dfa().build(pattern).is_ok() {
                sources.push(source.clone());
                good.push(pattern.as_str());
            }
        }
        if good.is_empty() {
            return Self::nothing();
        }
        match all_matches_dfa().build_many(&good) {
            Ok(dfa) => Self::with_compiled(Arc::new(Compiled::new(dfa, sources)), false),
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
        if at_eof {
            return buf.len();
        }
        self.scan(buf).flush_len()
    }

    /// One pass over `buf`: the flush length (see [`Self::safe_flush_len`]) and
    /// what [`HoldScan::straddling_start`] needs to find a completed match a
    /// split would cut.
    ///
    /// A split falls only at 0, end-of-buffer, or just after whitespace, so only
    /// a match containing whitespace can cross one. The DFA pass records, per
    /// pattern with such a match before the live point, the first start and the
    /// furthest end it saw. Where the lazy DFA cannot decide (a cache failure)
    /// the start counts as live — hold.
    #[must_use]
    pub(crate) fn scan(&self, buf: &[u8]) -> HoldScan {
        let mut spanning = SpanningPatterns::default();
        let mut flush_len = buf.len();
        if !self.empty {
            let mut guard = self.cache.lock().unwrap_or_else(|poisoned| {
                // An earlier call panicked mid-scan; its cache may be
                // half-updated, so start from a fresh one rather than trust it.
                let mut guard = poisoned.into_inner();
                *guard = self.compiled.dfa.create_cache();
                guard
            });
            for s in 0..buf.len() {
                spanning.advance_next_whitespace(buf, s);
                if !self.dies_from(&mut guard, buf, s, &mut spanning) {
                    flush_len = token_start(buf, s);
                    break;
                }
            }
        }
        HoldScan {
            flush_len,
            compiled: Arc::clone(&self.compiled),
            candidates: spanning.patterns,
        }
    }

    /// Feed `buf[start..]` into the anchored DFA. Returns `true` when it dies
    /// before end-of-buffer, noting in `spanning` each pattern that matched
    /// across whitespace on the way; `false` when it is still alive at
    /// end-of-buffer (a match could still be forming) or cannot decide.
    ///
    /// The byte before `start` is the look-behind, so a pattern opening with
    /// `\b` is not treated as live in the middle of a word.
    #[inline]
    fn dies_from(
        &self,
        cache: &mut Cache,
        buf: &[u8],
        start: usize,
        spanning: &mut SpanningPatterns,
    ) -> bool {
        let dfa = &self.compiled.dfa;
        let config = StartConfig::new()
            .anchored(Anchored::Yes)
            .look_behind(start.checked_sub(1).map(|i| buf[i]));
        let Ok(mut state) = dfa.start_state(cache, &config) else {
            return false;
        };
        // Lazy-DFA matches are reported one byte late: a match state reached
        // after feeding `buf[at]` is a match over `buf[start..at]`. Dead and
        // match states are both tagged, so the common path is a single check.
        for (at, &b) in (start..).zip(&buf[start..]) {
            let Ok(next) = dfa.next_state(cache, state, b) else {
                return false;
            };
            state = next;
            if !state.is_tagged() {
                continue;
            }
            if state.is_dead() {
                return true;
            }
            if state.is_match() && spanning.next_whitespace < at {
                self.note_patterns(cache, state, start, at, spanning);
            }
        }
        false
    }

    /// Note every pattern `state` matches as having a whitespace-spanning match
    /// over `start..end`.
    fn note_patterns(
        &self,
        cache: &Cache,
        state: LazyStateID,
        start: usize,
        end: usize,
        spanning: &mut SpanningPatterns,
    ) {
        let dfa = &self.compiled.dfa;
        for i in 0..dfa.match_len(cache, state) {
            let pattern = dfa.match_pattern(cache, state, i).as_usize();
            match spanning.patterns.iter_mut().find(|c| c.pattern == pattern) {
                Some(c) => c.furthest_end = c.furthest_end.max(end),
                None => spanning.patterns.push(Candidate {
                    pattern,
                    first_start: start,
                    furthest_end: end,
                    unary: OnceCell::new(),
                }),
            }
        }
    }
}

/// The patterns a [`HoldBackDfa::scan`] pass saw match across whitespace.
#[derive(Debug, Default)]
struct SpanningPatterns {
    /// The first whitespace byte at or after the current start offset. It only
    /// moves forward, so the whole pass finds it in linear time.
    next_whitespace: usize,
    /// In first-seen order. Few patterns span whitespace, so this stays short.
    patterns: Vec<Candidate>,
}

/// The extent of one pattern's whitespace-spanning DFA matches in a buffer.
#[derive(Debug)]
struct Candidate {
    pattern: usize,
    first_start: usize,
    /// The furthest end of any of them. A leftmost-first match from a start
    /// never ends past the longest DFA match from it, so no unary match of this
    /// pattern crosses a split outside `first_start..furthest_end`.
    furthest_end: usize,
    /// The pattern's unary matches over the buffer that start before the first
    /// split asked about, found on first use and kept while the runner moves its
    /// split back match by match. The split only moves back, so later queries
    /// need no match past it — and enumerating past it would rescan the live
    /// suffix on every push.
    unary: OnceCell<Option<Vec<(usize, usize)>>>,
}

impl SpanningPatterns {
    fn advance_next_whitespace(&mut self, buf: &[u8], start: usize) {
        self.next_whitespace = self.next_whitespace.max(start);
        while self.next_whitespace < buf.len() && !buf[self.next_whitespace].is_ascii_whitespace() {
            self.next_whitespace += 1;
        }
    }
}

/// The result of [`HoldBackDfa::scan`] over one buffer.
#[derive(Debug)]
pub(crate) struct HoldScan {
    flush_len: usize,
    compiled: Arc<Compiled>,
    candidates: Vec<Candidate>,
}

impl HoldScan {
    /// The byte offset up to which no match can still be forming.
    #[must_use]
    pub(crate) fn flush_len(&self) -> usize {
        self.flush_len
    }

    /// The start of the earliest completed match in `buf` (the buffer passed to
    /// [`HoldBackDfa::scan`]) that begins before `split` and ends after it, if
    /// any; the runner moves its split back to it.
    ///
    /// Calls on one scan must pass non-increasing splits, as the runner does:
    /// the first call caches only the matches it needs, which covers every
    /// smaller split but not a larger one.
    ///
    /// Matches are each pattern's leftmost-first, non-overlapping matches — the
    /// ones the unary `find_iter` reports — found once with its regex, only for
    /// a pattern whose DFA candidates straddle `split`. If that regex does not
    /// compile, the pattern's first candidate start is returned — hold.
    #[must_use]
    pub(crate) fn straddling_start(&self, buf: &[u8], split: usize) -> Option<usize> {
        let mut earliest: Option<usize> = None;
        for c in &self.candidates {
            if !(c.first_start < split && split < c.furthest_end) {
                continue;
            }
            let unary = c.unary.get_or_init(|| {
                let re = self.compiled.regex(c.pattern)?;
                let matches = re.find_iter(buf).take_while(|m| m.start() < split);
                Some(matches.map(|m| (m.start(), m.end())).collect())
            });
            let start = match unary {
                // Sorted and non-overlapping: only the last match starting
                // before `split` can contain it.
                Some(matches) => matches[..matches.partition_point(|&(s, _)| s < split)]
                    .last()
                    .filter(|&&(_, end)| split < end)
                    .map(|&(s, _)| s),
                None => Some(c.first_start),
            };
            if let Some(start) = start {
                earliest = Some(earliest.map_or(start, |e| e.min(start)));
            }
        }
        earliest
    }
}

fn all_matches_dfa() -> regex_automata::hybrid::dfa::Builder {
    let mut builder = DFA::builder();
    builder.configure(DFA::config().match_kind(MatchKind::All));
    builder
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
    match all_matches_dfa().build(r"[^\s\S]") {
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
    fn eof_collapses_holdback() {
        // At true end-of-stream a forming match can never complete; flush all.
        let d = dfa(&[r"AKIA[0-9A-Z]{16}"]);
        let buf = b"see AKIAABC";
        assert_eq!(d.safe_flush_len(buf, true), buf.len());
        assert_eq!(d.safe_flush_len(buf, false), 4);
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
        let buf = b"pay 1234 5678 now";
        let scan = d.scan(buf);
        assert_eq!(scan.flush_len(), 17);
        assert_eq!(scan.straddling_start(buf, 9), Some(4));
        assert_eq!(scan.straddling_start(buf, 4), None);
        assert_eq!(scan.straddling_start(buf, 14), None);
    }

    #[test]
    fn straddle_follows_each_patterns_non_overlapping_matches() {
        // A candidate starting inside the pattern's previous candidate is not a
        // match `find_iter` would report, so it cannot pull the split back.
        let d = dfa(&[r"[0-9]{4} [0-9]{4}"]);
        let buf = b"1111 2222 3333 4444 x";
        let scan = d.scan(buf);
        assert_eq!(scan.straddling_start(buf, 15), Some(10));
        assert_eq!(scan.straddling_start(buf, 10), None);
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
