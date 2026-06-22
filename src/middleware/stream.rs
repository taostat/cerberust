//! The streaming output runner: drive the output scanner stack over a sequence
//! of chunks, emitting only bytes that are provably safe and holding back any
//! tail that could still be completing a redactable match or a vault sentinel.
//!
//! # The no-leak contract
//!
//! A secret split across chunk boundaries must be **fully** redacted — the
//! runner must never emit a non-empty prefix of it. The runner therefore only
//! ever hands the unary [`ScannerStack::run_output`] a byte prefix it has proven
//! contains no match still forming, then emits that prefix's redacted form. The
//! held tail carries forward and is reconsidered when the next chunk arrives.
//! Because every emitted byte went through the same unary scan over a safe
//! prefix, the concatenated streamed output equals the unary `run_output` of the
//! whole response — streaming is identical to unary.
//!
//! # Two modes
//!
//! - **Incremental (Mode A).** When every output scanner is token-bounded
//!   ([`HoldBack::TokenBoundary`]/[`MaxLen`]), each chunk advances three
//!   hold-back bounds and flushes up to the tightest:
//!   1. the **token boundary** — never flush a partial trailing token, which
//!      bounds the secret scanner's high-entropy backstop (a heuristic with no
//!      regular shape the DFA could model) and any `\b`-anchored pattern;
//!   2. the **hold-back DFA** ([`HoldBackDfa`]) — hold from the earliest start
//!      at which a multi-token pattern (a PEM block, a spaced phone number)
//!      could still be forming;
//!   3. the **sentinel prefix** — never flush a partial vault sentinel, so the
//!      restore pass can rehydrate a sentinel that straddles a chunk boundary.
//!
//! - **Buffer-and-gate (Mode B).** If any output scanner declares
//!   [`HoldBack::WholeStream`] it cannot judge a chunk in isolation (toxicity,
//!   a blocking ban that must see the whole answer). The runner buffers the
//!   entire response and runs the unary scan once at the end — so first-token
//!   latency becomes full-generation latency. That is the unavoidable cost of a
//!   full-text gate and is documented here so a deployment chooses it knowingly.
//!
//! [`MaxLen`]: crate::HoldBack::MaxLen
//! [`HoldBack::WholeStream`]: crate::HoldBack::WholeStream
//! [`HoldBack::TokenBoundary`]: crate::HoldBack::TokenBoundary

use crate::middleware::holdback::HoldBackDfa;
use crate::middleware::MiddlewareError;
use crate::scanner::substitute::Substituter;
use crate::scanner::{Blocked, ScannerStack};

/// Drives the output scanner stack over streamed chunks with conservative
/// hold-back. One instance scans one response; it owns the carry buffer and is
/// finished by [`StreamOutput::finish`].
pub struct StreamOutput<'s> {
    stack: &'s mut ScannerStack,
    dfa: HoldBackDfa,
    /// Bytes received but not yet provably safe to flush.
    carry: Vec<u8>,
    /// `true` when any output scanner needs the whole stream — Mode B.
    whole_stream: bool,
}

impl<'s> StreamOutput<'s> {
    /// Build a streaming output runner over `stack`. Reads the stack's output
    /// scanners once to decide the mode and compile the hold-back DFA.
    pub fn new(stack: &'s mut ScannerStack) -> Self {
        let whole_stream = stack.output_needs_whole_stream();
        let dfa = HoldBackDfa::new(&stack.output_stream_patterns());
        Self {
            stack,
            dfa,
            carry: Vec::new(),
            whole_stream,
        }
    }

    /// Accept the next `chunk`, returning the bytes safe to emit now (possibly
    /// empty — a chunk that only extends a forming match emits nothing).
    ///
    /// # Errors
    /// Returns [`MiddlewareError::Blocked`] if a `Block` output scanner rejects
    /// the flushed prefix.
    pub fn push(&mut self, chunk: &str) -> Result<String, MiddlewareError> {
        self.carry.extend_from_slice(chunk.as_bytes());
        if self.whole_stream {
            // Mode B: nothing is judged until the whole response is in hand.
            return Ok(String::new());
        }
        self.flush_safe_prefix(false)
    }

    /// End the stream: flush everything still held (no more bytes can extend a
    /// match), running the final unary scan over the remainder.
    ///
    /// # Errors
    /// Returns [`MiddlewareError::Blocked`] if a `Block` output scanner rejects.
    pub fn finish(mut self) -> Result<String, MiddlewareError> {
        self.flush_safe_prefix(true)
    }

    /// Compute the safe-flush split of `carry`, scan that prefix unary, emit it,
    /// and retain the rest. `at_eof` collapses every hold-back to the full
    /// buffer — no further bytes will arrive.
    fn flush_safe_prefix(&mut self, at_eof: bool) -> Result<String, MiddlewareError> {
        let split = self.safe_split(at_eof);
        if split == 0 {
            return Ok(String::new());
        }
        let prefix = self.take_prefix(split);
        let scanned = self.stack.run_output(&prefix).map_err(|b| blocked(&b))?;
        Ok(scanned)
    }

    /// Drain `split` bytes off the front of the carry, returning them as a UTF-8
    /// string. The split is chosen on a char boundary (see [`Self::safe_split`]),
    /// so this never severs a multi-byte char.
    fn take_prefix(&mut self, split: usize) -> String {
        let rest = self.carry.split_off(split);
        let prefix = std::mem::replace(&mut self.carry, rest);
        String::from_utf8(prefix)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
    }

    /// The byte offset up to which the carry is safe to flush: the tightest of
    /// the token-boundary floor, the DFA hold-back, and the sentinel-prefix
    /// hold-back — then snapped down to a UTF-8 char boundary.
    fn safe_split(&mut self, at_eof: bool) -> usize {
        let buf = &self.carry;
        if at_eof {
            return buf.len();
        }
        let mut split = self.dfa.safe_flush_len(buf, false);
        split = split.min(token_boundary_floor(buf));
        split = split.min(sentinel_floor(self.stack, buf));
        char_boundary_floor(buf, split)
    }
}

/// Never flush a partial trailing token: hold from the last whitespace boundary
/// to the end. This bounds the secret scanner's high-entropy backstop (a
/// per-token heuristic with no regular shape) and every `\b`-anchored pattern.
/// A token straddling the chunk end is held whole, never truncated mid-token.
fn token_boundary_floor(buf: &[u8]) -> usize {
    match buf.iter().rposition(u8::is_ascii_whitespace) {
        // Flush up to and including the last whitespace byte; hold the trailing
        // partial token.
        Some(pos) => pos + 1,
        None => 0,
    }
}

/// Never flush a partial vault sentinel: hold the longest trailing run that is a
/// non-empty prefix of some sentinel, so the restore pass can rehydrate a
/// sentinel that straddles a chunk boundary.
fn sentinel_floor(stack: &ScannerStack, buf: &[u8]) -> usize {
    let pairs: Vec<(String, String)> = stack
        .ctx()
        .vault
        .entries()
        .map(|(s, o)| (s.to_owned(), o.to_owned()))
        .collect();
    if pairs.is_empty() {
        return buf.len();
    }
    let sub = Substituter::from_pairs(pairs.iter().map(|(s, o)| (s.as_str(), o.as_str())));
    let longest = sub.longest_sentinel();
    // A sentinel opens on '[' and is at most `longest` bytes; only a trailing
    // run within that window can be an incomplete sentinel.
    let window_start = buf.len().saturating_sub(longest);
    for start in window_start..buf.len() {
        if sub.is_sentinel_prefix(&buf[start..]) {
            return start;
        }
    }
    buf.len()
}

/// Snap `split` down to the nearest UTF-8 char boundary so a flushed prefix is
/// always valid UTF-8 and never severs a multi-byte char (whose later bytes
/// could still be part of a forming match). A boundary is any index where the
/// byte is not a `10xxxxxx` continuation byte (and the ends of the buffer).
fn char_boundary_floor(buf: &[u8], mut split: usize) -> usize {
    while split > 0 && split < buf.len() && buf[split] & 0xC0 == 0x80 {
        split -= 1;
    }
    split
}

fn blocked(b: &Blocked) -> MiddlewareError {
    MiddlewareError::Blocked {
        detail: format!("{} (risk {})", b.scanner, b.risk),
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

    #[test]
    fn token_floor_holds_partial_trailing_token() {
        // Flush up to and including the last space; hold "AKIA".
        assert_eq!(token_boundary_floor(b"see AKIA"), 4);
    }

    #[test]
    fn token_floor_with_no_whitespace_holds_everything() {
        assert_eq!(token_boundary_floor(b"AKIAABC"), 0);
    }

    #[test]
    fn token_floor_trailing_space_flushes_whole() {
        assert_eq!(token_boundary_floor(b"done "), 5);
    }

    #[test]
    fn char_boundary_snaps_below_a_multibyte_char() {
        // "a€" is `61 E2 82 AC`; a split landing inside the euro snaps back to 1.
        let buf = "a€".as_bytes();
        assert_eq!(char_boundary_floor(buf, 2), 1);
        assert_eq!(char_boundary_floor(buf, 3), 1);
        assert_eq!(char_boundary_floor(buf, 1), 1);
        assert_eq!(char_boundary_floor(buf, 4), 4);
    }
}
