//! BIP39 seed-phrase detection.
//!
//! A mnemonic is 12, 15, 18, 21 or 24 words from the BIP39 English wordlist
//! whose last word carries a SHA-256 checksum of the rest. Words may be
//! separated by whitespace or commas and optionally numbered (`1.`, `2)`,
//! `3:`), as wallets display them. A run of wordlist words is redacted only
//! where a window of a valid length passes the checksum, which keeps ordinary
//! prose (many wordlist entries are common English words) from matching.
//!
//! Not part of the streaming hold-back DFA: a phrase is a run of common words
//! with no distinctive prefix, and holding back every word run would stall all
//! streamed prose. Unary scans (the input path, and each output flush) redact a
//! complete phrase; a phrase split across an output flush boundary may be
//! partially emitted.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::detect::Span;

/// The BIP39 English wordlist (MIT, bitcoin/bips), 2048 sorted words.
const WORDLIST: &str = include_str!("../../data/bip39/english.txt");

/// Valid mnemonic lengths, longest first so the longest valid window wins.
const LENGTHS: [usize; 5] = [24, 21, 18, 15, 12];

const CONFIDENCE: f32 = 0.99;

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST
            .lines()
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect()
    })
}

/// Wordlist index of an ASCII-letter `word` (case-insensitive). BIP39 English
/// words are 3–8 lowercase letters, so anything else is rejected before lookup.
fn index_of(word: &[u8]) -> Option<u16> {
    if !(3..=8).contains(&word.len()) {
        return None;
    }
    let mut lower = [0u8; 8];
    for (dst, &b) in lower.iter_mut().zip(word) {
        *dst = b.to_ascii_lowercase();
    }
    let lower = &lower[..word.len()];
    words()
        .binary_search_by(|w| w.as_bytes().cmp(lower))
        .ok()
        .and_then(|i| u16::try_from(i).ok())
}

/// Whether the bytes between two words only separate list entries: whitespace,
/// commas and list numbering (`12.`, `3)`, `4:`).
fn is_separator(gap: &[u8]) -> bool {
    gap.iter().all(|&b| {
        b.is_ascii_whitespace() || b.is_ascii_digit() || matches!(b, b',' | b'.' | b')' | b':')
    })
}

/// Whether `indices` (one of the valid lengths) form a checksum-valid mnemonic.
fn checksum_ok(indices: &[u16]) -> bool {
    let total_bits = indices.len() * 11;
    let checksum_bits = total_bits / 33;
    let entropy_bits = total_bits - checksum_bits;
    let mut bits = Vec::with_capacity(total_bits);
    for &index in indices {
        for shift in (0..11).rev() {
            bits.push((index >> shift) & 1 == 1);
        }
    }
    let entropy: Vec<u8> = bits[..entropy_bits]
        .chunks(8)
        .map(|byte| byte.iter().fold(0u8, |acc, &b| (acc << 1) | u8::from(b)))
        .collect();
    let hash = Sha256::digest(&entropy);
    (0..checksum_bits).all(|i| {
        let expected = (hash[i / 8] >> (7 - i % 8)) & 1 == 1;
        bits[entropy_bits + i] == expected
    })
}

/// Detect checksum-valid BIP39 mnemonics in `text`.
#[must_use]
pub(crate) fn detect(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for run in runs(text) {
        for (first, last) in select_windows(&run) {
            spans.push(Span::new(
                run[first].0,
                run[last].1,
                "SEED_PHRASE",
                CONFIDENCE,
            ));
        }
    }
    spans
}

/// Choose which checksum-valid windows of `run` to redact, as inclusive word
/// ranges. Words like "seed", "phrase" and "wallet" are on the list, so a phrase
/// is often preceded by list words, and a window of any length that starts among
/// them can pass the checksum by chance (1 in 16 to 1 in 256). Picking one window
/// per region could then leave part of the real phrase unredacted, so every
/// checksum-valid window is found, across all starts and lengths, and
/// overlapping windows are redacted as their union. The cost is occasionally
/// redacting list words adjacent to a phrase.
fn select_windows(run: &[(usize, usize, u16)]) -> Vec<(usize, usize)> {
    let indices: Vec<u16> = run.iter().map(|w| w.2).collect();
    let mut windows: Vec<(usize, usize)> = Vec::new();
    for &len in &LENGTHS {
        for first in 0..=indices.len().saturating_sub(len) {
            if first + len <= indices.len() && checksum_ok(&indices[first..first + len]) {
                windows.push((first, first + len - 1));
            }
        }
    }
    windows.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (first, last) in windows {
        match merged.last_mut() {
            Some(m) if first <= m.1 => m.1 = m.1.max(last),
            _ => merged.push((first, last)),
        }
    }
    merged
}

/// Maximal runs of wordlist words joined only by separators, as
/// `(start, end, index)` triples; runs shorter than 12 words are dropped.
fn runs(text: &str) -> Vec<Vec<(usize, usize, u16)>> {
    let bytes = text.as_bytes();
    let mut runs = Vec::new();
    let mut current: Vec<(usize, usize, u16)> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let joined = current
            .last()
            .is_some_and(|&(_, end, _)| is_separator(&bytes[end..start]));
        if !joined {
            flush(&mut runs, &mut current);
        }
        match index_of(&bytes[start..i]) {
            Some(index) => current.push((start, i, index)),
            None => flush(&mut runs, &mut current),
        }
    }
    flush(&mut runs, &mut current);
    runs
}

/// Close the current run, keeping it only if it could hold a mnemonic.
fn flush(runs: &mut Vec<Vec<(usize, usize, u16)>>, current: &mut Vec<(usize, usize, u16)>) {
    if current.len() >= LENGTHS[LENGTHS.len() - 1] {
        runs.push(std::mem::take(current));
    } else {
        current.clear();
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use std::fmt::Write as _;

    use super::*;

    /// BIP39 test vectors (trezor/python-mnemonic, all-zero and all-0x7f entropy).
    const ABANDON_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const LEGAL_24: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

    /// Encode `entropy` (16–32 bytes, a multiple of 4) as a BIP39 mnemonic.
    fn encode(entropy: &[u8]) -> Vec<&'static str> {
        let hash = Sha256::digest(entropy);
        let checksum_bits = entropy.len() * 8 / 32;
        let mut bits: Vec<bool> = entropy
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
            .collect();
        bits.extend((0..checksum_bits).map(|i| (hash[i / 8] >> (7 - i % 8)) & 1 == 1));
        bits.chunks(11)
            .map(|c| words()[c.iter().fold(0usize, |acc, &b| (acc << 1) | usize::from(b))])
            .collect()
    }

    proptest::proptest! {
        #[test]
        fn phrase_after_list_word_prefix_is_fully_redacted(
            words_len in proptest::sample::select(vec![12usize, 15, 18, 21, 24]),
            seed in proptest::collection::vec(proptest::num::u8::ANY, 32),
            prefix in proptest::collection::vec(0usize..2048, 0..4),
        ) {
            let entropy = &seed[..words_len * 4 / 3];
            let phrase = encode(entropy).join(" ");
            let lead: Vec<&str> = prefix.iter().map(|&i| words()[i]).collect();
            let text = format!("My wallet {} seed phrase: {phrase} thanks", lead.join(" "));
            let start = text.find(&phrase).unwrap();
            let end = start + phrase.len();
            let spans = detect(&text);
            proptest::prop_assert!(
                spans.iter().any(|s| s.start <= start && s.end >= end),
                "phrase not fully covered in {text:?}: {spans:?}"
            );
        }
    }

    #[test]
    fn wordlist_is_complete_and_sorted() {
        assert_eq!(words().len(), 2048);
        assert!(words().windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn detects_valid_12_and_24_word_phrases() {
        for phrase in [ABANDON_12, LEGAL_24] {
            let text = format!("my seed is {phrase} thanks");
            let spans = detect(&text);
            assert_eq!(spans.len(), 1, "{phrase}");
            assert_eq!(&text[spans[0].start..spans[0].end], phrase);
        }
    }

    #[test]
    fn numbered_and_comma_separated_phrases_match() {
        let mut numbered = String::new();
        for (i, word) in ABANDON_12.split(' ').enumerate() {
            writeln!(numbered, "{}. {word}", i + 1).unwrap();
        }
        assert_eq!(detect(&numbered).len(), 1);
        assert_eq!(detect(&ABANDON_12.replace(' ', ", ")).len(), 1);
        assert_eq!(detect(&ABANDON_12.to_uppercase()).len(), 1);
    }

    #[test]
    fn bad_checksum_is_not_redacted() {
        let wrong = ABANDON_12.replace("about", "abandon");
        assert!(detect(&wrong).is_empty());
    }

    #[test]
    fn short_or_interrupted_runs_do_not_match() {
        let eleven = ABANDON_12.rsplit_once(' ').unwrap().0;
        assert!(detect(eleven).is_empty());
        let interrupted = ABANDON_12.replacen("abandon abandon", "abandon the abandon", 1);
        assert!(detect(&interrupted).is_empty());
        assert!(detect("").is_empty());
    }
}
