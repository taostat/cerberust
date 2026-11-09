//! Remove selected invisible characters that can smuggle instructions past a
//! human reader, while preserving legitimate Unicode and emoji uses.

use std::borrow::Cow;
use std::iter::Peekable;
use std::str::CharIndices;

use crate::scanner::{Direction, Disposition, ScanCtx, ScanResult, Scanner, ScannerId, Verdict};

const INVISIBLE_TEXT_LABEL: &str = "INVISIBLE_TEXT";
const HIT_RISK: f32 = 1.0;
const BLACK_FLAG: char = '\u{1f3f4}';
const CANCEL_TAG: char = '\u{e007f}';

/// Redacts tag characters outside complete subdivision-flag emoji and bidi
/// embedding, override, and isolate controls. Defaults to redaction and runs on
/// input only; the streaming output runner never sees this scanner.
#[derive(Debug, Clone)]
pub struct InvisibleTextScanner {
    disposition: Disposition,
}

impl InvisibleTextScanner {
    /// This scanner's id.
    pub const ID: ScannerId = ScannerId("native:invisible-text");

    /// A scanner that removes invisible instruction-hiding characters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            disposition: Disposition::Transform,
        }
    }

    /// Reject input containing any targeted character instead of removing it.
    #[must_use]
    pub const fn blocking(mut self) -> Self {
        self.disposition = Disposition::Block;
        self
    }
}

impl Default for InvisibleTextScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for InvisibleTextScanner {
    fn id(&self) -> ScannerId {
        Self::ID
    }

    fn direction(&self) -> Direction {
        Direction::Input
    }

    fn disposition(&self) -> Disposition {
        self.disposition
    }

    fn needs_prompt(&self) -> bool {
        false
    }

    fn scan<'a>(&self, text: &'a str, ctx: &mut ScanCtx) -> ScanResult<'a> {
        let redact = self.disposition == Disposition::Transform;
        let (sanitized, removed) = remove_invisible(text, redact);
        if redact {
            let count = u32::try_from(removed).unwrap_or(u32::MAX);
            ctx.vault.note_redacted(INVISIBLE_TEXT_LABEL, count);
            Ok(Verdict::transformed(sanitized))
        } else {
            let risk = if removed == 0 { 0.0 } else { HIT_RISK };
            Ok(Verdict::detected(text, risk, HIT_RISK))
        }
    }
}

#[derive(Clone, Copy)]
struct TagRun {
    end: usize,
    count: usize,
    well_formed: bool,
}

fn remove_invisible(text: &str, redact: bool) -> (Cow<'_, str>, usize) {
    let mut chars = text.char_indices().peekable();
    let mut output = None;
    let mut copy_from = 0;
    let mut removed = 0;

    while let Some((index, ch)) = chars.next() {
        if is_bidi_control(ch) {
            removed += 1;
            if redact {
                remove_range(
                    &mut output,
                    text,
                    &mut copy_from,
                    index,
                    index + ch.len_utf8(),
                );
            }
        } else if ch == BLACK_FLAG {
            if let Some(run) = consume_flag_tags(&mut chars) {
                if !run.well_formed {
                    removed += run.count;
                    if redact {
                        remove_range(
                            &mut output,
                            text,
                            &mut copy_from,
                            index + ch.len_utf8(),
                            run.end,
                        );
                    }
                }
            }
        } else if is_tag(ch) {
            let run = consume_tag_run(&mut chars, (index, ch));
            removed += run.count;
            if redact {
                remove_range(&mut output, text, &mut copy_from, index, run.end);
            }
        }
    }

    match output {
        Some(mut output) => {
            output.push_str(&text[copy_from..]);
            (Cow::Owned(output), removed)
        }
        None => (Cow::Borrowed(text), removed),
    }
}

fn consume_flag_tags(chars: &mut Peekable<CharIndices<'_>>) -> Option<TagRun> {
    let first = take_tag(chars)?;
    if !is_tag_payload(first.1) {
        return Some(consume_tag_run(chars, first));
    }

    let mut run = TagRun {
        end: first.0 + first.1.len_utf8(),
        count: 1,
        well_formed: false,
    };
    while matches!(chars.peek(), Some((_, ch)) if is_tag_payload(*ch)) {
        if let Some((index, ch)) = chars.next() {
            run.end = index + ch.len_utf8();
            run.count += 1;
        }
    }

    if matches!(chars.peek(), Some((_, ch)) if *ch == CANCEL_TAG) {
        if let Some((index, ch)) = chars.next() {
            run.end = index + ch.len_utf8();
            run.count += 1;
            run.well_formed = true;
        }
    } else if let Some(next) = take_tag(chars) {
        let rest = consume_tag_run(chars, next);
        run.end = rest.end;
        run.count += rest.count;
    }
    Some(run)
}

fn take_tag(chars: &mut Peekable<CharIndices<'_>>) -> Option<(usize, char)> {
    if matches!(chars.peek(), Some((_, ch)) if is_tag(*ch)) {
        chars.next()
    } else {
        None
    }
}

fn consume_tag_run(chars: &mut Peekable<CharIndices<'_>>, first: (usize, char)) -> TagRun {
    let mut run = TagRun {
        end: first.0 + first.1.len_utf8(),
        count: 1,
        well_formed: false,
    };
    while let Some((index, ch)) = take_tag(chars) {
        run.end = index + ch.len_utf8();
        run.count += 1;
    }
    run
}

fn remove_range(
    output: &mut Option<String>,
    text: &str,
    copy_from: &mut usize,
    start: usize,
    end: usize,
) {
    let output = output.get_or_insert_with(|| String::with_capacity(text.len()));
    output.push_str(&text[*copy_from..start]);
    *copy_from = end;
}

fn is_tag(ch: char) -> bool {
    ('\u{e0000}'..='\u{e007f}').contains(&ch)
}

fn is_tag_payload(ch: char) -> bool {
    ('\u{e0020}'..='\u{e007e}').contains(&ch)
}

fn is_bidi_control(ch: char) -> bool {
    ('\u{202a}'..='\u{202e}').contains(&ch) || ('\u{2066}'..='\u{2069}').contains(&ch)
}
