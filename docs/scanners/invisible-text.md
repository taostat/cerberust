# InvisibleTextScanner — invisible instruction text

## What it protects you from

Some Unicode characters can carry text that is invisible or hard to notice when
someone reads a prompt. Tag characters can encode an entire hidden payload, and
bidirectional embedding, override, and isolate controls can change how nearby
text appears. `InvisibleTextScanner` removes those characters before the prompt
reaches a model, or blocks the request when configured to do so.

The scanner is deliberately narrow. It does not remove every Unicode format
character. In particular, it preserves joiners, direction marks, Arabic letter
marks, soft hyphens, byte order marks, variation selectors, ordinary text, and
valid emoji sequences.

## Tag characters and subdivision flags

The scanner targets every tag character in U+E0000..=U+E007F unless it is part
of this complete sequence:

1. U+1F3F4 (waving black flag);
2. immediately followed by one or more tag payload characters from
   U+E0020..=U+E007E;
3. immediately followed by U+E007F (CANCEL TAG).

That sequence is preserved byte-for-byte. This covers the England, Scotland,
and Wales subdivision flags. Any tag character outside that complete sequence
is removed. For example, a missing terminator, a payload not preceded by the
black flag, U+E0001 LANGUAGE TAG, and extra tag characters after CANCEL TAG are
removed. The black flag itself is ordinary visible text and is kept when its
following tag sequence is malformed.

The other targeted characters are U+202A..=U+202E and U+2066..=U+2069. Other
code points in Unicode's `Cf` category are left alone.

## Quick example

Redact hidden tag characters and bidi controls (the default):

```rust
use cerberust::{InvisibleTextScanner, ScanCtx, Scanner};

let scanner = InvisibleTextScanner::new();
let mut ctx = ScanCtx::new();
let verdict = scanner.scan("Hello\u{202e} world", &mut ctx)?;
assert_eq!(verdict.text, "Hello world");
# Ok::<(), cerberust::ScanError>(())
```

Block instead of rewriting:

```rust
use cerberust::{InvisibleTextScanner, ScanCtx, Scanner};

let scanner = InvisibleTextScanner::new().blocking();
let verdict = scanner.scan("Hello\u{202e} world", &mut ScanCtx::new())?;
assert!(!verdict.valid);
# Ok::<(), cerberust::ScanError>(())
```

## Options / config

| Method | Effect |
|---|---|
| `InvisibleTextScanner::new()` | redact targeted characters; input only |
| `.blocking()` | reject input when any targeted character is present |

**Default:** off — add the scanner to a `ScannerStack` to enable it. Redaction
counts appear in `ScanReport` under the `INVISIBLE_TEXT` entity type. Reports
contain counts and labels only; the removed characters are not stored in the
vault.

## Streaming and performance

This scanner is input-only and has no direction override. `ScannerStack` keeps it
on the input path, while the streaming runner consults only output scanners. The
scanner's inherited empty `stream_patterns()` and `HoldBack::TokenBoundary`
defaults therefore do not affect streamed output. Output scanning is out of scope
for this version.

Scanning takes linear time in the input length and visits Unicode scalar values
once. When no targeted character is present, it returns the same borrowed input
without allocating or copying. On a match it allocates a rewritten string and
removes only targeted characters; all remaining bytes stay unchanged.
