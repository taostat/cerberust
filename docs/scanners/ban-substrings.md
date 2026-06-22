# BanSubstringsScanner — forbidden phrases

## What it protects you from

Sometimes the rule is simple: *this exact phrase should never appear.* A competitor's
name you don't want your assistant discussing. An internal codeword. A canned model
disclaimer ("as an AI language model…") you'd rather never ship to users. A slur
list. You don't need a model or a clever pattern for these — you need an exact-match
list and a decision about what to do on a hit.

`BanSubstringsScanner` is that list. Give it the phrases; it either **blocks** the
request/response outright or **redacts** each occurrence, your choice.

## Why you'd use it

- **Two modes, one scanner.** Block on any hit, or quietly redact each occurrence.
- **Works on prompts and on replies.** Catch a forbidden phrase a user typed, or one
  the model generated — including the classic "as an AI language model" deflection.
- **Literal and predictable.** No regex to get wrong; just the phrases you listed,
  optionally case-insensitive.

## Quick example

Block on a forbidden phrase:

```rust
use cerberust::{BanSubstringsScanner, ScanCtx, Scanner};

let scanner = BanSubstringsScanner::new(["internal-codeword".to_owned()]);
let mut ctx = ScanCtx::new();

let verdict = scanner.scan("the internal-codeword is secret", &mut ctx)?;
assert!(!verdict.valid); // blocked
# Ok::<(), cerberust::ScanError>(())
```

Gate model output for a canned phrase (case-insensitive, whole-stream):

```rust
use cerberust::BanSubstringsScanner;

let gate = BanSubstringsScanner::output_phrase_gate(
    ["as an ai language model".to_owned()],
);
// Blocks the reply if the phrase appears anywhere, even split across stream chunks.
```

Or redact instead of block:

```rust
use cerberust::BanSubstringsScanner;

let redactor = BanSubstringsScanner::new(["forbidden".to_owned()]).redacting();
// Each occurrence is replaced with a placeholder; the request is not blocked.
```

## How it works

Matching is **literal** — a banned-words list doesn't need a pattern engine — with
an optional case-insensitivity flag. Case-insensitive matching lower-cases a scratch
copy to find offsets, then redacts the *original* text at those offsets, so casing
outside the match is preserved.

The disposition is chosen at construction:

- **Block** (default) — any configured substring present rejects the
  request/response, scoring a definite policy hit.
- **Redact** (`.redacting()`) — each occurrence is interned into the vault and
  replaced with a placeholder, **one-way** (a banned phrase is never echoed back).

### On streamed output

When **redacting** a stream, a banned phrase forming across a chunk boundary is held
back (via the hold-back DFA) so it's never half-emitted. When **blocking** a stream,
the scanner needs the whole reply to judge it — so it buffers the entire response and
gates once at the end. That catches a phrase even when it's split across chunks, at
the cost of first-token latency. (See [streaming](../concepts.md#streaming-hold-back).)

## Options / config

| Method | Effect |
|---|---|
| `BanSubstringsScanner::new([phrases])` | case-sensitive, **block**, input |
| `BanSubstringsScanner::output_phrase_gate([phrases])` | case-insensitive **block** on the output (whole-stream gate) |
| `.case_insensitive()` | match ignoring ASCII case |
| `.redacting()` | redact each hit into the vault instead of blocking |
| `.with_direction(dir)` | run on `Input` or `Output` |

**Default:** off — it does nothing until you give it phrases.

## Performance

On the benchmark corpus, the ban-substrings scanner runs at **~1.16M samples/sec**,
about 9× the Python equivalent at the same task. Note that a literal phrase list is
a *baseline*, not a detector — on the injection corpus a five-phrase list only covers
about a third of the attacks (recall 0.27 on both cerberust and `llm-guard`). That's
the honest ceiling of keyword matching, and exactly why the
[ML prompt-injection scanner](prompt-injection.md) exists. See
[benchmarks](../benchmarks.md).
