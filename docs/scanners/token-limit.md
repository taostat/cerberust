# TokenLimitScanner — oversized prompts

## What it protects you from

A model call costs money per token, and every model has a context window it can't
exceed. A user (or a bug, or an abuse attempt) can paste a novel into a prompt and
either blow your context budget, spike your bill, or get a hard provider error
mid-request. You'd rather reject an over-budget prompt **before** it reaches the
model than pay for it or crash on it.

`TokenLimitScanner` rejects input whose approximate token count exceeds a limit you
set. It's the cheap pre-check that keeps a runaway prompt from becoming a runaway
bill.

## Why you'd use it

- **Reject early, pay nothing.** An over-budget prompt is blocked before the model
  call, so it costs you no tokens.
- **Predictable cost and context.** Cap the input size so a single request can't
  exceed your context window or your per-call budget.
- **Zero dependencies.** It's a whitespace heuristic — no tokenizer to load.

## Quick example

```rust
use cerberust::{ScanCtx, Scanner, TokenLimitScanner};

let scanner = TokenLimitScanner::new(1000); // max ~1000 tokens

let mut ctx = ScanCtx::new();
let verdict = scanner.scan("a short prompt", &mut ctx)?;
assert!(verdict.valid); // well under the limit

# Ok::<(), cerberust::ScanError>(())
```

In a stack, put it first so it short-circuits an over-budget request before any
redaction work runs.

## How it works

The token count is a **heuristic estimate**, not a real tokenizer. The text is split
on whitespace, and each whitespace-delimited chunk contributes
`ceil(chars / 4)` tokens — four characters per token is the conventional
English-text rule of thumb, and counting long runs by length approximates how a BPE
tokenizer fragments a URL or a base64 blob into several tokens rather than one.

If the estimate exceeds the configured maximum, the scanner blocks
(`Direction::Input`, `Disposition::Block`). It never rewrites text and never runs on
output — its only job is to reject an over-budget prompt.

## Options / config

| Method | Effect |
|---|---|
| `TokenLimitScanner::new(max_tokens)` | reject input over `max_tokens` approximate tokens |
| `.max_tokens()` | the configured maximum |

**Default:** off — you set the limit that fits your model and budget.

## What it doesn't do

The estimate is approximate by design. If you need a model-accurate count — to pin
exactly to a provider's context window — a real tokenizer (`tiktoken` or the
provider's BPE) is the natural refinement; the scanner's estimate function is the
seam where that plugs in without changing the scanner's contract. For "reject the
obvious novel-in-a-prompt," the heuristic is fast and good enough.

## Performance

A whitespace split with a per-chunk arithmetic cost — effectively free relative to a
model call, and orders of magnitude cheaper than the redaction scanners. It is not
separately benchmarked in the [comparison table](../benchmarks.md).
