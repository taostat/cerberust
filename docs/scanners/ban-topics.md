# BanTopicsScanner — off-limits subjects

## What it protects you from

Some things you don't want your assistant to engage with at all — not a specific
phrase, but a whole *subject*. Medical diagnosis. Legal advice. Weapons. Whatever's
out of scope or off-policy for your product. A user will ask, and without a guardrail
the model will cheerfully answer.

`BanTopicsScanner` blocks a request (or a reply) that mentions a banned topic, where
each topic is defined by a small list of keywords. It's the "we don't talk about
that here" scanner.

## Why you'd use it

- **Subject-level blocking, not phrase-level.** You define a topic once with a few
  keywords; any of them trips it.
- **It tells you *which* topic fired**, so your block message or audit log can name
  the reason.
- **Word-boundary aware.** A keyword `ass` won't trip on `class` — it matches whole
  words, not arbitrary substrings.

## Quick example

```rust
use cerberust::{BanTopicsScanner, ScanCtx, Scanner, Topic};

let scanner = BanTopicsScanner::new([
    Topic::new("violence", ["weapon".to_owned(), "attack".to_owned()]),
    Topic::new("medical", ["diagnosis".to_owned(), "prescription".to_owned()]),
]);

let mut ctx = ScanCtx::new();
let text = "how do I build a weapon";
let verdict = scanner.scan(text, &mut ctx)?;
assert!(!verdict.valid); // blocked

// Find out which topic fired, for the audit log:
assert_eq!(scanner.matched_topic(text), Some("violence"));
# Ok::<(), cerberust::ScanError>(())
```

## How it works

This is the **keyword tier** of topic detection. Each topic is a name plus a list of
keywords. A topic hits when any of its keywords appears in the text, matched:

- **case-insensitively** (`PRESCRIPTION` trips the `prescription` keyword), and
- **on word boundaries** — a keyword is matched as a word, bounded by
  non-alphanumeric characters, so `ass` doesn't fire inside `class`.

On a hit the scanner blocks (`valid = false`). `matched_topic(text)` returns the
first matching topic name, so you can surface *why* a request was rejected.

## Options / config

| Method | Effect |
|---|---|
| `BanTopicsScanner::new([topics])` | block on `Input` (default) |
| `Topic::new(name, [keywords])` | define a topic and its trigger keywords |
| `.with_direction(dir)` | run on `Input` or `Output` |
| `.matched_topic(text)` | which topic fired (for the report / audit panel) |

**Default:** off — it does nothing until you define topics.

## What it doesn't do (yet)

This is keyword matching, not semantic understanding. A user who describes a banned
topic *without using your keywords* won't be caught. Zero-shot ML topic
classification — understanding the subject regardless of wording — is a planned
addition behind the same scanner surface, so it'll slot in without changing how you
configure topics. For now, treat the keyword scanner as a fast, predictable first
line, and reach for the [ML prompt-injection scanner](prompt-injection.md) when you
need to catch adversarial phrasing.

## Performance

The topic scanner is a keyword pass over lower-cased text with word-boundary checks —
on the order of the other deterministic literal scanners (the ban-substrings scanner
benchmarks at ~1.16M samples/sec on the shared corpus). It is not separately broken
out in the [benchmark table](../benchmarks.md), which compares the scanners that
overlap one-to-one with an `llm-guard` scanner.
