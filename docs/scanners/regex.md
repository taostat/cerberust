# RegexScanner — your own sensitive formats

## What it protects you from

Not every sensitive thing in your prompts is a credit card or an AWS key. You have
your *own* formats: internal ticket ids, customer account numbers, an in-house
secret shape, an order reference that maps to a real person. The built-in scanners
don't know about those — only you do.

`RegexScanner` is the extensibility seam: you bring the patterns, it redacts every
match the same way `PiiScanner` redacts an email. It's the "redact *this specific
thing* I care about" scanner.

## Why you'd use it

- **It redacts what's specific to your business.** `TICKET-4821`, `ACCT-009912`,
  whatever shape your sensitive data takes.
- **You choose round-trip or one-way per scanner.** Restore your internal id in the
  reply, or mask it permanently — your call.
- **It can't be tripped into a ReDoS.** Patterns compile with a backtracking-free
  engine, so even a caller-supplied pattern can't blow up to exponential time on a
  crafted input.

## Quick example

```rust
use cerberust::{RegexScanner, ScanCtx, Scanner};

// Redact internal ticket ids.
let (scanner, errors) = RegexScanner::from_patterns([(r"TICKET-\d+", "TICKET_ID")]);
assert!(errors.is_empty()); // any pattern that failed to compile is reported here

let mut ctx = ScanCtx::new();
let verdict = scanner.scan("see TICKET-4821 for details", &mut ctx)?;
assert!(verdict.text.contains("[REDACTED_TICKET_ID_1_"));
assert!(!verdict.text.contains("TICKET-4821"));
# Ok::<(), cerberust::ScanError>(())
```

Each pattern is paired with an **entity label** (`"TICKET_ID"` above). That label
becomes the type in the placeholder, so a `RestoreScanner` configured for that
label can rehydrate it on output.

## How it works

You supply `(pattern, label)` pairs. Each pattern is compiled at construction;
matches become spans under the pattern's label, and the spans flow into the **same
redact path** the PII and secret scanners use — collect spans, resolve overlaps,
intern into the vault, rewrite span-by-span. The only difference from the built-in
scanners is that the patterns and labels come from you.

**Round-trip by default.** Pair the scanner with a `RestoreScanner` that owns your
labels, and matches are restored in the reply:

```rust
use cerberust::RestoreScanner;
use cerberust::ScannerId;

let restore = RestoreScanner::for_types(
    ScannerId("custom:restore"),
    ["TICKET_ID".to_owned()],
);
```

Switch to one-way with `.with_policy(RestorePolicy::OneWay)` and simply don't pair a
restorer — the match stays a placeholder forever.

### ReDoS safety

Patterns compile with the `regex` crate, whose matcher is **linear in input length**
with no backtracking. A pattern that would cause catastrophic backtracking under a
PCRE engine — the classic `(a+)+$` — both compiles and runs in linear time here,
even on an adversarial input. A caller can't smuggle a pattern that hangs your
service, and a pattern that fails to compile is reported at construction, never
silently dropped at scan time.

## Options / config

| Method | Effect |
|---|---|
| `RegexScanner::from_patterns([(pat, label), …])` | compile `(pattern, label)` pairs; returns the scanner **and** a list of patterns that failed to compile |
| `RegexScanner::new(rules)` | build from pre-compiled `RegexRule`s |
| `.with_direction(dir)` | run on `Input`, `Output`, or both (register it twice) |
| `.with_policy(policy)` | `RoundTrip` (restore) or `OneWay` (mask permanently) |
| `.labels()` | the entity labels this scanner interns under — the set a restorer must own |

**Default:** off — it does nothing until you give it patterns.

## Performance

On the benchmark corpus (same email pattern as `llm-guard`'s regex scanner, so
detection is identical by construction), the regex scanner runs at **~7.81M
samples/sec** — about 63× the Python equivalent. Throughput scales with the number
and complexity of your patterns. See [benchmarks](../benchmarks.md).
