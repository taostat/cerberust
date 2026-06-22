# RestoreScanner — putting redacted data back

## What it protects you from

This one isn't a detector — it's the *other half* of a round-trip. When `PiiScanner`
replaces your user's email with a placeholder so the model never sees it, something
has to put the real email back in the reply, or your user reads
`[REDACTED_EMAIL_1_…]` instead of their own address. `RestoreScanner` is that
something.

It also protects you from the subtle mistake of restoring the *wrong* things: it
rehydrates only the data you marked round-trip, and never a secret, and never a value
the model itself generated.

## Why you'd use it

- **It completes the PII round-trip.** Your user typed their email; they read their
  email back. The model worked on a placeholder the whole time.
- **It won't un-mask a secret.** It only restores the entity types it's configured
  to own, so a one-way secret placeholder survives untouched.
- **It won't echo model-generated data.** Restore is per-placeholder: a value the
  model emitted has no round-trip vault entry, so it's never "restored" into the
  reply.

## Quick example

```rust
use cerberust::{PiiScanner, RestoreScanner, ScannerStack, Scanner, SecretScanner};

let scanners: Vec<Box<dyn Scanner>> = vec![
    Box::new(PiiScanner::new()),         // input:  email -> placeholder
    Box::new(SecretScanner::new()),      // input:  key   -> placeholder (one-way)
    Box::new(RestoreScanner::for_pii()), // output: email restored, key NOT
];
let mut stack = ScannerStack::new(scanners, true);

let redacted = stack.run_input("mail alice@example.com key AKIAIOSFODNN7EXAMPLE")?;
let reply = stack.run_output(&redacted)?; // model echoes the placeholders back

assert!(reply.contains("alice@example.com"));            // PII restored
assert!(reply.contains("[REDACTED_AWS_ACCESS_KEY_1_"));  // secret stays masked
# Ok::<(), cerberust::Blocked>(())
```

## How it works

`RestoreScanner` runs on the **output** path. It reads the same vault the input
scanners populated and substitutes each placeholder back to its original — but only
for placeholders that pass **two** tests:

1. **It's an entity type this restorer owns.** The scanner is built with a set of
   types (`for_pii()` owns `EMAIL`, `PHONE`, `US_SSN`, `IP_ADDRESS`,
   `CREDIT_CARD`, `IBAN`). A placeholder of any other type is left alone — so a secret,
   owned by no PII restorer, stays masked.
2. **It was interned round-trip.** A value the model generated and that was masked
   one-way on the output path shares the entity type but isn't restorable, so it's
   never echoed back.

Because output scanners run **LIFO** (back-to-front), restore unwinds redaction in
the exact inverse order it was applied. Matching is exact plus
ASCII-case-insensitive — a model that echoes `[redacted_email_1_…]` in lower case
still restores correctly — but there is deliberately **no** fuzzy matching: a
hallucinated counter or nonce is one character off from a real placeholder, and
restoring it would splice a *different* value's original into the reply.

## Options / config

| Constructor | Effect |
|---|---|
| `RestoreScanner::for_pii()` | restores the structured-PII types — the default companion to `PiiScanner` |
| `RestoreScanner::for_types(id, [types])` | restores an explicit set of entity labels — pair with a `RegexScanner`'s custom labels |

A restorer only rehydrates the types it owns. To make a custom round-trip scanner's
matches restore, give the restorer that scanner's labels:

```rust
use cerberust::{RestoreScanner, ScannerId};

let restore = RestoreScanner::for_types(
    ScannerId("custom:restore"),
    ["TICKET_ID".to_owned(), "ACCOUNT_NUMBER".to_owned()],
);
```

**Default:** pair it with any round-trip scanner. To make a redaction one-way, simply
don't give its type to a restorer.

## Cache-stable deterministic redaction

A placeholder carries a per-value suffix so a caller can't *guess* one and trick the
restore pass into splicing a different request's data into the reply. By default that
suffix is a **fresh random nonce per request**: unguessable, but the same email
redacts to a *different* placeholder every request. That's the safe default, and for
single-shot calls it's all you want.

For a **multi-turn conversation**, randomness has a cost. Each turn you resend the
prefix to the model — and if `alice@example.com` redacts to a different placeholder
every turn, the redacted prefix changes every turn, and the provider's prompt cache
misses on text that should have been a hit. You pay full price to re-process a prefix
the provider already has.

Deterministic mode fixes that. The suffix becomes a **keyed function of the value** —
`HMAC(key, value)` truncated — so the same value under the same key always produces
the same placeholder, byte-identical across requests:

```rust
use cerberust::{PiiScanner, RestoreScanner, ScanCtx, ScannerStack, Scanner, Vault};

// One key per conversation (caller-owned secret bytes). The same value redacts to
// the same placeholder on every turn, so the redacted prefix is cache-stable.
let key = b"per-conversation-secret";
let ctx = ScanCtx::new().with_vault(Vault::deterministic(key));

let scanners: Vec<Box<dyn Scanner>> = vec![
    Box::new(PiiScanner::new()),
    Box::new(RestoreScanner::for_pii()),
];
let mut stack = ScannerStack::with_ctx(scanners, true, ctx);

let redacted = stack.run_input("mail alice@example.com")?;
// Re-running the same prefix on the next turn, under the same key, yields the
// exact same `[REDACTED_EMAIL_1_…]` — the provider's prompt cache stays warm.
# Ok::<(), cerberust::Blocked>(())
```

Two things to keep honest about it:

- **The key must be a real secret.** The suffix is a *keyed* HMAC, not a bare hash,
  precisely because low-entropy PII — an email, a phone number, an SSN — would be
  brute-forceable out of an unkeyed digest. Supply a non-empty, high-entropy,
  per-conversation key. cerberust does not police this; supplying the key well is
  your responsibility.
- **It's opt-in.** `Vault::new()` (the default) stays random. You select deterministic
  mode explicitly with `Vault::deterministic(key)` (or `NonceStrategy::deterministic`)
  and thread it in via `ScanCtx::new().with_vault(...)` / `ScannerStack::with_ctx(...)`.

Restore works identically either way — it matches placeholders exactly, whatever
minted the suffix. Deterministic mode changes only how the suffix is derived, never
the round-trip semantics.

## Performance

Restore is a single left-to-right scan with a longest-placeholder-first substitution
table — linear in the reply length and proportional to the number of redactions. It
runs inline with the other output scanners and is not a separate benchmark row. See
[benchmarks](../benchmarks.md).
