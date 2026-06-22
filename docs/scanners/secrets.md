# SecretScanner — API keys & credentials

## What it protects you from

Secrets end up in prompts constantly, and almost always by accident. A developer
pastes a stack trace with an API key in it. Someone drops a config file into a
"what's wrong with this?" prompt. A `.env` line sneaks into a code snippet. Every
one of those sends a live credential to a model provider — and worse, a model asked
to "repeat the config above" will happily **echo the secret straight back** to the
user.

`SecretScanner` catches credentials in both directions: API keys, tokens, private
keys, and labelled secrets. It masks them on the way to the model so the provider
never sees them, and — by default — **never** restores them, so they're never
echoed back either.

## Why you'd use it

- **Secrets never reach the provider.** They're replaced with a placeholder before
  the model call.
- **One-way by default.** Unlike PII, a secret is never put back in the reply. Once
  masked, it stays masked — for the model, the provider, and the user.
- **It catches the bespoke ones too.** Beyond known vendor formats, a high-entropy
  backstop flags opaque tokens that match no known pattern, so your internal
  service token doesn't slip through just because it isn't an AWS key.

## Quick example

```rust
use cerberust::{ScanCtx, Scanner, SecretScanner};

let scanner = SecretScanner::new();
let mut ctx = ScanCtx::new();

let verdict = scanner.scan("deploy with AKIAIOSFODNN7EXAMPLE", &mut ctx)?;
assert!(verdict.text.contains("[REDACTED_AWS_ACCESS_KEY_1_"));
assert!(!verdict.text.contains("AKIAIOSFODNN7EXAMPLE"));
# Ok::<(), cerberust::ScanError>(())
```

Drop it into a stack alongside `PiiScanner` and `RestoreScanner::for_pii()` — the
PII round-trips, the secret stays redacted, because the PII restorer only owns the
PII entity types.

## How it works

Three layers of detection, all emitting spans into the shared redact path:

1. **Known vendor formats** — exact patterns for the credentials that have a
   recognizable shape:
   - AWS access keys (`AKIA…`)
   - GitHub tokens (`ghp_…`)
   - Stripe live keys (`sk_live_…`)
   - OpenAI keys (`sk-…`)
   - Google API keys (`AIza…`)
   - Slack webhook URLs
   - PEM private-key blocks (full block, and the lone header for truncated keys)

2. **Labelled secrets** — `password=…`, `api_key: …`, `token = …`, and
   `scheme://user:password@host` URL credentials. Here it redacts **just the
   value**, not the label, so `password=hunter2` becomes `password=[REDACTED…]`.

3. **High-entropy backstop** — for the credential that matches no known pattern.
   Each whitespace-delimited token that *looks* like an opaque secret (long, and
   either hex or base64-ish) has its Shannon entropy measured; high-entropy tokens
   are flagged. This is what catches your in-house token format without you writing
   a pattern for it. The cheap character-class check runs first, so ordinary prose
   words never pay for the entropy scan.

All hits are interned into the vault under a **one-way** policy: redacted on input,
never restored. Even if you pair the stack with a PII restorer, secrets stay masked,
because restore is enforced per placeholder and the restorer only owns PII types.

## Options / config

| Method | Effect |
|---|---|
| `SecretScanner::new()` | input scanner, `OneWay` (the default — never restored) |
| `.with_direction(dir)` | run on `Input` or `Output` (mask secrets the model emits) |
| `.with_policy(policy)` | override the restore policy (rarely — one-way is the safe default) |

Running it on `Direction::Output` masks secrets the **model** emits — useful when a
model might echo a credential it was shown or fabricate a plausible one.

**Opt-in**, like every scanner — nothing runs until you add it to a `ScannerStack`.
Ships in the default build (no extra cargo feature).

## Performance

On the benchmark corpus, the secret scanner runs at **~1.31M samples/sec** with
**perfect precision and recall (1.00 / 1.00)**. On detection, `llm-guard`'s
detect-secrets recalls only 0.45 on the same corpus — it doesn't recognize several of
the OpenAI / Stripe / labelled `key=value` forms cerberust catches. See
[benchmarks](../benchmarks.md) for the full table and methodology.
