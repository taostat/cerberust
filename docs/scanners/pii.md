# PiiScanner — personal data

## What it protects you from

Your users will paste personal data into prompts — their own and other people's.
An email in a support ticket, a phone number in a "draft a reply to this customer"
request, a credit card in a billing question. The moment that prompt leaves your
app for a model provider, that PII is in a third party's logs, and you didn't
choose that — a user did, mid-sentence.

`PiiScanner` catches structured PII before it leaves: **email addresses, phone
numbers, credit card numbers, IP addresses, US Social Security numbers, and IBANs.**
It replaces each one with a placeholder the model can't read, and — by default — puts
the real value back in the reply so your user still sees their own data.

## Why you'd use it

- **The model never sees real PII.** It works on placeholders the whole time.
- **Your user's experience is unchanged.** They typed their email; they read their
  email back. The round-trip is invisible to them.
- **It's checksum-backed, so it doesn't cry wolf.** A 16-digit number is only
  flagged as a card if it has a plausible issuer prefix and passes the Luhn
  checksum; an IP is validated octet by octet. You get high precision, not a
  wall of false positives.

## Quick example

```rust
use cerberust::{PiiScanner, RestoreScanner, ScannerStack, Scanner};

// Redact on the way in, restore on the way out.
let scanners: Vec<Box<dyn Scanner>> = vec![
    Box::new(PiiScanner::new()),
    Box::new(RestoreScanner::for_pii()),
];
let mut stack = ScannerStack::new(scanners, true);

let safe = stack.run_input("invoice alice@example.com, card 4111 1111 1111 1111")?;
// `safe` has placeholders where the email and card were — send it to the model.

// After the model replies (echoing the placeholders), restore puts the originals back:
let reply = stack.run_output(&safe)?;
assert!(reply.contains("alice@example.com"));
# Ok::<(), cerberust::Blocked>(())
```

## How it works

The scanner runs a set of regex detectors, then **gates the ambiguous ones with a
checksum** so it doesn't over-match:

- **Email** — a standard address pattern.
- **Phone** — international and US grouping with separators.
- **US SSN** — `123-45-6789`.
- **IP address** — dotted-quad, then validated so each octet is 0–255 (so
  `999.1.1.1` is rejected).
- **Credit card** — 13–19 digits, optionally space/hyphen grouped, then gated by
  a plausible issuer prefix and the **Luhn checksum**, so machine identifiers
  are not mistaken for cards just because they pass Luhn by chance.
- **IBAN** — an ISO 13616 international bank account number, gated by the
  country-specific length **and** the **mod-97 checksum**, so a random `GB00…`
  string isn't mistaken for an account.

Each detected region becomes a **span** (a byte range + an entity type +
confidence). Overlapping spans are resolved into a clean, non-overlapping set that
still covers every flagged byte — so two detectors firing on the same digits never
leave part of the value exposed. The text is then rewritten span-by-span, each one
replaced with a vault placeholder.

By default, PII is **round-trip**: the placeholder is restorable, and a paired
`RestoreScanner` (`RestoreScanner::for_pii()`) rehydrates it on the output path.

### Redacting PII the *model* generates

The same detector can run on the output path to catch PII the **model** emitted —
say it hallucinates a real-looking email in its answer. That value has no vault
entry (it came from the model, not your user), so it's masked **one-way**, never
"restored." Both jobs happen in one output pass: your user's input PII round-trips
while fresh model-generated PII is masked.

```rust
use cerberust::{Direction, PiiScanner};

// Mask PII the model emits, one-way, on the output path.
let output_pii = PiiScanner::sensitive_output();
assert_eq!(output_pii.direction(), Direction::Output);
```

## Options / config

| Method | Effect |
|---|---|
| `PiiScanner::new()` | input scanner, `RoundTrip` (the default — restore on output) |
| `PiiScanner::sensitive_output()` | output scanner, `OneWay` — masks PII the model generated |
| `.with_direction(dir)` | run on `Input` or `Output` |
| `.with_policy(policy)` | override to `OneWay` (mask permanently) or `RoundTrip` |

Pair an input `PiiScanner` with `RestoreScanner::for_pii()` in the same stack to
complete the round-trip. The entity types it restores are `EMAIL`, `PHONE`,
`US_SSN`, `IP_ADDRESS`, `CREDIT_CARD`, and `IBAN`.

**Opt-in**, like every scanner — nothing runs until you add it to a `ScannerStack`.
Ships in the default build (no extra cargo feature).

## What it doesn't do

This scanner detects **structured** PII — entities with a recognizable shape. It
does *not* detect free-text names, street addresses, or organizations, which need
named-entity recognition (NER). cerberust **deliberately omits fuzzy NER**: ML
name-detection over-redacts ordinary words and domain terms, trading the precision a
guardrail needs for recall. If you need free-text name coverage, pair cerberust with
a dedicated NER tool. On the structured PII it does handle, it scores perfect
precision and recall in the [benchmarks](../benchmarks.md).

## Performance

On the structured benchmark corpus, the PII scanner runs at **~1.34M samples/sec**
with **perfect precision and recall (1.00 / 1.00)** — and, being deterministic, it
doesn't over-redact ordinary words the way an NER pipeline can. It's regex +
checksums, not a neural net, so we don't race it on speed against `llm-guard`'s NER
(which scores 0.75 / 0.89 here); NER leads on free-text names cerberust deliberately
doesn't attempt. See [benchmarks](../benchmarks.md) for methodology and caveats.
