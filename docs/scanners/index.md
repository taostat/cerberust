# Scanner reference

Each scanner is a small, composable guard you stack in front of your model. Every
page starts with **what it protects you from** in plain language, then works up to
configuration and performance.

## Redaction scanners

These detect sensitive data and replace it with a placeholder — round-trip (restored
in the reply) or one-way (never restored).

- **[PiiScanner](pii.md)** — personal data: emails, phones, credit cards, IPs, SSNs.
  *On by default, restores by default.*
- **[SecretScanner](secrets.md)** — API keys, tokens, private keys, labelled
  secrets. *On by default, one-way.*
- **[RegexScanner](regex.md)** — your own sensitive formats, from patterns you
  supply. *Opt-in.*
- **[RestoreScanner](restore.md)** — the output half that puts redacted PII back in
  the reply. *Pair with a round-trip scanner.*

## Blocking scanners

These reject a request or a reply outright.

- **[BanSubstringsScanner](ban-substrings.md)** — forbidden phrases (block or
  redact). *Opt-in.*
- **[BanTopicsScanner](ban-topics.md)** — off-limits subjects, defined by keywords.
  *Opt-in.*
- **[TokenLimitScanner](token-limit.md)** — reject oversized prompts before they
  cost you. *Opt-in.*
- **[PromptInjectionScanner](prompt-injection.md)** — ML jailbreak/injection
  detection. *Off by default — opt-in feature, loads a model.*

## Custom guards

- **[WasmScanner](wasm-guards.md)** — run an untrusted custom guard sandboxed, with
  no way to egress. *Off by default — opt-in feature.*

---

## At a glance

| Scanner | Protects you from | Direction | Action | Default |
|---|---|---|---|---|
| [PiiScanner](pii.md) | leaking PII to a provider | input (or output) | redact (round-trip) | on |
| [SecretScanner](secrets.md) | leaking/echoing secrets | input (or output) | redact (one-way) | on |
| [RegexScanner](regex.md) | leaking your own formats | input/output/both | redact (configurable) | opt-in |
| [RestoreScanner](restore.md) | — (completes the round-trip) | output | restore | paired |
| [BanSubstringsScanner](ban-substrings.md) | forbidden phrases | input/output | block or redact | opt-in |
| [BanTopicsScanner](ban-topics.md) | off-limits subjects | input/output | block | opt-in |
| [TokenLimitScanner](token-limit.md) | oversized prompts | input | block | opt-in |
| [PromptInjectionScanner](prompt-injection.md) | jailbreaks / injection | input | block | off (ML) |
| [WasmScanner](wasm-guards.md) | running untrusted guards | input/output | configurable | off (WASM) |

New to the mental model behind direction, action, and round-trip vs one-way? Read
[Core concepts](../concepts.md) first.
