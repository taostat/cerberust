# Scanner reference

Each scanner is a small, composable guard you stack in front of your model. Every
page starts with **what it protects you from** in plain language, then works up to
configuration and performance.

## Redaction scanners

These detect sensitive data and replace it with a placeholder — round-trip (restored
in the reply) or one-way (never restored).

> **Everything is opt-in.** cerberust is pass-through until you add a scanner to a
> `ScannerStack` — there is no global "on". The italic note on each is its *mode*.
> `PromptInjectionScanner` and `WasmScanner` additionally need an off-by-default
> cargo feature (they pull heavy dependencies).

- **[PiiScanner](pii.md)** — personal data: emails, phones, credit cards, IPs, SSNs,
  IBANs. *Round-trip — restored in the reply.*
- **[SecretScanner](secrets.md)** — API keys, tokens, private keys, labelled
  secrets. *One-way — never restored.*
- **[RegexScanner](regex.md)** — your own sensitive formats, from patterns you
  supply. *Redacts your patterns.*
- **[RestoreScanner](restore.md)** — the output half that puts redacted PII back in
  the reply. *Pair with a round-trip scanner.*

## Blocking scanners

These reject a request or a reply outright.

- **[BanSubstringsScanner](ban-substrings.md)** — forbidden phrases. *Block or
  redact on match.*
- **[BanTopicsScanner](ban-topics.md)** — off-limits subjects, defined by keywords.
  *Block on match.*
- **[TokenLimitScanner](token-limit.md)** — reject oversized prompts before they
  cost you. *Block when over the limit.*
- **[PromptInjectionScanner](prompt-injection.md)** — ML jailbreak/injection
  detection. *Needs the `prompt-injection` feature — loads a model.*

## Custom guards

- **[WasmScanner](wasm-guards.md)** — run an untrusted custom guard sandboxed, with
  no way to egress. *Needs the `wasm` feature.*

---

## At a glance

All scanners are opt-in (add them to a stack); the last column is the **cargo feature** that ships them.

| Scanner | Protects you from | Direction | Action | Cargo feature |
|---|---|---|---|---|
| [PiiScanner](pii.md) | leaking PII to a provider | input (or output) | redact (round-trip) | default |
| [SecretScanner](secrets.md) | leaking/echoing secrets | input (or output) | redact (one-way) | default |
| [RegexScanner](regex.md) | leaking your own formats | input/output/both | redact (configurable) | default |
| [RestoreScanner](restore.md) | — (completes the round-trip) | output | restore | default |
| [BanSubstringsScanner](ban-substrings.md) | forbidden phrases | input/output | block or redact | default |
| [BanTopicsScanner](ban-topics.md) | off-limits subjects | input/output | block | default |
| [TokenLimitScanner](token-limit.md) | oversized prompts | input | block | default |
| [PromptInjectionScanner](prompt-injection.md) | jailbreaks / injection | input | block | `prompt-injection` |
| [WasmScanner](wasm-guards.md) | running untrusted guards | input/output | configurable | `wasm` |

New to the mental model behind direction, action, and round-trip vs one-way? Read
[Core concepts](../concepts.md) first.
