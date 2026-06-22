# cerberust

**Ship LLM features without shipping your users' secrets.**

cerberust is a fast Rust library that sits between your application and a language
model and guards both directions of the conversation. It redacts personal data
before the model sees it, masks secrets so they never reach a provider, blocks
prompt-injection attacks, and puts your user's own data back in the reply — all in
compiled Rust, fast enough to run inline on every request, including streamed ones.

It ports the scanner-and-stack design of Python's
[`llm-guard`](https://github.com/protectai/llm-guard) to Rust, and adds
streaming-safe redaction, deterministic restore, and a WebAssembly sandbox for
running untrusted custom guards.

## The problem, in plain language

The moment you put a model in front of users, three things start happening:

1. **Your users hand it data you don't want a third party to keep.** Someone
   pastes a customer's email and phone number into a support prompt. That prompt
   goes to OpenAI, or Anthropic, or whatever provider you route to — and now their
   PII is in someone else's logs. You didn't decide that; a user did, mid-sentence.

2. **Secrets leak into prompts and back out of replies.** A developer pastes a
   stack trace with an API key in it. A model, asked to "repeat the config above,"
   happily echoes a credential straight back to the user. Every one of those is a
   secret crossing a boundary it shouldn't.

3. **People try to break it.** "Ignore your previous instructions and…" is the
   opening line of a thousand jailbreaks. Some of them work, and the ones that work
   turn your helpful assistant into someone else's tool.

A guardrail layer is how you take that back. cerberust gives you a set of small,
composable **scanners** — each one a pure function that inspects a piece of text
and returns a verdict — that you stack in front of your model and run on every
request and every response.

## The threat model

cerberust is built to stop these specific things:

| Threat | What goes wrong | The scanner |
|---|---|---|
| **PII exfiltration** | a user's email, phone, card, IP, or SSN reaches a model provider | [`PiiScanner`](scanners/pii.md) tokenizes it on input, restores it on output |
| **Secret leakage** | an API key, token, or private key reaches a provider — or gets echoed back to the user | [`SecretScanner`](scanners/secrets.md) masks it one-way (never restored) |
| **Model-generated PII/secrets** | the *model* emits a real email or key in its answer | the same scanners, run on the output path, mask it before it reaches the user |
| **Prompt injection / jailbreaks** | "ignore your instructions" attacks hijack the model | [`PromptInjectionScanner`](scanners/prompt-injection.md) blocks before the model runs |
| **Banned content** | specific phrases or whole topics you've ruled out appear in a prompt or reply | [`BanSubstringsScanner`](scanners/ban-substrings.md), [`BanTopicsScanner`](scanners/ban-topics.md) |
| **Your own sensitive formats** | internal ids, account numbers, in-house secret shapes | [`RegexScanner`](scanners/regex.md) — you supply the patterns |
| **Oversized prompts** | a request blows the context window or the bill | [`TokenLimitScanner`](scanners/token-limit.md) rejects it early |
| **An untrusted custom guard** | you want to run a third party's guard but can't trust it not to phone home | [`WasmScanner`](scanners/wasm-guards.md) runs it sandboxed, with no way to egress |

## What makes it different

- **Streaming-safe.** Redaction on a *streamed* response is the hard case: a secret
  can straddle two chunks, and emitting the first chunk before the secret is
  complete leaks half of it. cerberust holds back exactly the bytes that could
  still be part of a forming match — and not a byte more — so streamed output is
  identical to what you'd get scanning the whole response at once.

- **Restore, not just redact.** PII is replaced with a placeholder on the way to
  the model and the *original is spliced back* on the way out. Your user reads
  their own data in the reply; the model never saw it. Secrets get the same
  redaction but are deliberately never restored.

- **Deterministic where it counts, ML where it has to be.** The PII, secret,
  regex, and ban scanners are deterministic regex-and-checksum matchers — fast,
  predictable, and shipped in the default build. The prompt-injection scanner is an
  ML model behind an opt-in feature flag, because it's heavy and its precision
  depends on your traffic.

## Where to next

- **[Getting started](getting-started.md)** — install, your first scanner,
  composing a stack, the middleware, and streaming.
- **[Core concepts](concepts.md)** — the mental model: scanners, the stack,
  middleware, the vault, restore policy, and hold-back.
- **[Scanner reference](scanners/)** — one page per scanner, each starting with
  what it protects you from.
- **[Benchmarks](benchmarks.md)** — measured numbers vs `llm-guard`.
