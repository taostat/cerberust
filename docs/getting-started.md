# Getting started

This page takes you from `cargo add` to a guarded model call, including streaming.

## Install

```toml
[dependencies]
cerberust = "0.1"
```

The core library has no heavy dependencies. Two optional capabilities are behind
feature flags because each pulls a large dependency tree:

```toml
# ML prompt-injection: ONNX Runtime + a tokenizer, and a ~739 MB model download.
cerberust = { version = "0.1", features = ["prompt-injection"] }

# Sandboxed WASM guards: the wasmtime component-model runtime.
cerberust = { version = "0.1", features = ["wasm"] }
```

## Your first scanner

A scanner is a pure function: hand it text, get back a verdict. Here's PII
redaction on its own:

```rust
use cerberust::{PiiScanner, ScanCtx, Scanner};

let scanner = PiiScanner::new();
let mut ctx = ScanCtx::new();

let verdict = scanner.scan("mail me at alice@example.com", &mut ctx)?;
// The email is gone, replaced by a placeholder the model can't read:
assert!(verdict.text.contains("[REDACTED_EMAIL_1_"));
assert!(!verdict.text.contains("alice@example.com"));
// And the original is safe in the request-scoped vault:
assert_eq!(ctx.vault.len(), 1);
# Ok::<(), cerberust::ScanError>(())
```

`ScanCtx` carries the **vault** — the request-scoped map from each placeholder
back to the original it stands for. You usually don't touch it directly; the stack
threads it for you.

## Composing a ScannerStack

In practice you run several scanners in order. A `ScannerStack` does that — it
threads the (possibly rewritten) text through each scanner, shares one vault across
all of them, and aggregates the risk.

```rust
use cerberust::{
    PiiScanner, RestoreScanner, ScannerStack, Scanner, SecretScanner,
};

let scanners: Vec<Box<dyn Scanner>> = vec![
    Box::new(PiiScanner::new()),         // input:  tokenize PII (restorable)
    Box::new(SecretScanner::new()),      // input:  mask secrets (one-way)
    Box::new(RestoreScanner::for_pii()), // output: put the PII back in the reply
];

// `true` = fail-fast: a blocking scanner that rejects short-circuits the rest.
let mut stack = ScannerStack::new(scanners, true);

let redacted = stack.run_input("email alice@example.com, key AKIAIOSFODNN7EXAMPLE")?;
// `redacted` has the email and the key replaced with placeholders — safe to
// send to the model.
# Ok::<(), cerberust::Blocked>(())
```

Each scanner declares which **direction** it runs on (input or output). The stack
sorts them: input scanners run front-to-back before the model; output scanners run
back-to-front after it (so restore unwinds redaction in the inverse order it was
applied). You build one flat list and the stack does the partitioning.

## The Middleware: guard a whole model call

The stack handles the text. The `GuardrailRunner` middleware wires it around an
actual model call: input scan → model → output scan, in one shot.

```rust
use cerberust::{
    GuardrailRunner, MiddlewareChain, Model, MiddlewareError, Params,
    PiiScanner, RestoreScanner, ScannerStack, Scanner, SecretScanner,
};

// Your model: anything implementing the `Model` trait. Here, an echo stand-in.
struct EchoModel;
impl Model for EchoModel {
    fn generate(&self, params: &Params) -> Result<String, MiddlewareError> {
        Ok(params.prompt.clone())
    }
}

let scanners: Vec<Box<dyn Scanner>> = vec![
    Box::new(PiiScanner::new()),
    Box::new(SecretScanner::new()),
    Box::new(RestoreScanner::for_pii()),
];
let runner = GuardrailRunner::new("guard", ScannerStack::new(scanners, true));
let chain = MiddlewareChain::new(vec![&runner]);

let out = chain.generate(
    Params::new("mail alice@example.com key AKIAIOSFODNN7EXAMPLE"),
    &EchoModel,
)?;

// PII is restored in the reply; the secret is not (one-way).
assert!(out.contains("alice@example.com"));
assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
# Ok::<(), MiddlewareError>(())
```

After the call, ask the runner which scanners fired:

```rust
let report = runner.into_report();
for entry in report.entries() {
    println!("{} valid={} risk={}", entry.scanner, entry.valid, entry.risk);
}
```

`MiddlewareChain::new([a, b])` nests middlewares `a(b(model))` — the first is
outermost. The guardrail runner is one middleware; others (a privacy-tier router
guard, your own metering layer) compose in the same chain.

## Streaming

For a streamed response, the runner emits only the bytes it has *proven* safe and
holds back any tail that could still be completing a secret, a PII match, or a
placeholder. Drive it with `StreamModel` and `MiddlewareChain::stream`:

```rust
use cerberust::{Chunk, MiddlewareError, Params, StreamModel};

struct ChunkedModel;
impl StreamModel for ChunkedModel {
    fn stream(&self, _params: &Params) -> Box<dyn Iterator<Item = Chunk> + '_> {
        // A reply where a secret is split across two chunks:
        Box::new(
            ["here is the key AKIAIOS", "FODNN7EXAMPLE done"]
                .into_iter()
                .map(|s| Ok::<String, MiddlewareError>(s.to_owned())),
        )
    }
}

// chain.stream(Params::new("…"), &ChunkedModel) yields the guarded chunks.
// The "AKIAIOS" half is never emitted on its own — the runner holds it back
// until it can see the whole key and mask it.
```

The guarantee: the concatenation of the streamed output equals what you'd get by
scanning the entire response at once. Streaming changes *when* bytes come out, never
*what* comes out. See [Concepts → streaming hold-back](concepts.md#streaming-hold-back).

To drive the runner yourself frame-by-frame — e.g. over per-frame SSE callbacks —
use `StreamOutput` directly: `StreamOutput::new(&stack)`, then `runner.push(&mut
stack, chunk)?` per frame and `runner.finish(&mut stack)?` at the end. The runner
holds no long-lived borrow on the stack between calls. When you splice restored
values into a structured stream, install a `RestoreEncoder` on the stack to escape
each restored original (e.g. JSON-escaping a value placed inside a JSON string);
the default leaves originals verbatim.

## Where to next

- **[Core concepts](concepts.md)** — the full mental model.
- **[Scanner reference](scanners/)** — every scanner, what it stops, and how to
  configure it.
