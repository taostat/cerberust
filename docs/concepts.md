# Core concepts

cerberust has a small, deliberately layered design. Once these five ideas click,
every scanner and every config knob falls into place.

## Scanner

A **scanner** inspects or transforms one piece of text and returns a verdict. It's
a pure function — same text in, same verdict out — with no I/O, no clock, no hidden
state:

```rust
fn scan<'a>(&self, text: &'a str, ctx: &mut ScanCtx) -> ScanResult<'a>;
// returns Verdict { text, valid, risk }
```

The verdict carries three things:

- **`text`** — the possibly-rewritten text. A pure detector returns the input
  unchanged (borrowed, zero-copy); a transformer returns the rewrite.
- **`valid`** — `false` means "the stack should reject this." Honoured for
  scanners that are allowed to block.
- **`risk`** — `0.0` (safe) to `1.0` (high). A pure transformer reports "not a risk
  judgment" so it doesn't pollute the aggregate.

Each scanner also declares two things about itself:

- **Direction** — `Input` (runs on the prompt) or `Output` (runs on the reply).
- **Disposition** — `Transform` (rewrites text, never blocks) or `Block` (may
  reject the request or response).

That's the whole contract. Every scanner in cerberust — PII, secrets, the ML
prompt-injection classifier, a sandboxed WASM guard — is the same shape.

## ScannerStack

A **stack** is an ordered set of scanners run as a unit. You hand it one flat list;
it partitions by direction and runs:

- **Input** scanners front-to-back, threading the rewritten text from one to the
  next. Redact PII, then mask secrets, then check the token budget — each sees the
  output of the last.
- **Output** scanners back-to-front (**LIFO**). Restore unwinds redaction in the
  exact inverse order it was applied.
- **Risk** aggregates as the **max** across scanners — one high-risk hit dominates.
  Pure transformers are skipped in the aggregate.

If a `Block` scanner returns `valid = false` and the stack is **fail-fast**, it
short-circuits: the request is rejected before the model is ever called. That's the
point of running blocking scanners first — a jailbreak or an over-budget prompt
never costs you a model call.

## Middleware

The stack works on text. **Middleware** wraps it around a real model call. The
shape is borrowed from the Vercel AI SDK: each middleware can transform the request
params on the way in (`transform_params`), wrap the generation (`wrap_generate`),
and wrap a streamed generation (`wrap_stream`).

```rust
MiddlewareChain::new(vec![&a, &b]) // nests a(b(model)) — first element outermost
```

The one middleware that bridges to the scanner tier is the **`GuardrailRunner`**:
it runs the input scanners before the model and the output scanners after. Other
middlewares compose in the same chain — for example `TierPolicy`, a fail-closed
guard that refuses to route a request marked confidential to a model whose provider
would see the prompt, unless the caller explicitly consents.

You don't have to use the middleware tier. If you just want to scan text, call
`stack.run_input(...)` and `stack.run_output(...)` directly. The middleware exists
to make "guard this model call" a one-liner and to compose with other request-level
concerns.

## The Vault

The **vault** is the keystone of redaction. It's a request-scoped map from each
placeholder back to the original it stands in for:

```
[REDACTED_EMAIL_1_a1b2c3d4]  ->  alice@example.com
```

A few properties make it safe:

- **Nonce-tagged.** Every request mints a fresh random nonce baked into every
  placeholder it emits (the `a1b2c3d4` above). This stops a caller from *guessing* a
  placeholder — embedding `[REDACTED_EMAIL_1_...]` in their own prompt and tricking
  the restore pass into splicing a different request's data into the reply. Without
  the nonce the placeholder is predictable; with it, they'd have to guess a random
  token.
- **Per-type counters.** Two different emails become
  `[REDACTED_EMAIL_1_...]` and `[REDACTED_EMAIL_2_...]`, so distinct values stay
  distinct and each restores to the right original. The same value seen twice in one
  request gets the same placeholder.
- **Zeroized on drop.** When the request ends, the originals are wiped from memory,
  not just freed.

The vault is shared across the whole stack and both directions: input scanners
intern into it, the restore scanner reads from it on output.

### Random vs deterministic suffix

That `a1b2c3d4` suffix is minted one of two ways, and the choice is the caller's:

- **Random (default).** A fresh nonce per request, shared by every placeholder it
  emits. Unguessable, but the same value redacts to a *different* placeholder each
  request.
- **Deterministic.** The suffix is `HMAC(key, value)` — a keyed function of the
  value — so the same value under the same key yields a byte-identical placeholder
  across requests. A replayed conversation prefix then redacts the same way turn
  after turn, which keeps a provider's prompt cache warm on the redacted text. It's
  a *keyed* HMAC, never a bare hash, so low-entropy PII isn't brute-forceable out of
  its placeholder — and it's opt-in (`Vault::deterministic(key)`), threaded in via
  `ScanCtx::new().with_vault(...)`. See
  [cache-stable redaction](scanners/restore.md#cache-stable-deterministic-redaction).

## RestorePolicy: round-trip vs one-way

Here's the design decision that makes cerberust composable: **whether a redaction is
reversible is a *policy*, not a property of the data.** The exact same redaction
machinery runs for PII and for secrets — they differ only in their restore policy.

| Policy | Behaviour | Default for |
|---|---|---|
| **`RoundTrip`** | redact on input → restore the original on output | PII |
| **`OneWay`** | redact on input → **never** restore | secrets |

- **`RoundTrip`** is for your user's own data. Their email is tokenized so the model
  never sees it, then put back in the reply so they read their real address. The
  model worked on a placeholder the whole time.
- **`OneWay`** is for things that should never come back: a leaked API key, a banned
  phrase. It's redacted on the way in and stays a placeholder forever — the provider
  never sees it and the user never gets it echoed back.

Restore is enforced **per placeholder**, not per type. So if the *model itself*
generates a new email in its reply, that email shares the `EMAIL` type but has no
vault entry from the input — it's masked one-way, never "restored" to something it
never was. Your user's input email round-trips; a model-hallucinated email gets
masked. Both happen in one output pass.

Every scanner that redacts lets you override its policy, so the same scanner can be
round-trip in one stack and one-way in another.

## Streaming hold-back

Redacting a streamed reply is the subtle case. The reply arrives in chunks, and a
secret can land *across* a chunk boundary:

```
chunk 1: "...here is the key AKIAIOS"
chunk 2: "FODNN7EXAMPLE, use it wisely"
```

If you emit chunk 1 as soon as it arrives, you've leaked `AKIAIOS` — half the key —
before you ever saw the rest. The fix is **hold-back**: don't flush a tail that
could still be completing a match.

Each scanner declares how much it needs held back:

- **`TokenBoundary`** — never flush a partial trailing token. Most PII and secret
  patterns are token-bounded; this is the default.
- **`MaxLen(n)`** — hold at most `n` bytes (the longest a pattern could still be
  completing).
- **`WholeStream`** — the scanner can't judge a chunk in isolation; it needs the
  whole reply (a blocking content gate, a future toxicity model).

The streaming runner combines these into one of two modes:

- **Incremental.** When every active output scanner is token-bounded, the runner
  flushes up to the *tightest* of three bounds: the last token boundary, a
  byte-fed DFA that knows when a multi-token pattern (a PEM block, a spaced card
  number) could still be forming, and the longest trailing run that could be an
  incomplete placeholder. It emits the safe prefix and carries the rest forward.
- **Buffer-and-gate.** If any output scanner needs the whole stream, the runner
  buffers the entire reply and scans once at the end. That trades first-token
  latency for a full-text verdict — the unavoidable cost of a gate that has to see
  everything, and documented so you choose it knowingly.

The guarantee either way: **streamed output is byte-identical to scanning the whole
response at once.** Streaming changes when bytes come out, never what comes out.

### Driving the runner

`StreamOutput` owns its hold-back state and borrows nothing across calls: you
create it once from the stack, then pass the stack to each `push` and to
`finish`. So one runner can be held across many independent async frame
callbacks — a per-frame SSE/JSON consumer keeps the `StreamOutput`, and hands it
the stack each time a frame arrives:

```rust
let mut runner = StreamOutput::new(&stack);
// …later, once per arriving frame, with no long-lived borrow on `stack`:
let safe = runner.push(&mut stack, frame)?;
// …at end of stream:
let tail = runner.finish(&mut stack)?;
```

The same stack must drive the whole stream — it holds the shared `Vault` the
restore pass reads.

### Encoding restored values

When you splice a restored original back into a structured stream (a value inside
a JSON string in an SSE frame), the raw original may carry characters the
surrounding format must escape. Install a `RestoreEncoder` on the stack
(`stack.set_restore_encoder(RestoreEncoder::new(json_escape))`) and the restore
pass runs it over **each restored original only** — never the surrounding model
bytes, which the upstream already encoded. The default is
`RestoreEncoder::identity`: originals are emitted verbatim, so restore is
unchanged unless you opt in.

## How they fit together

```
Params (prompt)
   │
   ▼  MiddlewareChain.transform_params
GuardrailRunner ──► ScannerStack.run_input ──► [PII redact][Secret mask][TokenLimit]
   │                                              │ interns into the Vault
   ▼                                              ▼
Model.generate  ◄───────────────────────── redacted prompt
   │
   ▼  reply
GuardrailRunner ──► ScannerStack.run_output ──► [Restore PII][Mask model PII]
   │                                              │ reads the Vault (round-trip only)
   ▼
guarded reply ──► your user
```

Ready for specifics? Each scanner has its own page in the
[scanner reference](scanners/), starting with what it protects you from.
