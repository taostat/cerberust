# WasmScanner — sandboxed custom guards

> **Opt-in.** This scanner is behind the `wasm` feature flag because it loads the
> `wasmtime` WebAssembly runtime. It is **off by default**. See
> [Install](#install--caveats).

## What it protects you from

Say you want to run a guard someone *else* wrote — a third-party content filter, a
community-contributed detector, a guard you bought. It has to see your prompts to do
its job. But a guard that sees your prompts is a guard that *could* exfiltrate them.
How do you run untrusted code on your most sensitive data without trusting it?

`WasmScanner` is the answer: it runs a custom guard compiled to WebAssembly with **no
filesystem, no network, and no clock**. The guard sees the text you hand it and can
return a verdict — and it **physically cannot do anything else**. Egress isn't
blocked by a policy you have to trust; it's impossible by construction.

## Why you'd use it

- **Run untrusted guards safely.** A guard you didn't write inspects your prompts
  without any way to phone home with them.
- **Write a guard in any language.** Anything that compiles to a WebAssembly
  Component — Rust, and others — can be a guard.
- **It's an ordinary scanner.** Once loaded, a WASM guard drops into a
  `ScannerStack` next to the native ones; same `text -> verdict` surface.

## Quick example

```rust
use cerberust::{Direction, Disposition, ScannerId, WasmScanner};

let guard = WasmScanner::from_file(
    "my-guard.wasm",
    ScannerId("wasm:my-guard"),
    Direction::Input,
    Disposition::Block,
)?;
// `guard` is a Scanner — put it in a ScannerStack alongside PiiScanner, etc.
# Ok::<(), cerberust::WasmLoadError>(())
```

A guard's source is tiny. The bundled example redacts the literal token `FOO`:

```rust
// examples/redact-foo-guard — compiled to a WebAssembly Component.
impl Guest for Guard {
    fn scan(text: String) -> Verdict {
        let redacted = text.replace("FOO", "[REDACTED]");
        let found = redacted != text;
        Verdict { text: redacted, valid: !found, risk: if found { 1.0 } else { 0.0 } }
    }
}
```

## How it works

A guard guest exports exactly one function — `scan(text) -> verdict` — and
**imports nothing**. The contract is a small WebAssembly Interface Type (WIT)
definition; the `verdict` mirrors the host's `Verdict { text, valid, risk }` one
field at a time, so the boundary is a plain value copy with no hidden capability.

`WasmScanner` loads the component with `wasmtime` and instantiates it against an
**import-less linker** — a linker with nothing added to it. Because the guest has no
host import of any kind, it has no filesystem, no network, and no clock. It's a pure
function over the text it's handed.

**The sandbox is enforced at load, not at runtime.** A component that imports *any*
host capability — WASI, a custom egress interface, anything — can't be satisfied by
the empty linker, so it's **rejected at instantiation** and never runs. cerberust
ships an adversarial test fixture (a guard that imports an `egress` interface and
tries to call it) precisely to prove this: loading it fails. "No ambient authority"
is a property of construction, not a runtime check you have to trust.

**The vault stays host-side.** The guest never holds the placeholder→original map.
It only ever sees text the host chose to hand it, so it can't read an original it
wasn't given.

## Options / config

| Method | Effect |
|---|---|
| `WasmScanner::from_file(path, id, direction, disposition)` | load a guard from a `.wasm` file |
| `WasmScanner::from_bytes(bytes, id, direction, disposition)` | load from in-memory component bytes |

You choose the guard's `Direction` (input/output) and `Disposition`
(transform/block) at load time, exactly as for a native scanner.

## Install & caveats

```toml
cerberust = { version = "0.1", features = ["wasm"] }
```

- **The feature pulls the `wasmtime` runtime** — a large dependency tree, which is
  why it's off by default.
- **Building a guard needs the WASM toolchain** — the `wasm32-unknown-unknown`
  target and `wasm-tools` to produce a component. The bundled examples ship as
  committed `.wasm` fixtures so the test suite runs without the toolchain.
- **One guard call at a time per loaded guard.** Guard state is serialized, so a
  single `WasmScanner` runs its guard calls one at a time; load several for
  concurrency across different guards.

## Performance

The cost is one `wasmtime` call per scan plus the guard's own work. For a simple
guard that's small relative to model latency, and the runtime is a release-grade
sandbox (the Cranelift-compiled component model). The WASM path is not a row in the
[comparison benchmark](../benchmarks.md), which measures the native scanners against
`llm-guard`; the WASM scanner's value is the **sandbox**, not raw throughput.
