//! The WASM guard runner: load a user-submitted guard compiled to a WebAssembly
//! Component and run it as a [`Scanner`](crate::Scanner), sandboxed.
//!
//! A guard guest exports `scan(text) -> verdict` (see `wit/guard.wit`) and
//! imports **nothing**. [`WasmScanner`] loads such a component with `wasmtime`
//! and instantiates it against an **import-less [`Linker`]** — no WASI, no
//! filesystem, no network, no clock. The guest is therefore a pure function
//! over the text it is handed: it cannot egress, because there is no host import
//! through which to egress. A component that *did* import anything is rejected
//! at instantiation (see the `imports_are_rejected` test), so "no ambient
//! authority" is enforced by construction, not by policy.
//!
//! The [`Vault`](crate::Vault) stays entirely host-side: the guest never sees
//! the placeholder->original map. It receives the text the host chose to hand
//! it and returns redactions/verdicts over that text — it cannot read an
//! original it was not given. Exposing host-owned `intern`/`restore` to the
//! guest as a WIT *resource* (so a guard could tokenize into the host vault
//! without holding the map) is a noted follow-up; this MVP keeps the guest a
//! pure `text -> verdict` function, which is the strictly safer subset.

use std::borrow::Cow;
use std::path::Path;
use std::sync::Mutex;

use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

use crate::scanner::{
    Direction, Disposition, ScanCtx, ScanError, ScanResult, Scanner, ScannerId, Verdict,
};

wasmtime::component::bindgen!({
    world: "guard",
    path: "wit",
});

/// Errors raised while loading or compiling a guard component, distinct from a
/// guard's own [`Verdict`] (a working guard's judgment) and from a
/// [`ScanError`] (a guard that traps at call time).
///
/// The message carries wasmtime's full error chain (`{e:#}`); a load failure
/// because the component imported a host capability the import-less linker does
/// not provide — the sandbox rejecting egress — names the unsatisfied import.
#[derive(Debug, thiserror::Error)]
pub enum WasmLoadError {
    /// The component bytes failed to compile, or imported a host capability the
    /// import-less linker does not provide (the sandbox rejecting egress).
    #[error("failed to load guard component: {0}")]
    Load(String),
}

/// A guard compiled to a WebAssembly Component, run as a [`Scanner`].
///
/// Holds a pre-instantiated guest behind a [`Mutex`]: the component model store
/// is `!Sync`, and a guard call mutates guest linear memory, so calls are
/// serialised. One `WasmScanner` is one loaded guard; load many for many guards.
pub struct WasmScanner {
    id: ScannerId,
    direction: Direction,
    disposition: Disposition,
    // Store + instantiated bindings, locked together: one guard call is one
    // critical section, never re-entrant.
    instance: Mutex<GuardInstance>,
}

/// The wasmtime store and the instantiated `scan` export, owned together.
struct GuardInstance {
    store: Store<()>,
    bindings: Guard,
}

impl WasmScanner {
    /// Load a guard component from a `.wasm` file and run it under `id`,
    /// `direction`, and `disposition`.
    ///
    /// The guest is instantiated against an **import-less** linker: it gets no
    /// host capability of any kind. A component that imports anything (WASI, a
    /// custom egress interface) is rejected here.
    ///
    /// # Errors
    /// Returns [`WasmLoadError`] if the bytes do not compile, or if the
    /// component imports a host capability (egress) the empty linker cannot
    /// satisfy.
    pub fn from_file(
        path: impl AsRef<Path>,
        id: ScannerId,
        direction: Direction,
        disposition: Disposition,
    ) -> Result<Self, WasmLoadError> {
        let engine = Engine::default();
        let component = Component::from_file(&engine, path)
            .map_err(|e| WasmLoadError::Load(format!("{e:#}")))?;
        Self::from_component(&engine, &component, id, direction, disposition)
    }

    /// Load a guard component from in-memory bytes. The byte-slice peer of
    /// [`Self::from_file`] — same import-less instantiation, same rejection of a
    /// component that imports anything.
    ///
    /// # Errors
    /// Returns [`WasmLoadError`] if the bytes do not compile, or if the
    /// component imports a host capability the empty linker cannot satisfy.
    pub fn from_bytes(
        bytes: &[u8],
        id: ScannerId,
        direction: Direction,
        disposition: Disposition,
    ) -> Result<Self, WasmLoadError> {
        let engine = Engine::default();
        let component = Component::from_binary(&engine, bytes)
            .map_err(|e| WasmLoadError::Load(format!("{e:#}")))?;
        Self::from_component(&engine, &component, id, direction, disposition)
    }

    fn from_component(
        engine: &Engine,
        component: &Component,
        id: ScannerId,
        direction: Direction,
        disposition: Disposition,
    ) -> Result<Self, WasmLoadError> {
        // The whole sandbox: an import-less linker. Nothing is added to it, so a
        // guest that imports any host function is rejected by instantiate().
        let linker: Linker<()> = Linker::new(engine);
        let mut store = Store::new(engine, ());
        let bindings = Guard::instantiate(&mut store, component, &linker)
            .map_err(|e| WasmLoadError::Load(format!("{e:#}")))?;
        Ok(Self {
            id,
            direction,
            disposition,
            instance: Mutex::new(GuardInstance { store, bindings }),
        })
    }
}

impl Scanner for WasmScanner {
    fn id(&self) -> ScannerId {
        self.id
    }

    fn direction(&self) -> Direction {
        self.direction
    }

    fn disposition(&self) -> Disposition {
        self.disposition
    }

    fn scan<'a>(&self, text: &'a str, _ctx: &mut ScanCtx) -> ScanResult<'a> {
        let mut guard = self.instance.lock().map_err(|_| ScanError::Detector {
            scanner: self.id,
            reason: "guard mutex poisoned by an earlier panic".to_owned(),
        })?;
        let GuardInstance { store, bindings } = &mut *guard;
        let verdict = bindings
            .cerberust_guard_scanner()
            .call_scan(&mut *store, text)
            .map_err(|e| ScanError::Detector {
                scanner: self.id,
                reason: format!("guard trapped: {e}"),
            })?;
        Ok(Verdict {
            text: Cow::Owned(verdict.text),
            valid: verdict.valid,
            risk: verdict.risk,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "tests assert on known-good values"
    )]
    use super::*;

    /// The example guard, built from `examples/redact-foo-guard` and committed
    /// to the repo so the test runs without the WASM toolchain in CI.
    const FOO_GUARD: &[u8] = include_bytes!("../../tests/fixtures/redact-foo-guard.wasm");

    /// A guard that imports a host `egress` interface — the import-less linker
    /// must refuse to instantiate it.
    const EGRESS_GUARD: &[u8] = include_bytes!("../../tests/fixtures/egress-guard.wasm");

    fn foo_scanner() -> WasmScanner {
        WasmScanner::from_bytes(
            FOO_GUARD,
            ScannerId("wasm:redact-foo"),
            Direction::Input,
            Disposition::Block,
        )
        .expect("example guard loads")
    }

    #[test]
    fn guard_redacts_and_flags_through_scanner_surface() {
        let scanner = foo_scanner();
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("hello FOO world", &mut ctx).unwrap();
        assert_eq!(verdict.text, "hello [REDACTED] world");
        assert!(!verdict.valid);
        assert!((verdict.risk - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn guard_passes_clean_text_unchanged() {
        let scanner = foo_scanner();
        let mut ctx = ScanCtx::new();
        let verdict = scanner.scan("nothing to see", &mut ctx).unwrap();
        assert_eq!(verdict.text, "nothing to see");
        assert!(verdict.valid);
        assert!(verdict.risk.abs() < f32::EPSILON);
    }

    #[test]
    fn guard_runs_inside_a_scanner_stack() {
        use crate::scanner::ScannerStack;
        let mut stack = ScannerStack::new(vec![Box::new(foo_scanner())], true);
        let err = stack.run_input("leak FOO please").unwrap_err();
        assert_eq!(err.scanner, ScannerId("wasm:redact-foo"));
    }

    /// The sandbox proof: a guard that imports any host capability cannot be
    /// instantiated against the import-less linker, so it can never run — egress
    /// is impossible by construction, not by runtime policy.
    #[test]
    fn imports_are_rejected_no_ambient_authority() {
        let result = WasmScanner::from_bytes(
            EGRESS_GUARD,
            ScannerId("wasm:egress"),
            Direction::Input,
            Disposition::Block,
        );
        let Err(WasmLoadError::Load(msg)) = result else {
            panic!("a guard importing egress must be rejected");
        };
        assert!(
            msg.contains("egress") || msg.contains("import"),
            "rejection should name the unsatisfied import, got: {msg}"
        );
    }
}
