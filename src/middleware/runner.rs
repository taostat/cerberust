//! The guardrail-runner middleware: the one [`Middleware`] that bridges the two
//! tiers by driving a [`ScannerStack`].
//!
//! `transform_params` runs the input scanners (redact, block) before the model
//! sees the prompt; `wrap_generate` runs the model and then the output scanners
//! (restore, output block) over the response. This is the proof that the outer
//! middleware tier and the inner scanner tier compose.
//!
//! Provenance: after a call, [`GuardrailRunner::into_report`] yields the
//! [`ScanReport`](crate::scanner::ScanReport) of which scanners fired.

use std::sync::Mutex;

use crate::middleware::stream::StreamOutput;
use crate::middleware::{ChunkSink, ChunkSource, Middleware, MiddlewareError, Params};
use crate::scanner::{Blocked, ScanReport, ScannerStack};

/// A middleware that runs a [`ScannerStack`] around a model call.
///
/// The stack is held in a [`Mutex`] because the [`Middleware`] methods take
/// `&self` (the chain shares layers by reference, `Send + Sync`) but the stack
/// threads mutable per-request state (the vault, the report). One runner is one
/// request; the mutex is uncontended (a single request drives it serially).
pub struct GuardrailRunner {
    id: String,
    stack: Mutex<ScannerStack>,
}

impl GuardrailRunner {
    /// Wrap a stack as a middleware.
    #[must_use]
    pub fn new(id: impl Into<String>, stack: ScannerStack) -> Self {
        Self {
            id: id.into(),
            stack: Mutex::new(stack),
        }
    }

    /// Consume the runner and return the provenance report. A poisoned mutex
    /// (a panic mid-scan) still yields the partial report rather than panicking.
    #[must_use]
    pub fn into_report(self) -> ScanReport {
        match self.stack.into_inner() {
            Ok(stack) => stack.report().clone(),
            Err(poisoned) => poisoned.into_inner().report().clone(),
        }
    }
}

impl Middleware for GuardrailRunner {
    fn id(&self) -> &str {
        &self.id
    }

    fn transform_params(&self, params: Params) -> Result<Params, MiddlewareError> {
        let mut stack = lock(&self.stack);
        match stack.run_input(&params.prompt) {
            Ok(redacted) => Ok(Params {
                prompt: redacted,
                ..params
            }),
            Err(blocked) => Err(blocked_error(&blocked)),
        }
    }

    fn wrap_generate(
        &self,
        params: &Params,
        next: &dyn Fn(&Params) -> Result<String, MiddlewareError>,
    ) -> Result<String, MiddlewareError> {
        let response = next(params)?;
        let mut stack = lock(&self.stack);
        stack.run_output(&response).map_err(|b| blocked_error(&b))
    }

    fn wrap_stream(
        &self,
        next: &mut ChunkSource<'_>,
        sink: &mut ChunkSink<'_>,
    ) -> Result<(), MiddlewareError> {
        let mut stack = lock(&self.stack);
        let mut runner = StreamOutput::new(&stack);
        for chunk in next {
            let safe = runner.push(&mut stack, &chunk?)?;
            if !safe.is_empty() {
                sink(safe)?;
            }
        }
        let tail = runner.finish(&mut stack)?;
        if !tail.is_empty() {
            sink(tail)?;
        }
        Ok(())
    }
}

/// Lock the stack, recovering the guard from a poisoned mutex rather than
/// propagating a panic — the per-request stack carries no cross-request
/// invariant that poisoning protects.
fn lock(stack: &Mutex<ScannerStack>) -> std::sync::MutexGuard<'_, ScannerStack> {
    stack
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn blocked_error(blocked: &Blocked) -> MiddlewareError {
    MiddlewareError::Blocked {
        detail: format!("{} (risk {})", blocked.scanner, blocked.risk),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use crate::middleware::{MiddlewareChain, Model};
    use crate::scanner::Scanner;
    use crate::scanners::{PiiScanner, RestoreScanner, SecretScanner};

    use super::*;

    /// A model that echoes the (already-redacted) prompt back — so the output
    /// path sees the sentinels and the restore scanner can rehydrate PII.
    struct EchoModel;
    impl Model for EchoModel {
        fn generate(&self, params: &Params) -> Result<String, MiddlewareError> {
            Ok(params.prompt.clone())
        }
    }

    fn pii_secret_stack() -> ScannerStack {
        let scanners: Vec<Box<dyn Scanner>> = vec![
            Box::new(PiiScanner::new()),
            Box::new(SecretScanner::new()),
            Box::new(RestoreScanner::for_pii()),
        ];
        ScannerStack::new(scanners, true)
    }

    #[test]
    fn pii_round_trips_secret_stays_redacted() {
        let runner = GuardrailRunner::new("native:guard", pii_secret_stack());
        let prompt = "mail alice@x.com key AKIAIOSFODNN7EXAMPLE";
        let out = {
            let chain = MiddlewareChain::new(vec![&runner]);
            chain.generate(Params::new(prompt), &EchoModel).unwrap()
        };
        // PII restored on output; secret never restored (OneWay).
        assert!(out.contains("alice@x.com"));
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(out.contains("[REDACTED_AWS_ACCESS_KEY_1_"));

        let report = runner.into_report();
        // pii + secrets (input) + pii-restore (output) all fired.
        assert_eq!(report.entries().len(), 3);
    }
}
