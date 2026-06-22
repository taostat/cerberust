//! The outer tier: a Vercel-AI-SDK-shaped [`Middleware`] trait and a
//! [`MiddlewareChain`] that nests middlewares around a model call.
//!
//! A [`Middleware`] wraps the request params (`transform_params`), the unary
//! generation (`wrap_generate`), and — declared for the streaming follow-up —
//! the streamed generation (`wrap_stream`). This is the same onion as Vercel's
//! `wrapLanguageModel({ model, middleware: [a, b] })`: the first element is
//! outermost, request flows in front-to-back, response unwinds back-to-front.
//!
//! One middleware is implemented here — the
//! [`GuardrailRunner`](runner::GuardrailRunner) — which wraps a
//! [`ScannerStack`](crate::ScannerStack): input scan before the model, output
//! scan after. It proves the two-tier shape. Future peers at this tier
//! (provider failover, response fusion, billing/metering) are separate
//! middlewares that compose in the same chain — they are deliberately not built
//! here.

pub mod holdback;
pub mod runner;
pub mod stream;
pub mod tier;

use thiserror::Error;

pub use runner::GuardrailRunner;
pub use tier::{ModelSpec, PrivacyTier, TierPolicy};

/// Why a middleware rejected a request or response.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum MiddlewareError {
    /// A guardrail (or other middleware) blocked the call. `detail` is a
    /// human-readable reason (e.g. the blocking scanner id).
    #[error("blocked: {detail}")]
    Blocked { detail: String },
}

/// The request params a middleware may rewrite before the model call. Kept
/// minimal and provider-agnostic for the core: the prompt text plus the routing
/// shape a privacy-tier policy inspects. A real deployment threads richer
/// params; the shape is what matters for the two-tier design.
///
/// The routing fields describe what a router *may* do with the
/// request, not what it has done: `primary` is the model the request targets,
/// `fallback` the ordered candidates a failover may swap to, and `fusion` the
/// set a response-fusion may fan out across. The [`TierPolicy`] middleware reads
/// these — it does not own the router — to refuse a confidentiality downgrade
/// before any candidate runs.
#[derive(Debug, Clone, Default)]
pub struct Params {
    /// The prompt text the input scanners run over.
    pub prompt: String,
    /// The model the request primarily targets, when known. `None` leaves
    /// tier-policy a pass-through (the prompt-only core path).
    pub primary: Option<ModelSpec>,
    /// Ordered failover candidates the router may swap to for `primary`.
    pub fallback: Vec<ModelSpec>,
    /// Candidates a response-fusion may fan the request out across.
    pub fusion: Vec<ModelSpec>,
    /// The caller explicitly accepted routing a Confidential request to a
    /// Frontier model (a privacy downgrade). Defaults to `false`: fail-closed.
    pub consent_cross_tier: bool,
}

impl Params {
    /// Construct params from a prompt, with no routing candidates and no
    /// cross-tier consent (fail-closed). Use the builder setters to add the
    /// model targets a [`TierPolicy`] inspects.
    #[must_use]
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            ..Self::default()
        }
    }

    /// Set the primary target model.
    #[must_use]
    pub fn with_primary(mut self, primary: ModelSpec) -> Self {
        self.primary = Some(primary);
        self
    }

    /// Set the ordered failover candidates.
    #[must_use]
    pub fn with_fallback(mut self, fallback: Vec<ModelSpec>) -> Self {
        self.fallback = fallback;
        self
    }

    /// Set the response-fusion candidate set.
    #[must_use]
    pub fn with_fusion(mut self, fusion: Vec<ModelSpec>) -> Self {
        self.fusion = fusion;
        self
    }

    /// Record the caller's explicit consent to a cross-tier (Confidential →
    /// Frontier) downgrade.
    #[must_use]
    pub fn with_cross_tier_consent(mut self, consent: bool) -> Self {
        self.consent_cross_tier = consent;
        self
    }
}

/// A model call: takes (possibly-transformed) [`Params`], returns the generated
/// text. The `dyn` model the chain wraps. Sync here for a simple, testable
/// core; an async variant is a mechanical change for a real deployment.
pub trait Model {
    /// Generate a unary response for `params`.
    ///
    /// # Errors
    /// Returns a [`MiddlewareError`] if the underlying model call fails.
    fn generate(&self, params: &Params) -> Result<String, MiddlewareError>;
}

/// One token (or chunk) of a streamed response, or a model-side error mid-stream.
pub type Chunk = Result<String, MiddlewareError>;

/// A streamed model call: yields response chunks in order. Sync (an iterator)
/// for a testable core, mirroring [`Model`]; a real deployment swaps in an async
/// `Stream` behind the same [`Middleware::wrap_stream`] seam.
pub trait StreamModel {
    /// Begin streaming a response for `params`, yielding chunks in order.
    fn stream(&self, params: &Params) -> Box<dyn Iterator<Item = Chunk> + '_>;
}

/// The inner stream a [`Middleware::wrap_stream`] wraps: the chunk producer of
/// the next layer in (or the model itself at the innermost layer).
pub type ChunkSource<'a> = dyn Iterator<Item = Chunk> + 'a;

/// Where a [`Middleware::wrap_stream`] writes the chunks it emits downstream.
pub type ChunkSink<'a> = dyn FnMut(String) -> Result<(), MiddlewareError> + 'a;

/// One layer of request/response processing around a [`Model`].
///
/// Mirrors `LanguageModelV2Middleware`: `transform_params` runs on both paths'
/// inputs, `wrap_generate` wraps the unary result. `wrap_stream` is declared
/// for the streaming follow-up; the core drives only the unary path.
pub trait Middleware: Send + Sync {
    /// A stable identifier for provenance.
    fn id(&self) -> &str;

    /// Rewrite the request params before the model call (the input path).
    ///
    /// # Errors
    /// Returns [`MiddlewareError::Blocked`] to reject before the model runs.
    fn transform_params(&self, params: Params) -> Result<Params, MiddlewareError> {
        Ok(params)
    }

    /// Wrap the unary generation: call `next` to produce the response, then
    /// post-process it (the output path).
    ///
    /// # Errors
    /// Returns a [`MiddlewareError`] if the inner call fails or the response is
    /// blocked.
    fn wrap_generate(
        &self,
        params: &Params,
        next: &dyn Fn(&Params) -> Result<String, MiddlewareError>,
    ) -> Result<String, MiddlewareError> {
        next(params)
    }

    /// Wrap the streamed generation: pull chunks from `next` (the inner stream),
    /// transform them, and write the result to `sink`. The default forwards each
    /// chunk untouched — a middleware that does not stream-transform is a
    /// pass-through.
    ///
    /// The [`GuardrailRunner`] overrides this to run the output scanner stack
    /// with conservative hold-back (see [`stream`]): it emits only bytes proven
    /// safe and holds back any tail that could still be completing a redactable
    /// match or a vault sentinel.
    ///
    /// # Errors
    /// Returns a [`MiddlewareError`] if the inner stream errors or a `Block`
    /// scanner rejects the response.
    fn wrap_stream(
        &self,
        next: &mut ChunkSource<'_>,
        sink: &mut ChunkSink<'_>,
    ) -> Result<(), MiddlewareError> {
        for chunk in next {
            sink(chunk?)?;
        }
        Ok(())
    }
}

/// A nest of middlewares around a model: `[a, b]` runs `a(b(model))`.
pub struct MiddlewareChain<'m> {
    layers: Vec<&'m dyn Middleware>,
}

impl<'m> MiddlewareChain<'m> {
    /// Build a chain. The first layer is outermost.
    #[must_use]
    pub fn new(layers: Vec<&'m dyn Middleware>) -> Self {
        Self { layers }
    }

    /// Drive the unary path: transform params front-to-back, then wrap the
    /// model generation through the onion.
    ///
    /// # Errors
    /// Propagates the first [`MiddlewareError`] from any layer or the model.
    pub fn generate(&self, params: Params, model: &dyn Model) -> Result<String, MiddlewareError> {
        let mut params = params;
        for layer in &self.layers {
            params = layer.transform_params(params)?;
        }
        self.wrap_at(0, &params, model)
    }

    /// Recursively wrap generation: layer `i` calls into layer `i+1`, and the
    /// innermost call hits the model.
    fn wrap_at(
        &self,
        i: usize,
        params: &Params,
        model: &dyn Model,
    ) -> Result<String, MiddlewareError> {
        match self.layers.get(i) {
            Some(layer) => {
                let next = |p: &Params| self.wrap_at(i + 1, p, model);
                layer.wrap_generate(params, &next)
            }
            None => model.generate(params),
        }
    }

    /// Drive the streaming path: transform params front-to-back, then unwind the
    /// response stream through the onion, innermost layer first. Each layer's
    /// [`Middleware::wrap_stream`] consumes the chunks the next-inner layer
    /// emitted; the outermost layer's emissions are collected and returned.
    ///
    /// Between two layers the inner layer's emitted chunks are buffered before
    /// the outer layer consumes them. A single-guardrail chain — the real case —
    /// has no inter-layer buffer and streams end-to-end; the guardrail's own
    /// hold-back is exercised regardless.
    ///
    /// # Errors
    /// Propagates the first [`MiddlewareError`] from any layer or the model.
    pub fn stream(
        &self,
        params: Params,
        model: &dyn StreamModel,
    ) -> Result<Vec<String>, MiddlewareError> {
        let mut params = params;
        for layer in &self.layers {
            params = layer.transform_params(params)?;
        }
        let model_chunks: Vec<Chunk> = model.stream(&params).collect();
        let mut chunks = model_chunks;
        // Innermost (last) layer wraps the model stream first; each outer layer
        // then wraps the previous layer's emissions.
        for layer in self.layers.iter().rev() {
            let mut emitted: Vec<String> = Vec::new();
            let mut source = chunks.into_iter();
            let mut sink = |s: String| -> Result<(), MiddlewareError> {
                emitted.push(s);
                Ok(())
            };
            layer.wrap_stream(&mut source, &mut sink)?;
            chunks = emitted.into_iter().map(Ok).collect();
        }
        chunks.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on known-good values"
    )]
    use super::*;

    struct Echo;
    impl Model for Echo {
        fn generate(&self, params: &Params) -> Result<String, MiddlewareError> {
            Ok(format!("echo: {}", params.prompt))
        }
    }

    struct Tag(&'static str);
    impl Middleware for Tag {
        fn id(&self) -> &str {
            self.0
        }
        fn wrap_generate(
            &self,
            params: &Params,
            next: &dyn Fn(&Params) -> Result<String, MiddlewareError>,
        ) -> Result<String, MiddlewareError> {
            let inner = next(params)?;
            Ok(format!("[{}]{inner}[/{}]", self.0, self.0))
        }
    }

    #[test]
    fn chain_nests_first_outermost() {
        let a = Tag("a");
        let b = Tag("b");
        let chain = MiddlewareChain::new(vec![&a, &b]);
        let out = chain.generate(Params::new("hi"), &Echo).unwrap();
        assert_eq!(out, "[a][b]echo: hi[/b][/a]");
    }

    #[test]
    fn empty_chain_calls_model_directly() {
        let chain = MiddlewareChain::new(vec![]);
        let out = chain.generate(Params::new("hi"), &Echo).unwrap();
        assert_eq!(out, "echo: hi");
    }
}
