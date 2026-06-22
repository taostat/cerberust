//! The ML prompt-injection scanner (feature `prompt-injection`): classify a
//! prompt with a fine-tuned DeBERTa-v3 sequence classifier and block when the
//! injection probability crosses a threshold.
//!
//! The model is `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0) —
//! the same model `llm-guard` ships, chosen for benchmark parity. It is a binary
//! `DebertaV2ForSequenceClassification` with `id2label = {0: SAFE, 1:
//! INJECTION}`; the scanner reads logit index 1 through a softmax to a single
//! `P(injection)` in `[0, 1]` and reports it as the verdict risk.
//!
//! [`Direction::Input`], [`Disposition::Block`], [`HoldBack::WholeStream`]: the
//! classifier needs the whole prompt, judges it once, and rejects an injection
//! before any model forward. It never runs on output and never rewrites text.
//!
//! # Model handling
//!
//! The ONNX weights (~739 MB fp32) are **not** vendored. The scanner loads a
//! directory holding `model.onnx` and `tokenizer.json`; `scripts/fetch-model.sh`
//! downloads them from Hugging Face. int8 quantization (a smaller artifact) is
//! left to the embedding application, not this crate.
//!
//! `ort`'s `download-binaries` feature fetches a prebuilt ONNX Runtime at build
//! time, so the crate compiles with no system ORT install.

use std::path::Path;
use std::sync::Mutex;

use ort::session::Session;
use ort::value::Tensor;
use tokenizers::Tokenizer;

use crate::scanner::{
    Direction, Disposition, HoldBack, ScanCtx, ScanError, ScanResult, Scanner, ScannerId,
    Threshold, Verdict,
};

/// The default block threshold on `P(injection)`. `llm-guard` runs this model at
/// a 0.5 match threshold; a clearly benign prompt scores ~0.0 and a clear
/// injection ~1.0, so 0.5 is the natural midpoint and the documented default.
const DEFAULT_THRESHOLD: f32 = 0.5;

/// The model filename expected inside the model directory.
const MODEL_FILE: &str = "model.onnx";
/// The tokenizer filename expected inside the model directory.
const TOKENIZER_FILE: &str = "tokenizer.json";

/// The graph input names the DeBERTa-v3 ONNX export declares. DeBERTa-v3
/// disables token-type embeddings, so the export takes only these two — no
/// `token_type_ids`.
const INPUT_IDS: &str = "input_ids";
const ATTENTION_MASK: &str = "attention_mask";
/// The logits output name.
const LOGITS: &str = "logits";

/// Errors raised while loading the model or tokenizer, distinct from a
/// [`Verdict`] (a working classifier's judgment) and from a [`ScanError`] (a
/// classifier that fails at call time).
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The ONNX model failed to load (missing file, bad graph, ORT init).
    #[error("failed to load prompt-injection model from {path}: {reason}")]
    Model { path: String, reason: String },
    /// The tokenizer failed to load (missing or malformed `tokenizer.json`).
    #[error("failed to load tokenizer from {path}: {reason}")]
    Tokenizer { path: String, reason: String },
}

/// A DeBERTa-v3 prompt-injection classifier run as a [`Scanner`].
///
/// Holds the ORT [`Session`] behind a [`Mutex`]: `Session::run` takes `&mut
/// self`, but [`Scanner::scan`] is `&self`, so calls are serialised — one
/// classification at a time per loaded model, the same shape as the WASM runner.
pub struct PromptInjectionScanner {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    threshold: Threshold,
}

impl PromptInjectionScanner {
    /// This scanner's id.
    pub const ID: ScannerId = ScannerId("native:prompt-injection");

    /// Load the classifier from a directory holding `model.onnx` and
    /// `tokenizer.json`, with the [`DEFAULT_THRESHOLD`] block threshold.
    ///
    /// # Errors
    /// Returns [`LoadError`] if the model or tokenizer cannot be loaded.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, LoadError> {
        Self::from_dir_with_threshold(dir, Threshold::new(DEFAULT_THRESHOLD))
    }

    /// Load the classifier with an explicit block threshold on `P(injection)`.
    ///
    /// # Errors
    /// Returns [`LoadError`] if the model or tokenizer cannot be loaded.
    pub fn from_dir_with_threshold(
        dir: impl AsRef<Path>,
        threshold: Threshold,
    ) -> Result<Self, LoadError> {
        let dir = dir.as_ref();
        let model_path = dir.join(MODEL_FILE);
        let tokenizer_path = dir.join(TOKENIZER_FILE);

        let session = Session::builder()
            .and_then(|mut b| b.commit_from_file(&model_path))
            .map_err(|e| LoadError::Model {
                path: model_path.display().to_string(),
                reason: format!("{e}"),
            })?;
        let tokenizer =
            Tokenizer::from_file(&tokenizer_path).map_err(|e| LoadError::Tokenizer {
                path: tokenizer_path.display().to_string(),
                reason: format!("{e}"),
            })?;

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            threshold,
        })
    }

    /// The configured block threshold on `P(injection)`.
    #[must_use]
    pub fn threshold(&self) -> Threshold {
        self.threshold
    }

    /// Tokenize `text` and run the classifier, returning `P(injection)` in
    /// `[0, 1]`.
    fn injection_probability(&self, text: &str) -> Result<f32, ScanError> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| detector_error(format!("tokenize: {e}")))?;
        let len = encoding.get_ids().len();
        let ids: Vec<i64> = encoding.get_ids().iter().map(|&id| i64::from(id)).collect();
        let mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&m| i64::from(m))
            .collect();

        // [batch=1, seq_len]; the export is dynamic in both dims.
        let shape = [1_i64, i64::try_from(len).unwrap_or(i64::MAX)];
        let ids_tensor = Tensor::from_array((shape, ids))
            .map_err(|e| detector_error(format!("input_ids tensor: {e}")))?;
        let mask_tensor = Tensor::from_array((shape, mask))
            .map_err(|e| detector_error(format!("attention_mask tensor: {e}")))?;

        let mut session = self
            .session
            .lock()
            .map_err(|_| detector_error("session mutex poisoned".to_owned()))?;
        let outputs = session
            .run(ort::inputs![
                INPUT_IDS => ids_tensor,
                ATTENTION_MASK => mask_tensor,
            ])
            .map_err(|e| detector_error(format!("inference: {e}")))?;
        let (_shape, logits) = outputs[LOGITS]
            .try_extract_tensor::<f32>()
            .map_err(|e| detector_error(format!("extract logits: {e}")))?;

        injection_softmax(logits)
    }
}

/// Softmax index 1 (`INJECTION`) of a two-class logit slice. Computed in the
/// max-shifted form so a large logit never overflows `exp`.
fn injection_softmax(logits: &[f32]) -> Result<f32, ScanError> {
    let [safe, injection] = logits else {
        return Err(detector_error(format!(
            "expected 2 logits (SAFE, INJECTION), got {}",
            logits.len()
        )));
    };
    let max = safe.max(*injection);
    let exp_safe = (safe - max).exp();
    let exp_injection = (injection - max).exp();
    Ok(exp_injection / (exp_safe + exp_injection))
}

/// A [`ScanError::Detector`] tagged with this scanner's id.
fn detector_error(reason: String) -> ScanError {
    ScanError::Detector {
        scanner: PromptInjectionScanner::ID,
        reason,
    }
}

impl Scanner for PromptInjectionScanner {
    fn id(&self) -> ScannerId {
        Self::ID
    }

    fn direction(&self) -> Direction {
        Direction::Input
    }

    fn disposition(&self) -> Disposition {
        Disposition::Block
    }

    fn scan<'a>(&self, text: &'a str, _ctx: &mut ScanCtx) -> ScanResult<'a> {
        let risk = self.injection_probability(text)?;
        Ok(Verdict::detected(text, risk, self.threshold.get()))
    }

    fn hold_back(&self) -> HoldBack {
        // Input-only and block-only: it never runs on a stream. WholeStream is
        // the conservative declaration for a scanner that judges complete text.
        HoldBack::WholeStream
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

    #[test]
    fn softmax_index_one_is_injection_probability() {
        // Equal logits → 0.5.
        assert!((injection_softmax(&[0.0, 0.0]).unwrap() - 0.5).abs() < 1e-6);
        // INJECTION logit dominates → ~1.0.
        assert!(injection_softmax(&[-10.0, 10.0]).unwrap() > 0.999);
        // SAFE logit dominates → ~0.0.
        assert!(injection_softmax(&[10.0, -10.0]).unwrap() < 0.001);
    }

    #[test]
    fn softmax_does_not_overflow_on_large_logits() {
        // The max-shift keeps exp finite even at extreme magnitudes.
        let p = injection_softmax(&[1.0e30, 1.0e30]).unwrap();
        assert!((p - 0.5).abs() < 1e-6);
    }

    #[test]
    fn softmax_rejects_wrong_arity() {
        assert!(injection_softmax(&[0.0]).is_err());
        assert!(injection_softmax(&[0.0, 0.0, 0.0]).is_err());
    }

    #[test]
    fn missing_model_dir_is_a_load_error() {
        match PromptInjectionScanner::from_dir("/nonexistent/model/dir") {
            Err(LoadError::Model { .. }) => {}
            Err(other) => panic!("expected a Model load error, got {other:?}"),
            Ok(_) => panic!("loading a nonexistent model dir must fail"),
        }
    }
}
