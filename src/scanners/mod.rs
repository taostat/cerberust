//! The shipped scanner set: [`pii::PiiScanner`] and [`secrets::SecretScanner`],
//! plus the shared [`restore::RestoreScanner`] that rehydrates `RoundTrip`
//! redactions on the output path; and the pattern scanners
//! ([`regex::RegexScanner`], [`ban_substrings::BanSubstringsScanner`],
//! [`ban_topics::BanTopicsScanner`], [`token_limit::TokenLimitScanner`]).
//!
//! The detect-and-redact scanners (PII, secrets, regex, redacting ban-substrings)
//! share one machinery (collect spans → resolve overlaps → intern into the vault
//! → rewrite span-by-span). They differ only in their detectors and their
//! [`RestorePolicy`](crate::RestorePolicy): PII is `RoundTrip` (a `RestoreScanner`
//! restores it on output), secrets are `OneWay` (nothing restores them), and the
//! regex scanner is configurable. That policy difference — not the data type — is
//! the whole point of the two-tier design. The block-only scanners (ban-topics,
//! token-limit, blocking ban-substrings) reject rather than rewrite.
//!
//! With the `prompt-injection` feature, [`prompt_injection::PromptInjectionScanner`]
//! adds an ML block-only scanner: a DeBERTa-v3 classifier that scores
//! `P(injection)` and rejects an injection before any model forward.

pub mod ban_substrings;
pub mod ban_topics;
pub mod pii;
#[cfg(feature = "prompt-injection")]
pub mod prompt_injection;
pub mod redact;
pub mod regex;
pub mod restore;
pub mod secrets;
pub mod token_limit;

pub use ban_substrings::BanSubstringsScanner;
pub use ban_topics::{BanTopicsScanner, Topic};
pub use pii::PiiScanner;
#[cfg(feature = "prompt-injection")]
pub use prompt_injection::{LoadError as PromptInjectionLoadError, PromptInjectionScanner};
pub use regex::{RegexRule, RegexScanner};
pub use restore::RestoreScanner;
pub use secrets::SecretScanner;
pub use token_limit::TokenLimitScanner;
