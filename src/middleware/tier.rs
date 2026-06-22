//! Privacy-tier routing policy: an outer-tier [`Middleware`] that refuses to
//! silently downgrade a request's confidentiality across a tier boundary.
//!
//! A [`PrivacyTier`] is a property of a model. [`PrivacyTier::Confidential`]
//! means the prompt stays sealed (e.g. inside a TEE) — the model provider never
//! sees the request content. [`PrivacyTier::Frontier`] means the provider sees
//! the prompt. Routing a Confidential request to a Frontier model is a
//! **downgrade**: it breaks the confidentiality the caller asked for.
//!
//! [`TierPolicy`] is fail-closed. It inspects the request [`Params`] — the
//! primary target plus any failover or fusion candidates the router *may* use —
//! and blocks before the model runs if serving, falling back, or fusing would
//! send a Confidential request to any Frontier model without the caller's
//! explicit `consent_cross_tier`. Frontier → Confidential is an *upgrade* and is
//! always allowed; same-tier and consented downgrades pass through.
//!
//! cerberust does not own the router. This policy is the reusable seam a router's
//! failover/fusion logic consults: the router threads its real candidate set onto
//! [`Params`] and lets this middleware veto a cross-tier downgrade, so the rule
//! lives in one audited place rather than being re-derived at every routing site.

use crate::middleware::{Middleware, MiddlewareError, Params};

/// The confidentiality tier a model serves at.
///
/// A property of a model, not of a request. The request's *own* tier is the tier
/// of its primary target; the policy's job is to keep candidate routes from
/// dropping below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivacyTier {
    /// The prompt stays sealed; the model provider never sees the request
    /// content. The stronger tier.
    Confidential,
    /// The model provider sees the prompt. The weaker tier.
    Frontier,
}

impl PrivacyTier {
    /// Human-readable tier name for policy messages.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PrivacyTier::Confidential => "Confidential",
            PrivacyTier::Frontier => "Frontier",
        }
    }

    /// Whether routing a request *from* `self` *to* `other` lowers
    /// confidentiality — only Confidential → Frontier does.
    #[must_use]
    fn downgrades_to(self, other: PrivacyTier) -> bool {
        matches!(
            (self, other),
            (PrivacyTier::Confidential, PrivacyTier::Frontier)
        )
    }
}

/// A model the router may target, paired with the tier it serves at. The value
/// descriptor the [`TierPolicy`] reasons over — the callable [`Model`](crate::Model)
/// trait is a separate concern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSpec {
    /// A stable model identifier (e.g. the catalog SKU), used in policy
    /// messages so a block names the offending model.
    pub id: String,
    /// The confidentiality tier this model serves at.
    pub tier: PrivacyTier,
}

impl ModelSpec {
    /// Construct a model spec from an id and its tier.
    #[must_use]
    pub fn new(id: impl Into<String>, tier: PrivacyTier) -> Self {
        Self {
            id: id.into(),
            tier,
        }
    }
}

/// Fail-closed privacy-tier routing policy.
///
/// Blocks any request whose primary target is [`PrivacyTier::Confidential`] when
/// a failover or fusion candidate sits at [`PrivacyTier::Frontier`] and the
/// caller has not set `consent_cross_tier`. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct TierPolicy {
    id: String,
}

impl TierPolicy {
    /// Construct the policy with a provenance id.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

impl Default for TierPolicy {
    fn default() -> Self {
        Self::new("native:tier-policy")
    }
}

impl Middleware for TierPolicy {
    fn id(&self) -> &str {
        &self.id
    }

    /// Reject early, before any candidate model runs: a downgrade caught here
    /// never reaches a model.
    fn transform_params(&self, params: Params) -> Result<Params, MiddlewareError> {
        let Some(primary) = params.primary.as_ref() else {
            // No primary target declared: nothing to compare candidates against.
            // The prompt-only core path is a pass-through.
            return Ok(params);
        };

        if params.consent_cross_tier {
            return Ok(params);
        }

        // Every route the router *might* take, primary included: a downgrade on
        // any of them breaks the confidentiality promise, so all are checked.
        let candidates = std::iter::once(primary)
            .chain(params.fallback.iter())
            .chain(params.fusion.iter());

        for candidate in candidates {
            if primary.tier.downgrades_to(candidate.tier) {
                return Err(downgrade_error(primary.tier, candidate));
            }
        }

        Ok(params)
    }
}

/// A block naming both tiers and the offending model, so the caller (or
/// whatever logs the refusal) sees exactly which route was vetoed.
fn downgrade_error(from: PrivacyTier, to: &ModelSpec) -> MiddlewareError {
    MiddlewareError::Blocked {
        detail: format!(
            "cross-tier downgrade without consent: {} request would route to \
             {} model \"{}\" — set consent_cross_tier to allow",
            from.as_str(),
            to.tier.as_str(),
            to.id
        ),
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

    use super::*;

    struct Echo;
    impl Model for Echo {
        fn generate(&self, params: &Params) -> Result<String, MiddlewareError> {
            Ok(params.prompt.clone())
        }
    }

    fn confidential(id: &str) -> ModelSpec {
        ModelSpec::new(id, PrivacyTier::Confidential)
    }

    fn frontier(id: &str) -> ModelSpec {
        ModelSpec::new(id, PrivacyTier::Frontier)
    }

    /// Drive `params` through a single-policy chain; return the chain result.
    fn run(params: Params) -> Result<String, MiddlewareError> {
        let policy = TierPolicy::default();
        let chain = MiddlewareChain::new(vec![&policy]);
        chain.generate(params, &Echo)
    }

    #[test]
    fn same_tier_fallback_passes() {
        let params = Params::new("hi")
            .with_primary(confidential("tee-a"))
            .with_fallback(vec![confidential("tee-b")]);
        assert!(run(params).is_ok());
    }

    #[test]
    fn confidential_to_frontier_fallback_blocks_without_consent() {
        let params = Params::new("hi")
            .with_primary(confidential("tee-a"))
            .with_fallback(vec![frontier("gpt-x")]);
        let err = run(params).unwrap_err();
        let MiddlewareError::Blocked { detail } = err;
        assert!(
            detail.contains("Confidential"),
            "names source tier: {detail}"
        );
        assert!(detail.contains("Frontier"), "names target tier: {detail}");
        assert!(detail.contains("gpt-x"), "names offending model: {detail}");
    }

    #[test]
    fn confidential_to_frontier_fallback_passes_with_consent() {
        let params = Params::new("hi")
            .with_primary(confidential("tee-a"))
            .with_fallback(vec![frontier("gpt-x")])
            .with_cross_tier_consent(true);
        assert!(run(params).is_ok());
    }

    #[test]
    fn fusion_set_spanning_tiers_blocks_without_consent() {
        let params = Params::new("hi")
            .with_primary(confidential("tee-a"))
            .with_fusion(vec![confidential("tee-b"), frontier("claude-x")]);
        let err = run(params).unwrap_err();
        let MiddlewareError::Blocked { detail } = err;
        assert!(detail.contains("Confidential") && detail.contains("Frontier"));
        assert!(detail.contains("claude-x"));
    }

    #[test]
    fn all_confidential_fusion_passes() {
        let params = Params::new("hi")
            .with_primary(confidential("tee-a"))
            .with_fusion(vec![confidential("tee-b"), confidential("tee-c")]);
        assert!(run(params).is_ok());
    }

    #[test]
    fn frontier_to_confidential_upgrade_passes() {
        // A Frontier primary may fall back to a Confidential model: confidentiality
        // only rises, so the policy never blocks.
        let params = Params::new("hi")
            .with_primary(frontier("gpt-x"))
            .with_fallback(vec![confidential("tee-a")]);
        assert!(run(params).is_ok());
    }

    #[test]
    fn frontier_only_passes() {
        let params = Params::new("hi")
            .with_primary(frontier("gpt-x"))
            .with_fallback(vec![frontier("claude-x")]);
        assert!(run(params).is_ok());
    }

    #[test]
    fn no_primary_is_pass_through() {
        // The prompt-only core path (no routing declared) is untouched.
        assert!(run(Params::new("hi")).is_ok());
    }
}
