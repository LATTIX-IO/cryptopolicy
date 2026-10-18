//! FOSS-500/A: exact-scope, caller-authorized Deny waiver candidate assessment.
//!
//! This module does NOT authenticate policy ownership, signatures or exception
//! evidence and does not enforce an operation. The authority verifier belongs
//! to the consuming caller. The returned candidate is never a signed Permit.
//! Original compiled policies remain immutable, pinned and available for audit.

use crate::{
    CompositionError, ContractError, CryptoContext, DecisionOutcome, EffectiveDecision,
    EffectivePolicy, EvaluationTime, EvidenceId, ExceptionBoundContext, ExceptionDeviation,
    ExceptionReference, ExceptionReferenceFinding, ExceptionScope, ExceptionSourceVerifier, Limits,
    PolicyDecision, PolicyDigest, PolicyReference, ReasonCode, RuleEffect, RuleId, SchemaVersion,
    assess_exception_reference, evaluate_with_limits,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Explicit policy-owner grant for one independently verified Deny deviation.
///
/// This reference is untrusted until authenticated by a caller-supplied
/// PolicyWaiverAuthorityVerifier. It is not a signature or authorization token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyWaiverGrant {
    /// Closed v1 contract version.
    pub schema_version: SchemaVersion,
    /// Original exact policy and canonical digest.
    pub policy: PolicyReference,
    /// Exactly one waivable rule.
    pub target_rule: RuleId,
    /// The corresponding signed-reference exception ID.
    pub exception_id: EvidenceId,
    /// Correlation digest of the exact exception DTO, not a signature.
    pub exception_digest: PolicyDigest,
    /// Original owner-approved waiver artifact reference (unverified claim).
    pub policy_authority_ref: EvidenceId,
    /// Exact requested deviation, currently only a targeted explicit Deny.
    pub deviation: ExceptionDeviation,
    /// Exact immutable tenant/environment/operation/algorithm/key scope.
    pub scope: ExceptionScope,
    /// Exact, mandatory, sorted compensation rule references.
    pub compensating_controls: Vec<RuleId>,
    /// Grant activation time, inclusive, explicitly injected.
    pub authorized_at: EvaluationTime,
    /// Grant expiry time, exclusive.
    pub expires_at: EvaluationTime,
}

impl PolicyWaiverGrant {
    /// Strict resource-bounded validation, not owner authentication.
    pub fn validate(&self, limits: &Limits) -> Result<(), ContractError> {
        self.validate_reviewed(limits, false)
    }

    /// Additional RuleRequirement mode is valid ONLY for externally reviewed
    /// FOSS-502 waivability registry admission, not the legacy E1 API.
    pub(crate) fn validate_reviewed(
        &self,
        limits: &Limits,
        allow_requirement: bool,
    ) -> Result<(), ContractError> {
        limits.validate()?;
        self.scope.validate()?;
        if self.authorized_at >= self.expires_at {
            return Err(ContractError::InvalidDocument("waiver_grant_time"));
        }
        if self.deviation != ExceptionDeviation::RuleDeny
            && !(allow_requirement && self.deviation == ExceptionDeviation::RuleRequirement)
        {
            return Err(ContractError::InvalidDocument(
                "unsupported_waiver_deviation",
            ));
        }
        if self.compensating_controls.is_empty()
            || self.compensating_controls.len() > crate::MAX_EXCEPTION_COMPENSATING_CONTROLS
        {
            return Err(ContractError::ResourceLimitExceeded("waiver_compensators"));
        }
        let mut previous = None;
        let mut seen = BTreeSet::new();
        for id in &self.compensating_controls {
            if id == &self.target_rule {
                return Err(ContractError::InvalidDocument("self_compensating_waiver"));
            }
            if !seen.insert(id) {
                return Err(ContractError::DuplicateIdentifier);
            }
            if previous.is_some_and(|last: &RuleId| last >= id) {
                return Err(ContractError::InvalidDocument(
                    "unordered_waiver_compensators",
                ));
            }
            previous = Some(id);
        }
        let bytes =
            serde_json::to_vec(self).map_err(|e| ContractError::InvalidJson(e.to_string()))?;
        if bytes.len() > crate::MAX_EXCEPTION_REFERENCE_JSON_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        limits.check_json(&bytes)
    }

    /// Parse and validate a closed, bounded grant. Unknown keys fail closed.
    pub fn parse_json_with_limits(bytes: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        limits.check_json(bytes)?;
        if bytes.len() > crate::MAX_EXCEPTION_REFERENCE_JSON_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        let grant: Self =
            serde_json::from_slice(bytes).map_err(|e| ContractError::InvalidJson(e.to_string()))?;
        grant.validate(limits)?;
        Ok(grant)
    }
}

/// Independently approved waiver grant authority verification callback.
///
/// Real implementations MUST authenticate grant source/issuer, delegation to
/// this policy owner, signer/key revocation, approval provenance, exact scope
/// including actual key ownership, target rule and original policy digest.
/// This crate deliberately performs no signature verification or I/O.
pub trait PolicyWaiverAuthorityVerifier {
    /// Validate the exact grant against the original effective policy/context.
    fn authorize(
        &self,
        grant: &PolicyWaiverGrant,
        reference: &ExceptionReference,
        effective: &EffectivePolicy,
        context: &CryptoContext,
    ) -> Result<bool, ContractError>;
}

impl<F> PolicyWaiverAuthorityVerifier for F
where
    F: Fn(
        &PolicyWaiverGrant,
        &ExceptionReference,
        &EffectivePolicy,
        &CryptoContext,
    ) -> Result<bool, ContractError>,
{
    fn authorize(
        &self,
        grant: &PolicyWaiverGrant,
        reference: &ExceptionReference,
        effective: &EffectivePolicy,
        context: &CryptoContext,
    ) -> Result<bool, ContractError> {
        self(grant, reference, effective, context)
    }
}

/// Safe default: owner authorization may never be inferred from a grant DTO.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnverifiedPolicyWaiverAuthority;

impl PolicyWaiverAuthorityVerifier for UnverifiedPolicyWaiverAuthority {
    fn authorize(
        &self,
        _grant: &PolicyWaiverGrant,
        _reference: &ExceptionReference,
        _effective: &EffectivePolicy,
        _context: &CryptoContext,
    ) -> Result<bool, ContractError> {
        Ok(false)
    }
}

/// Why a candidate waiver was never applied to the original policy graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaiverAdmissionDisposition {
    /// Supplied caller context did not match the requested operation/source.
    ScopeMismatch,
    /// Original pinned policy has no matching explicit Deny to waive.
    NoMatchingExplicitDeny,
    /// Exception reference is expired, unverified or out of exact scope.
    ExceptionNotReady,
    /// Grant is not an exact authorized owner-approved reference or is expired.
    GrantNotAuthorized,
    /// Required compensation rules are absent, inapplicable or not satisfied.
    CompensationNotSatisfied,
    /// No exact matching denied/indeterminate Require target was present.
    NoMatchingMandatoryRule,
    /// The owner registry failed an exact-match, live-approval or replay check.
    RegistryNotAuthorized,
    /// No explicitly approved waivable rule matched the exact scoped request.
    RuleNotWaivable,
    /// The actual key/profile binding was not independently authenticated.
    KeyBindingUnverified,
    /// A strictly scoped *simulated* decision was calculated.
    ///
    /// This does not imply a Permit or any enforcement authority.
    CandidateEvaluated,
}

/// Non-authorizing admission report retaining the unchanged original result.
///
/// The derived candidate policy digest is distinct from the pinned original;
/// callers MUST NOT represent it as the original policy or an attestation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverAdmissionReport {
    /// Immutable original effective decision, before any attempted waiver.
    pub original: EffectiveDecision,
    /// Original pinned effective-policy identity, never rewritten.
    pub original_effective_digest: PolicyDigest,
    /// Exact exception used for this assessment.
    pub exception_id: EvidenceId,
    /// Injected evaluation time.
    pub evaluated_at: EvaluationTime,
    /// Why a waiver was or was not simulated.
    pub disposition: WaiverAdmissionDisposition,
    /// Hypothetical overall outcome; not an authenticated Permit.
    pub candidate_outcome: DecisionOutcome,
    /// Hypothetical target-layer decision using a distinct derived digest.
    pub candidate_target_layer: Option<PolicyDecision>,
}

/// One immutable evaluation request, retaining each independently bound input.
///
/// This grouping prevents accidentally swapping the policy, authority, time,
/// scope or exception across a security-sensitive call boundary.
#[derive(Clone, Copy, Debug)]
pub struct WaiverCandidateRequest<'a> {
    /// Original immutable compiled policy graph.
    pub effective: &'a EffectivePolicy,
    /// Original cryptographic operation evidence and explicit UTC time.
    pub context: &'a CryptoContext,
    /// Independently caller-bound exact tenant/key/operation/algorithm scope.
    pub actual_scope: &'a ExceptionScope,
    /// Exact evaluation time, not a system wall clock.
    pub time: EvaluationTime,
    /// Strict untrusted signed-reference exception metadata.
    pub exception: &'a ExceptionReference,
    /// Separately caller-authorized exact policy-owner grant.
    pub grant: &'a PolicyWaiverGrant,
    /// Resource bounds for all parsing and simulated evaluation.
    pub limits: &'a Limits,
}

/// Conservative single-rule Deny exception candidate with full layer isolation.
///
/// Preconditions:
/// 1. original immutable compiled graph evaluated at explicit UTC time;
/// 2. actual current context equals exact grant scope and original targeted Deny;
/// 3. reference separately verified via FOSS-499 external verifier;
/// 4. policy-owner grant independently authorized for the identical exact
///    reference/digest/scope, using a separate external verifier;
/// 5. compensating Require rules exist, match and evaluate satisfied; and
/// 6. all other mandatory layers are still evaluated without alteration.
///
/// Only a cloned, LOCAL target policy is simulated with its one Deny removed.
/// This cannot grant an enforcement authorization, mutate EffectivePolicy,
/// remove unrelated Deny/Require, or bypass policy expiry/activation. An
/// unrecognized deviation (including RuleRequirement) is rejected at validation.
/// External callers MUST independently bind the key_ref to the actual key.
pub fn evaluate_deny_waiver_candidate<
    E: ExceptionSourceVerifier,
    A: PolicyWaiverAuthorityVerifier,
>(
    request: WaiverCandidateRequest<'_>,
    exception_verifier: &E,
    owner_verifier: &A,
) -> Result<WaiverAdmissionReport, CompositionError> {
    evaluate_waiver_candidate_core(request, exception_verifier, owner_verifier, None, false)
}

/// Shared offline candidate evaluator; the extra powers are restricted to the
/// externally verified FOSS-502 owner registry and key/profile trust boundary.
/// The public E1 entrypoint above always denies profile-bearing contexts and
/// RuleRequirement deviations, preserving its earlier conservative behavior.
pub(crate) fn evaluate_waiver_candidate_core<
    E: ExceptionSourceVerifier,
    A: PolicyWaiverAuthorityVerifier,
>(
    request: WaiverCandidateRequest<'_>,
    exception_verifier: &E,
    owner_verifier: &A,
    bound_profile: Option<&crate::ProfileId>,
    allow_requirement: bool,
) -> Result<WaiverAdmissionReport, CompositionError> {
    let WaiverCandidateRequest {
        effective,
        context,
        actual_scope,
        time,
        exception,
        grant,
        limits,
    } = request;
    limits.validate()?;
    exception.validate(limits)?;
    grant.validate_reviewed(limits, allow_requirement)?;
    actual_scope.validate()?;
    let original = effective.evaluate(context, time, limits)?;
    let fallback = |disposition| WaiverAdmissionReport {
        original: original.clone(),
        original_effective_digest: effective.digest().clone(),
        exception_id: exception.exception_id.clone(),
        evaluated_at: time,
        disposition,
        candidate_outcome: original.outcome,
        candidate_target_layer: None,
    };

    // The exact scope is supplied by the authenticated caller, not self-proven
    // by client-submitted tenant, key handle, or provider metadata.
    if context.evaluation_time != time
        || context.operation != actual_scope.operation
        || context.environment.as_deref() != Some(actual_scope.environment.as_str())
        || context.facts.len() != 1
        || context.facts[0].algorithm_id.as_ref() != Some(&actual_scope.algorithm_id)
        // Legacy E1 only allows None. FOSS-502 requires its additional
        // authenticated exact key/profile binding before supplying Some.
        || context.facts[0].profile_id.as_ref() != bound_profile
        || exception.scope != *actual_scope
    {
        return Ok(fallback(WaiverAdmissionDisposition::ScopeMismatch));
    }

    let target = effective
        .components()
        .iter()
        .find(|node| node.reference == exception.policy);
    let Some(target) = target else {
        return Ok(fallback(WaiverAdmissionDisposition::NoMatchingExplicitDeny));
    };
    let targeted_rule = target
        .document
        .rules
        .iter()
        .find(|rule| rule.rule_id == exception.target_rule);
    let (effect, reasons, absent) = match exception.deviation {
        ExceptionDeviation::RuleDeny => (
            RuleEffect::Deny,
            &[ReasonCode::ExplicitDeny][..],
            WaiverAdmissionDisposition::NoMatchingExplicitDeny,
        ),
        ExceptionDeviation::RuleRequirement if allow_requirement => (
            RuleEffect::Require,
            &[
                ReasonCode::RequirementNotSatisfied,
                ReasonCode::MissingRequiredAttribute,
            ][..],
            WaiverAdmissionDisposition::NoMatchingMandatoryRule,
        ),
        ExceptionDeviation::RuleRequirement => {
            return Ok(fallback(WaiverAdmissionDisposition::GrantNotAuthorized));
        }
    };
    if !targeted_rule.is_some_and(|rule| rule.effect == effect) {
        return Ok(fallback(absent));
    }
    let originally_blocked_by_target = original.components.iter().any(|layer| {
        layer.reference == exception.policy
            && layer.decision.reasons.iter().any(|reason| {
                reasons.contains(&reason.code)
                    && reason.rule_id.as_ref() == Some(&exception.target_rule)
            })
    });
    if !originally_blocked_by_target {
        return Ok(fallback(absent));
    }

    let bound = ExceptionBoundContext {
        policy: target.reference.clone(),
        target_rule: exception.target_rule.clone(),
        scope: actual_scope.clone(),
        evaluation_time: time,
    };
    let proof = assess_exception_reference(exception, &bound, exception_verifier)?;
    if proof.finding != ExceptionReferenceFinding::ReferenceReadyForPolicyAdmission {
        return Ok(fallback(WaiverAdmissionDisposition::ExceptionNotReady));
    }
    if grant.schema_version != SchemaVersion::V1
        || grant.policy != target.reference
        || grant.target_rule != exception.target_rule
        || grant.exception_id != exception.exception_id
        || grant.exception_digest != proof.exception_digest
        || grant.scope != exception.scope
        || grant.deviation != exception.deviation
        || grant.compensating_controls != exception.compensating_controls
        || time < grant.authorized_at
        || time >= grant.expires_at
        || !owner_verifier.authorize(grant, exception, effective, context)?
    {
        return Ok(fallback(WaiverAdmissionDisposition::GrantNotAuthorized));
    }

    // Every compensating rule is mandatory, separately matched and checked.
    for id in &grant.compensating_controls {
        if !target.document.rules.iter().any(|rule| {
            rule.rule_id == *id
                && rule.effect == RuleEffect::Require
                && !rule.requirements.is_empty()
        }) {
            return Ok(fallback(
                WaiverAdmissionDisposition::CompensationNotSatisfied,
            ));
        }
    }

    // Clone-only targeted rule removal for a non-authorizing what-if decision.
    // Source policy identity/digest and other layers remain untouched.
    let mut hypothetical = target.document.clone();
    hypothetical
        .rules
        .retain(|rule| rule.rule_id != exception.target_rule);
    let candidate = evaluate_with_limits(&hypothetical, context, time, limits)?;

    let compensators_satisfied = grant.compensating_controls.iter().all(|id| {
        candidate.reasons.iter().any(|reason| {
            reason.rule_id.as_ref() == Some(id) && reason.code == ReasonCode::RequirementSatisfied
        })
    });
    if !compensators_satisfied {
        return Ok(fallback(
            WaiverAdmissionDisposition::CompensationNotSatisfied,
        ));
    }

    // Conjunctive original layers, with ONLY the exact affected layer changed.
    // An unrelated Deny dominates every possible waiver candidate.
    let mut any_deny = false;
    let mut any_indeterminate = false;
    for layer in &original.components {
        let outcome = if layer.reference == exception.policy {
            candidate.outcome
        } else {
            layer.decision.outcome
        };
        if outcome == DecisionOutcome::Deny {
            any_deny = true;
        } else if outcome == DecisionOutcome::Indeterminate {
            any_indeterminate = true;
        }
    }
    let outcome = if any_deny {
        DecisionOutcome::Deny
    } else if any_indeterminate {
        DecisionOutcome::Indeterminate
    } else {
        DecisionOutcome::Permit
    };
    Ok(WaiverAdmissionReport {
        original,
        original_effective_digest: effective.digest().clone(),
        exception_id: exception.exception_id.clone(),
        evaluated_at: time,
        disposition: WaiverAdmissionDisposition::CandidateEvaluated,
        candidate_outcome: outcome,
        candidate_target_layer: Some(candidate),
    })
}
