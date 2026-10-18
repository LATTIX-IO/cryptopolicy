//! FOSS-502: externally authenticated waivability registry and exact key/profile
//! bindings for non-authorizing, offline waiver simulations.
//!
//! Registry bytes, digests and references are not signatures. The caller's
//! separate registry and key-profile trust verifiers MUST authenticate those
//! sources, ownership/delegation, nonce freshness, key identity and revocation.

use crate::{
    CompositionError, ContractError, CryptoContext, EvaluationTime, EvidenceId,
    ExceptionBoundContext, ExceptionDeviation, ExceptionReferenceFinding, ExceptionScope,
    ExceptionSourceVerifier, ExceptionStatus, Limits, PolicyReference,
    PolicyWaiverAuthorityVerifier, ProfileId, RuleId, SchemaVersion, WaiverAdmissionDisposition,
    WaiverAdmissionReport, WaiverCandidateRequest, assess_exception_reference,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum versioned waivable rules within one owner-controlled registry.
pub const MAX_WAIVABILITY_ENTRIES: usize = 16;

/// One exact owner-approved, non-wildcard rule and named profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaivableRuleEntry {
    /// Exact RuleId in the pinned policy document.
    pub target_rule: RuleId,
    /// Exact approved deviation kind.
    pub deviation: ExceptionDeviation,
    /// Exact tenant/environment/operation/algorithm/key scope.
    pub scope: ExceptionScope,
    /// Exact named profile, never an unbounded algorithm family.
    pub profile_id: ProfileId,
    /// Required, sorted, unique compensating Require rule identifiers.
    pub compensating_controls: Vec<RuleId>,
}

/// Closed owner registry requiring external signature/delegation verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaivabilityRegistry {
    /// Current wire version. An unknown version must never be accepted.
    pub schema_version: SchemaVersion,
    /// Immutable pinned policy for all entries.
    pub policy: PolicyReference,
    /// Unique registry identity, never a signature.
    pub registry_ref: EvidenceId,
    /// External document/approval evidence identity, not proof.
    pub authority_ref: EvidenceId,
    /// Monotonic external revision, checked for rollback by consuming verifier.
    pub revision: u64,
    /// One-time nonce; freshness must be externally checked.
    pub nonce: EvidenceId,
    /// Claimed registry administrative status.
    pub status: ExceptionStatus,
    /// Earliest externally verified issue time.
    pub issued_at: EvaluationTime,
    /// Inclusive activation boundary.
    pub effective_at: EvaluationTime,
    /// Exclusive expiration boundary.
    pub expires_at: EvaluationTime,
    /// Explicit, unique owner-waivable targets. No wildcard entries.
    pub entries: Vec<WaivableRuleEntry>,
}

impl WaivabilityRegistry {
    /// Strict bounded parsing, duplicate-key detection and closed DTO contract.
    pub fn parse_json_with_limits(bytes: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        limits.check_json(bytes)?;
        if bytes.len() > crate::MAX_EXCEPTION_REFERENCE_JSON_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        let registry: Self =
            serde_json::from_slice(bytes).map_err(|e| ContractError::InvalidJson(e.to_string()))?;
        registry.validate(limits)?;
        Ok(registry)
    }

    /// Validate a constructed/mutated registry without authenticating it.
    pub fn validate(&self, limits: &Limits) -> Result<(), ContractError> {
        limits.validate()?;
        if self.schema_version != SchemaVersion::V1 || self.revision == 0 {
            return Err(ContractError::InvalidDocument(
                "waivability_registry_version",
            ));
        }
        if self.issued_at > self.effective_at || self.effective_at >= self.expires_at {
            return Err(ContractError::InvalidDocument("waivability_registry_time"));
        }
        if self.entries.is_empty() || self.entries.len() > MAX_WAIVABILITY_ENTRIES {
            return Err(ContractError::ResourceLimitExceeded("waivability_entries"));
        }
        let mut ids = BTreeSet::new();
        for entry in &self.entries {
            entry.scope.validate()?;
            if !ids.insert(&entry.target_rule) {
                return Err(ContractError::DuplicateIdentifier);
            }
            if entry.compensating_controls.is_empty()
                || entry.compensating_controls.len() > crate::MAX_EXCEPTION_COMPENSATING_CONTROLS
            {
                return Err(ContractError::ResourceLimitExceeded(
                    "waivability_compensators",
                ));
            }
            let mut seen = BTreeSet::new();
            for id in &entry.compensating_controls {
                if id == &entry.target_rule {
                    return Err(ContractError::InvalidDocument(
                        "waivability_self_compensation",
                    ));
                }
                if !seen.insert(id) {
                    return Err(ContractError::DuplicateIdentifier);
                }
            }
            if entry.compensating_controls.windows(2).any(|v| v[0] >= v[1]) {
                return Err(ContractError::InvalidDocument("waivability_order"));
            }
        }
        if self
            .entries
            .windows(2)
            .any(|v| v[0].target_rule >= v[1].target_rule)
        {
            return Err(ContractError::InvalidDocument("waivability_entry_order"));
        }
        let encoded =
            serde_json::to_vec(self).map_err(|e| ContractError::InvalidJson(e.to_string()))?;
        if encoded.len() > crate::MAX_EXCEPTION_REFERENCE_JSON_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        limits.check_json(&encoded)
    }
}

/// Exact claimed key and profile, independently checked by caller verifier.
///
/// Cannot self-authenticate a tenant, key owner, provider, or key-to-profile
/// binding simply because these fields have the expected string values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyProfileBinding {
    /// Exact scope of the real proposed operation.
    pub scope: ExceptionScope,
    /// Named profile of the actual key/operation; must match observed fact.
    pub profile_id: ProfileId,
    /// External collector / HSM attestation evidence reference.
    pub evidence_ref: EvidenceId,
    /// Exact key generation/version reference for replay protection.
    pub key_version_ref: EvidenceId,
}

/// Four independent policy authority facts verified outside this crate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegistryVerification {
    /// Original registry bytes and signature externally authenticated.
    pub registry_authenticated: bool,
    /// Registry signer independently delegated by pinned policy owner.
    pub owner_delegation_verified: bool,
    /// Live revocation and expiry independently checked at exact time.
    pub revocation_fresh: bool,
    /// Revision and nonce independently checked against persistent replay state.
    pub replay_fresh: bool,
}

/// Caller-controlled, cryptographically authenticated waivability trust gate.
pub trait WaivabilityRegistryVerifier {
    /// Authenticate pinned registry and current operational authorization.
    fn verify(
        &self,
        registry: &WaivabilityRegistry,
        request: &WaiverCandidateRequest<'_>,
    ) -> Result<RegistryVerification, ContractError>;
}
impl<F> WaivabilityRegistryVerifier for F
where
    F: Fn(
        &WaivabilityRegistry,
        &WaiverCandidateRequest<'_>,
    ) -> Result<RegistryVerification, ContractError>,
{
    fn verify(
        &self,
        registry: &WaivabilityRegistry,
        request: &WaiverCandidateRequest<'_>,
    ) -> Result<RegistryVerification, ContractError> {
        self(registry, request)
    }
}

/// Caller-controlled key-owner/profile attestation and source-trust gate.
pub trait KeyProfileBindingVerifier {
    /// Authenticate the actual key owner, named profile and key generation.
    fn verify(
        &self,
        binding: &KeyProfileBinding,
        context: &CryptoContext,
    ) -> Result<bool, ContractError>;
}
impl<F> KeyProfileBindingVerifier for F
where
    F: Fn(&KeyProfileBinding, &CryptoContext) -> Result<bool, ContractError>,
{
    fn verify(
        &self,
        binding: &KeyProfileBinding,
        context: &CryptoContext,
    ) -> Result<bool, ContractError> {
        self(binding, context)
    }
}

/// Safe default: unsigned registry and unproven owner claims are untrusted.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnverifiedWaivabilityRegistry;
impl WaivabilityRegistryVerifier for UnverifiedWaivabilityRegistry {
    fn verify(
        &self,
        _registry: &WaivabilityRegistry,
        _request: &WaiverCandidateRequest<'_>,
    ) -> Result<RegistryVerification, ContractError> {
        Ok(RegistryVerification::default())
    }
}

/// Safe default: no claimed key/profile identity can establish real ownership.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnverifiedKeyProfileBinding;
impl KeyProfileBindingVerifier for UnverifiedKeyProfileBinding {
    fn verify(
        &self,
        _binding: &KeyProfileBinding,
        _context: &CryptoContext,
    ) -> Result<bool, ContractError> {
        Ok(false)
    }
}

/// The review-time trust inputs are separate from the untrusted E0/E1 DTOs.
pub struct ReviewedWaiverRequest<'a> {
    /// Original bounded E1 request and pinned compiled policy.
    pub request: WaiverCandidateRequest<'a>,
    /// Versioned policy-owner waiver registry, not self-authenticating.
    pub registry: &'a WaivabilityRegistry,
    /// Exact key owner/profile evidence awaiting independent authentication.
    pub key_binding: &'a KeyProfileBinding,
}

/// Evaluate only a reviewable, non-authorizing waiver candidate.
///
/// Four separate caller-owned gate families are required: E0 signed approval,
/// E1 owner-issued grant, current policy-owner registry and actual key/profile
/// ownership. A "CandidateEvaluated" result is hypothetical and MUST NOT be
/// used as an authenticated enforcement Permit.
pub fn evaluate_reviewed_waiver_candidate<
    E: ExceptionSourceVerifier,
    A: PolicyWaiverAuthorityVerifier,
    R: WaivabilityRegistryVerifier,
    K: KeyProfileBindingVerifier,
>(
    reviewed: ReviewedWaiverRequest<'_>,
    exception_verifier: &E,
    owner_verifier: &A,
    registry_verifier: &R,
    key_verifier: &K,
) -> Result<WaiverAdmissionReport, CompositionError> {
    let ReviewedWaiverRequest {
        request,
        registry,
        key_binding,
    } = reviewed;
    let WaiverCandidateRequest {
        effective,
        context,
        actual_scope,
        time,
        exception,
        grant,
        limits,
    } = request;
    registry.validate(limits)?;
    actual_scope.validate()?;
    key_binding.scope.validate()?;

    // Preserve an original, entirely unmodified decision for every rejection.
    let original = effective.evaluate(context, time, limits)?;
    let reject = |disposition| WaiverAdmissionReport {
        original: original.clone(),
        original_effective_digest: effective.digest().clone(),
        exception_id: exception.exception_id.clone(),
        evaluated_at: time,
        disposition,
        candidate_outcome: original.outcome,
        candidate_target_layer: None,
    };
    // No way to infer scope from untrusted key metadata. Both externally
    // authenticated exact scope and named profile MUST match actual facts.
    if context.evaluation_time != time
        || context.operation != actual_scope.operation
        || context.environment.as_deref() != Some(actual_scope.environment.as_str())
        || context.facts.len() != 1
        || context.facts[0].profile_id.as_ref() != Some(&key_binding.profile_id)
        || context.facts[0].algorithm_id.as_ref() != Some(&actual_scope.algorithm_id)
        || key_binding.scope != *actual_scope
        || exception.scope != *actual_scope
        || grant.scope != *actual_scope
    {
        return Ok(reject(WaiverAdmissionDisposition::ScopeMismatch));
    }
    if !key_verifier.verify(key_binding, context)? {
        return Ok(reject(WaiverAdmissionDisposition::KeyBindingUnverified));
    }
    if registry.status != ExceptionStatus::Active
        || time < registry.effective_at
        || time >= registry.expires_at
        || registry.policy != exception.policy
        || registry.policy != grant.policy
    {
        return Ok(reject(WaiverAdmissionDisposition::RegistryNotAuthorized));
    }
    let entry = registry.entries.iter().find(|entry| {
        entry.target_rule == exception.target_rule
            && entry.deviation == exception.deviation
            && entry.profile_id == key_binding.profile_id
            && entry.scope == *actual_scope
            && entry.compensating_controls == exception.compensating_controls
            && entry.compensating_controls == grant.compensating_controls
    });
    if entry.is_none() {
        return Ok(reject(WaiverAdmissionDisposition::RuleNotWaivable));
    }
    let proof = registry_verifier.verify(registry, &request)?;
    if !(proof.registry_authenticated
        && proof.owner_delegation_verified
        && proof.revocation_fresh
        && proof.replay_fresh)
    {
        return Ok(reject(WaiverAdmissionDisposition::RegistryNotAuthorized));
    }
    // Enforce independent E0 and E1 approval after registry and key binding.
    // A verified registry must not mask an unsigned source exception,
    // missing/expired approval or unrelated policy-owner grant.
    exception.validate(limits)?;
    if grant.deviation == ExceptionDeviation::RuleDeny {
        // The legacy public E1 validator must continue to reject Require.
        grant.validate(limits)?;
    }
    let digest = exception.correlation_digest()?;
    if grant.schema_version != SchemaVersion::V1
        || grant.policy != exception.policy
        || grant.target_rule != exception.target_rule
        || grant.exception_id != exception.exception_id
        || grant.exception_digest != digest
        || grant.deviation != exception.deviation
        || grant.scope != exception.scope
        || grant.compensating_controls != exception.compensating_controls
        || grant.authorized_at >= grant.expires_at
        || time < grant.authorized_at
        || time >= grant.expires_at
    {
        return Ok(reject(WaiverAdmissionDisposition::GrantNotAuthorized));
    }
    let bound = ExceptionBoundContext {
        policy: exception.policy.clone(),
        target_rule: exception.target_rule.clone(),
        scope: actual_scope.clone(),
        evaluation_time: time,
    };
    let e0 = assess_exception_reference(exception, &bound, exception_verifier)?;
    if e0.finding != ExceptionReferenceFinding::ReferenceReadyForPolicyAdmission {
        return Ok(reject(WaiverAdmissionDisposition::ExceptionNotReady));
    }
    if !owner_verifier.authorize(grant, exception, effective, context)? {
        return Ok(reject(WaiverAdmissionDisposition::GrantNotAuthorized));
    }
    // The pure evaluator's requires_unavailable_profile() intentionally blocks
    // ALL named profile Permit outcomes. These independent verifiers still
    // cannot override that unsupported profile boundary.
    Ok(reject(
        WaiverAdmissionDisposition::ProfileEvaluatorUnsupported,
    ))
}
