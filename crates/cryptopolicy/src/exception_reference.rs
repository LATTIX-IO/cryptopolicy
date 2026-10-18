//! FOSS-499: strict, non-authorizing signed-reference exception metadata.
//!
//! No cryptographic verification, waiver, policy override, Permit or approval
//! is performed. A separately authenticated caller is responsible for proof.

use crate::{
    AlgorithmId, ContractError, CryptoOperation, EvaluationTime, EvidenceId, Limits, PolicyDigest,
    PolicyId, PolicyReference, RuleId, SchemaVersion,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Absolute bound for one serialized exception reference.
pub const MAX_EXCEPTION_REFERENCE_JSON_BYTES: usize = 16_384;
/// Number of independently enforced compensating rule references permitted.
pub const MAX_EXCEPTION_COMPENSATING_CONTROLS: usize = 16;
/// Domain prefix for correlation fingerprints; it is not a signature.
pub const EXCEPTION_REFERENCE_DOMAIN_V1: &[u8] = b"cryptopolicy-exception-reference-v1\0";

/// One exact, non-wildcard scope, including the existing key identity.
///
/// These fields are identity claims until the caller verifies each binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionScope {
    /// Exact tenant (never an all-tenants wildcard).
    pub tenant_id: PolicyId,
    /// Exact deployment environment, canonical bounded ASCII identifier.
    pub environment: String,
    /// Single cryptographic operation.
    pub operation: CryptoOperation,
    /// Exact algorithm identity, never a family or fuzzy alias.
    pub algorithm_id: AlgorithmId,
    /// Exact opaque key reference; no bytes or private key material.
    pub key_ref: EvidenceId,
}

impl ExceptionScope {
    /// Validate a strict environment and exact identity grammar.
    pub fn validate(&self) -> Result<(), ContractError> {
        let bytes = self.environment.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 64
            || !bytes[0].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"-._:/".contains(c))
        {
            return Err(ContractError::InvalidDocument(
                "exception_scope_environment",
            ));
        }
        Ok(())
    }
}

/// Explicitly requested deviation. These are *not* evaluator instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionDeviation {
    /// Request exemption for one targeted mandatory rule requirement.
    RuleRequirement,
    /// Request exemption for one targeted explicit Deny rule.
    RuleDeny,
}

/// Claimed administrative status. Revocation requires independent verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionStatus {
    /// Caller asserts this record is eligible for consideration.
    Active,
    /// Caller marks the record as permanently revoked.
    Revoked,
    /// Caller marks the record as administratively suspended.
    Suspended,
}

/// Immutable exact-scope reference envelope. Its contents are untrusted.
///
/// Even an active, apparently signed or independently approved-looking record
/// cannot modify policies. FOSS-500 must separately implement exact policy
/// authority, waivability and compensating requirements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionReference {
    /// Closed v1 wire schema.
    pub schema_version: SchemaVersion,
    /// Stable exception ID, never an approval proof.
    pub exception_id: EvidenceId,
    /// Exact policy ID, version and canonical digest target.
    pub policy: PolicyReference,
    /// Exact targeted rule, not a wildcard or rule family.
    pub target_rule: RuleId,
    /// Claimed accountable owner; not an authenticated principal.
    pub owner: PolicyId,
    /// Claimed independent approver; not a verified signature.
    pub approver: PolicyId,
    /// Opaque reference to original approval artifact.
    pub approval_ref: EvidenceId,
    /// Opaque reference to source record/signature material stored externally.
    pub source_ref: EvidenceId,
    /// Exact tenant/environment/operation/algorithm/key scope.
    pub scope: ExceptionScope,
    /// Request-only deviation type, not executable authorization.
    pub deviation: ExceptionDeviation,
    /// Nonempty, strictly sorted references to mandatory compensating rules.
    pub compensating_controls: Vec<RuleId>,
    /// Nonempty, bounded, printable justification, never a secret token.
    pub justification: String,
    /// Administrative status claim.
    pub status: ExceptionStatus,
    /// Earliest point at which approval could have been issued.
    pub issued_at: EvaluationTime,
    /// Inclusive activation time.
    pub effective_at: EvaluationTime,
    /// Exclusive expiration time.
    pub expires_at: EvaluationTime,
}

impl ExceptionReference {
    /// Parse one closed JSON envelope, enforcing both absolute and caller caps.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        Self::parse_json_with_limits(input, &Limits::default())
    }

    /// Parse using bounded JSON preflight; unknown/duplicate fields fail closed.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        limits.check_json(input)?;
        if input.len() > MAX_EXCEPTION_REFERENCE_JSON_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        let value: Self =
            serde_json::from_slice(input).map_err(|e| ContractError::InvalidJson(e.to_string()))?;
        value.validate(limits)?;
        Ok(value)
    }

    /// Validate independently constructed or mutated DTOs as well as JSON.
    pub fn validate(&self, limits: &Limits) -> Result<(), ContractError> {
        limits.validate()?;
        self.scope.validate()?;
        if self.owner == self.approver {
            return Err(ContractError::InvalidDocument("exception_self_approval"));
        }
        if self.issued_at > self.effective_at || self.effective_at >= self.expires_at {
            return Err(ContractError::InvalidDocument(
                "exception_invalid_time_window",
            ));
        }
        if self.justification.trim().is_empty()
            || self.justification.len() > 512
            || self.justification.chars().any(char::is_control)
        {
            return Err(ContractError::InvalidDocument("exception_justification"));
        }
        if self.compensating_controls.is_empty()
            || self.compensating_controls.len() > MAX_EXCEPTION_COMPENSATING_CONTROLS
        {
            return Err(ContractError::ResourceLimitExceeded(
                "exception_compensating_controls",
            ));
        }
        let mut seen = BTreeSet::new();
        for rule in &self.compensating_controls {
            if rule == &self.target_rule {
                return Err(ContractError::InvalidDocument(
                    "exception_self_compensation",
                ));
            }
            if !seen.insert(rule) {
                return Err(ContractError::DuplicateIdentifier);
            }
        }
        if self
            .compensating_controls
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(ContractError::InvalidDocument(
                "exception_unsorted_compensating_controls",
            ));
        }

        // Calculate actual serialized size only after all variable-sized
        // fields have independent small bounds.
        let value =
            serde_json::to_vec(self).map_err(|e| ContractError::InvalidJson(e.to_string()))?;
        if value.len() > MAX_EXCEPTION_REFERENCE_JSON_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        limits.check_json(&value)
    }

    /// Stable, domain-separated SHA-256 correlation fingerprint, NOT a signature.
    pub fn correlation_digest(&self) -> Result<PolicyDigest, ContractError> {
        self.validate(&Limits::default())?;
        let serialized =
            serde_json::to_vec(self).map_err(|e| ContractError::InvalidJson(e.to_string()))?;
        let mut hash = Sha256::new();
        hash.update(EXCEPTION_REFERENCE_DOMAIN_V1);
        hash.update(
            u32::try_from(serialized.len())
                .map_err(|_| ContractError::PayloadTooLarge)?
                .to_be_bytes(),
        );
        hash.update(serialized);
        PolicyDigest::try_from(format!("{:x}", hash.finalize()))
    }
}

/// Exact target and time supplied by the consuming policy authority.
///
/// A match means equality of caller-asserted fields, not authentic policy or
/// current key ownership. There is no ambient clock, resolver or I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExceptionBoundContext {
    /// Exact pinned policy being considered.
    pub policy: PolicyReference,
    /// Exact rule whose exception is being considered.
    pub target_rule: RuleId,
    /// Exact intended use, including tenant and key.
    pub scope: ExceptionScope,
    /// Injected deterministic UTC millisecond timestamp.
    pub evaluation_time: EvaluationTime,
}

/// Distinct verification facts. Any missing flag prevents reference readiness.
///
/// A client MUST implement real source authentication, approval delegation,
/// signed-artifact checking and current revocation lookup externally.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExceptionVerification {
    /// Original source/reference binding was externally authenticated.
    pub source_authenticated: bool,
    /// Approver was independently authorized for exact deviation/scope.
    pub approver_authorized: bool,
    /// Original approval artifact was cryptographically verified externally.
    pub approval_verified: bool,
    /// Current status/revocation was independently checked at evaluation time.
    pub revocation_checked: bool,
}

/// A caller-owned trust check; no implementation is automatically trusted.
///
/// Its boolean claims are meaningful only if the caller has independently
/// reviewed and authenticated the verifier itself.
pub trait ExceptionSourceVerifier {
    /// Inspect the exact reference and bound context without granting a waiver.
    fn verify(
        &self,
        reference: &ExceptionReference,
        context: &ExceptionBoundContext,
    ) -> Result<ExceptionVerification, ContractError>;
}

impl<F> ExceptionSourceVerifier for F
where
    F: Fn(
        &ExceptionReference,
        &ExceptionBoundContext,
    ) -> Result<ExceptionVerification, ContractError>,
{
    fn verify(
        &self,
        reference: &ExceptionReference,
        context: &ExceptionBoundContext,
    ) -> Result<ExceptionVerification, ContractError> {
        self(reference, context)
    }
}

/// Default verifier: untrusted metadata never authenticates itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnverifiedExceptionReferences;

impl ExceptionSourceVerifier for UnverifiedExceptionReferences {
    fn verify(
        &self,
        _reference: &ExceptionReference,
        _context: &ExceptionBoundContext,
    ) -> Result<ExceptionVerification, ContractError> {
        Ok(ExceptionVerification::default())
    }
}

/// Conservative result classifications. NONE grants a waiver or Permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionReferenceFinding {
    /// Record is explicitly revoked.
    Revoked,
    /// Record is suspended.
    Suspended,
    /// A pinned policy or targeted rule differs.
    WrongTarget,
    /// Tenant/environment/algorithm/operation/key scope differs.
    OutOfScope,
    /// Before inclusive activation boundary.
    NotEffective,
    /// At or after exclusive expiration boundary.
    Expired,
    /// External source/approval/revocation verification is incomplete.
    Unverified,
    /// The supplied external verifier claims every check succeeded.
    ///
    /// Even this is NOT approval to waive policy or an authorization token.
    ReferenceReadyForPolicyAdmission,
}

/// Stable, safe projection for audit linkage; no raw source or signature bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExceptionReferenceReport {
    /// Immutable exception reference ID.
    pub exception_id: EvidenceId,
    /// Domain-separated correlation digest, not an attestation.
    pub exception_digest: PolicyDigest,
    /// Exact supplied evaluation time.
    pub evaluated_at: EvaluationTime,
    /// The non-authorizing classification.
    pub finding: ExceptionReferenceFinding,
    /// Externally asserted verification flags; not independently attested here.
    pub verification: ExceptionVerification,
}

/// Bounded, deterministic metadata preflight, NOT policy waiver admission.
///
/// Invalid shape -> typed error; wrong scope/status/time -> nonauthorizing
/// finding; all claims externally verified -> reference readiness *only*.
/// The PolicyDocument and policy evaluator are NEVER modified by this call.
pub fn assess_exception_reference<V: ExceptionSourceVerifier>(
    reference: &ExceptionReference,
    context: &ExceptionBoundContext,
    verifier: &V,
) -> Result<ExceptionReferenceReport, ContractError> {
    reference.validate(&Limits::default())?;
    context.scope.validate()?;
    let finding = if reference.status == ExceptionStatus::Revoked {
        ExceptionReferenceFinding::Revoked
    } else if reference.status == ExceptionStatus::Suspended {
        ExceptionReferenceFinding::Suspended
    } else if reference.policy != context.policy || reference.target_rule != context.target_rule {
        ExceptionReferenceFinding::WrongTarget
    } else if reference.scope != context.scope {
        ExceptionReferenceFinding::OutOfScope
    } else if context.evaluation_time < reference.effective_at {
        ExceptionReferenceFinding::NotEffective
    } else if context.evaluation_time >= reference.expires_at {
        ExceptionReferenceFinding::Expired
    } else {
        ExceptionReferenceFinding::Unverified
    };

    // Rejecting a reference never calls a potentially unsafe verifier.
    let mut verification = ExceptionVerification::default();
    let finding = if finding == ExceptionReferenceFinding::Unverified {
        verification = verifier.verify(reference, context)?;
        if verification.source_authenticated
            && verification.approver_authorized
            && verification.approval_verified
            && verification.revocation_checked
        {
            ExceptionReferenceFinding::ReferenceReadyForPolicyAdmission
        } else {
            ExceptionReferenceFinding::Unverified
        }
    } else {
        finding
    };
    Ok(ExceptionReferenceReport {
        exception_id: reference.exception_id.clone(),
        exception_digest: reference.correlation_digest()?,
        evaluated_at: context.evaluation_time,
        finding,
        verification,
    })
}
