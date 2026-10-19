//! FOSS-504 / FOSS-501/A: deterministic blocked-exception audit receipts.
//!
//! These receipts are non-authorizing, redact free-form source data, and
//! record only actual block decisions. Content digests are NOT signatures,
//! external trust attestations, replay protection or cryptographic approval.

use crate::{
    DecisionOutcome, EvaluationTime, EvidenceId, ExceptionBoundContext, ExceptionReference,
    ExceptionReferenceFinding, ExceptionSourceVerifier, Limits, PolicyDigest, PolicyReference,
    ReasonCode, RuleId, SchemaVersion, UnverifiedExceptionReferences, WaiverAdmissionDisposition,
    WaiverAdmissionReport, assess_exception_reference,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};

/// Domain-separated, correlation-only receipt digest prefix.
pub const EXCEPTION_BLOCK_RECEIPT_DOMAIN_V1: &[u8] = b"cryptopolicy-exception-block-audit-v1\0";

/// Closed public audit error family; no free-form policy/source secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExceptionAuditError {
    /// Exception has missing/untrusted approval or invalid exact-scope input.
    InvalidException,
    /// An attempted positive/authorizing output cannot be audited as blocked.
    PositiveDecisionUnsupported,
    /// Pinned policy, time, rule or decision linkage was inconsistent.
    ReceiptInconsistent,
    /// Output exceeded bounds.
    ResourceLimit,
}
impl fmt::Display for ExceptionAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ExceptionAuditError {}

/// Source-specific reason references only; no raw evidence or subject data.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedExceptionAuditReason {
    /// Exact pinned policy node, never a claim of signer authenticity.
    pub policy: PolicyReference,
    /// Optional source rule, preserving reason identity.
    pub rule_id: Option<RuleId>,
    /// Exact actual policy-evaluator reason.
    pub code: ReasonCode,
}

/// A no-authorization result. There is deliberately no Allow variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedExceptionEnforcement {
    /// Downstream callers must not execute the proposed crypto operation.
    Block,
}

/// Strictly non-authorizing E0 finding stored in a bounded audit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedReferenceFinding {
    /// Original reference was revoked.
    Revoked,
    /// Original reference was suspended.
    Suspended,
    /// Target policy/rule did not match.
    WrongTarget,
    /// Claimed tenant or cryptographic scope did not match actual request.
    OutOfScope,
    /// Inclusive activation time had not been reached.
    NotEffective,
    /// Exclusive expiry cutoff was reached.
    Expired,
    /// Source/approval cannot be authenticated by the safe default verifier.
    Unverified,
}

/// Immutable-by-construction, bounded, structured denied-waiver receipt.
///
/// It cannot contain a signature, justification text, key bytes, raw source
/// credentials, unredacted fact properties or a permissive disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedExceptionAuditReceipt {
    /// Closed v1 security audit schema.
    pub schema_version: SchemaVersion,
    /// Effective immutable graph content digest.
    pub effective_policy_digest: PolicyDigest,
    /// Exact source policy reference.
    pub target_policy: PolicyReference,
    /// Exact target RuleId in the source policy.
    pub target_rule: RuleId,
    /// Opaque reference ID, not evidence authentication.
    pub exception_id: EvidenceId,
    /// Correlation-only exact E0 exception content digest.
    pub exception_digest: PolicyDigest,
    /// Caller-injected deterministic UTC time.
    pub evaluated_at: EvaluationTime,
    /// Original aggregate outcome, never Permit.
    pub original_outcome: DecisionOutcome,
    /// Hypothetical result, never Permit for this negative-only contract.
    pub candidate_outcome: DecisionOutcome,
    /// Actual typed E1 candidate rejection, not a waiver grant.
    pub disposition: WaiverAdmissionDisposition,
    /// Structural E0 reference state, with safe no-proof default.
    pub reference_finding: BlockedReferenceFinding,
    /// Names of required compensating rules, not evidence of satisfaction.
    pub compensating_rules: Vec<RuleId>,
    /// Controlling reasons collected from ACTUAL original policy decisions.
    pub blocking_reasons: Vec<BlockedExceptionAuditReason>,
    /// Exact unambiguous operation enforcement action.
    pub enforcement: BlockedExceptionEnforcement,
}

impl BlockedExceptionAuditReceipt {
    /// Validate the blocked-only contract even when a caller constructs or
    /// deserializes a receipt without using the safe builder.
    ///
    /// Validation is structural; it cannot authenticate the supplied source,
    /// caller or policy computation. A digest is only a correlation handle.
    pub fn validate_blocked_invariants(&self) -> Result<(), ExceptionAuditError> {
        if self.schema_version != SchemaVersion::V1
            || self.original_outcome != DecisionOutcome::Deny
            || self.candidate_outcome != DecisionOutcome::Deny
            || self.disposition == WaiverAdmissionDisposition::CandidateEvaluated
        {
            return Err(ExceptionAuditError::ReceiptInconsistent);
        }
        if self.compensating_rules.is_empty()
            || self.compensating_rules.len() > crate::MAX_EXCEPTION_COMPENSATING_CONTROLS
            || self
                .compensating_rules
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.compensating_rules.contains(&self.target_rule)
        {
            return Err(ExceptionAuditError::ReceiptInconsistent);
        }
        if self.blocking_reasons.is_empty()
            || self.blocking_reasons.len() > Limits::default().max_decision_reasons
            || self
                .blocking_reasons
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !self.blocking_reasons.iter().any(|reason| {
                reason.policy == self.target_policy
                    && reason.rule_id.as_ref() == Some(&self.target_rule)
                    && reason.code == ReasonCode::ExplicitDeny
            })
        {
            return Err(ExceptionAuditError::ReceiptInconsistent);
        }
        Ok(())
    }

    /// Stable, domain-separated fingerprint for correlation only.
    ///
    /// The digest is NOT an HMAC, signature, source proof or Permit.
    pub fn correlation_digest(&self) -> Result<PolicyDigest, ExceptionAuditError> {
        self.validate_blocked_invariants()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| ExceptionAuditError::ReceiptInconsistent)?;
        if bytes.len() > crate::MAX_EXCEPTION_REFERENCE_JSON_BYTES {
            return Err(ExceptionAuditError::ResourceLimit);
        }
        let len = u32::try_from(bytes.len()).map_err(|_| ExceptionAuditError::ResourceLimit)?;
        let mut hash = Sha256::new();
        hash.update(EXCEPTION_BLOCK_RECEIPT_DOMAIN_V1);
        hash.update(len.to_be_bytes());
        hash.update(bytes);
        PolicyDigest::try_from(format!("{:x}", hash.finalize()))
            .map_err(|_| ExceptionAuditError::ReceiptInconsistent)
    }
}

/// Validate the original closed reference plus caller-owned external proof.
///
/// An approver string and missing approval evidence fail with a *typed*
/// InvalidException; source claims and well-formed JSON never self-authenticate.
pub fn validate_verified_exception_reference<V: ExceptionSourceVerifier>(
    bytes: &[u8],
    bound: &ExceptionBoundContext,
    verifier: &V,
    limits: &Limits,
) -> Result<ExceptionReference, ExceptionAuditError> {
    let parsed = ExceptionReference::parse_json_with_limits(bytes, limits)
        .map_err(|_| ExceptionAuditError::InvalidException)?;
    let state = assess_exception_reference(&parsed, bound, verifier)
        .map_err(|_| ExceptionAuditError::InvalidException)?;
    if state.finding != ExceptionReferenceFinding::ReferenceReadyForPolicyAdmission {
        return Err(ExceptionAuditError::InvalidException);
    }
    Ok(parsed)
}

/// Generate a blocked-only audit receipt from REAL E1 and E0 runtime results.
///
/// E0 structural scope/expiry is checked using the safe default verifier
/// specifically to prevent a second untrusted/side-effectful proof call.
/// The actual E1 rejection and all blocking reasons originate from the
/// supplied already evaluated immutable policy graph, never a fixture echo.
/// No external source-authentication assertion is added by this function.
pub fn build_blocked_exception_audit_receipt(
    report: &WaiverAdmissionReport,
    reference: &ExceptionReference,
    bound: &ExceptionBoundContext,
    limits: &Limits,
) -> Result<BlockedExceptionAuditReceipt, ExceptionAuditError> {
    limits
        .validate()
        .map_err(|_| ExceptionAuditError::ResourceLimit)?;
    reference
        .validate(limits)
        .map_err(|_| ExceptionAuditError::InvalidException)?;
    if report.original.outcome != DecisionOutcome::Deny
        || report.candidate_outcome == DecisionOutcome::Permit
        || report.candidate_target_layer.is_some()
    {
        return Err(ExceptionAuditError::PositiveDecisionUnsupported);
    }
    // A rejection may not rewrite the original outcome or invent a candidate
    // without its independently derived target-layer decision. Fail rather
    // than fingerprint an internally contradictory, user-deserialized report.
    if report.disposition == WaiverAdmissionDisposition::CandidateEvaluated
        || report.candidate_outcome != report.original.outcome
    {
        return Err(ExceptionAuditError::ReceiptInconsistent);
    }
    if report.original_effective_digest != report.original.effective_policy_digest
        || report.original.evaluated_at != report.evaluated_at
        || report.evaluated_at != bound.evaluation_time
        || report.exception_id != reference.exception_id
        || reference.policy != bound.policy
        || reference.target_rule != bound.target_rule
    {
        return Err(ExceptionAuditError::ReceiptInconsistent);
    }

    let reference_state =
        assess_exception_reference(reference, bound, &UnverifiedExceptionReferences)
            .map_err(|_| ExceptionAuditError::InvalidException)?;
    let target = report
        .original
        .components
        .iter()
        .find(|layer| {
            layer.reference == reference.policy
                && layer.decision.policy_digest == reference.policy.digest
                && layer.decision.evaluated_at == bound.evaluation_time
        })
        .ok_or(ExceptionAuditError::ReceiptInconsistent)?;
    // Independently validate each target's actual outcome. An untrusted
    // serialized report cannot claim Permit on the target while smuggling an
    // ExplicitDeny reason into an aggregate Deny receipt.
    if target.decision.outcome != DecisionOutcome::Deny {
        return Err(ExceptionAuditError::ReceiptInconsistent);
    }
    // This negative-only receipt must really be based on a matching Deny,
    // not invented "block" metadata or a no-rule/default policy.
    if !target.decision.reasons.iter().any(|reason| {
        reason.rule_id.as_ref() == Some(&reference.target_rule)
            && reason.code == ReasonCode::ExplicitDeny
    }) {
        return Err(ExceptionAuditError::ReceiptInconsistent);
    }
    // Recompute aggregate precedence from every real serialized layer.
    // A forged aggregate Deny cannot be justified by all-Permit components.
    // This is consistency validation, not cryptographic source proof.
    let recomputed = if report
        .original
        .components
        .iter()
        .any(|layer| layer.decision.outcome == DecisionOutcome::Deny)
    {
        DecisionOutcome::Deny
    } else if report
        .original
        .components
        .iter()
        .any(|layer| layer.decision.outcome == DecisionOutcome::Indeterminate)
    {
        DecisionOutcome::Indeterminate
    } else {
        DecisionOutcome::Permit
    };
    if recomputed != report.original.outcome {
        return Err(ExceptionAuditError::ReceiptInconsistent);
    }
    let mut actual_reasons = BTreeSet::new();
    for layer in &report.original.components {
        if layer.decision.policy_digest != layer.reference.digest
            || layer.decision.evaluated_at != bound.evaluation_time
        {
            return Err(ExceptionAuditError::ReceiptInconsistent);
        }
        for reason in &layer.decision.reasons {
            actual_reasons.insert(BlockedExceptionAuditReason {
                policy: layer.reference.clone(),
                rule_id: reason.rule_id.clone(),
                code: reason.code,
            });
        }
    }
    if actual_reasons.is_empty() || actual_reasons.len() > limits.max_decision_reasons {
        return Err(ExceptionAuditError::ResourceLimit);
    }
    let receipt = BlockedExceptionAuditReceipt {
        schema_version: SchemaVersion::V1,
        effective_policy_digest: report.original_effective_digest.clone(),
        target_policy: reference.policy.clone(),
        target_rule: reference.target_rule.clone(),
        exception_id: reference.exception_id.clone(),
        exception_digest: reference
            .correlation_digest()
            .map_err(|_| ExceptionAuditError::InvalidException)?,
        evaluated_at: bound.evaluation_time,
        original_outcome: report.original.outcome,
        candidate_outcome: report.candidate_outcome,
        disposition: report.disposition,
        reference_finding: match reference_state.finding {
            ExceptionReferenceFinding::Revoked => BlockedReferenceFinding::Revoked,
            ExceptionReferenceFinding::Suspended => BlockedReferenceFinding::Suspended,
            ExceptionReferenceFinding::WrongTarget => BlockedReferenceFinding::WrongTarget,
            ExceptionReferenceFinding::OutOfScope => BlockedReferenceFinding::OutOfScope,
            ExceptionReferenceFinding::NotEffective => BlockedReferenceFinding::NotEffective,
            ExceptionReferenceFinding::Expired => BlockedReferenceFinding::Expired,
            ExceptionReferenceFinding::Unverified => BlockedReferenceFinding::Unverified,
            ExceptionReferenceFinding::ReferenceReadyForPolicyAdmission => {
                return Err(ExceptionAuditError::PositiveDecisionUnsupported);
            }
        },
        compensating_rules: reference.compensating_controls.clone(),
        blocking_reasons: actual_reasons.into_iter().collect(),
        enforcement: BlockedExceptionEnforcement::Block,
    };
    receipt.validate_blocked_invariants()?;
    let bytes =
        serde_json::to_vec(&receipt).map_err(|_| ExceptionAuditError::ReceiptInconsistent)?;
    if bytes.len() > crate::MAX_EXCEPTION_REFERENCE_JSON_BYTES {
        return Err(ExceptionAuditError::ResourceLimit);
    }
    limits
        .check_json(&bytes)
        .map_err(|_| ExceptionAuditError::ResourceLimit)?;
    Ok(receipt)
}
