//! FOSS-507: guarded, offline, source-attested named-profile policy evaluation.
//!
//! The original evaluate_with_limits() remains unchanged for unverified facts.
//! This module independently invokes actual FOSS-505 qualification on EVERY
//! request before enabling a crate-private profile-aware evaluator path.
//! No signature, policy issuer authorization, waiver or PEP is created.

use crate::{
    ContractError, KeyProfileBindingVerifier, PolicyDecision, PolicyDocument,
    ProfileEvidenceVerifier, ProfileQualificationFinding, ProfileQualificationReport,
    ProfileQualificationRequest, evaluate_with_limits, qualify_embedded_profile,
};

/// An inspectable *policy-data* decision, NOT an enforcement capability.
///
/// Both fields are untrusted when deserialized or constructed externally:
/// the only supported fresh evaluation is through the API below. The caller
/// must separately authenticate policy issuer and implement trusted PEP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualifiedProfilePolicyDecision {
    /// Pinned catalog identity and independently supplied verification status.
    pub qualification: ProfileQualificationReport,
    /// Exact original policy digest, stable reasons and normal rule semantics.
    pub decision: PolicyDecision,
}

/// Re-evaluate policy with a profile only after exact source/key attestation.
///
/// A positive ProfileQualificationReport is NOT accepted as an input.
/// Instead, on EVERY call this function re-runs bounded canonical embedded
/// catalog validation and BOTH independent external verifier callbacks.
/// Failed qualification falls back to the original strictly conservative
/// evaluator, ensuring unrelated Deny/Require/expiry constraints still run.
/// Named hybrid requirements stay unsupported even with source proof.
///
/// A returned DecisionOutcome::Permit is only policy-evaluation data. It is
/// never a signed authorization token and cannot directly execute crypto.
/// Policy issuer authentication remains an explicit consuming-app boundary.
pub fn evaluate_qualified_profile_with_limits<
    E: ProfileEvidenceVerifier,
    K: KeyProfileBindingVerifier,
>(
    policy: &PolicyDocument,
    request: ProfileQualificationRequest<'_>,
    source_verifier: &E,
    key_verifier: &K,
) -> Result<QualifiedProfilePolicyDecision, ContractError> {
    let qualification = qualify_embedded_profile(request, source_verifier, key_verifier)?;
    let decision =
        if qualification.finding == ProfileQualificationFinding::ReadyForVerifiedEvaluator {
            crate::evaluator::evaluate_with_attested_profile(
                policy,
                request.context,
                request.time,
                request.limits,
            )?
        } else {
            evaluate_with_limits(policy, request.context, request.time, request.limits)?
        };
    Ok(QualifiedProfilePolicyDecision {
        qualification,
        decision,
    })
}
