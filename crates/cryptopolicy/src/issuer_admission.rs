//! FOSS-515: policy-issuer provenance admission for the CASE-031 trust boundary.
//!
//! The ordinary parser/evaluator treats Issuer as untrusted data. This separate,
//! opt-in gate validates exact claimed bindings and REQUIRES a caller-owned,
//! independently authenticating verifier on every call. It never grants a
//! cryptographic operation, waives a policy or issues an enforcement token.

use crate::{
    CryptoOperation, EvaluationTime, EvidenceId, Limits, PolicyAdmissionError, PolicyDocument,
    PolicyId, PolicyReference, SchemaVersion, parse_policy_for_admission_with_limits,
};
use serde::{Deserialize, Serialize};

/// Caller-requested identity, operation and one-use freshness challenge.
///
/// These values must come from the trusted consuming boundary, independently
/// of the untrusted issuer proof. The verifier owns replay state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerAdmissionScope {
    /// Tenant in whose context issuer provenance is being checked.
    pub tenant_id: PolicyId,
    /// Operation the caller wants to evaluate later (not authorized here).
    pub operation: CryptoOperation,
    /// Fresh challenge independently supplied by the consuming caller.
    pub challenge: EvidenceId,
}

/// Untrusted reference to a source-authenticated policy issuer assertion.
///
/// Every field is a claim until checked by a caller-owned source verifier.
/// No signatures, source trust, revocation status, delegation or replay state
/// can be inferred from this DTO or from Issuer.assurance_ref.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerProvenanceClaim {
    /// Closed wire-contract version.
    pub schema_version: SchemaVersion,
    /// Exact document identity, version and canonical SHA-256 content digest.
    pub policy: PolicyReference,
    /// Claimed issuer identity; must exactly match the policy.
    pub issuer_subject: String,
    /// Exact source assurance reference; must match the policy assertion.
    pub assurance_ref: EvidenceId,
    /// Untrusted reference identifying the alleged policy owner.
    pub owner_ref: EvidenceId,
    /// Untrusted reference identifying the signing key/certificate.
    pub signer_key_ref: EvidenceId,
    /// Optional, explicitly named ownership delegation for external checking.
    pub delegation_ref: Option<EvidenceId>,
    /// Identifier of the original grant to authenticate and check for replay.
    pub grant_ref: EvidenceId,
    /// Exact tenant, operation and caller freshness challenge.
    pub scope: IssuerAdmissionScope,
    /// Creation time of the alleged attestation, not independently verified.
    pub issued_at: EvaluationTime,
    /// Inclusive validity start.
    pub valid_from: EvaluationTime,
    /// Exclusive validity end.
    pub expires_at: EvaluationTime,
}

/// Complete, immutable per-call context supplied to an external verifier.
///
/// A real verifier MUST authenticate the issuer-source signature, the signer
/// key/certificate, issuer-to-owner authority or delegation, revocation at the
/// explicit time, and exact digest/scope. It MUST reject replayed grant and
/// challenge identifiers through caller-owned durable replay state.
pub struct IssuerVerificationContext<'a> {
    /// Untrusted attestation and exact source identity.
    pub claim: &'a IssuerProvenanceClaim,
    /// Validated policy whose canonical identity was recomputed.
    pub document: &'a PolicyDocument,
    /// Recomputed canonical identity (equal to the caller-pinned reference).
    pub reference: &'a PolicyReference,
    /// Independently supplied desired scope.
    pub scope: &'a IssuerAdmissionScope,
    /// Explicit trusted UTC millisecond evaluation instant.
    pub time: EvaluationTime,
}

/// External source authentication, delegation, revocation and replay boundary.
///
/// A true result is meaningful ONLY to a caller that securely implements and
/// protects this verifier. Returning true for unverified claims is insecure.
/// The library deliberately provides no always-allow verifier.
pub trait PolicyIssuerSourceVerifier {
    /// Recheck the complete binding on EACH invocation; false must fail closed.
    fn verify(&self, context: &IssuerVerificationContext<'_>) -> bool;
}

/// Default verifier: no untrusted issuer data can establish authenticity.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnverifiedPolicyIssuerSource;

impl PolicyIssuerSourceVerifier for UnverifiedPolicyIssuerSource {
    fn verify(&self, _context: &IssuerVerificationContext<'_>) -> bool {
        false
    }
}

/// Exact admission request. Its policy, reference and scope are separately
/// provided; the claim itself is never an authority for these values.
pub struct IssuerAdmissionRequest<'a> {
    /// A syntactically validated policy (revalidated at this boundary).
    pub document: &'a PolicyDocument,
    /// Caller-trusted, pinned canonical policy identity.
    pub pinned_policy: &'a PolicyReference,
    /// Untrusted asserted issuer proof.
    pub claim: &'a IssuerProvenanceClaim,
    /// Caller-owned tenant, operation and freshness challenge.
    pub scope: &'a IssuerAdmissionScope,
    /// Caller-supplied UTC time; no system clock is read.
    pub time: EvaluationTime,
    /// Maximum resource budget, including canonical serialization.
    pub limits: &'a Limits,
}

/// Non-serializable result of a completed caller-owned issuer-source check.
///
/// This is a provenance assessment, NOT an authorization/Permit, signature,
/// bearer capability or cacheable approval. It must not bypass future checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerProvenanceAssessment {
    reference: PolicyReference,
    checked_at: EvaluationTime,
}

impl IssuerProvenanceAssessment {
    /// Validated reference at the time of this assessment.
    pub fn reference(&self) -> &PolicyReference {
        &self.reference
    }

    /// Supplied time at which the independent verifier ran.
    pub fn checked_at(&self) -> EvaluationTime {
        self.checked_at
    }
}

/// Validate a policy and independently recheck its issuer binding.
///
/// All malformed, unverified, expired, revoked, delegated-to-the-wrong-owner,
/// mismatched or replayed claims must return InvalidPolicy. This gate performs
/// deterministic structural checks and calls the external verifier once, on
/// each invocation, for all authority and replay questions it cannot prove.
/// Resource failures are typed separately without exposing raw attacker input.
pub fn admit_policy_issuer<V: PolicyIssuerSourceVerifier + ?Sized>(
    request: &IssuerAdmissionRequest<'_>,
    verifier: &V,
) -> Result<IssuerProvenanceAssessment, PolicyAdmissionError> {
    let limits = request.limits;
    limits
        .validate()
        .map_err(|_| PolicyAdmissionError::ResourceLimit)?;
    request
        .document
        .validate_with_limits(limits)
        .map_err(|_| PolicyAdmissionError::InvalidPolicy)?;
    let reference = PolicyReference::from_document(request.document)
        .map_err(|_| PolicyAdmissionError::InvalidPolicy)?;
    let proof = request.claim;
    let policy = request.document;
    let now = request.time;

    if reference != *request.pinned_policy
        || proof.policy != reference
        || proof.issuer_subject != policy.issuer.subject
        || policy.issuer.assurance_ref.as_ref() != Some(&proof.assurance_ref)
        || proof.scope != *request.scope
        || proof.issued_at > proof.valid_from
        || proof.valid_from >= proof.expires_at
        || now < proof.valid_from
        || now >= proof.expires_at
        || now < policy.created_at
        || policy.effective_at.is_some_and(|at| now < at)
        || policy.expires_at.is_some_and(|at| now >= at)
    {
        return Err(PolicyAdmissionError::InvalidPolicy);
    }

    // Source claims cannot increase effective budgets or leak in errors.
    // Both policy and claimed proof remain bounded before external I/O.
    let bytes = serde_json::to_vec(proof).map_err(|_| PolicyAdmissionError::InvalidPolicy)?;
    limits
        .check_json(&bytes)
        .map_err(|_| PolicyAdmissionError::ResourceLimit)?;

    let context = IssuerVerificationContext {
        claim: proof,
        document: policy,
        reference: &reference,
        scope: request.scope,
        time: now,
    };
    if !verifier.verify(&context) {
        return Err(PolicyAdmissionError::InvalidPolicy);
    }

    Ok(IssuerProvenanceAssessment {
        reference,
        checked_at: now,
    })
}

/// Parse strict untrusted policy JSON BEFORE invoking issuer provenance checks.
///
/// This wrapper cannot turn rejected JSON into an authenticated policy. The
/// existing FOSS-514 fail-closed UnsupportedSchema/InvalidPolicy/ResourceLimit
/// classification is preserved, and no verifier is called on parser failure.
pub fn admit_policy_issuer_json<V: PolicyIssuerSourceVerifier + ?Sized>(
    json: &[u8],
    pinned_policy: &PolicyReference,
    claim: &IssuerProvenanceClaim,
    scope: &IssuerAdmissionScope,
    time: EvaluationTime,
    limits: &Limits,
    verifier: &V,
) -> Result<IssuerProvenanceAssessment, PolicyAdmissionError> {
    let document = parse_policy_for_admission_with_limits(json, limits)?;
    admit_policy_issuer(
        &IssuerAdmissionRequest {
            document: &document,
            pinned_policy,
            claim,
            scope,
            time,
            limits,
        },
        verifier,
    )
}
