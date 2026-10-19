//! FOSS-505: pinned, externally source-attested named-profile qualification.
//!
//! **No Permit, authorization, waiver or cryptographic operation is created.**
//! Embedded catalog membership is not a provider/KMS attestation. Four
//! independent external provenance facts and the separately authenticated
//! actual-key binding are mandatory before indicating metadata readiness.

use crate::{
    AlgorithmId, ContractError, CryptoContext, CryptoOperation, EvaluationTime, EvidenceQuality,
    ExceptionScope, FactOrigin, KeyProfileBinding, KeyProfileBindingVerifier, Limits, PolicyDigest,
    ProfileId,
};
use pqc_kit::{Catalog, CatalogError, EMBEDDED_CATALOG_SHA256_V1, OperationClass, UsageParameter};
use serde::{Deserialize, Serialize};

/// Exactly attested public parameters, not guessed from an algorithm string.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProfileParameterWitness {
    /// Exact classical key length proven for this key generation.
    KeyBits(u32),
    /// Exact canonical named PQ parameter set; no alias, draft or family.
    NamedSet(ProfileId),
}

/// Four distinct verifier-controlled provenance facts. JSON claims alone
/// NEVER set these fields; a security-reviewed caller supplies the verifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProfileEvidenceVerification {
    /// The observed/negotiated source was independently authenticated.
    pub source_authenticated: bool,
    /// The exact provider for this real operation was authenticated.
    pub provider_attested: bool,
    /// The key-generation parameter witness was independently verified.
    pub parameters_attested: bool,
    /// External observation and signer/key revocation were checked for time.
    pub revocation_fresh: bool,
}

/// Caller-owned, independent profile/source attestation trust boundary.
pub trait ProfileEvidenceVerifier {
    /// Verify evidence and immutable profile witness against actual source.
    fn verify(
        &self,
        request: &ProfileQualificationRequest<'_>,
    ) -> Result<ProfileEvidenceVerification, ContractError>;
}
impl<F> ProfileEvidenceVerifier for F
where
    F: for<'a> Fn(
        &ProfileQualificationRequest<'a>,
    ) -> Result<ProfileEvidenceVerification, ContractError>,
{
    fn verify(
        &self,
        request: &ProfileQualificationRequest<'_>,
    ) -> Result<ProfileEvidenceVerification, ContractError> {
        self(request)
    }
}

/// Explicit deny-by-default provenance verifier.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnverifiedProfileEvidence;

impl ProfileEvidenceVerifier for UnverifiedProfileEvidence {
    fn verify(
        &self,
        _request: &ProfileQualificationRequest<'_>,
    ) -> Result<ProfileEvidenceVerification, ContractError> {
        Ok(ProfileEvidenceVerification::default())
    }
}

/// Exactly one authenticatable target fact and source-pinned key identity.
///
/// This API never trusts the caller's scope/binding or fact verification flag:
/// separate key and source verifiers must authenticate all relevant claims.
#[derive(Clone, Copy)]
pub struct ProfileQualificationRequest<'a> {
    /// Caller-supplied structured operation evidence.
    pub context: &'a CryptoContext,
    /// Independently bound real tenant/environment/operation/algorithm/key.
    pub actual_scope: &'a ExceptionScope,
    /// Exact key generation, named profile and source evidence reference.
    pub binding: &'a KeyProfileBinding,
    /// Original typed and externally attested parameter witness.
    pub parameter: &'a ProfileParameterWitness,
    /// Explicit UTC milliseconds; never access the host clock.
    pub time: EvaluationTime,
    /// Caller-configured bounds within hard ceilings.
    pub limits: &'a Limits,
}

/// Conservative profile qualification statuses with no Permitted variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileQualificationFinding {
    /// Operation/time/tenant/key/profile did not exactly match bound sources.
    ScopeMismatch,
    /// The evidence is not an actual observed/negotiated source.
    EvidenceIncomplete,
    /// Independent source/provider/parameter/revocation proof is absent.
    SourceNotAuthenticated,
    /// Independent actual-key-generation ownership proof is absent.
    KeyNotAuthenticated,
    /// Canonical profile does not exist in reviewed embedded catalog.
    UnknownOrAliasProfile,
    /// Profile exists but is not standardized for authorization-adjacent use.
    NonStandardProfile,
    /// Profile exists but cannot perform the exact requested operation.
    OperationUnsupported,
    /// Named set / key size is incomplete or does not match the pinned profile.
    ParameterMismatch,
    /// External proof and exact standardized catalog identity are ready to
    /// be evaluated by a separately reviewed policy engine.
    ///
    /// This is **not** a policy decision, cryptographic authorization, or
    /// trusted statement about FIPS module/provider certification.
    ReadyForVerifiedEvaluator,
}

/// Stable metadata-only projection; never contains key bytes or private facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileQualificationReport {
    /// SHA-256 of reviewed embedded catalog bytes, not signer authentication.
    pub catalog_digest: PolicyDigest,
    /// Canonical profile identity, not a free-form alias.
    pub profile_id: ProfileId,
    /// Exact algorithm identity, separated from policy admission.
    pub algorithm_id: AlgorithmId,
    /// Explicit cryptographic operation.
    pub operation: CryptoOperation,
    /// Injected time, used consistently for all verifier checks.
    pub evaluated_at: EvaluationTime,
    /// Strict, non-authorizing metadata qualification result.
    pub finding: ProfileQualificationFinding,
}

/// Perform deterministic, *non-authorizing* exact profile qualification.
///
/// Even a positive metadata finding does NOT relax the conservative
/// evaluate_with_limits() named-profile restriction. FOSS-503/B owns safe
/// integration into the real policy evaluator and waiver composition.
pub fn qualify_embedded_profile<E: ProfileEvidenceVerifier, K: KeyProfileBindingVerifier>(
    request: ProfileQualificationRequest<'_>,
    source_verifier: &E,
    key_verifier: &K,
) -> Result<ProfileQualificationReport, ContractError> {
    let ProfileQualificationRequest {
        context,
        actual_scope,
        binding,
        parameter,
        time,
        limits,
    } = request;
    limits.validate()?;
    actual_scope.validate()?;
    binding.scope.validate()?;
    let encoded = serde_json::to_vec(context)
        .map_err(|_| ContractError::InvalidDocument("profile_context_encoding"))?;
    limits.check_json(&encoded)?;
    if CryptoContext::parse_json_with_limits(&encoded, limits)? != *context {
        return Err(ContractError::InvalidDocument("profile_context_roundtrip"));
    }
    // Only checked-in immutable snapshot is eligible. Never accept a network
    // catalog, runtime aliases, silently updated fingerprint or raw strings.
    let catalog = Catalog::embedded_v1()
        .map_err(|_| ContractError::InvalidDocument("embedded_catalog_invalid"))?;
    if catalog.fingerprint() != EMBEDDED_CATALOG_SHA256_V1 {
        return Err(ContractError::InvalidDocument("catalog_digest_mismatch"));
    }
    let digest = PolicyDigest::try_from(catalog.fingerprint().to_owned())?;
    let report = |finding| ProfileQualificationReport {
        catalog_digest: digest.clone(),
        profile_id: binding.profile_id.clone(),
        algorithm_id: actual_scope.algorithm_id.clone(),
        operation: actual_scope.operation,
        evaluated_at: time,
        finding,
    };
    if context.facts.len() != 1
        || context.evaluation_time != time
        || context.operation != actual_scope.operation
        || context.environment.as_deref() != Some(actual_scope.environment.as_str())
        || binding.scope != *actual_scope
    {
        return Ok(report(ProfileQualificationFinding::ScopeMismatch));
    }
    let fact = &context.facts[0];
    // v1 qualified canonical profile ID is identical to its canonical
    // algorithm ID. Composite/hybrid multiple-ID profiles are deferred.
    if fact.algorithm_id.as_ref() != Some(&actual_scope.algorithm_id)
        || fact.profile_id.as_ref() != Some(&binding.profile_id)
        || binding.profile_id.as_str() != actual_scope.algorithm_id.as_str()
    {
        return Ok(report(ProfileQualificationFinding::ScopeMismatch));
    }
    let props = fact.properties.as_ref();
    if !matches!(fact.origin, FactOrigin::Observed | FactOrigin::Negotiated)
        || !fact.verified
        || fact.evidence_ref.as_ref() != Some(&binding.evidence_ref)
        || props.and_then(|p| p.provider_id.as_ref()).is_none()
        || props.and_then(|p| p.source_quality) != Some(EvidenceQuality::ExternallyVerified)
    {
        return Ok(report(ProfileQualificationFinding::EvidenceIncomplete));
    }

    let parameter = match parameter {
        ProfileParameterWitness::KeyBits(bits) => {
            if props.and_then(|p| p.key_size_bits) != Some(*bits) {
                return Ok(report(ProfileQualificationFinding::ParameterMismatch));
            }
            UsageParameter::KeyBits(*bits)
        }
        ProfileParameterWitness::NamedSet(name) => {
            if name != &binding.profile_id || props.and_then(|p| p.key_size_bits).is_some() {
                return Ok(report(ProfileQualificationFinding::ParameterMismatch));
            }
            UsageParameter::NamedSet(name.as_str())
        }
    };
    let operation = match context.operation {
        CryptoOperation::Encrypt => OperationClass::Encrypt,
        CryptoOperation::Decrypt => OperationClass::Decrypt,
        CryptoOperation::Sign => OperationClass::Sign,
        CryptoOperation::Verify => OperationClass::Verify,
        CryptoOperation::Hash => OperationClass::Hash,
        CryptoOperation::Encapsulate => OperationClass::Encapsulate,
        CryptoOperation::Decapsulate => OperationClass::Decapsulate,
    };
    match catalog.validate_usage(binding.profile_id.as_str(), operation, parameter) {
        Ok(_) => {}
        Err(CatalogError::UnknownProfile | CatalogError::AliasNotCanonical) => {
            return Ok(report(ProfileQualificationFinding::UnknownOrAliasProfile));
        }
        Err(CatalogError::NonStandard(_)) => {
            return Ok(report(ProfileQualificationFinding::NonStandardProfile));
        }
        Err(CatalogError::OperationMismatch) => {
            return Ok(report(ProfileQualificationFinding::OperationUnsupported));
        }
        Err(CatalogError::ParameterMismatch) => {
            return Ok(report(ProfileQualificationFinding::ParameterMismatch));
        }
        Err(_) => {
            return Err(ContractError::InvalidDocument("catalog_unexpected_error"));
        }
    }
    // Identity comparisons and catalog membership do not attest anything.
    // Both trust gates are caller-owned; the safe defaults reject all.
    if !key_verifier.verify(binding, context)? {
        return Ok(report(ProfileQualificationFinding::KeyNotAuthenticated));
    }
    let checked = source_verifier.verify(&request)?;
    if !(checked.source_authenticated
        && checked.provider_attested
        && checked.parameters_attested
        && checked.revocation_fresh)
    {
        return Ok(report(ProfileQualificationFinding::SourceNotAuthenticated));
    }
    Ok(report(
        ProfileQualificationFinding::ReadyForVerifiedEvaluator,
    ))
}
