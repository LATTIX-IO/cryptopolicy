//! FOSS-449: bounded, offline Keymesh-style provider capability preflight.
//!
//! This module checks independently authenticated provider capability *claims*
//! against a key-operation request and a pinned FOSS-445 algorithm catalog.
//! A CapabilityReport Permit means only compatible *advertised capability*.
//! It is NEVER a PolicyDecision, an observed key use, a CMVP validation,
//! an authorization to create/use a key, or an enforcement token.

use crate::{
    AlgorithmId, ContractError, CryptoOperation, DecisionOutcome, EvaluationTime, EvidenceId,
    KeyProtection, Limits, PolicyDigest, PolicyVersion, ProviderId, RequestId, SchemaVersion,
};
use pqc_kit::{AlgorithmProfile, Catalog, OperationClass, UsageParameter};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum capability claims processed within a single pinned snapshot.
pub const MAX_PROVIDER_CAPABILITY_CLAIMS: usize = 128;
/// Absolute maximum allowable age of asserted capabilities: 30 days.
pub const MAX_CAPABILITY_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Exact key-related algorithm parameter, never a post-quantum category.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum KeyParameter {
    /// Exact numeric key length.
    KeyBits(u32),
    /// Fully qualified FIPS parameter-set identity, never a guessed bit size.
    NamedSet(AlgorithmId),
}

impl KeyParameter {
    fn usage(&self) -> UsageParameter<'_> {
        match self {
            Self::KeyBits(bits) => UsageParameter::KeyBits(*bits),
            Self::NamedSet(name) => UsageParameter::NamedSet(name.as_str()),
        }
    }
}

/// Key generation/custody origin claimed by a provider, not authenticated here.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrigin {
    /// Material was generated inside the named provider.
    ProviderGenerated,
    /// Material was imported from an external boundary.
    Imported,
    /// Material was derived from an existing key or secret.
    Derived,
    /// The provider did not establish a known origin.
    Unknown,
}

/// Assurance maturity claimed in a source record; NOT proof of validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceClaim {
    /// Provider self-assertion without external assurance evidence.
    ProviderAsserted,
    /// A named independent review/attestation is claimed, not verified.
    IndependentAssessment,
}

/// Provider claim's explicit availability; absence is not Unsupported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAvailability {
    /// Provider advertises this capability at the cited point in time.
    Supported,
    /// Provider explicitly reports this capability unsupported.
    Unsupported,
    /// Provider cannot establish this capability.
    Unknown,
}

/// One mandatory request constraint; all required capabilities are conjunctive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum RequiredCapability {
    /// Require an exact and known origin.
    KeyOrigin(KeyOrigin),
    /// Require provider assurance that key material is not exportable.
    NonExportable,
    /// Require a minimum key protection class (independently checked for hardware).
    ProtectionAtLeast(KeyProtection),
    /// Require an independently verified assurance claim and evidence reference.
    IndependentAssurance,
}

/// One forbidden property; missing data cannot prove its absence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ForbiddenCapability {
    /// Forbid exportable key material.
    Exportable,
    /// Forbid a specified key origin such as imported material.
    KeyOrigin(KeyOrigin),
    /// Forbid exactly this protection class, e.g. software.
    Protection(KeyProtection),
}

/// A strict, versioned key-operation compatibility request.
///
/// It intentionally carries no key bytes, provider credential, signed policy
/// decision, or implicit authorization to execute a cryptographic operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRequest {
    /// Explicit v1 wire contract.
    pub schema_version: SchemaVersion,
    /// Correlation for the requested key operation.
    pub request_id: RequestId,
    /// Exact intended provider identity.
    pub provider_id: ProviderId,
    /// Optional opaque existing key handle; no key material.
    pub key_ref: Option<EvidenceId>,
    /// Exact canonical algorithm/profile ID from the reviewed catalog.
    pub algorithm_id: AlgorithmId,
    /// Requested key-related operation.
    pub operation: CryptoOperation,
    /// Exact mandatory parameter. PQ set suffixes are not key bits.
    pub parameter: KeyParameter,
    /// Explicit evaluation time, independent of local wall clock.
    pub evaluation_time: EvaluationTime,
    /// Largest acceptable age of an evidence assertion in milliseconds.
    pub max_evidence_age_ms: u64,
    /// Independently pinned catalog release version.
    pub catalog_version: PolicyVersion,
    /// Exact SHA-256 checksum of the pinned catalog JSON.
    pub catalog_digest: PolicyDigest,
    /// Requirements that all must be known and true.
    pub required: Vec<RequiredCapability>,
    /// Properties that must be known and absent.
    pub forbidden: Vec<ForbiddenCapability>,
}

/// One original capability assertion. A signed statement of support is not
/// proof the named operation was ever executed by the provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilityClaim {
    /// Stable source-side capability claim identity.
    pub claim_id: EvidenceId,
    /// Original source identity; not independently authenticated.
    pub source_id: EvidenceId,
    /// Reference to independently verifiable original evidence.
    pub evidence_ref: Option<EvidenceId>,
    /// Exact algorithm claimed supported/unsupported/unknown.
    pub algorithm_id: AlgorithmId,
    /// Which key operation the provider claims to support.
    pub operation: CryptoOperation,
    /// Exact typed algorithm parameters.
    pub parameter: KeyParameter,
    /// Explicit support status.
    pub availability: CapabilityAvailability,
    /// Key material origin, when declared.
    pub key_origin: Option<KeyOrigin>,
    /// Whether the resulting key is exportable, when declared.
    pub key_exportable: Option<bool>,
    /// Actual claimed custody/protection class, when declared.
    pub protection: Option<KeyProtection>,
    /// Claimed assurance status, NOT cryptographic attestation.
    pub assurance: Option<AssuranceClaim>,
    /// Reference to an independently verifiable assessment/attestation.
    pub assurance_ref: Option<EvidenceId>,
    /// Provider claim issuance timestamp.
    pub asserted_at: EvaluationTime,
    /// Exclusive validity boundary. May be shorter than maximum evidence age.
    pub expires_at: EvaluationTime,
}

/// Strict versioned provider snapshot with a pinned catalog interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilitySnapshot {
    /// Required v1 schema.
    pub schema_version: SchemaVersion,
    /// Exact provider whose evidence is being considered.
    pub provider_id: ProviderId,
    /// Original snapshot identity, bound into each verification callback.
    pub snapshot_id: EvidenceId,
    /// Exact FOSS-445 catalog semantic version.
    pub catalog_version: PolicyVersion,
    /// Exact reviewed FOSS-445 JSON checksum.
    pub catalog_digest: PolicyDigest,
    /// Individual original claims. Unrelated operations may be retained.
    pub claims: Vec<ProviderCapabilityClaim>,
}

/// A verifier result separates provider source authentication from proof
/// of hardware/assurance claims. Neither boolean is trusted without a
/// security-reviewed caller implementation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderVerification {
    /// The source, snapshot, request and claim/evidence binding was authenticated.
    pub source_authenticated: bool,
    /// The referenced independent assessment was actually verified.
    pub assurance_authenticated: bool,
}

/// Caller-supplied trust boundary for exact snapshot/source/evidence binding.
///
/// A production implementation MUST authenticate provider identity, issuer,
/// snapshot, claim ID, original evidence, request/key scope, expiry/revocation
/// and independent hardware attestation if claimed. The library does no I/O,
/// signature validation, network lookup or secret handling by itself.
pub trait ProviderClaimVerifier {
    /// Verify exactly one claim against the original request and snapshot.
    fn verify(
        &self,
        request: &KeyRequest,
        snapshot: &ProviderCapabilitySnapshot,
        claim: &ProviderCapabilityClaim,
    ) -> Result<ProviderVerification, ContractError>;
}

impl<F> ProviderClaimVerifier for F
where
    F: Fn(&KeyRequest, &ProviderCapabilitySnapshot, &ProviderCapabilityClaim)
        -> Result<ProviderVerification, ContractError>,
{
    fn verify(
        &self,
        request: &KeyRequest,
        snapshot: &ProviderCapabilitySnapshot,
        claim: &ProviderCapabilityClaim,
    ) -> Result<ProviderVerification, ContractError> {
        self(request, snapshot, claim)
    }
}

/// Safe default: an imported capability claim never authenticates itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnverifiedProviderClaims;

impl ProviderClaimVerifier for UnverifiedProviderClaims {
    fn verify(
        &self,
        _request: &KeyRequest,
        _snapshot: &ProviderCapabilitySnapshot,
        _claim: &ProviderCapabilityClaim,
    ) -> Result<ProviderVerification, ContractError> {
        Ok(ProviderVerification::default())
    }
}

/// Stable, orderable compatibility reason codes; no secret attributes leaked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityReason {
    /// Requested algorithm was not a supported standardized canonical profile.
    UnsupportedRequestedAlgorithm,
    /// The algorithm does not implement the requested key-related operation.
    UnsupportedRequestedOperation,
    /// Mandatory requested parameters violate the versioned catalog.
    InvalidRequestedParameter,
    /// No matching authenticated capability was available.
    MissingCapability,
    /// Explicit provider availability is unknown.
    CapabilityUnknown,
    /// An independently authenticated claim explicitly denies availability.
    ProviderUnsupported,
    /// A supported weaker same-family profile would downgrade the request.
    DowngradeDetected,
    /// Provider's exact-profile parameter is inconsistent with the request.
    ParameterMismatch,
    /// Original evidence reference missing from the claimed source.
    MissingEvidence,
    /// Independent source and claim verification was not established.
    UnauthenticatedSource,
    /// Claim was issued after evaluation time or has exceeded its validity.
    StaleOrFutureEvidence,
    /// Required capability metadata was not supplied by an authenticated claim.
    MissingRequiredCapability,
    /// Authenticated capability definitely violates a required property.
    RequiredCapabilityFailed,
    /// Authenticated capability definitely has a forbidden property.
    ForbiddenCapabilityPresent,
    /// Independent assurance evidence is missing or not authenticated.
    AssuranceNotVerified,
    /// Different applicable provider claims contradict one another.
    ConflictingClaims,
    /// Exact supported capability passed all explicit compatibility preconditions.
    CompatibleCapability,
}

/// Whether and how a single provider claim was examined.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDisposition {
    /// Different profile/operation and no documented downgrade relationship.
    Unrelated,
    /// Missing independent evidence or verifier rejected provenance.
    Unauthenticated,
    /// Evidence was expired, stale, or from the future.
    Stale,
    /// Provider does not know whether this operation is supported.
    Unknown,
    /// Provider explicitly reports no support for requested capability.
    Unsupported,
    /// Provider only advertised a weaker parameter set.
    Downgrade,
    /// Claim was checked against explicit requirements/forbidden properties.
    Evaluated,
}

/// Per-claim original evidence retained with stable, redaction-safe findings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityFinding {
    /// Original claim reference.
    pub claim_id: EvidenceId,
    /// Original source identity.
    pub source_id: EvidenceId,
    /// Original evidence reference.
    pub evidence_ref: Option<EvidenceId>,
    /// Claimed exact profile, not proof of a validated implementation.
    pub algorithm_id: AlgorithmId,
    /// Exact claimed algorithm parameter.
    pub parameter: KeyParameter,
    /// Claimed status.
    pub availability: CapabilityAvailability,
    /// Verified source and separately verified attestation flags.
    pub source_authenticated: bool,
    /// The assurance reference was independently verified.
    pub assurance_authenticated: bool,
    /// How the source claim was used.
    pub disposition: CapabilityDisposition,
    /// Deterministically ordered reason codes for this claim.
    pub reasons: Vec<CapabilityReason>,
}

/// A compatibility preflight result, NOT a cryptopolicy PolicyDecision.
///
/// Permit here means "declared capability appears compatible under these
/// verified snapshot facts" and cannot authorize key creation or actual use.
/// Consumers still require separate authenticated policy Permit and PEP checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    /// Explicit wire contract version.
    pub schema_version: SchemaVersion,
    /// Original key-request correlation.
    pub request_id: RequestId,
    /// Exact provider identity.
    pub provider_id: ProviderId,
    /// Original snapshot identity.
    pub snapshot_id: EvidenceId,
    /// Exact catalog version and content SHA-256.
    pub catalog_version: PolicyVersion,
    /// Exact catalog content fingerprint.
    pub catalog_digest: PolicyDigest,
    /// The request's exact intended key operation and profile.
    pub operation: CryptoOperation,
    /// The request's exact algorithm/profile identity.
    pub algorithm_id: AlgorithmId,
    /// Only a compatibility preflight verdict; not a policy authorization.
    pub outcome: DecisionOutcome,
    /// Stable redaction-safe aggregate reasons.
    pub reasons: Vec<CapabilityReason>,
    /// Stable original-claim ordered per-source findings.
    pub findings: Vec<CapabilityFinding>,
}

fn codec_json<T: for<'de> Deserialize<'de>>(
    input: &[u8],
    limits: &Limits,
) -> Result<T, ContractError> {
    limits.check_json(input)?;
    if input.len() > limits.max_adapter_bytes {
        return Err(ContractError::PayloadTooLarge);
    }
    serde_json::from_slice(input).map_err(|e| ContractError::InvalidJson(e.to_string()))
}

fn checked_wire_bytes<T: Serialize>(
    value: &T,
    limits: &Limits,
) -> Result<Vec<u8>, ContractError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ContractError::InvalidDocument("provider_serialization"))?;
    limits.check_json(&bytes)?;
    if bytes.len() > limits.max_adapter_bytes {
        return Err(ContractError::PayloadTooLarge);
    }
    Ok(bytes)
}

fn validate_parameter(parameter: &KeyParameter) -> Result<(), ContractError> {
    match parameter {
        KeyParameter::KeyBits(bits) if (1..=crate::MAX_DECLARED_KEY_BITS).contains(bits) => Ok(()),
        KeyParameter::NamedSet(id) if !id.as_str().is_empty() => Ok(()),
        _ => Err(ContractError::InvalidDocument("invalid_key_parameter")),
    }
}

fn constraints_unique<T: Serialize>(values: &[T]) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        let bytes = serde_json::to_vec(value)
            .map_err(|_| ContractError::InvalidDocument("constraint_serialization"))?;
        if !seen.insert(bytes) {
            return Err(ContractError::DuplicateIdentifier);
        }
    }
    Ok(())
}

impl KeyRequest {
    /// Deserialize a bounded, strict v1 request.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        Self::parse_json_with_limits(input, &Limits::default())
    }

    /// Deserialize using caller limits that cannot exceed FOSS-433 hard ceilings.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        let value: Self = codec_json(input, limits)?;
        value.validate(limits)?;
        Ok(value)
    }

    /// Check all structural v1 invariants without authorizing anything.
    pub fn validate(&self, limits: &Limits) -> Result<(), ContractError> {
        limits.validate()?;
        validate_parameter(&self.parameter)?;
        if self.max_evidence_age_ms == 0 || self.max_evidence_age_ms > MAX_CAPABILITY_AGE_MS {
            return Err(ContractError::InvalidDocument("invalid_evidence_age_budget"));
        }
        if self.required.is_empty() && self.forbidden.is_empty() {
            return Err(ContractError::InvalidDocument("unconstrained_key_request"));
        }
        let count = self.required.len().checked_add(self.forbidden.len())
            .ok_or(ContractError::ResourceLimitExceeded("key requirements"))?;
        limits.check_count(count, limits.max_requirements_per_rule, "key requirements")?;
        constraints_unique(&self.required)?;
        constraints_unique(&self.forbidden)?;
        for required in &self.required {
            if matches!(required, RequiredCapability::KeyOrigin(KeyOrigin::Unknown)) {
                return Err(ContractError::InvalidDocument("requirement_unknown_origin"));
            }
        }
        for forbidden in &self.forbidden {
            if matches!(forbidden, ForbiddenCapability::KeyOrigin(KeyOrigin::Unknown)) {
                return Err(ContractError::InvalidDocument("forbid_unknown_origin"));
            }
        }
        checked_wire_bytes(self, limits)?;
        Ok(())
    }
}

impl ProviderCapabilitySnapshot {
    /// Parse a strict versioned provider capability snapshot.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        Self::parse_json_with_limits(input, &Limits::default())
    }

    /// Parse with resource-limited, explicit input semantics.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        let value: Self = codec_json(input, limits)?;
        value.validate(limits)?;
        Ok(value)
    }

    /// Reject duplicate IDs, implausible claim intervals and large payloads.
    pub fn validate(&self, limits: &Limits) -> Result<(), ContractError> {
        limits.validate()?;
        limits.check_count(
            self.claims.len(),
            limits.max_facts.min(MAX_PROVIDER_CAPABILITY_CLAIMS),
            "provider claims",
        )?;
        let mut unique = BTreeSet::new();
        for claim in &self.claims {
            if !unique.insert(&claim.claim_id) {
                return Err(ContractError::DuplicateIdentifier);
            }
            validate_parameter(&claim.parameter)?;
            if claim.expires_at <= claim.asserted_at {
                return Err(ContractError::InvalidDocument("invalid_claim_validity"));
            }
            if claim.availability != CapabilityAvailability::Supported
                && (claim.key_origin.is_some()
                    || claim.key_exportable.is_some()
                    || claim.protection.is_some()
                    || claim.assurance.is_some()
                    || claim.assurance_ref.is_some())
            {
                return Err(ContractError::InvalidDocument("nonsupport_with_key_attributes"));
            }
        }
        checked_wire_bytes(self, limits)?;
        Ok(())
    }
}

impl CapabilityReport {
    /// Strict, bounded round-trip parser for compatibility reports.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        let value: Self = codec_json(input, limits)?;
        limits.check_count(
            value.findings.len(),
            limits.max_facts.min(MAX_PROVIDER_CAPABILITY_CLAIMS),
            "capability findings",
        )?;
        limits.check_count(value.reasons.len(), limits.max_decision_reasons, "capability reasons")?;
        for finding in &value.findings {
            limits.check_count(finding.reasons.len(), limits.max_decision_reasons, "claim reasons")?;
        }
        Ok(value)
    }
}

fn catalog_operation(operation: CryptoOperation) -> Option<OperationClass> {
    match operation {
        CryptoOperation::Encrypt => Some(OperationClass::Encrypt),
        CryptoOperation::Decrypt => Some(OperationClass::Decrypt),
        CryptoOperation::Sign => Some(OperationClass::Sign),
        CryptoOperation::Verify => Some(OperationClass::Verify),
        CryptoOperation::Encapsulate => Some(OperationClass::Encapsulate),
        CryptoOperation::Decapsulate => Some(OperationClass::Decapsulate),
        // Hashing is not a key capability. Key agreement / derivation are not
        // covered by the versioned FOSS-445 algorithm profiles yet.
        CryptoOperation::Hash | CryptoOperation::KeyAgreement | CryptoOperation::DeriveKey => None,
    }
}

fn rank(protection: KeyProtection) -> u8 {
    match protection {
        KeyProtection::Software => 0,
        KeyProtection::HardwareBacked => 1,
        KeyProtection::HardwareSecurityModule => 2,
    }
}

fn weaker_same_family(requested: &AlgorithmProfile, candidate: &AlgorithmProfile) -> bool {
    if requested.family != candidate.family {
        return false;
    }
    if let Some((expected, actual)) = requested.security.pqc_category.zip(candidate.security.pqc_category) {
        return actual < expected;
    }
    if let Some((expected, actual)) = requested.security.classical_bits.zip(candidate.security.classical_bits) {
        return actual < expected;
    }
    false
}

fn check_constraints(
    request: &KeyRequest,
    claim: &ProviderCapabilityClaim,
    assurance_verified: bool,
) -> (bool, bool, BTreeSet<CapabilityReason>) {
    let mut denied = false;
    let mut unknown = false;
    let mut reasons = BTreeSet::new();
    for requirement in &request.required {
        match requirement {
            RequiredCapability::KeyOrigin(expected) => match claim.key_origin {
                None | Some(KeyOrigin::Unknown) => unknown = true,
                Some(origin) if origin != *expected => denied = true,
                _ => {}
            },
            RequiredCapability::NonExportable => match claim.key_exportable {
                None => unknown = true,
                Some(true) => denied = true,
                Some(false) => {}
            },
            RequiredCapability::ProtectionAtLeast(minimum) => match claim.protection {
                None => unknown = true,
                Some(observed) if rank(observed) < rank(*minimum) => denied = true,
                Some(observed) if rank(observed) >= rank(KeyProtection::HardwareBacked) && !assurance_verified => {
                    reasons.insert(CapabilityReason::AssuranceNotVerified);
                    unknown = true;
                }
                Some(_) => {}
            },
            RequiredCapability::IndependentAssurance => {
                if claim.assurance != Some(AssuranceClaim::IndependentAssessment)
                    || claim.assurance_ref.is_none()
                    || !assurance_verified
                {
                    reasons.insert(CapabilityReason::AssuranceNotVerified);
                    unknown = true;
                }
            }
        }
    }
    for forbidden in &request.forbidden {
        match forbidden {
            ForbiddenCapability::Exportable => match claim.key_exportable {
                None => unknown = true,
                Some(true) => denied = true,
                Some(false) => {}
            },
            ForbiddenCapability::KeyOrigin(forbidden) => match claim.key_origin {
                None | Some(KeyOrigin::Unknown) => unknown = true,
                Some(origin) if origin == *forbidden => denied = true,
                _ => {}
            },
            ForbiddenCapability::Protection(forbidden) => match claim.protection {
                None => unknown = true,
                Some(observed) if observed == *forbidden => denied = true,
                Some(observed) if rank(observed) >= rank(KeyProtection::HardwareBacked)
                    && !assurance_verified => {
                        reasons.insert(CapabilityReason::AssuranceNotVerified);
                        unknown = true;
                    }
                Some(_) => {}
            },
        }
    }
    if denied {
        reasons.insert(CapabilityReason::RequiredCapabilityFailed);
        if request.forbidden.iter().any(|forbidden| match forbidden {
            ForbiddenCapability::Exportable => claim.key_exportable == Some(true),
            ForbiddenCapability::KeyOrigin(origin) => claim.key_origin == Some(*origin),
            ForbiddenCapability::Protection(protection) => claim.protection == Some(*protection),
        }) {
            reasons.insert(CapabilityReason::ForbiddenCapabilityPresent);
        }
    }
    if unknown {
        reasons.insert(CapabilityReason::MissingRequiredCapability);
    }
    (denied, unknown, reasons)
}

fn claim_facts_equal(a: &ProviderCapabilityClaim, b: &ProviderCapabilityClaim) -> bool {
    a.algorithm_id == b.algorithm_id
        && a.operation == b.operation
        && a.parameter == b.parameter
        && a.availability == b.availability
        && a.key_origin == b.key_origin
        && a.key_exportable == b.key_exportable
        && a.protection == b.protection
        && a.assurance == b.assurance
        && a.assurance_ref == b.assurance_ref
}

/// Evaluate a key-operation request against an immutable, authenticated
/// provider capability snapshot. This is **not** policy enforcement.
///
/// - A failed catalog check or confirmed unsupported/downgrade/forbidden
///   capability returns Deny.
/// - Unknown, missing, expired, unverified or conflicting claims return
///   Indeterminate, unless another independently established Deny exists.
/// - A Permit requires exact standardized profile/operation/parameters,
///   all constraints and all relevant sources independently verified.
///
/// The caller still must authenticate policy, provider evidence and any
/// hardware attestation, and separately acquire/enforce a policy Permit.
pub fn assess_key_capabilities<V: ProviderClaimVerifier>(
    request: &KeyRequest,
    snapshot: &ProviderCapabilitySnapshot,
    verifier: &V,
) -> Result<CapabilityReport, ContractError> {
    assess_key_capabilities_with_limits(request, snapshot, verifier, &Limits::default())
}

/// Bounded, offline compatibility preflight. It invokes no provider or key.
pub fn assess_key_capabilities_with_limits<V: ProviderClaimVerifier>(
    request: &KeyRequest,
    snapshot: &ProviderCapabilitySnapshot,
    verifier: &V,
    limits: &Limits,
) -> Result<CapabilityReport, ContractError> {
    request.validate(limits)?;
    snapshot.validate(limits)?;
    if request.provider_id != snapshot.provider_id {
        return Err(ContractError::InvalidDocument("provider_identity_mismatch"));
    }
    if request.catalog_version != snapshot.catalog_version
        || request.catalog_digest != snapshot.catalog_digest
    {
        return Err(ContractError::InvalidDocument("catalog_binding_mismatch"));
    }
    let catalog = Catalog::embedded_v1()
        .map_err(|_| ContractError::InvalidDocument("embedded_catalog_unavailable"))?;
    if request.catalog_version.as_str() != catalog.snapshot().catalog_version
        || request.catalog_digest.as_str() != catalog.fingerprint()
    {
        return Err(ContractError::InvalidDocument("unreviewed_catalog_binding"));
    }

    let mut findings = Vec::with_capacity(snapshot.claims.len());
    let mut reasons = BTreeSet::new();
    let mut denied = false;
    let mut uncertain = false;
    let mut compatible = false;

    let catalog_operation = catalog_operation(request.operation);
    let requested_profile = catalog.get(request.algorithm_id.as_str());
    if requested_profile.is_none() {
        denied = true;
        reasons.insert(CapabilityReason::UnsupportedRequestedAlgorithm);
    } else if let (Some(op), Some(profile)) = (catalog_operation, requested_profile) {
        if !profile.operations.contains(&op) {
            denied = true;
            reasons.insert(CapabilityReason::UnsupportedRequestedOperation);
        } else if catalog.validate_usage(request.algorithm_id.as_str(), op, request.parameter.usage()).is_err() {
            denied = true;
            reasons.insert(CapabilityReason::InvalidRequestedParameter);
        }
    } else {
        denied = true;
        reasons.insert(CapabilityReason::UnsupportedRequestedOperation);
    }

    let mut sorted: Vec<_> = snapshot.claims.iter().collect();
    sorted.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
    let mut previous: Option<&ProviderCapabilityClaim> = None;

    for claim in sorted {
        let mut claim_reasons = BTreeSet::new();
        let mut source_authenticated = false;
        let mut assurance_authenticated = false;
        let mut disposition = CapabilityDisposition::Unrelated;
        let exact = claim.algorithm_id == request.algorithm_id && claim.operation == request.operation;
        let downgrade = !exact
            && claim.operation == request.operation
            && requested_profile.zip(catalog.get(claim.algorithm_id.as_str()))
                .is_some_and(|(expected, observed)| weaker_same_family(expected, observed));
        if exact || downgrade {
            // A strict request cannot cherry-pick one of several contradictory
            // claims for the same provider, operation and intended profile.
            if let Some(prior) = previous {
                if !claim_facts_equal(prior, claim) {
                    uncertain = true;
                    reasons.insert(CapabilityReason::ConflictingClaims);
                    claim_reasons.insert(CapabilityReason::ConflictingClaims);
                }
            }
            previous = Some(claim);
            if claim.evidence_ref.is_none() {
                uncertain = true;
                disposition = CapabilityDisposition::Unauthenticated;
                claim_reasons.insert(CapabilityReason::MissingEvidence);
            } else {
                let proof = verifier.verify(request, snapshot, claim)?;
                source_authenticated = proof.source_authenticated;
                assurance_authenticated = proof.source_authenticated && proof.assurance_authenticated
                    && claim.assurance_ref.is_some();
                if !source_authenticated {
                    uncertain = true;
                    disposition = CapabilityDisposition::Unauthenticated;
                    claim_reasons.insert(CapabilityReason::UnauthenticatedSource);
                } else {
                    let age = request.evaluation_time.unix_millis
                        .checked_sub(claim.asserted_at.unix_millis);
                    let stale = age.is_none_or(|delta| delta < 0
                        || u64::try_from(delta).is_err_or(|elapsed| elapsed > request.max_evidence_age_ms))
                        || request.evaluation_time >= claim.expires_at;
                    if stale {
                        uncertain = true;
                        disposition = CapabilityDisposition::Stale;
                        claim_reasons.insert(CapabilityReason::StaleOrFutureEvidence);
                    } else if downgrade {
                        denied = true;
                        disposition = CapabilityDisposition::Downgrade;
                        claim_reasons.insert(CapabilityReason::DowngradeDetected);
                    } else {
                        match claim.availability {
                            CapabilityAvailability::Unknown => {
                                uncertain = true;
                                disposition = CapabilityDisposition::Unknown;
                                claim_reasons.insert(CapabilityReason::CapabilityUnknown);
                            }
                            CapabilityAvailability::Unsupported => {
                                denied = true;
                                disposition = CapabilityDisposition::Unsupported;
                                claim_reasons.insert(CapabilityReason::ProviderUnsupported);
                            }
                            CapabilityAvailability::Supported => {
                                disposition = CapabilityDisposition::Evaluated;
                                if claim.parameter != request.parameter {
                                    denied = true;
                                    claim_reasons.insert(CapabilityReason::ParameterMismatch);
                                } else {
                                    let (bad, missing, findings) =
                                        check_constraints(request, claim, assurance_authenticated);
                                    denied |= bad;
                                    uncertain |= missing;
                                    claim_reasons.extend(findings);
                                    if !bad && !missing {
                                        compatible = true;
                                        claim_reasons.insert(CapabilityReason::CompatibleCapability);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        reasons.extend(claim_reasons.iter().copied());
        findings.push(CapabilityFinding {
            claim_id: claim.claim_id.clone(),
            source_id: claim.source_id.clone(),
            evidence_ref: claim.evidence_ref.clone(),
            algorithm_id: claim.algorithm_id.clone(),
            parameter: claim.parameter.clone(),
            availability: claim.availability,
            source_authenticated,
            assurance_authenticated,
            disposition,
            reasons: claim_reasons.into_iter().collect(),
        });
    }

    if !compatible && !denied {
        uncertain = true;
        reasons.insert(CapabilityReason::MissingCapability);
    }
    let outcome = if denied {
        DecisionOutcome::Deny
    } else if uncertain || !compatible {
        DecisionOutcome::Indeterminate
    } else {
        DecisionOutcome::Permit
    };
    let report = CapabilityReport {
        schema_version: SchemaVersion::V1,
        request_id: request.request_id.clone(),
        provider_id: request.provider_id.clone(),
        snapshot_id: snapshot.snapshot_id.clone(),
        catalog_version: request.catalog_version.clone(),
        catalog_digest: request.catalog_digest.clone(),
        operation: request.operation,
        algorithm_id: request.algorithm_id.clone(),
        outcome,
        reasons: reasons.into_iter().collect(),
        findings,
    };
    limits.check_count(report.reasons.len(), limits.max_decision_reasons, "capability reasons")?;
    for finding in &report.findings {
        limits.check_count(finding.reasons.len(), limits.max_decision_reasons, "claim reasons")?;
    }
    checked_wire_bytes(&report, limits)?;
    Ok(report)
}
