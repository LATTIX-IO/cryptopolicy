//! FOSS-447: versioned, provenance-preserving third-party assessments.
//!
//! A third-party inventory is not an authorization source. Facts remain
//! separate by observation, source and use-site, with explicit coverage.
//! An independently supplied verifier must authenticate source/evidence
//! bindings before this adapter may project a verified fact to FOSS-435.
//! The verifier and policy issuer are NOT authenticated by this crate.

use crate::{
    AlgorithmId, ContractError, CryptoContext, CryptoFact, CryptoOperation, CryptoProperties,
    DecisionOutcome, EvaluationTime, EvidenceId, EvidenceQuality, FactOrigin, Limits,
    PolicyDecision, PolicyDigest, PolicyDocument, PolicyId, PolicyVersion, ProfileId, ReasonCode,
    RequestId, SchemaVersion, evaluate_with_limits,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeSet;

/// Absolute additional cap to prevent quadratic conflict analysis.
pub const MAX_ASSESSMENT_OBSERVATIONS: usize = 128;

/// Whether a scoped target/use-site has actually been inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentCoverage {
    /// No operation-level inspection has been performed.
    Uninspected,
    /// Some relevant uses/sources may not have been inspected.
    Partial,
    /// Caller asserts all relevant uses were inspected; not an attestation.
    Complete,
}

/// Confidence is a caller assertion, kept distinct from authentication and policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentConfidence {
    /// Weak or speculative observation.
    Low,
    /// Intermediate or incomplete observation.
    Medium,
    /// High-quality observation claim; **not** proof of authenticity.
    High,
}

/// Classification of original evidence, never inferred from algorithm names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// Directly observed cryptographic operation.
    DirectOperation,
    /// A protocol suite actually negotiated on a particular session.
    NegotiatedProtocol,
    /// Configured cipher or crypto usage, not necessarily invoked.
    Configuration,
    /// Installed dependency/available primitive, not observed use.
    InstalledDependency,
    /// Provider advertises support, not evidence of actual use.
    ProviderCapability,
    /// A derived hypothesis, not direct observation.
    Inferred,
}

impl ObservationKind {
    /// Preserve the original source classification in the core model.
    pub const fn origin(self) -> FactOrigin {
        match self {
            Self::DirectOperation => FactOrigin::Observed,
            Self::NegotiatedProtocol => FactOrigin::Negotiated,
            Self::Configuration => FactOrigin::Configured,
            Self::InstalledDependency | Self::Inferred => FactOrigin::Inferred,
            Self::ProviderCapability => FactOrigin::ProviderCapability,
        }
    }

    /// Only directly observed or session-negotiated activity may support Permit.
    pub const fn is_operational(self) -> bool {
        matches!(self, Self::DirectOperation | Self::NegotiatedProtocol)
    }
}

/// Meaning of the exact recorded parameter (never a PQ category).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedParameterKind {
    /// Cryptographic key size in bits.
    KeyBits,
    /// Output length of a fixed-output digest.
    HashOutputBits,
    /// Exact named algorithm parameter set.
    NamedSet,
}

/// Closed parameter representation: numeric lengths and names cannot mix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ObservedParameterValue {
    /// Unsigned length in bits.
    Bits(u32),
    /// Complete exact algorithm parameter-set ID.
    Name(AlgorithmId),
}

/// Typed observed parameter, distinct from security category/assurance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedParameter {
    /// How to interpret the parameter value.
    pub kind: ObservedParameterKind,
    /// Exact numeric value or named parameter set.
    pub value: ObservedParameterValue,
}

/// Bound subject and particular use/operation activity. No cross-site joins.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentScope {
    /// Asset/service being assessed.
    pub asset_id: PolicyId,
    /// Use-site or endpoint within the asset.
    pub use_site_id: PolicyId,
    /// A single session/operation activity; distinct events need distinct assessments.
    pub activity_id: EvidenceId,
}

/// One independently sourced assertion with its original immutable identifiers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentObservation {
    /// Original collector/snapshot observation identity.
    pub observation_id: EvidenceId,
    /// Original source/collector identity, never evidence verification.
    pub source_id: EvidenceId,
    /// Independent source evidence reference, if known.
    pub evidence_ref: Option<EvidenceId>,
    /// Explicit asset/site/session binding; mismatches reject the input.
    pub scope: AssessmentScope,
    /// Actual observation or nonoperational inventory classification.
    pub kind: ObservationKind,
    /// Which operation this record describes, if known.
    pub operation: Option<CryptoOperation>,
    /// Exact algorithm claimed by the collector, with no alias mapping.
    pub algorithm_id: Option<AlgorithmId>,
    /// Exact named profile, not approved by this DTO.
    pub profile_id: Option<ProfileId>,
    /// Precise observed parameter (no guessing from an algorithm suffix).
    pub parameter: Option<ObservedParameter>,
    /// Claims about crypto attributes, NOT verified evidence.
    pub properties: Option<CryptoProperties>,
    /// Origin time from the collector, not a trusted wall-clock source.
    pub observed_at: EvaluationTime,
    /// Caller-supplied confidence; separate from source verification.
    pub confidence: AssessmentConfidence,
}

/// Fully scoped v1 assessment input with explicit coverage gaps.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentContext {
    /// Exact supported wire schema.
    pub schema_version: SchemaVersion,
    /// Opaque request correlation ID, also used for projected core requests.
    pub assessment_id: RequestId,
    /// Source inventory snapshot identifier.
    pub snapshot_id: EvidenceId,
    /// Assessment's single bound target/use-site/activity.
    pub scope: AssessmentScope,
    /// Operation being assessed; no union across operation classes.
    pub operation: CryptoOperation,
    /// Injected UTC Unix millisecond evaluation timestamp.
    pub evaluation_time: EvaluationTime,
    /// Explicit environment, subject to the existing bounded contract.
    pub environment: Option<String>,
    /// Inspection completeness, which is only a caller claim.
    pub coverage: AssessmentCoverage,
    /// Named uninspected sources, if known; incomplete coverage can be wider.
    pub uninspected_sources: Vec<EvidenceId>,
    /// Independent observations; ordering carries no priority.
    pub observations: Vec<AssessmentObservation>,
}

impl AssessmentContext {
    /// Read strict versioned JSON with the same bounded input preflight as v1.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        Self::parse_json_with_limits(input, &Limits::default())
    }

    /// Read and validate input without trusting its provenance claims.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        limits.check_json(input)?;
        let context: Self = serde_json::from_slice(input)
            .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
        context.validate(limits)?;
        Ok(context)
    }

    /// Check all scope, cardinality, time, parameter and correlation invariants.
    pub fn validate(&self, limits: &Limits) -> Result<(), ContractError> {
        limits.validate()?;
        limits.check_count(
            self.observations.len(),
            limits.max_facts.min(MAX_ASSESSMENT_OBSERVATIONS),
            "assessment observations",
        )?;
        limits.check_count(
            self.uninspected_sources.len(),
            limits.max_evidence_refs,
            "uninspected sources",
        )?;
        if self.coverage == AssessmentCoverage::Complete && !self.uninspected_sources.is_empty() {
            return Err(ContractError::InvalidDocument(
                "complete_coverage_with_gaps",
            ));
        }
        // Reuse the trusted core validator for environment values.
        let skeleton = CryptoContext {
            schema_version: SchemaVersion::V1,
            request_id: self.assessment_id.clone(),
            operation: self.operation,
            evaluation_time: self.evaluation_time,
            environment: self.environment.clone(),
            facts: Vec::new(),
        };
        crate::validate_context_properties(&skeleton)?;
        let mut ids = BTreeSet::new();
        let mut gaps = BTreeSet::new();
        for source in &self.uninspected_sources {
            if !gaps.insert(source) {
                return Err(ContractError::DuplicateIdentifier);
            }
        }
        for record in &self.observations {
            if !ids.insert(&record.observation_id) {
                return Err(ContractError::DuplicateIdentifier);
            }
            if record.scope != self.scope {
                return Err(ContractError::InvalidDocument("assessment_scope_mismatch"));
            }
            if record.observed_at > self.evaluation_time {
                return Err(ContractError::InvalidDocument("future_observation"));
            }
            validate_observed_parameter(record)?;
            let fact = project_fact(record, false);
            let one = CryptoContext {
                schema_version: SchemaVersion::V1,
                request_id: self.assessment_id.clone(),
                operation: self.operation,
                evaluation_time: self.evaluation_time,
                environment: self.environment.clone(),
                facts: vec![fact],
            };
            crate::validate_context_properties(&one)?;
        }
        // Validate serialized in-memory inputs as well; cannot skip byte limit
        // or serde's strictness by constructing a struct directly in Rust.
        let encoded = serde_json::to_vec(self)
            .map_err(|_| ContractError::InvalidDocument("assessment_serialization"))?;
        limits.check_json(&encoded)?;
        Ok(())
    }
}

fn validate_observed_parameter(record: &AssessmentObservation) -> Result<(), ContractError> {
    let Some(parameter) = &record.parameter else {
        return Ok(());
    };
    match (&parameter.kind, &parameter.value) {
        (ObservedParameterKind::KeyBits, ObservedParameterValue::Bits(bits)) => {
            if !(1..=crate::MAX_DECLARED_KEY_BITS).contains(bits) {
                return Err(ContractError::InvalidDocument("invalid_observed_key_bits"));
            }
            if record
                .properties
                .as_ref()
                .and_then(|p| p.key_size_bits)
                .is_some_and(|value| value != *bits)
            {
                return Err(ContractError::InvalidDocument("contradictory_key_bits"));
            }
        }
        (ObservedParameterKind::HashOutputBits, ObservedParameterValue::Bits(bits)) => {
            if !(1..=65_536).contains(bits) {
                return Err(ContractError::InvalidDocument("invalid_hash_output_bits"));
            }
            if let Some(id) = &record.algorithm_id {
                let named = id
                    .as_str()
                    .strip_prefix("SHA3-")
                    .or_else(|| id.as_str().strip_prefix("SHA-"));
                if named
                    .and_then(|number| number.parse::<u32>().ok())
                    .is_some_and(|expected| expected != *bits)
                {
                    return Err(ContractError::InvalidDocument(
                        "contradictory_hash_output_bits",
                    ));
                }
            }
        }
        (ObservedParameterKind::NamedSet, ObservedParameterValue::Name(id)) => {
            if record.algorithm_id.as_ref() != Some(id) {
                return Err(ContractError::InvalidDocument(
                    "named_set_identity_mismatch",
                ));
            }
        }
        _ => return Err(ContractError::InvalidDocument("invalid_observed_parameter")),
    }
    Ok(())
}

/// Caller-owned verification policy. A verifier MUST authenticate the exact
/// snapshot, asset/use-site/activity, source, observation and evidence binding.
///
/// This callback is a trust boundary; the library cannot verify signatures
/// or assert that a caller-supplied implementation is secure. Fail closed on
/// failed verification, errors, or missing evidence references.
pub trait EvidenceVerifier {
    /// Return true only when exact scoped provenance was verified externally.
    fn verify(
        &self,
        context: &AssessmentContext,
        observation: &AssessmentObservation,
    ) -> Result<bool, ContractError>;
}

impl<F> EvidenceVerifier for F
where
    F: Fn(&AssessmentContext, &AssessmentObservation) -> Result<bool, ContractError>,
{
    fn verify(
        &self,
        context: &AssessmentContext,
        observation: &AssessmentObservation,
    ) -> Result<bool, ContractError> {
        self(context, observation)
    }
}

/// Default verifier never upgrades imported evidence assertions into trust.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnverifiedEvidence;

impl EvidenceVerifier for UnverifiedEvidence {
    fn verify(
        &self,
        _context: &AssessmentContext,
        _observation: &AssessmentObservation,
    ) -> Result<bool, ContractError> {
        Ok(false)
    }
}

/// What was and was not projected to the one-fact policy evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentDisposition {
    /// Configured, inferred, dependency or provider capability is not use.
    NotOperational,
    /// An observation concerns a different operation than the requested one.
    DifferentOperation,
    /// Missing an exact algorithm ID.
    MissingAlgorithm,
    /// Missing an exact mandatory algorithm parameter.
    MissingParameter,
    /// No attached evidence reference exists to authenticate.
    MissingEvidence,
    /// The independent verifier did not authenticate this observation.
    Unauthenticated,
    /// Direct observation was evaluated, including its explicit limitations.
    Evaluated,
}

/// Stable, bounded assessment-level (not policy-level) reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentReason {
    /// The caller did not assert complete inspection coverage.
    CoverageIncomplete,
    /// Sources were explicitly identified as not inspected.
    UninspectedSources,
    /// No direct/negotiated operational observation was present.
    NoOperationalObservation,
    /// At least two same-activity observations materially disagree.
    ConflictingObservations,
    /// Relevant observation lacked an algorithm ID or mandatory parameter.
    MissingOperationalFields,
    /// The reported original evidence reference is absent.
    MissingEvidenceReference,
    /// External exact-source verification was absent/unsuccessful.
    EvidenceNotAuthenticated,
    /// Caller confidence was below High; confidence never authenticates data.
    InsufficientConfidence,
    /// A per-observation FOSS-435 decision was Deny.
    CoreDenied,
    /// A per-observation FOSS-435 decision was Indeterminate.
    CoreIndeterminate,
    /// A per-observation FOSS-435 decision was Permit.
    CorePermitted,
    /// Definitive global Deny (explicit Deny or inactive/expired policy).
    GlobalPolicyDeny,
}

/// Conflicting observed attributes; no cross-observation reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictField {
    /// Two observed algorithms differ.
    Algorithm,
    /// Named profiles differ.
    Profile,
    /// Cryptographic parameter kind/value differs.
    Parameter,
    /// Claimed security categories differ.
    SecurityCategory,
    /// Key custody classes differ.
    KeyProtection,
    /// Key exportability claims differ.
    KeyExportable,
    /// Claimed provider identity differs.
    Provider,
    /// Claimed key bit lengths differ.
    KeySizeBits,
    /// Claimed data sensitivity differs.
    DataSensitivity,
}

/// Stable comparison of two original observation references.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationConflict {
    /// First (lexically smaller) original observation ID.
    pub first: EvidenceId,
    /// Second original observation ID.
    pub second: EvidenceId,
    /// Exactly which independently reported attribute disagreed.
    pub field: ConflictField,
}

/// An independently traceable finding; policy decision and claimed confidence
/// are distinct. No key bytes or raw certificate material are emitted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentFinding {
    /// Original observation identity.
    pub observation_id: EvidenceId,
    /// Original collector/source identity.
    pub source_id: EvidenceId,
    /// Original source evidence reference, if any.
    pub evidence_ref: Option<EvidenceId>,
    /// Distinguishes direct operation, negotiation and nonoperational claims.
    pub kind: ObservationKind,
    /// Original claimed operation (untrusted source fact).
    pub operation: Option<CryptoOperation>,
    /// Claimed algorithm ID, not automatically catalog-approved.
    pub algorithm_id: Option<AlgorithmId>,
    /// Claimed named profile.
    pub profile_id: Option<ProfileId>,
    /// Exact typed original parameter, not borrowed from another observation.
    pub parameter: Option<ObservedParameter>,
    /// Original observation timestamp supplied by the source.
    pub observed_at: EvaluationTime,
    /// Claimed confidence, not authenticated assurance.
    pub confidence: AssessmentConfidence,
    /// Claimed evidence quality from source metadata; never automatically trusted.
    pub source_quality_claim: Option<EvidenceQuality>,
    /// True only when the external verifier accepted the exact binding.
    pub externally_authenticated: bool,
    /// Mapping status, separate from the decision.
    pub disposition: AssessmentDisposition,
    /// One-fact FOSS-435 result; None means it was not a usable operational fact.
    pub core_decision: Option<PolicyDecision>,
}

/// Stable aggregate of separately evaluated original facts; no invented joined
/// evidence and no credentials/signatures are included in the output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentReport {
    /// v1 assessment output schema.
    pub schema_version: SchemaVersion,
    /// Original request and snapshot correlation.
    pub assessment_id: RequestId,
    /// Original inventory snapshot reference.
    pub snapshot_id: EvidenceId,
    /// Exact assessment target/use-site/session.
    pub scope: AssessmentScope,
    /// Assessed operation; prevents reusing one result for another operation.
    pub operation: CryptoOperation,
    /// Exact evaluated policy ID.
    pub policy_id: PolicyId,
    /// Exact policy version.
    pub policy_version: PolicyVersion,
    /// Canonical policy digest, not a signature.
    pub policy_digest: PolicyDigest,
    /// Explicit input time.
    pub evaluated_at: EvaluationTime,
    /// Fail-closed aggregate; ONLY Permit can eventually authorize.
    pub outcome: DecisionOutcome,
    /// Original completeness claim, not independently attested.
    pub coverage: AssessmentCoverage,
    /// Exact original IDs of any known uninspected sources, sorted.
    pub uninspected_sources: Vec<EvidenceId>,
    /// Minimum claimed confidence among operational observations, if any.
    pub evidence_confidence: Option<AssessmentConfidence>,
    /// Stable, bounded reason codes, distinct from core policy reasons.
    pub reasons: Vec<AssessmentReason>,
    /// Stable original-ID ordered conflicts.
    pub conflicts: Vec<ObservationConflict>,
    /// Stable original-ID ordered per-source findings and core decisions.
    pub findings: Vec<AssessmentFinding>,
}

impl AssessmentReport {
    /// Parse a strict report, preserving independent evidence and decision fields.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        limits.check_json(input)?;
        let report: Self = serde_json::from_slice(input)
            .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
        limits.check_count(
            report.findings.len(),
            limits.max_facts.min(MAX_ASSESSMENT_OBSERVATIONS),
            "assessment findings",
        )?;
        limits.check_count(
            report.uninspected_sources.len(),
            limits.max_evidence_refs,
            "uninspected sources",
        )?;
        limits.check_count(
            report.conflicts.len(),
            limits.max_diagnostics,
            "assessment conflicts",
        )?;
        limits.check_count(
            report.reasons.len(),
            limits.max_decision_reasons,
            "assessment reasons",
        )?;
        Ok(report)
    }
}

fn project_fact(record: &AssessmentObservation, verified: bool) -> CryptoFact {
    let mut properties = record.properties.clone().unwrap_or_default();
    // Never trust imported source_quality. Only this independent verification
    // result may establish ExternallyVerified for the core evaluator.
    properties.source_quality = if verified {
        Some(EvidenceQuality::ExternallyVerified)
    } else {
        None
    };
    if let Some(ObservedParameter {
        kind: ObservedParameterKind::KeyBits,
        value: ObservedParameterValue::Bits(bits),
    }) = &record.parameter
    {
        properties.key_size_bits = Some(*bits);
    }
    CryptoFact {
        fact_id: record.observation_id.clone(),
        origin: record.kind.origin(),
        algorithm_id: record.algorithm_id.clone(),
        profile_id: record.profile_id.clone(),
        evidence_ref: record.evidence_ref.clone(),
        verified,
        properties: Some(properties),
    }
}

fn conflicting<T: Eq>(first: &Option<T>, second: &Option<T>) -> bool {
    first
        .as_ref()
        .zip(second.as_ref())
        .is_some_and(|(a, b)| a != b)
}

fn conflicts_between(a: &AssessmentObservation, b: &AssessmentObservation) -> Vec<ConflictField> {
    let mut found = Vec::new();
    if conflicting(&a.algorithm_id, &b.algorithm_id) {
        found.push(ConflictField::Algorithm);
    }
    if conflicting(&a.profile_id, &b.profile_id) {
        found.push(ConflictField::Profile);
    }
    if conflicting(&a.parameter, &b.parameter) {
        found.push(ConflictField::Parameter);
    }
    let pa = a.properties.as_ref();
    let pb = b.properties.as_ref();
    if pa
        .zip(pb)
        .is_some_and(|(a, b)| conflicting(&a.provider_id, &b.provider_id))
    {
        found.push(ConflictField::Provider);
    }
    if pa.zip(pb).is_some_and(|(a, b)| {
        a.key_protection
            .zip(b.key_protection)
            .is_some_and(|(x, y)| x != y)
    }) {
        found.push(ConflictField::KeyProtection);
    }
    if pa.zip(pb).is_some_and(|(a, b)| {
        a.key_exportable
            .zip(b.key_exportable)
            .is_some_and(|(x, y)| x != y)
    }) {
        found.push(ConflictField::KeyExportable);
    }
    if pa.zip(pb).is_some_and(|(a, b)| {
        a.security_category
            .zip(b.security_category)
            .is_some_and(|(x, y)| x != y)
    }) {
        found.push(ConflictField::SecurityCategory);
    }
    if pa.zip(pb).is_some_and(|(a, b)| {
        a.key_size_bits
            .zip(b.key_size_bits)
            .is_some_and(|(x, y)| x != y)
    }) {
        found.push(ConflictField::KeySizeBits);
    }
    if pa.zip(pb).is_some_and(|(a, b)| {
        a.data_sensitivity
            .zip(b.data_sensitivity)
            .is_some_and(|(x, y)| x != y)
    }) {
        found.push(ConflictField::DataSensitivity);
    }
    found
}

/// Assess with an external verifier of exact source/evidence bindings.
///
/// No fact from another observation may fill missing attributes. All
/// directly observed/negotiated matching-operation records are checked via
/// FOSS-435 as *independent single-fact* contexts. An explicit Deny dominates;
/// without complete scope coverage, conflict-free high-confidence authenticated
/// observations, and every core decision Permit, result is Indeterminate.
/// No observations yields Indeterminate rather than guessing no use.
///
/// This library does not verify policy signatures, collector implementations
/// or external proof; the caller must securely supply the verifier and enforce.
pub fn assess<V: EvidenceVerifier>(
    policy: &PolicyDocument,
    context: &AssessmentContext,
    explicit_time: EvaluationTime,
    verifier: &V,
) -> Result<AssessmentReport, ContractError> {
    assess_with_limits(policy, context, explicit_time, verifier, &Limits::default())
}

/// Assessment with full caller-validated structural/serialization budgets.
pub fn assess_with_limits<V: EvidenceVerifier>(
    policy: &PolicyDocument,
    context: &AssessmentContext,
    explicit_time: EvaluationTime,
    verifier: &V,
    limits: &Limits,
) -> Result<AssessmentReport, ContractError> {
    context.validate(limits)?;
    if context.evaluation_time != explicit_time {
        return Err(ContractError::InvalidDocument("assessment_time_mismatch"));
    }
    let policy_bytes = policy.canonical_json_with_limits(limits)?;
    let hash = sha2::Sha256::digest(&policy_bytes);
    let policy_digest = PolicyDigest::try_from(
        hash.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )?;
    let mut ordered: Vec<&AssessmentObservation> = context.observations.iter().collect();
    ordered.sort_by(|a, b| a.observation_id.cmp(&b.observation_id));
    let operational: Vec<_> = ordered
        .iter()
        .copied()
        .filter(|record| {
            record.kind.is_operational() && record.operation == Some(context.operation)
        })
        .collect();

    let mut conflicts = Vec::new();
    for (index, a) in operational.iter().enumerate() {
        for b in operational.iter().skip(index + 1) {
            for field in conflicts_between(a, b) {
                conflicts.push(ObservationConflict {
                    first: a.observation_id.clone(),
                    second: b.observation_id.clone(),
                    field,
                });
                limits.check_count(
                    conflicts.len(),
                    limits.max_diagnostics,
                    "assessment conflicts",
                )?;
            }
        }
    }
    conflicts.sort();

    // Global explicit Deny and policy lifetime restrictions still apply even
    // when no usable observation exists. DefaultDenied on an empty fact alone
    // must NOT be mistaken for proof of absent cryptographic use.
    let global = evaluate_with_limits(
        policy,
        &CryptoContext {
            schema_version: SchemaVersion::V1,
            request_id: context.assessment_id.clone(),
            operation: context.operation,
            evaluation_time: context.evaluation_time,
            environment: context.environment.clone(),
            facts: Vec::new(),
        },
        explicit_time,
        limits,
    )?;
    let global_deny = global.outcome == DecisionOutcome::Deny
        && global.reasons.iter().any(|r| {
            matches!(
                r.code,
                ReasonCode::ExplicitDeny
                    | ReasonCode::PolicyExpired
                    | ReasonCode::PolicyNotEffective
            )
        });

    let mut reasons = BTreeSet::new();
    if context.coverage != AssessmentCoverage::Complete {
        reasons.insert(AssessmentReason::CoverageIncomplete);
    }
    if !context.uninspected_sources.is_empty() {
        reasons.insert(AssessmentReason::UninspectedSources);
    }
    if operational.is_empty() {
        reasons.insert(AssessmentReason::NoOperationalObservation);
    }
    if !conflicts.is_empty() {
        reasons.insert(AssessmentReason::ConflictingObservations);
    }
    if global_deny {
        reasons.insert(AssessmentReason::GlobalPolicyDeny);
    }

    let mut findings = Vec::with_capacity(ordered.len());
    let mut has_deny = global_deny;
    let mut every_permit = !operational.is_empty();
    let mut min_confidence = None;
    for record in ordered {
        let mut authenticated = false;
        let mut core_decision = None;
        let mut disposition = AssessmentDisposition::NotOperational;
        let relevant = record.kind.is_operational() && record.operation == Some(context.operation);
        if record.kind.is_operational() && !relevant {
            disposition = AssessmentDisposition::DifferentOperation;
        }
        if relevant {
            min_confidence = Some(
                min_confidence.map_or(record.confidence, |current: AssessmentConfidence| {
                    current.min(record.confidence)
                }),
            );
            if record.algorithm_id.is_none() {
                disposition = AssessmentDisposition::MissingAlgorithm;
                reasons.insert(AssessmentReason::MissingOperationalFields);
                every_permit = false;
            } else if record.parameter.is_none() {
                disposition = AssessmentDisposition::MissingParameter;
                reasons.insert(AssessmentReason::MissingOperationalFields);
                every_permit = false;
            } else {
                if record.evidence_ref.is_none() {
                    disposition = AssessmentDisposition::MissingEvidence;
                    reasons.insert(AssessmentReason::MissingEvidenceReference);
                    every_permit = false;
                } else {
                    authenticated = verifier.verify(context, record)?;
                    if !authenticated {
                        disposition = AssessmentDisposition::Unauthenticated;
                        reasons.insert(AssessmentReason::EvidenceNotAuthenticated);
                        every_permit = false;
                    }
                }
                if authenticated {
                    disposition = AssessmentDisposition::Evaluated;
                    if record.confidence != AssessmentConfidence::High {
                        reasons.insert(AssessmentReason::InsufficientConfidence);
                    }
                    let projected = CryptoContext {
                        schema_version: SchemaVersion::V1,
                        request_id: context.assessment_id.clone(),
                        operation: context.operation,
                        evaluation_time: context.evaluation_time,
                        environment: context.environment.clone(),
                        facts: vec![project_fact(record, authenticated)],
                    };
                    let decision = evaluate_with_limits(policy, &projected, explicit_time, limits)?;
                    match decision.outcome {
                        DecisionOutcome::Deny => {
                            has_deny = true;
                            reasons.insert(AssessmentReason::CoreDenied);
                            every_permit = false;
                        }
                        DecisionOutcome::Indeterminate => {
                            reasons.insert(AssessmentReason::CoreIndeterminate);
                            every_permit = false;
                        }
                        DecisionOutcome::Permit => {
                            reasons.insert(AssessmentReason::CorePermitted);
                        }
                    }
                    if record.confidence != AssessmentConfidence::High {
                        every_permit = false;
                    }
                    core_decision = Some(decision);
                }
            }
        }
        findings.push(AssessmentFinding {
            observation_id: record.observation_id.clone(),
            source_id: record.source_id.clone(),
            evidence_ref: record.evidence_ref.clone(),
            kind: record.kind,
            operation: record.operation,
            algorithm_id: record.algorithm_id.clone(),
            profile_id: record.profile_id.clone(),
            parameter: record.parameter.clone(),
            observed_at: record.observed_at,
            confidence: record.confidence,
            source_quality_claim: record.properties.as_ref().and_then(|p| p.source_quality),
            externally_authenticated: authenticated,
            disposition,
            core_decision,
        });
    }
    let outcome = if has_deny {
        DecisionOutcome::Deny
    } else if every_permit
        && context.coverage == AssessmentCoverage::Complete
        && conflicts.is_empty()
    {
        DecisionOutcome::Permit
    } else {
        DecisionOutcome::Indeterminate
    };
    let mut uninspected_sources = context.uninspected_sources.clone();
    uninspected_sources.sort();
    let report = AssessmentReport {
        schema_version: SchemaVersion::V1,
        assessment_id: context.assessment_id.clone(),
        snapshot_id: context.snapshot_id.clone(),
        scope: context.scope.clone(),
        operation: context.operation,
        policy_id: policy.policy_id.clone(),
        policy_version: policy.version.clone(),
        policy_digest,
        evaluated_at: explicit_time,
        outcome,
        coverage: context.coverage,
        uninspected_sources,
        evidence_confidence: min_confidence,
        reasons: reasons.into_iter().collect(),
        conflicts,
        findings,
    };
    limits.check_count(
        report.reasons.len(),
        limits.max_decision_reasons,
        "assessment reasons",
    )?;
    limits.check_count(
        report.findings.len(),
        limits.max_facts.min(MAX_ASSESSMENT_OBSERVATIONS),
        "assessment findings",
    )?;
    let bytes = serde_json::to_vec(&report)
        .map_err(|_| ContractError::InvalidDocument("assessment_report_serialization"))?;
    limits.check_json(&bytes)?;
    Ok(report)
}
