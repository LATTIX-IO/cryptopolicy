//! Versioned policy, request-context and decision models.
use crate::Limits;
use crate::types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// An asserted policy issuer, not independently authenticated by this crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Issuer {
    /// Claimed issuer identity.
    pub subject: String,
    /// Optional caller-provided reference to independently verified provenance.
    pub assurance_ref: Option<EvidenceId>,
}

/// Optional finite attributes of a typed selector.
///
/// All present fields compose by logical AND. This data is not executable.
/// Field presence and missing-fact behavior are specified in validation.rs.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvancedSelector {
    /// Exact claimed cryptographic security category (1 through 5).
    pub security_category: Option<u8>,
    /// Exact request data classification.
    pub data_sensitivity: Option<DataSensitivity>,
    /// Exact provider identifier (no aliases).
    pub provider_id: Option<ProviderId>,
    /// Exact key custody/protection class.
    pub key_protection: Option<KeyProtection>,
    /// Exact key exportability state.
    pub key_exportable: Option<bool>,
    /// Exact key-size bit length; algorithm validity is checked by FOSS-445.
    pub key_size_bits: Option<u32>,
    /// Exact evidence origin, with configured and observed never conflated.
    pub source_origin: Option<FactOrigin>,
    /// Source quality claim, not source authentication.
    pub source_quality: Option<EvidenceQuality>,
}

impl AdvancedSelector {
    /// Determine whether the object provides any actual typed constraints.
    pub fn is_empty(&self) -> bool {
        self.security_category.is_none()
            && self.data_sensitivity.is_none()
            && self.provider_id.is_none()
            && self.key_protection.is_none()
            && self.key_exportable.is_none()
            && self.key_size_bits.is_none()
            && self.source_origin.is_none()
            && self.source_quality.is_none()
    }
}

/// Explicit and bounded rule selector. Interpretation is a future increment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSelector {
    /// Match all operations if no other selector is present.
    pub match_all: bool,
    /// Match an exact operation.
    pub operation: Option<CryptoOperation>,
    /// Match an exact algorithm identifier.
    pub algorithm_id: Option<AlgorithmId>,
    /// Match an exact profile identifier.
    pub profile_id: Option<ProfileId>,
    /// Match a caller-supplied environment value.
    pub environment: Option<String>,
    /// Additional finite exact-match constraints, absent for existing v1 policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advanced: Option<AdvancedSelector>,
}

/// Typed constraints. The future evaluator must interpret these as conjunctions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Requirement {
    /// Require exact algorithm identity.
    Algorithm(AlgorithmId),
    /// Require exact profile identity.
    Profile(ProfileId),
    /// Require a registered minimum security category.
    MinSecurityCategory(u8),
    /// Forbid exportable key material.
    NonExportable,
    /// Require an exact, named hybrid construction profile.
    NamedHybrid(ProfileId),
    /// Require an exact external provider identity.
    Provider(ProviderId),
    /// Require an exact request data sensitivity classification.
    Sensitivity(DataSensitivity),
    /// Require exact hardware/software protection class.
    KeyProtection(KeyProtection),
    /// Require explicit key exportability status.
    KeyExportable(bool),
    /// Require evidence from a specific origin without promoting its trust.
    SourceOrigin(FactOrigin),
    /// Require a source-quality classification, independently attested elsewhere.
    SourceQuality(EvidenceQuality),
    /// Require an exact declared key bit length.
    KeySizeBits(u32),
    /// Require at least this many key bits (algorithm feasibility deferred).
    MinimumKeyBits(u32),
}

/// One typed rule. Its serialized position must not determine deny precedence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Stable rule identifier.
    pub rule_id: RuleId,
    /// Required effect type.
    pub effect: RuleEffect,
    /// Typed predicate.
    pub selector: RuleSelector,
    /// List of mandatory constraints.
    pub requirements: Vec<Requirement>,
}

/// A metadata key/value that is not an authorization assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataEntry {
    /// ASCII-safe key.
    pub key: PolicyId,
    /// Descriptive value.
    pub value: String,
}

/// Strict versioned JSON policy document; not yet an executable policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Required JSON schema version.
    pub schema_version: SchemaVersion,
    /// Stable identity.
    pub policy_id: PolicyId,
    /// Policy-specific semantic version.
    pub version: PolicyVersion,
    /// Untrusted author ownership assertion.
    pub issuer: Issuer,
    /// Explicit creation timestamp.
    pub created_at: EvaluationTime,
    /// Optional effective time.
    pub effective_at: Option<EvaluationTime>,
    /// Optional expiry time.
    pub expires_at: Option<EvaluationTime>,
    /// Mandatory explicit default effect.
    pub default_effect: DefaultEffect,
    /// Policy rules, whose ordering is not precedence.
    pub rules: Vec<PolicyRule>,
    /// Non-normative metadata.
    pub metadata: Vec<MetadataEntry>,
}

/// Optional typed attributes of one cryptographic fact.
///
/// Every field remains a claim until authenticated and interpreted by an
/// appropriate future connector, registry and policy evaluator.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoProperties {
    /// Security category claim.
    pub security_category: Option<u8>,
    /// Key size in bits, where known.
    pub key_size_bits: Option<u32>,
    /// Data classification for the fact.
    pub data_sensitivity: Option<DataSensitivity>,
    /// Exact provider identity, where known.
    pub provider_id: Option<ProviderId>,
    /// Claimed protection of the corresponding key.
    pub key_protection: Option<KeyProtection>,
    /// Claimed exportability.
    pub key_exportable: Option<bool>,
    /// Claimed evidence quality, not independent attestation.
    pub source_quality: Option<EvidenceQuality>,
}

/// An individual cryptographic fact, with evidence origin preserved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoFact {
    /// Distinct fact identifier.
    pub fact_id: EvidenceId,
    /// Requested, configured, observed, inferred, or capability origin.
    pub origin: FactOrigin,
    /// Exact algorithm identifier, if known.
    pub algorithm_id: Option<AlgorithmId>,
    /// Exact profile identifier, if known.
    pub profile_id: Option<ProfileId>,
    /// Source reference, not proof of source authenticity.
    pub evidence_ref: Option<EvidenceId>,
    /// Asserted external verification flag, not independently checked here.
    pub verified: bool,
    /// Optional typed metadata, kept separately from provenance/verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<CryptoProperties>,
}

/// Wire request context, including explicit time and unpromoted evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CryptoContext {
    /// Required wire format version.
    pub schema_version: SchemaVersion,
    /// Opaque request identifier.
    pub request_id: RequestId,
    /// Requested operation.
    pub operation: CryptoOperation,
    /// Explicit evaluation time, without hidden wall-clock dependence.
    pub evaluation_time: EvaluationTime,
    /// Caller environment, if present, as a strict bounded identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Facts with independently retained provenance.
    pub facts: Vec<CryptoFact>,
}

/// Structured decision reason for downstream audit use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReason {
    /// Stable reason category.
    pub code: ReasonCode,
    /// Referenced rule if applicable.
    pub rule_id: Option<RuleId>,
}

/// A typed decision record, not proof of trusted evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    /// Required decision schema.
    pub schema_version: SchemaVersion,
    /// Source policy identifier.
    pub policy_id: PolicyId,
    /// Source policy version.
    pub policy_version: PolicyVersion,
    /// Canonical policy content digest.
    pub policy_digest: PolicyDigest,
    /// Evaluation time.
    pub evaluated_at: EvaluationTime,
    /// Stated result: no evaluator exists in this increment.
    pub outcome: DecisionOutcome,
    /// Referenced matching rules.
    pub matched_rules: Vec<RuleId>,
    /// Stable reason records.
    pub reasons: Vec<DecisionReason>,
    /// Evidence identities used.
    pub evidence: Vec<EvidenceId>,
}

fn parse<T: for<'de> Deserialize<'de>>(input: &[u8], limits: &Limits) -> Result<T, ContractError> {
    limits.check_json(input)?;
    serde_json::from_slice(input).map_err(|e| ContractError::InvalidJson(e.to_string()))
}

impl PolicyDocument {
    /// Parse JSON with strict known-fields and structural validation.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        Self::parse_json_with_limits(input, &Limits::default())
    }

    /// Parse strict policy JSON under validated caller-supplied limits.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        let document: Self = parse(input, limits)?;
        document.validate_with_limits(limits)?;
        Ok(document)
    }

    /// Validate bounded document size and nested policy structures.
    pub fn validate_with_limits(&self, limits: &Limits) -> Result<(), ContractError> {
        limits.validate()?;
        limits.check_count(self.rules.len(), limits.max_rules, "policy rules")?;
        limits.check_count(self.metadata.len(), limits.max_metadata, "policy metadata")?;
        self.validate_core()?;
        self.static_validate_with_limits(limits)?.require_valid()?;
        // Preflight attacker-controlled String allocations before cloning or
        // serializing an in-memory document. Escaping growth is checked again
        // against the final encoded size by canonical_json_with_limits.
        let mut text_bytes = self.issuer.subject.len();
        for entry in &self.metadata {
            text_bytes = text_bytes.saturating_add(entry.value.len());
        }
        for rule in &self.rules {
            if let Some(environment) = &rule.selector.environment {
                text_bytes = text_bytes.saturating_add(environment.len());
            }
        }
        if text_bytes > limits.max_json_bytes {
            return Err(ContractError::PayloadTooLarge);
        }
        for rule in &self.rules {
            limits.check_count(
                rule.requirements.len(),
                limits.max_requirements_per_rule,
                "requirements per rule",
            )?;
        }
        Ok(())
    }

    /// Validate structural consistency; does not match or execute rules.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_core()?;
        self.static_validate()?.require_valid()
    }

    /// Validate legacy structural invariants before static diagnostics.
    fn validate_core(&self) -> Result<(), ContractError> {
        if self.issuer.subject.trim().is_empty() || self.issuer.subject.len() > 256 {
            return Err(ContractError::InvalidDocument("empty or oversized issuer"));
        }
        if self.effective_at.is_some_and(|t| t < self.created_at) {
            return Err(ContractError::InvalidDocument("effective before creation"));
        }
        if self
            .expires_at
            .is_some_and(|t| t <= self.effective_at.unwrap_or(self.created_at))
        {
            return Err(ContractError::InvalidDocument("invalid validity range"));
        }
        let mut rules = BTreeSet::new();
        for rule in &self.rules {
            if !rules.insert(&rule.rule_id) {
                return Err(ContractError::DuplicateIdentifier);
            }
            let constrained = rule.selector.operation.is_some()
                || rule.selector.algorithm_id.is_some()
                || rule.selector.profile_id.is_some()
                || rule.selector.environment.is_some()
                || rule
                    .selector
                    .advanced
                    .as_ref()
                    .is_some_and(|extra| !extra.is_empty());
            if rule.selector.match_all == constrained {
                return Err(ContractError::InvalidDocument("ambiguous rule selector"));
            }
            if rule
                .requirements
                .iter()
                .any(|r| matches!(r, Requirement::MinSecurityCategory(0 | 6..)))
            {
                return Err(ContractError::InvalidDocument("invalid security category"));
            }
        }
        let mut keys = BTreeSet::new();
        for entry in &self.metadata {
            if !keys.insert(&entry.key) {
                return Err(ContractError::DuplicateIdentifier);
            }
        }
        Ok(())
    }

    /// Produce deterministic cryptopolicy-canon-v1 JSON. Rule ordering is
    /// normalized by rule identity; metadata by key; AND-requirements by
    /// serialized value. This is not RFC 8785 canonicalization.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ContractError> {
        self.canonical_json_with_limits(&Limits::default())
    }

    /// Serialize under caller-supplied, bounded resource constraints.
    pub fn canonical_json_with_limits(&self, limits: &Limits) -> Result<Vec<u8>, ContractError> {
        self.validate_with_limits(limits)?;
        let mut document = self.clone();
        document.rules.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        document.metadata.sort_by(|a, b| a.key.cmp(&b.key));
        for rule in &mut document.rules {
            let mut requirements = rule
                .requirements
                .iter()
                .map(|requirement| {
                    let key = serde_json::to_string(requirement)
                        .map_err(|err| ContractError::InvalidJson(err.to_string()))?;
                    Ok((key, requirement.clone()))
                })
                .collect::<Result<Vec<(String, Requirement)>, ContractError>>()?;
            requirements.sort_by(|a, b| a.0.cmp(&b.0));
            rule.requirements = requirements
                .into_iter()
                .map(|(_, requirement)| requirement)
                .collect();
        }
        let encoded = serde_json::to_vec(&document)
            .map_err(|err| ContractError::InvalidJson(err.to_string()))?;
        limits.check_json(&encoded)?;
        Ok(encoded)
    }

    /// SHA-256 fingerprint of normalized bytes; never proof of policy authority.
    pub fn canonical_digest(&self) -> Result<PolicyDigest, ContractError> {
        let hash = Sha256::digest(self.canonical_json()?);
        let hex = hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        PolicyDigest::try_from(hex)
    }
}

impl CryptoContext {
    /// Parse strict versioned input without promoting configured or inferred
    /// evidence into observed usage.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        Self::parse_json_with_limits(input, &Limits::default())
    }

    /// Parse context with caller-chosen, validated fact and JSON budgets.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        let context: Self = parse(input, limits)?;
        limits.check_count(context.facts.len(), limits.max_facts, "context facts")?;
        let mut ids = BTreeSet::new();
        for fact in &context.facts {
            if !ids.insert(&fact.fact_id) {
                return Err(ContractError::DuplicateIdentifier);
            }
        }
        crate::validate_context_properties(&context)?;
        Ok(context)
    }
}

impl PolicyDecision {
    /// Parse strict decision records. Authentication of the producing
    /// evaluator must be performed outside this library.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        Self::parse_json_with_limits(input, &Limits::default())
    }

    /// Parse a decision with independently bounded reasoning and evidence.
    pub fn parse_json_with_limits(input: &[u8], limits: &Limits) -> Result<Self, ContractError> {
        let decision: Self = parse(input, limits)?;
        limits.check_count(
            decision.matched_rules.len(),
            limits.max_matched_rules,
            "decision matched rules",
        )?;
        limits.check_count(
            decision.reasons.len(),
            limits.max_decision_reasons,
            "decision reasons",
        )?;
        limits.check_count(
            decision.evidence.len(),
            limits.max_evidence_refs,
            "decision evidence",
        )?;
        Ok(decision)
    }
}
