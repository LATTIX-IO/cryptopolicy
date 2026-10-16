//! Versioned policy, request-context and decision models.
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
}

/// Typed constraints. The future evaluator must interpret these as conjunctions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

fn parse<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T, ContractError> {
    if input.len() > MAX_CONTRACT_BYTES {
        return Err(ContractError::PayloadTooLarge);
    }
    serde_json::from_slice(input).map_err(|e| ContractError::InvalidJson(e.to_string()))
}

impl PolicyDocument {
    /// Parse JSON with strict known-fields and structural validation.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        let document: Self = parse(input)?;
        document.validate()?;
        Ok(document)
    }

    /// Validate structural consistency; does not match or execute rules.
    pub fn validate(&self) -> Result<(), ContractError> {
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
                || rule.selector.environment.is_some();
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
        self.validate()?;
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
            rule.requirements = requirements.into_iter().map(|(_, requirement)| requirement).collect();
        }
        let encoded = serde_json::to_vec(&document)
            .map_err(|err| ContractError::InvalidJson(err.to_string()))?;
        if encoded.len() > MAX_CONTRACT_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        Ok(encoded)
    }

    /// SHA-256 fingerprint of normalized bytes; never proof of policy authority.
    pub fn canonical_digest(&self) -> Result<PolicyDigest, ContractError> {
        let hash = Sha256::digest(self.canonical_json()?);
        let hex = hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        PolicyDigest::try_from(hex)
    }
}

impl CryptoContext {
    /// Parse strict versioned input without promoting configured or inferred
    /// evidence into observed usage.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        let context: Self = parse(input)?;
        let mut ids = BTreeSet::new();
        for fact in &context.facts {
            if !ids.insert(&fact.fact_id) {
                return Err(ContractError::DuplicateIdentifier);
            }
        }
        Ok(context)
    }
}

impl PolicyDecision {
    /// Parse strict decision records. Authentication of the producing
    /// evaluator must be performed outside this library.
    pub fn parse_json(input: &[u8]) -> Result<Self, ContractError> {
        parse(input)
    }
}
