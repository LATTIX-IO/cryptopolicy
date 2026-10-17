//! Pure static checks and deterministic diagnostics for typed policy rules.
//!
//! This module never matches a request or returns a Permit. Rule selectors are
//! conjunctions of exact typed fields; no scripting or regex is supported.
//! Registry approval and trusted evidence assessment remain separate features.

use crate::{
    AlgorithmId, ContractError, DataSensitivity, DefaultEffect, EvidenceQuality, FactOrigin,
    KeyProtection, Limits, PolicyDocument, ProfileId, ProviderId, Requirement, RuleEffect, RuleId,
    RuleSelector, SchemaVersion,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Generic upper bound for a declared key bit length, not a declaration that
/// every number in this range is cryptographically possible for every algorithm.
pub const MAX_DECLARED_KEY_BITS: u32 = 1_048_576;

/// Severity of a static compile diagnostic. Warnings do not authorize use.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// A structural policy error that prevents use by a future evaluator.
    Error,
    /// A potentially dangerous construction that is still structurally valid.
    Warning,
}

/// Stable code for a policy-construction error or advisory.
///
/// Only bounded codes and rule references are emitted, never raw policy facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCode {
    /// The policy explicitly chose an allow default; later evaluator still may not infer authorization.
    ExplicitAllowDefault,
    /// Repeated rule identifier.
    DuplicateRule,
    /// Repeated policy metadata key.
    DuplicateMetadata,
    /// A match-all selector has other constraints.
    AmbiguousSelector,
    /// Selector has no matching constraints and is not an explicit match-all.
    EmptySelector,
    /// An advanced selector object has no constraints.
    EmptyAdvancedSelector,
    /// The environment is empty, overlong or contains unsupported characters.
    InvalidEnvironment,
    /// A category is not one of the supported levels 1 through 5.
    InvalidSecurityCategory,
    /// A key size is zero or exceeds the generic hard ceiling.
    InvalidKeySize,
    /// Require rule provides no requirements.
    EmptyRequirementRule,
    /// An unrestricted Allow does not identify any exact algorithm/profile.
    UnconstrainedAllow,
    /// Warning rule contains requirements with no defined warning-specific semantics.
    WarnRequirementsUnsupported,
    /// Deny requirements must not be treated as conditional permission or bypass.
    DenyRequirementsIgnored,
    /// Two exact algorithm constraints cannot both hold.
    ConflictingAlgorithm,
    /// Two exact profile / named-hybrid constraints cannot both hold.
    ConflictingProfile,
    /// Two provider identifiers cannot both hold.
    ConflictingProvider,
    /// Two sensitivity classifications cannot both hold.
    ConflictingSensitivity,
    /// Two key protection classes cannot both hold.
    ConflictingKeyProtection,
    /// Two exportability predicates cannot both hold.
    ConflictingExportability,
    /// Two source origin predicates cannot both hold.
    ConflictingSourceOrigin,
    /// Two source quality predicates cannot both hold.
    ConflictingSourceQuality,
    /// Exact selector and mandatory requirement refer to incompatible values.
    ContradictorySelectorRequirement,
}

impl ValidationCode {
    /// Stable snake-case diagnostic identifier for external integrations.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitAllowDefault => "explicit_allow_default",
            Self::DuplicateRule => "duplicate_rule",
            Self::DuplicateMetadata => "duplicate_metadata",
            Self::AmbiguousSelector => "ambiguous_selector",
            Self::EmptySelector => "empty_selector",
            Self::EmptyAdvancedSelector => "empty_advanced_selector",
            Self::InvalidEnvironment => "invalid_environment",
            Self::InvalidSecurityCategory => "invalid_security_category",
            Self::InvalidKeySize => "invalid_key_size",
            Self::EmptyRequirementRule => "empty_requirement_rule",
            Self::UnconstrainedAllow => "unconstrained_allow",
            Self::WarnRequirementsUnsupported => "warn_requirements_unsupported",
            Self::DenyRequirementsIgnored => "deny_requirements_ignored",
            Self::ConflictingAlgorithm => "conflicting_algorithm",
            Self::ConflictingProfile => "conflicting_profile",
            Self::ConflictingProvider => "conflicting_provider",
            Self::ConflictingSensitivity => "conflicting_sensitivity",
            Self::ConflictingKeyProtection => "conflicting_key_protection",
            Self::ConflictingExportability => "conflicting_exportability",
            Self::ConflictingSourceOrigin => "conflicting_source_origin",
            Self::ConflictingSourceQuality => "conflicting_source_quality",
            Self::ContradictorySelectorRequirement => "contradictory_selector_requirement",
        }
    }
}

/// Bounded, redaction-safe policy diagnostic.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationDiagnostic {
    /// Severity of this finding.
    pub severity: DiagnosticSeverity,
    /// Machine-readable stable code.
    pub code: ValidationCode,
    /// Affected rule identity, omitted for global problems.
    pub rule_id: Option<RuleId>,
}

/// Deterministic structural validation result, never a policy decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReport {
    /// Explicit report schema.
    pub schema_version: SchemaVersion,
    /// Findings sorted by RuleId, code and severity independent of rule order.
    pub diagnostics: Vec<ValidationDiagnostic>,
}

impl ValidationReport {
    /// Whether any errors prevent a policy from being compiled in FOSS-435.
    pub fn is_valid(&self) -> bool {
        !self
            .diagnostics
            .iter()
            .any(|item| item.severity == DiagnosticSeverity::Error)
    }

    /// Convert the first deterministic error into the existing contract API.
    pub fn require_valid(&self) -> Result<(), ContractError> {
        if let Some(item) = self
            .diagnostics
            .iter()
            .find(|item| item.severity == DiagnosticSeverity::Error)
        {
            return Err(ContractError::InvalidDocument(item.code.as_str()));
        }
        Ok(())
    }
}

/// Selector field whose absence must be handled explicitly by the evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SelectorField {
    /// Operation.
    Operation,
    /// Algorithm identifier.
    Algorithm,
    /// Exact profile.
    Profile,
    /// Caller environment.
    Environment,
    /// Cryptographic security category.
    SecurityCategory,
    /// Data sensitivity classification.
    DataSensitivity,
    /// Provider identity.
    Provider,
    /// Key-protection class.
    KeyProtection,
    /// Key exportability.
    KeyExportability,
    /// Exact key bit length.
    KeySizeBits,
    /// Evidence origin.
    SourceOrigin,
    /// Evidence quality.
    SourceQuality,
}

/// Missing-fact state for a selector or mandatory requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingFactDisposition {
    /// Missing Allow/Warn selector fact makes the rule nonmatching; never Permit.
    NonMatch,
    /// Missing potentially matching Deny/Require or mandatory requirement blocks authorization.
    Indeterminate,
}

/// Classify a missing selector fact according to its rule effect.
///
/// Deny and Require cannot be silently bypassed by an absent potentially
/// decisive fact. Allow and Warn with absent selector facts do not match.
pub const fn missing_selector_fact(effect: RuleEffect) -> MissingFactDisposition {
    match effect {
        RuleEffect::Deny | RuleEffect::Require => MissingFactDisposition::Indeterminate,
        RuleEffect::Allow | RuleEffect::Warn => MissingFactDisposition::NonMatch,
    }
}

/// A missing mandatory requirement never counts as satisfied.
pub const fn missing_required_fact() -> MissingFactDisposition {
    MissingFactDisposition::Indeterminate
}

impl RuleSelector {
    /// Enumerate exactly which typed attributes this AND selector requires.
    /// The order of fields is stable and is not evaluation precedence.
    pub fn predicate_fields(&self) -> Vec<SelectorField> {
        let mut fields = Vec::new();
        if self.operation.is_some() {
            fields.push(SelectorField::Operation);
        }
        if self.algorithm_id.is_some() {
            fields.push(SelectorField::Algorithm);
        }
        if self.profile_id.is_some() {
            fields.push(SelectorField::Profile);
        }
        if self.environment.is_some() {
            fields.push(SelectorField::Environment);
        }
        if let Some(extra) = &self.advanced {
            if extra.security_category.is_some() {
                fields.push(SelectorField::SecurityCategory);
            }
            if extra.data_sensitivity.is_some() {
                fields.push(SelectorField::DataSensitivity);
            }
            if extra.provider_id.is_some() {
                fields.push(SelectorField::Provider);
            }
            if extra.key_protection.is_some() {
                fields.push(SelectorField::KeyProtection);
            }
            if extra.key_exportable.is_some() {
                fields.push(SelectorField::KeyExportability);
            }
            if extra.key_size_bits.is_some() {
                fields.push(SelectorField::KeySizeBits);
            }
            if extra.source_origin.is_some() {
                fields.push(SelectorField::SourceOrigin);
            }
            if extra.source_quality.is_some() {
                fields.push(SelectorField::SourceQuality);
            }
        }
        fields
    }
}

fn valid_environment(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(b))
}

fn valid_category(category: u8) -> bool {
    (1..=5).contains(&category)
}

fn valid_key_bits(bits: u32) -> bool {
    (1..=MAX_DECLARED_KEY_BITS).contains(&bits)
}

fn add(
    out: &mut Vec<ValidationDiagnostic>,
    rule_id: Option<&RuleId>,
    code: ValidationCode,
    severity: DiagnosticSeverity,
) {
    out.push(ValidationDiagnostic {
        code,
        severity,
        rule_id: rule_id.cloned(),
    });
}

fn conflict<T: Eq + Clone>(
    current: &mut Option<T>,
    next: &T,
    code: ValidationCode,
    rule_id: &RuleId,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    if let Some(existing) = current {
        if existing != next {
            add(diagnostics, Some(rule_id), code, DiagnosticSeverity::Error);
        }
    } else {
        *current = Some(next.clone());
    }
}

#[derive(Default)]
struct ExactRequirements {
    algorithm: Option<AlgorithmId>,
    profile: Option<ProfileId>,
    provider: Option<ProviderId>,
    sensitivity: Option<DataSensitivity>,
    protection: Option<KeyProtection>,
    exportable: Option<bool>,
    origin: Option<FactOrigin>,
    quality: Option<EvidenceQuality>,
    key_bits: Option<u32>,
    min_key_bits: Option<u32>,
    min_category: Option<u8>,
}

fn validate_rule(
    rule: &crate::PolicyRule,
    diagnostics: &mut Vec<ValidationDiagnostic>,
) {
    use DiagnosticSeverity::{Error, Warning};
    use ValidationCode::*;

    let id = &rule.rule_id;
    let selector = &rule.selector;
    let fields = selector.predicate_fields();
    if selector.match_all && !fields.is_empty() {
        add(diagnostics, Some(id), AmbiguousSelector, Error);
    } else if !selector.match_all && fields.is_empty() {
        add(diagnostics, Some(id), EmptySelector, Error);
    }
    if selector.advanced.as_ref().is_some_and(|extra| extra.is_empty()) {
        add(diagnostics, Some(id), EmptyAdvancedSelector, Error);
    }
    if selector.environment.as_deref().is_some_and(|env| !valid_environment(env)) {
        add(diagnostics, Some(id), InvalidEnvironment, Error);
    }
    if let Some(extra) = &selector.advanced {
        if extra.security_category.is_some_and(|value| !valid_category(value)) {
            add(diagnostics, Some(id), InvalidSecurityCategory, Error);
        }
        if extra.key_size_bits.is_some_and(|value| !valid_key_bits(value)) {
            add(diagnostics, Some(id), InvalidKeySize, Error);
        }
    }

    if rule.effect == RuleEffect::Require && rule.requirements.is_empty() {
        add(diagnostics, Some(id), EmptyRequirementRule, Error);
    }
    if rule.effect == RuleEffect::Warn && !rule.requirements.is_empty() {
        add(diagnostics, Some(id), WarnRequirementsUnsupported, Error);
    }
    if rule.effect == RuleEffect::Deny && !rule.requirements.is_empty() {
        add(diagnostics, Some(id), DenyRequirementsIgnored, Warning);
    }
    if rule.effect == RuleEffect::Allow
        && selector.algorithm_id.is_none()
        && selector.profile_id.is_none()
        && !rule.requirements.iter().any(|req| matches!(
            req, Requirement::Algorithm(_) | Requirement::Profile(_) | Requirement::NamedHybrid(_)
        ))
    {
        add(diagnostics, Some(id), UnconstrainedAllow, Error);
    }

    let mut required = ExactRequirements::default();
    for requirement in &rule.requirements {
        match requirement {
            Requirement::Algorithm(value) => conflict(
                &mut required.algorithm, value, ConflictingAlgorithm, id, diagnostics,
            ),
            Requirement::Profile(value) | Requirement::NamedHybrid(value) => conflict(
                &mut required.profile, value, ConflictingProfile, id, diagnostics,
            ),
            Requirement::Provider(value) => conflict(
                &mut required.provider, value, ConflictingProvider, id, diagnostics,
            ),
            Requirement::Sensitivity(value) => conflict(
                &mut required.sensitivity, value, ConflictingSensitivity, id, diagnostics,
            ),
            Requirement::KeyProtection(value) => conflict(
                &mut required.protection, value, ConflictingKeyProtection, id, diagnostics,
            ),
            Requirement::KeyExportable(value) => conflict(
                &mut required.exportable, value, ConflictingExportability, id, diagnostics,
            ),
            Requirement::NonExportable => conflict(
                &mut required.exportable, &false, ConflictingExportability, id, diagnostics,
            ),
            Requirement::SourceOrigin(value) => conflict(
                &mut required.origin, value, ConflictingSourceOrigin, id, diagnostics,
            ),
            Requirement::SourceQuality(value) => conflict(
                &mut required.quality, value, ConflictingSourceQuality, id, diagnostics,
            ),
            Requirement::KeySizeBits(value) => {
                if !valid_key_bits(*value) {
                    add(diagnostics, Some(id), InvalidKeySize, Error);
                }
                conflict(&mut required.key_bits, value, InvalidKeySize, id, diagnostics);
            }
            Requirement::MinimumKeyBits(value) => {
                if !valid_key_bits(*value) {
                    add(diagnostics, Some(id), InvalidKeySize, Error);
                }
                required.min_key_bits = Some(required.min_key_bits.unwrap_or(0).max(*value));
            }
            Requirement::MinSecurityCategory(value) => {
                if !valid_category(*value) {
                    add(diagnostics, Some(id), InvalidSecurityCategory, Error);
                }
                required.min_category = Some(required.min_category.unwrap_or(0).max(*value));
            }
        }
    }

    if required.key_bits.zip(required.min_key_bits).is_some_and(|(exact, min)| exact < min) {
        add(diagnostics, Some(id), InvalidKeySize, Error);
    }
    if selector.algorithm_id.as_ref().zip(required.algorithm.as_ref())
        .is_some_and(|(a, b)| a != b)
        || selector.profile_id.as_ref().zip(required.profile.as_ref())
            .is_some_and(|(a, b)| a != b)
    {
        add(diagnostics, Some(id), ContradictorySelectorRequirement, Error);
    }
    if let Some(extra) = &selector.advanced {
        if extra.provider_id.as_ref().zip(required.provider.as_ref())
            .is_some_and(|(a, b)| a != b)
            || extra.data_sensitivity.zip(required.sensitivity)
                .is_some_and(|(a, b)| a != b)
            || extra.key_protection.zip(required.protection)
                .is_some_and(|(a, b)| a != b)
            || extra.key_exportable.zip(required.exportable)
                .is_some_and(|(a, b)| a != b)
            || extra.source_origin.zip(required.origin)
                .is_some_and(|(a, b)| a != b)
            || extra.source_quality.zip(required.quality)
                .is_some_and(|(a, b)| a != b)
            || extra.key_size_bits.zip(required.key_bits)
                .is_some_and(|(a, b)| a != b)
            || extra.key_size_bits.zip(required.min_key_bits)
                .is_some_and(|(a, b)| a < b)
            || extra.security_category.zip(required.min_category)
                .is_some_and(|(a, b)| a < b)
        {
            add(diagnostics, Some(id), ContradictorySelectorRequirement, Error);
        }
    }
}

impl PolicyDocument {
    /// Perform deterministic compile-time policy checks without evaluation.
    pub fn static_validate(&self) -> Result<ValidationReport, ContractError> {
        self.static_validate_with_limits(&Limits::default())
    }

    /// Perform static validation with caller-supplied, bounded work budgets.
    ///
    /// A rejected or excessive input is never converted to a decision.
    pub fn static_validate_with_limits(
        &self,
        limits: &Limits,
    ) -> Result<ValidationReport, ContractError> {
        limits.validate()?;
        limits.check_count(self.rules.len(), limits.max_rules, "policy rules")?;
        limits.check_count(self.metadata.len(), limits.max_metadata, "policy metadata")?;
        let mut diagnostics = Vec::new();
        if self.default_effect == DefaultEffect::Allow {
            add(
                &mut diagnostics, None, ValidationCode::ExplicitAllowDefault,
                DiagnosticSeverity::Warning,
            );
        }

        let mut seen = BTreeSet::new();
        for rule in &self.rules {
            limits.check_count(
                rule.requirements.len(), limits.max_requirements_per_rule,
                "requirements per rule",
            )?;
            if !seen.insert(&rule.rule_id) {
                add(
                    &mut diagnostics, Some(&rule.rule_id), ValidationCode::DuplicateRule,
                    DiagnosticSeverity::Error,
                );
            }
            validate_rule(rule, &mut diagnostics);
            if diagnostics.len() > limits.max_diagnostics {
                return Err(ContractError::ResourceLimitExceeded("static diagnostics"));
            }
        }
        let mut keys = BTreeSet::new();
        for entry in &self.metadata {
            if !keys.insert(&entry.key) {
                add(
                    &mut diagnostics, None, ValidationCode::DuplicateMetadata,
                    DiagnosticSeverity::Error,
                );
            }
            if diagnostics.len() > limits.max_diagnostics {
                return Err(ContractError::ResourceLimitExceeded("static diagnostics"));
            }
        }
        diagnostics.sort_by(|a, b| {
            a.rule_id.cmp(&b.rule_id)
                .then_with(|| a.code.cmp(&b.code))
                .then_with(|| a.severity.cmp(&b.severity))
        });
        diagnostics.dedup();
        Ok(ValidationReport {
            schema_version: SchemaVersion::V1,
            diagnostics,
        })
    }
}

/// Reject malformed context properties without pretending to attest evidence.
pub fn validate_context_properties(
    context: &crate::CryptoContext,
) -> Result<(), ContractError> {
    if context.environment.as_deref().is_some_and(|v| !valid_environment(v)) {
        return Err(ContractError::InvalidDocument("invalid_environment"));
    }
    for fact in &context.facts {
        if let Some(properties) = &fact.properties {
            if properties.security_category.is_some_and(|v| !valid_category(v)) {
                return Err(ContractError::InvalidDocument("invalid_security_category"));
            }
            if properties.key_size_bits.is_some_and(|v| !valid_key_bits(v)) {
                return Err(ContractError::InvalidDocument("invalid_key_size"));
            }
            // A provenance quality label and a verified bool are mere claims;
            // obvious internal contradictions are rejected, not "repaired".
            if properties.source_quality == Some(EvidenceQuality::ExternallyVerified)
                && !fact.verified
            {
                return Err(ContractError::InvalidDocument("inconsistent_source_quality"));
            }
        }
    }
    Ok(())
}
