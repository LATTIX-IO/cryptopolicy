//! Pure, deterministic single-target cryptographic policy evaluation.
//!
//! A decision is not an enforcement token or proof of evidence authenticity.
//! The caller must authenticate policy and observations and enforce Permit-only.

use crate::{
    AlgorithmId, ContractError, CryptoContext, CryptoFact, CryptoOperation, DecisionOutcome,
    DecisionReason, EvaluationTime, EvidenceId, EvidenceQuality, FactOrigin, Limits,
    PolicyDecision, PolicyDigest, PolicyDocument, PolicyRule, ReasonCode, Requirement, RuleEffect,
    RuleId, RuleSelector, SchemaVersion,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Truth {
    Yes,
    No,
    Unknown,
}

impl Truth {
    fn and(self, rhs: Self) -> Self {
        match (self, rhs) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Yes,
        }
    }
}

fn equal<T: PartialEq>(actual: Option<&T>, expected: &T) -> Truth {
    match actual {
        Some(value) if value == expected => Truth::Yes,
        Some(_) => Truth::No,
        None => Truth::Unknown,
    }
}

fn equal_copy<T: Copy + PartialEq>(actual: Option<T>, expected: T) -> Truth {
    match actual {
        Some(value) if value == expected => Truth::Yes,
        Some(_) => Truth::No,
        None => Truth::Unknown,
    }
}

fn at_least<T: Copy + Ord>(actual: Option<T>, min: T) -> Truth {
    match actual {
        Some(value) if value >= min => Truth::Yes,
        Some(_) => Truth::No,
        None => Truth::Unknown,
    }
}

fn target_selector(
    selector: &RuleSelector,
    context: &CryptoContext,
    fact: Option<&CryptoFact>,
) -> Truth {
    if selector.match_all {
        return Truth::Yes;
    }
    let mut result = Truth::Yes;
    if let Some(value) = selector.operation {
        result = result.and(equal_copy(Some(context.operation), value));
    }
    if let Some(value) = &selector.environment {
        result = result.and(equal(context.environment.as_ref(), value));
    }
    if let Some(value) = &selector.algorithm_id {
        result = result.and(equal(fact.and_then(|f| f.algorithm_id.as_ref()), value));
    }
    if let Some(value) = &selector.profile_id {
        result = result.and(equal(fact.and_then(|f| f.profile_id.as_ref()), value));
    }
    if let Some(advanced) = &selector.advanced {
        let props = fact.and_then(|f| f.properties.as_ref());
        if let Some(value) = advanced.security_category {
            result = result.and(equal_copy(props.and_then(|p| p.security_category), value));
        }
        if let Some(value) = advanced.data_sensitivity {
            result = result.and(equal_copy(props.and_then(|p| p.data_sensitivity), value));
        }
        if let Some(value) = &advanced.provider_id {
            result = result.and(equal(props.and_then(|p| p.provider_id.as_ref()), value));
        }
        if let Some(value) = advanced.key_protection {
            result = result.and(equal_copy(props.and_then(|p| p.key_protection), value));
        }
        if let Some(value) = advanced.key_exportable {
            result = result.and(equal_copy(props.and_then(|p| p.key_exportable), value));
        }
        if let Some(value) = advanced.key_size_bits {
            result = result.and(equal_copy(props.and_then(|p| p.key_size_bits), value));
        }
        if let Some(value) = advanced.source_origin {
            result = result.and(equal_copy(fact.map(|f| f.origin), value));
        }
        if let Some(value) = advanced.source_quality {
            result = result.and(equal_copy(props.and_then(|p| p.source_quality), value));
        }
    }
    result
}

fn check_requirement(req: &Requirement, fact: Option<&CryptoFact>) -> Truth {
    let props = fact.and_then(|f| f.properties.as_ref());
    match req {
        Requirement::Algorithm(value) => equal(fact.and_then(|f| f.algorithm_id.as_ref()), value),
        Requirement::Profile(value) | Requirement::NamedHybrid(value) => {
            equal(fact.and_then(|f| f.profile_id.as_ref()), value)
        }
        Requirement::MinSecurityCategory(value) => {
            at_least(props.and_then(|p| p.security_category), *value)
        }
        Requirement::NonExportable => equal_copy(props.and_then(|p| p.key_exportable), false),
        Requirement::Provider(value) => equal(props.and_then(|p| p.provider_id.as_ref()), value),
        Requirement::Sensitivity(value) => {
            equal_copy(props.and_then(|p| p.data_sensitivity), *value)
        }
        Requirement::KeyProtection(value) => {
            equal_copy(props.and_then(|p| p.key_protection), *value)
        }
        Requirement::KeyExportable(value) => {
            equal_copy(props.and_then(|p| p.key_exportable), *value)
        }
        Requirement::SourceOrigin(value) => equal_copy(fact.map(|f| f.origin), *value),
        Requirement::SourceQuality(value) => {
            equal_copy(props.and_then(|p| p.source_quality), *value)
        }
        Requirement::KeySizeBits(value) => equal_copy(props.and_then(|p| p.key_size_bits), *value),
        Requirement::MinimumKeyBits(value) => at_least(props.and_then(|p| p.key_size_bits), *value),
    }
}

fn check_requirements(rule: &PolicyRule, fact: Option<&CryptoFact>) -> Truth {
    rule.requirements.iter().fold(Truth::Yes, |state, item| {
        state.and(check_requirement(item, fact))
    })
}

/// Closed, operation-aware preview recognition table, NOT an algorithm
/// registry or standards/FIPS approval. Expanded by FOSS-445.
fn preview_algorithm_known(
    algorithm: &AlgorithmId,
    operation: CryptoOperation,
    fact: &CryptoFact,
) -> bool {
    let bits = fact.properties.as_ref().and_then(|p| p.key_size_bits);
    match algorithm.as_str() {
        "AES-256-GCM" => {
            matches!(
                operation,
                CryptoOperation::Encrypt | CryptoOperation::Decrypt
            ) && bits == Some(256)
        }
        "AES-128-GCM" => {
            matches!(
                operation,
                CryptoOperation::Encrypt | CryptoOperation::Decrypt
            ) && bits == Some(128)
        }
        "SHA3-256" | "SHA3-512" => operation == CryptoOperation::Hash,
        "ML-KEM-768" | "ML-KEM-1024" => {
            matches!(
                operation,
                CryptoOperation::Encapsulate | CryptoOperation::Decapsulate
            )
        }
        _ => false,
    }
}

/// Profile selectors/requirements remain untrusted by the original evaluator.
/// Only the crate-internal FOSS-507 path can interpret a named profile, and
/// only after actual FOSS-505 external key + source qualification succeeds.
/// Exact named-hybrid constructions remain unsupported in BOTH modes.
fn requires_unavailable_profile(
    rule: &PolicyRule,
    fact: &CryptoFact,
    qualified_profile: bool,
) -> bool {
    if qualified_profile {
        return rule
            .requirements
            .iter()
            .any(|r| matches!(r, Requirement::NamedHybrid(_)));
    }
    rule.selector.profile_id.is_some()
        || fact.profile_id.is_some()
        || rule
            .requirements
            .iter()
            .any(|r| matches!(r, Requirement::Profile(_) | Requirement::NamedHybrid(_)))
}

fn credible_preview_fact(fact: &CryptoFact) -> bool {
    fact.verified
        && fact.evidence_ref.is_some()
        && matches!(fact.origin, FactOrigin::Observed | FactOrigin::Negotiated)
        && fact.properties.as_ref().and_then(|p| p.source_quality)
            == Some(EvidenceQuality::ExternallyVerified)
}

/// Evaluate one explicitly bound target fact at the injected UTC time.
///
/// A Permit is only a data record. Callers are responsible for authenticating
/// the policy issuer and fact provenance and for enforcing Permit-only access.
/// Deny and Indeterminate must never authorize any protected operation.
pub fn evaluate(
    policy: &PolicyDocument,
    context: &CryptoContext,
    explicit_time: EvaluationTime,
) -> Result<PolicyDecision, ContractError> {
    evaluate_with_limits(policy, context, explicit_time, &Limits::default())
}

/// Evaluate with bounded caller-provided limits and no ambient I/O or clock.
///
/// Multiple crypto facts are rejected rather than selecting a convenient
/// subset or laundering assurance from one fact into another. FOSS-447 owns
/// correlated multi-fact inventory evaluation.
pub fn evaluate_with_limits(
    policy: &PolicyDocument,
    context: &CryptoContext,
    explicit_time: EvaluationTime,
    limits: &Limits,
) -> Result<PolicyDecision, ContractError> {
    evaluate_internal(policy, context, explicit_time, limits, false)
}

/// Crate-private permission to interpret the exact named profile. Call ONLY
/// after FOSS-505's real embedded-catalog and independent source/key checks,
/// NEVER from an externally supplied ProfileQualificationReport alone.
/// Returns policy data, not a signed/authorized cryptographic operation.
pub(crate) fn evaluate_with_attested_profile(
    policy: &PolicyDocument,
    context: &CryptoContext,
    explicit_time: EvaluationTime,
    limits: &Limits,
    _proof: &crate::verified_evaluator::QualifiedProfileProof,
) -> Result<PolicyDecision, ContractError> {
    evaluate_internal(policy, context, explicit_time, limits, true)
}

fn evaluate_internal(
    policy: &PolicyDocument,
    context: &CryptoContext,
    explicit_time: EvaluationTime,
    limits: &Limits,
    qualified_profile: bool,
) -> Result<PolicyDecision, ContractError> {
    limits.validate()?;
    let policy_bytes = policy.canonical_json_with_limits(limits)?;
    limits.check_count(context.facts.len(), limits.max_facts, "context facts")?;
    if context.facts.len() > 1 {
        return Err(ContractError::InvalidDocument(
            "multiple target facts unsupported",
        ));
    }
    if context.evaluation_time != explicit_time {
        return Err(ContractError::InvalidDocument("evaluation time mismatch"));
    }
    crate::validate_context_properties(context)?;
    let encoded_context = serde_json::to_vec(context)
        .map_err(|_| ContractError::InvalidDocument("context serialization failed"))?;
    limits.check_json(&encoded_context)?;
    if CryptoContext::parse_json_with_limits(&encoded_context, limits)? != *context {
        return Err(ContractError::InvalidDocument(
            "context round trip mismatch",
        ));
    }

    let digest = Sha256::digest(&policy_bytes);
    let fingerprint = PolicyDigest::try_from(
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    )?;
    let fact = context.facts.first();
    if explicit_time < policy.created_at
        || policy.effective_at.is_some_and(|time| explicit_time < time)
    {
        return build_decision(
            policy,
            context,
            fingerprint,
            DecisionOutcome::Deny,
            BTreeSet::new(),
            BTreeSet::from([(None, ReasonCode::PolicyNotEffective)]),
            limits,
        );
    }
    if policy.expires_at.is_some_and(|time| explicit_time >= time) {
        return build_decision(
            policy,
            context,
            fingerprint,
            DecisionOutcome::Deny,
            BTreeSet::new(),
            BTreeSet::from([(None, ReasonCode::PolicyExpired)]),
            limits,
        );
    }

    let mut matched = BTreeSet::new();
    let mut denied = BTreeSet::new();
    let mut requirement_failed = BTreeSet::new();
    let mut requirement_unknown = BTreeSet::new();
    let mut allow_failed = BTreeSet::new();
    let mut allow_unknown = BTreeSet::new();
    let mut allow_satisfied = BTreeSet::new();
    let mut require_satisfied = BTreeSet::new();
    let mut unvalidated_profile = BTreeSet::new();
    let mut deprecated = BTreeSet::new();

    for rule in &policy.rules {
        if rule
            .temporal
            .as_ref()
            .is_some_and(|window| !window.active_at(rule.effect, explicit_time))
        {
            continue;
        }
        match target_selector(&rule.selector, context, fact) {
            Truth::No => continue,
            Truth::Unknown => {
                if matches!(rule.effect, RuleEffect::Deny | RuleEffect::Require) {
                    requirement_unknown.insert(rule.rule_id.clone());
                }
                continue;
            }
            Truth::Yes => {
                matched.insert(rule.rule_id.clone());
            }
        }
        match rule.effect {
            RuleEffect::Deny => {
                // An attached requirement cannot make a matching Deny conditional.
                denied.insert(rule.rule_id.clone());
            }
            RuleEffect::Warn => {
                if rule
                    .temporal
                    .as_ref()
                    .is_some_and(|window| window.deprecated_from.is_some())
                {
                    deprecated.insert(rule.rule_id.clone());
                }
            }
            RuleEffect::Require => match check_requirements(rule, fact) {
                Truth::No => {
                    requirement_failed.insert(rule.rule_id.clone());
                }
                Truth::Unknown => {
                    requirement_unknown.insert(rule.rule_id.clone());
                }
                Truth::Yes => {
                    require_satisfied.insert(rule.rule_id.clone());
                    if fact
                        .is_some_and(|f| requires_unavailable_profile(rule, f, qualified_profile))
                    {
                        unvalidated_profile.insert(rule.rule_id.clone());
                    }
                }
            },
            RuleEffect::Allow => match check_requirements(rule, fact) {
                Truth::No => {
                    allow_failed.insert(rule.rule_id.clone());
                }
                Truth::Unknown => {
                    allow_unknown.insert(rule.rule_id.clone());
                }
                Truth::Yes => {
                    allow_satisfied.insert(rule.rule_id.clone());
                    if fact
                        .is_some_and(|f| requires_unavailable_profile(rule, f, qualified_profile))
                    {
                        unvalidated_profile.insert(rule.rule_id.clone());
                    }
                }
            },
        }
    }
    let mut reasons: BTreeSet<(Option<RuleId>, ReasonCode)> = BTreeSet::new();
    let outcome = if !denied.is_empty() {
        for id in &denied {
            reasons.insert((Some(id.clone()), ReasonCode::ExplicitDeny));
        }
        DecisionOutcome::Deny
    } else if !requirement_failed.is_empty() {
        for id in &requirement_failed {
            reasons.insert((Some(id.clone()), ReasonCode::RequirementNotSatisfied));
        }
        DecisionOutcome::Deny
    } else if !requirement_unknown.is_empty() {
        for id in &requirement_unknown {
            reasons.insert((Some(id.clone()), ReasonCode::MissingRequiredAttribute));
        }
        DecisionOutcome::Indeterminate
    } else if !allow_satisfied.is_empty() {
        if let Some(f) = fact {
            // A known v1 preview algorithm OR the independently qualified,
            // exact catalog profile may satisfy an ordinary Allow. In the
            // latter case source, provider, parameter, revocation and actual
            // key binding were separately verified before this call.
            let known = qualified_profile
                || f.algorithm_id
                    .as_ref()
                    .is_some_and(|id| preview_algorithm_known(id, context.operation, f));
            if !unvalidated_profile.is_empty() || !known {
                for id in &allow_satisfied {
                    reasons.insert((Some(id.clone()), ReasonCode::UnsupportedProfile));
                }
                DecisionOutcome::Indeterminate
            } else if !credible_preview_fact(f) {
                for id in &allow_satisfied {
                    reasons.insert((Some(id.clone()), ReasonCode::UnverifiedEvidence));
                }
                DecisionOutcome::Indeterminate
            } else {
                for id in &allow_satisfied {
                    reasons.insert((Some(id.clone()), ReasonCode::ExplicitAllow));
                }
                for id in &require_satisfied {
                    reasons.insert((Some(id.clone()), ReasonCode::RequirementSatisfied));
                }
                DecisionOutcome::Permit
            }
        } else {
            for id in &allow_satisfied {
                reasons.insert((Some(id.clone()), ReasonCode::MissingRequiredAttribute));
            }
            DecisionOutcome::Indeterminate
        }
    } else if !allow_unknown.is_empty() {
        for id in &allow_unknown {
            reasons.insert((Some(id.clone()), ReasonCode::MissingRequiredAttribute));
        }
        DecisionOutcome::Indeterminate
    } else {
        if allow_failed.is_empty() {
            // An explicit default Allow never grants a no-match Permit.
            reasons.insert((None, ReasonCode::DefaultDenied));
        } else {
            for id in &allow_failed {
                reasons.insert((Some(id.clone()), ReasonCode::RequirementNotSatisfied));
            }
        }
        DecisionOutcome::Deny
    };
    for id in deprecated {
        reasons.insert((Some(id), ReasonCode::DeprecationWarning));
    }
    build_decision(
        policy,
        context,
        fingerprint,
        outcome,
        matched,
        reasons,
        limits,
    )
}

fn build_decision(
    policy: &PolicyDocument,
    context: &CryptoContext,
    digest: PolicyDigest,
    outcome: DecisionOutcome,
    matched: BTreeSet<RuleId>,
    reasons: BTreeSet<(Option<RuleId>, ReasonCode)>,
    limits: &Limits,
) -> Result<PolicyDecision, ContractError> {
    limits.check_count(
        matched.len(),
        limits.max_matched_rules,
        "decision matched rules",
    )?;
    limits.check_count(
        reasons.len(),
        limits.max_decision_reasons,
        "decision reasons",
    )?;
    let mut evidence = BTreeSet::<EvidenceId>::new();
    if !matched.is_empty() {
        if let Some(f) = context.facts.first() {
            evidence.insert(f.fact_id.clone());
            if let Some(reference) = &f.evidence_ref {
                evidence.insert(reference.clone());
            }
        }
    }
    limits.check_count(
        evidence.len(),
        limits.max_evidence_refs,
        "decision evidence",
    )?;
    let result = PolicyDecision {
        schema_version: SchemaVersion::V1,
        policy_id: policy.policy_id.clone(),
        policy_version: policy.version.clone(),
        policy_digest: digest,
        evaluated_at: context.evaluation_time,
        outcome,
        matched_rules: matched.into_iter().collect(),
        reasons: reasons
            .into_iter()
            .map(|(rule_id, code)| DecisionReason { code, rule_id })
            .collect(),
        evidence: evidence.into_iter().collect(),
    };
    let bytes = serde_json::to_vec(&result)
        .map_err(|_| ContractError::InvalidDocument("decision serialization failed"))?;
    limits.check_json(&bytes)?;
    Ok(result)
}
