//! Deterministic single-context evaluator truth tables, security tests and regressions.
#![allow(clippy::unwrap_used)] // Test setup exercises explicitly fallible APIs.

use cryptopolicy::*;

fn policy() -> PolicyDocument {
    PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap()
}

fn context() -> CryptoContext {
    CryptoContext::parse_json(include_bytes!("fixtures/evaluator-context-v1.json")).unwrap()
}

fn at(value: i64) -> EvaluationTime {
    EvaluationTime { unix_millis: value }
}

fn result(p: &PolicyDocument, c: &CryptoContext) -> PolicyDecision {
    evaluate(p, c, c.evaluation_time).unwrap()
}

fn has_reason(d: &PolicyDecision, code: ReasonCode) -> bool {
    d.reasons.iter().any(|reason| reason.code == code)
}

fn id(value: &str) -> RuleId {
    RuleId::parse(value).unwrap()
}

fn deny(id_value: &str) -> PolicyRule {
    PolicyRule {
        rule_id: id(id_value),
        effect: RuleEffect::Deny,
        selector: RuleSelector {
            match_all: true,
            operation: None,
            algorithm_id: None,
            profile_id: None,
            environment: None,
            advanced: None,
        },
        requirements: vec![],
    }
}

#[test]
fn explicit_verified_allow_and_conjoined_require_produce_permit() {
    let p = policy();
    let c = context();
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Permit);
    assert_eq!(d.policy_id, p.policy_id);
    assert_eq!(d.policy_digest, p.canonical_digest().unwrap());
    assert_eq!(d.evaluated_at, at(150));
    assert_eq!(d.matched_rules, vec![id("r-allow-aes"), id("r-require-protection")]);
    assert_eq!(d.evidence, vec![EvidenceId::parse("attest:1").unwrap(), EvidenceId::parse("fact:1").unwrap()]);
    assert_eq!(
        d.reasons,
        vec![
            DecisionReason { code: ReasonCode::ExplicitAllow, rule_id: Some(id("r-allow-aes")) },
            DecisionReason { code: ReasonCode::RequirementSatisfied, rule_id: Some(id("r-require-protection")) },
        ],
    );
}

#[test]
fn rule_and_requirement_order_do_not_change_decision_or_digest() {
    let baseline = policy();
    let input = context();
    let gold = result(&baseline, &input);
    let golden = serde_json::to_vec(&gold).unwrap();
    let mut p = baseline.clone();
    let mut seed = 0x2db7_4f53_u64;
    for _ in 0..90 {
        for i in (1..p.rules.len()).rev() {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let other = (seed as usize) % (i + 1);
            p.rules.swap(i, other);
        }
        for rule in &mut p.rules {
            rule.requirements.reverse();
        }
        let next = result(&p, &input);
        assert_eq!(serde_json::to_vec(&next).unwrap(), golden);
        assert_eq!(next.policy_digest, gold.policy_digest);
    }
}

#[test]
fn matching_deny_overrides_matching_allow_even_when_after_allow() {
    let mut p = policy();
    p.rules.push(deny("zz-deny"));
    for permutation in 0..2 {
        if permutation == 1 {
            p.rules.reverse();
        }
        let d = result(&p, &context());
        assert_eq!(d.outcome, DecisionOutcome::Deny);
        assert!(has_reason(&d, ReasonCode::ExplicitDeny));
        assert!(!has_reason(&d, ReasonCode::ExplicitAllow));
    }
}

#[test]
fn matching_deny_does_not_become_conditional_due_to_requirements() {
    let mut p = policy();
    let mut rule = deny("d-with-ignored-requirements");
    rule.requirements.push(Requirement::NonExportable);
    p.rules.push(rule);
    let mut c = context();
    c.facts[0].properties.as_mut().unwrap().key_exportable = Some(true);
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(has_reason(&d, ReasonCode::ExplicitDeny));
}

#[test]
fn known_mismatch_in_deny_selector_does_not_block_allow() {
    let mut p = policy();
    let mut rule = deny("d-other");
    rule.selector.match_all = false;
    rule.selector.algorithm_id = Some(AlgorithmId::parse("RSA-1024").unwrap());
    p.rules.push(rule);
    assert_eq!(result(&p, &context()).outcome, DecisionOutcome::Permit);
}

#[test]
fn absent_potentially_decisive_deny_selector_returns_indeterminate() {
    let mut p = policy();
    let mut rule = deny("d-uncertain");
    rule.selector.match_all = false;
    rule.selector.profile_id = Some(ProfileId::parse("profile:unknown").unwrap());
    p.rules.push(rule);
    let d = result(&p, &context());
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(has_reason(&d, ReasonCode::MissingRequiredAttribute));
}

#[test]
fn definitive_deny_wins_over_unknown_other_deny() {
    let mut p = policy();
    p.rules.push(deny("d-explicit"));
    let mut uncertain = deny("d-uncertain");
    uncertain.selector.match_all = false;
    uncertain.selector.profile_id = Some(ProfileId::parse("profile:unknown").unwrap());
    p.rules.push(uncertain);
    let d = result(&p, &context());
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(has_reason(&d, ReasonCode::ExplicitDeny));
}

#[test]
fn known_mandatory_failure_blocks_otherwise_valid_allow() {
    let mut p = policy();
    let mandatory = p.rules.iter_mut().find(|r| r.effect == RuleEffect::Require).unwrap();
    mandatory.requirements.push(Requirement::MinimumKeyBits(512));
    let d = result(&p, &context());
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(has_reason(&d, ReasonCode::RequirementNotSatisfied));
}

#[test]
fn missing_mandatory_fact_yields_indeterminate_not_permit() {
    let p = policy();
    let mut c = context();
    c.facts[0].properties.as_mut().unwrap().security_category = None;
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(has_reason(&d, ReasonCode::MissingRequiredAttribute));
}

#[test]
fn unmet_allow_requirement_is_deny_and_unknown_is_indeterminate() {
    let p = policy();
    let mut c = context();
    c.facts[0].properties.as_mut().unwrap().key_exportable = Some(true);
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(has_reason(&d, ReasonCode::RequirementNotSatisfied));

    c.facts[0].properties.as_mut().unwrap().key_exportable = None;
    let u = result(&p, &c);
    assert_eq!(u.outcome, DecisionOutcome::Indeterminate);
    assert!(has_reason(&u, ReasonCode::MissingRequiredAttribute));
}

#[test]
fn default_allow_never_grants_permission_from_no_matching_rule() {
    let mut p = policy();
    p.default_effect = DefaultEffect::Allow;
    p.rules.clear();
    let d = result(&p, &context());
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(has_reason(&d, ReasonCode::DefaultDenied));
}

#[test]
fn warn_only_cannot_authorize() {
    let mut p = policy();
    p.rules.retain(|r| r.effect == RuleEffect::Warn);
    let d = result(&p, &context());
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(has_reason(&d, ReasonCode::DefaultDenied));
}

#[test]
fn unknown_algorithm_identity_never_grants_permit() {
    let mut p = policy();
    let allow = p.rules.iter_mut().find(|r| r.effect == RuleEffect::Allow).unwrap();
    allow.selector.algorithm_id = Some(AlgorithmId::parse("UNKNOWN-PQC-999").unwrap());
    allow.requirements.iter_mut().for_each(|req| {
        if let Requirement::Algorithm(value) = req {
            *value = AlgorithmId::parse("UNKNOWN-PQC-999").unwrap();
        }
    });
    let mut c = context();
    c.facts[0].algorithm_id = Some(AlgorithmId::parse("UNKNOWN-PQC-999").unwrap());
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(has_reason(&d, ReasonCode::UnsupportedProfile));
}

#[test]
fn exact_but_unapproved_profile_is_never_a_permit() {
    let mut p = policy();
    let allow = p.rules.iter_mut().find(|r| r.effect == RuleEffect::Allow).unwrap();
    allow.selector.profile_id = Some(ProfileId::parse("profile:unvalidated").unwrap());
    let mut c = context();
    c.facts[0].profile_id = Some(ProfileId::parse("profile:unvalidated").unwrap());
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(has_reason(&d, ReasonCode::UnsupportedProfile));
}

#[test]
fn declared_hybrid_requirement_cannot_bypass_unavailable_registry() {
    let mut p = policy();
    let allow = p.rules.iter_mut().find(|r| r.effect == RuleEffect::Allow).unwrap();
    allow.requirements.push(Requirement::NamedHybrid(ProfileId::parse("hybrid:unverified").unwrap()));
    let mut c = context();
    c.facts[0].profile_id = Some(ProfileId::parse("hybrid:unverified").unwrap());
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(has_reason(&d, ReasonCode::UnsupportedProfile));
}

#[test]
fn no_fact_does_not_satisfy_required_evidence() {
    let mut c = context();
    c.facts.clear();
    let d = result(&policy(), &c);
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(!d.outcome.eq(&DecisionOutcome::Permit));
}

#[test]
fn missing_evidence_reference_is_not_an_implicit_trust_proof() {
    let mut c = context();
    c.facts[0].evidence_ref = None;
    let d = result(&policy(), &c);
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(has_reason(&d, ReasonCode::UnverifiedEvidence));
}

#[test]
fn configured_claim_is_not_promoted_into_observed_usage() {
    let mut p = policy();
    let allow = p.rules.iter_mut().find(|r| r.effect == RuleEffect::Allow).unwrap();
    allow.requirements.retain(|req| !matches!(req, Requirement::SourceOrigin(_)));
    let mut c = context();
    c.facts[0].origin = FactOrigin::Configured;
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(has_reason(&d, ReasonCode::UnverifiedEvidence));
}

#[test]
fn provider_capability_never_counts_as_observation() {
    let mut p = policy();
    p.rules.iter_mut().find(|r| r.effect == RuleEffect::Allow).unwrap()
        .requirements.retain(|req| !matches!(req, Requirement::SourceOrigin(_)));
    let mut c = context();
    c.facts[0].origin = FactOrigin::ProviderCapability;
    assert_eq!(result(&p, &c).outcome, DecisionOutcome::Indeterminate);
}

#[test]
fn effective_inclusive_and_expiration_exclusive_with_injected_time() {
    let p = policy();
    for (millis, outcome, reason) in [
        (99, DecisionOutcome::Deny, Some(ReasonCode::PolicyNotEffective)),
        (100, DecisionOutcome::Permit, None),
        (199, DecisionOutcome::Permit, None),
        (200, DecisionOutcome::Deny, Some(ReasonCode::PolicyExpired)),
    ] {
        let mut c = context();
        c.evaluation_time = at(millis);
        let d = result(&p, &c);
        assert_eq!(d.outcome, outcome);
        if let Some(code) = reason {
            assert!(has_reason(&d, code));
            assert!(d.matched_rules.is_empty());
        }
    }
}

#[test]
fn before_created_time_is_a_definitive_deny() {
    let mut p = policy();
    p.created_at = at(100);
    let mut c = context();
    c.evaluation_time = at(99);
    let d = result(&p, &c);
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(has_reason(&d, ReasonCode::PolicyNotEffective));
}

#[test]
fn clock_mismatch_is_an_error_not_an_evaluation() {
    assert_eq!(
        evaluate(&policy(), &context(), at(151)),
        Err(ContractError::InvalidDocument("evaluation time mismatch")),
    );
}

#[test]
fn invalid_policy_context_and_multi_fact_inputs_return_error() {
    let mut p = policy();
    let duplicate_id = p.rules[1].rule_id.clone();
    p.rules[0].rule_id = duplicate_id;
    assert_eq!(evaluate(&p, &context(), at(150)), Err(ContractError::DuplicateIdentifier));

    let mut c = context();
    c.facts.push(c.facts[0].clone());
    assert_eq!(
        evaluate(&policy(), &c, at(150)),
        Err(ContractError::InvalidDocument("multiple target facts unsupported")),
    );
    let mut invalid = context();
    invalid.environment = Some("invalid environment".into());
    assert!(evaluate(&policy(), &invalid, at(150)).is_err());
    let mut invalid_prop = context();
    invalid_prop.facts[0].properties.as_mut().unwrap().key_size_bits = Some(0);
    assert!(evaluate(&policy(), &invalid_prop, at(150)).is_err());
}

#[test]
fn resource_limits_reject_unbounded_reason_and_evidence_output() {
    let mut p = policy();
    p.rules.push(deny("r-deny-one"));
    p.rules.push(deny("r-deny-two"));
    let limits = Limits {
        max_decision_reasons: 1,
        ..Limits::default()
    };
    assert_eq!(
        evaluate_with_limits(&p, &context(), at(150), &limits),
        Err(ContractError::ResourceLimitExceeded("decision reasons")),
    );
    let limits = Limits { max_matched_rules: 1, ..Limits::default() };
    assert_eq!(
        evaluate_with_limits(&p, &context(), at(150), &limits),
        Err(ContractError::ResourceLimitExceeded("decision matched rules")),
    );
    let limits = Limits { max_evidence_refs: 1, ..Limits::default() };
    assert_eq!(
        evaluate_with_limits(&policy(), &context(), at(150), &limits),
        Err(ContractError::ResourceLimitExceeded("decision evidence")),
    );
}

#[test]
fn malformed_input_mutations_never_panic_or_bypass_validation() {
    let fixture = include_bytes!("fixtures/evaluator-policy-v1.json");
    for i in (0..fixture.len()).step_by(11) {
        let mut altered = fixture.to_vec();
        altered[i] = 0xff;
        if let Ok(document) = PolicyDocument::parse_json(&altered) {
            // A syntactically valid mutation must still use the full evaluator;
            // whether metadata-only mutations preserve a Permit is intentional.
            let _ = evaluate(&document, &context(), at(150));
        }
    }
    assert!(PolicyDocument::parse_json(br#"{"default_effect":"allow"}"#).is_err());
}

#[test]
fn golden_decision_can_be_read_back_and_has_only_safe_reference_fields() {
    let p = policy();
    let d = result(&p, &context());
    let bytes = serde_json::to_vec(&d).unwrap();
    let parsed = PolicyDecision::parse_json(&bytes).unwrap();
    assert_eq!(parsed, d);
    let as_text = String::from_utf8(bytes).unwrap();
    assert!(!as_text.contains("fixture-owner-unverified"));
    assert!(!as_text.contains("hardware_security_module"));
    assert!(as_text.contains("explicit_allow"));
    assert!(as_text.contains("requirement_satisfied"));
}
