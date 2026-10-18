//! FOSS-459 runtime bindings to the immutable, specification-only security corpus.
//! These tests cover a declared subset; pending cases remain intentionally unverified.
#![allow(clippy::unwrap_used)]

use cryptopolicy::{
    AdvancedSelector, AlgorithmId, ContractError, CryptoContext, CryptoOperation, DataSensitivity,
    DecisionOutcome, EvaluationTime, PolicyDecision, PolicyDocument, ProfileId, ReasonCode,
    RuleEffect, RuleId, RuleTemporal, evaluate,
};
use serde_json::Value;

const CORPUS: &[u8] = include_bytes!("../../../tests/fixtures/security/contract-v1.json");
const POLICY: &[u8] = include_bytes!("fixtures/evaluator-policy-v1.json");
const CONTEXT: &[u8] = include_bytes!("fixtures/evaluator-context-v1.json");

fn spec_expected(id: &str) -> Value {
    let corpus: Value = serde_json::from_slice(CORPUS).unwrap();
    corpus["cases"].as_array().unwrap().iter()
        .find(|c| c["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing normative fixture: {id}"))
        ["expected"].clone()
}

fn fixture_policy() -> PolicyDocument {
    PolicyDocument::parse_json(POLICY).unwrap()
}
fn fixture_context() -> CryptoContext {
    CryptoContext::parse_json(CONTEXT).unwrap()
}
fn at(millis: i64) -> EvaluationTime {
    EvaluationTime { unix_millis: millis }
}
fn decide(policy: &PolicyDocument, context: &CryptoContext) -> PolicyDecision {
    evaluate(policy, context, context.evaluation_time).unwrap()
}

fn assert_decision(id: &str, decision: &PolicyDecision, outcome: DecisionOutcome) {
    let expected = spec_expected(id);
    assert_eq!(expected["kind"], "Decision", "fixture must be normative Decision: {id}");
    let status = match outcome {
        DecisionOutcome::Permit => "Permit",
        DecisionOutcome::Deny => "Deny",
        DecisionOutcome::Indeterminate => "Indeterminate",
    };
    assert_eq!(decision.outcome, outcome, "runtime result differs: {id}");
    assert_eq!(expected["status"], status, "normative outcome differs: {id}");
    assert_eq!(
        expected["enforcement"],
        if outcome == DecisionOutcome::Permit { "allow" } else { "block" },
        "downstream enforcement envelope not normative: {id}"
    );
    let actual_reasons: Vec<_> = decision.reasons.iter().map(|r| format!("{:?}", r.code)).collect();
    for expected_code in expected["reason_codes"].as_array().unwrap() {
        assert!(
            actual_reasons.iter().any(|code| Some(code.as_str()) == expected_code.as_str()),
            "{id}: normative required reason {expected_code} absent from actual {actual_reasons:?}"
        );
    }
    // The specification lists controlling reasons; the current runtime also
    // returns supplementary reasons. This subset does not claim exact ordered
    // golden conformance for all 33 cases.
}

fn hard_deny(id: &str) -> cryptopolicy::PolicyRule {
    let mut rule = fixture_policy().rules.iter()
        .find(|r| r.effect == RuleEffect::Warn).unwrap().clone();
    rule.rule_id = RuleId::parse(id).unwrap();
    rule.effect = RuleEffect::Deny;
    rule.selector.match_all = true;
    rule.selector.operation = None;
    rule.selector.algorithm_id = None;
    rule.selector.profile_id = None;
    rule.selector.advanced = None;
    rule.requirements.clear();
    rule.temporal = None;
    rule
}

#[test]
fn case_002_unmatched_default_deny() {
    let mut p = fixture_policy();
    p.rules.clear();
    let d = decide(&p, &fixture_context());
    assert_decision("CASE-002", &d, DecisionOutcome::Deny);
    assert_eq!(d.reasons[0].code, ReasonCode::DefaultDenied);
}

#[test]
fn case_003_explicit_deny_overrides_allow() {
    let mut p = fixture_policy();
    p.rules.push(hard_deny("runtime-case-003"));
    let d = decide(&p, &fixture_context());
    assert_decision("CASE-003", &d, DecisionOutcome::Deny);
    assert!(!d.reasons.iter().any(|r| r.code == ReasonCode::ExplicitAllow));
}

#[test]
fn case_004_missing_classification_in_potential_deny_is_indeterminate() {
    let mut p = fixture_policy();
    let mut deny = hard_deny("runtime-case-004");
    deny.selector.match_all = false;
    deny.selector.operation = Some(CryptoOperation::Encrypt);
    deny.selector.advanced = Some(AdvancedSelector {
        data_sensitivity: Some(DataSensitivity::Restricted),
        ..AdvancedSelector::default()
    });
    p.rules.push(deny);
    let mut c = fixture_context();
    c.facts[0].properties.as_mut().unwrap().data_sensitivity = None;
    assert_decision("CASE-004", &decide(&p, &c), DecisionOutcome::Indeterminate);
}

#[test]
fn case_006_missing_hsm_protection_is_indeterminate() {
    let p = fixture_policy();
    let mut c = fixture_context();
    c.facts[0].properties.as_mut().unwrap().key_protection = None;
    let decision = decide(&p, &c);
    assert_decision("CASE-006", &decision, DecisionOutcome::Indeterminate);
}

#[test]
fn case_011_invalid_rule_interval_is_rejected() {
    let mut p = fixture_policy();
    let rule = p.rules.iter_mut().find(|r| r.effect == RuleEffect::Allow).unwrap();
    rule.temporal = Some(RuleTemporal {
        effective_from: Some(at(200)), expires_at: Some(at(150)),
        deprecated_from: None, required_from: None, prohibited_from: None,
    });
    assert_eq!(spec_expected("CASE-011")["kind"], "Error");
    assert_eq!(spec_expected("CASE-011")["error_code"], "InvalidPolicy");
    assert!(matches!(p.validate(), Err(ContractError::InvalidDocument(_))));
}

#[test]
fn case_027_reordered_deny_is_semantically_identical() {
    let mut p = fixture_policy();
    p.rules.push(hard_deny("runtime-case-027"));
    let expected = decide(&p, &fixture_context());
    p.rules.reverse();
    let result = decide(&p, &fixture_context());
    assert_decision("CASE-027", &result, DecisionOutcome::Deny);
    assert_eq!(result, expected, "permutation must preserve reasons and policy digest");
}

#[test]
fn case_032_reversed_rule_file_order_preserves_deny() {
    let mut p = fixture_policy();
    p.rules.insert(0, hard_deny("runtime-case-032"));
    let forward = decide(&p, &fixture_context());
    p.rules.reverse();
    let reverse = decide(&p, &fixture_context());
    assert_decision("CASE-032", &reverse, DecisionOutcome::Deny);
    assert_eq!(reverse, forward);
}

#[test]
fn case_033_complete_fixture_positive_control_is_permit() {
    // The fixture describes an HSM-related claim. This library cannot itself
    // authenticate the source or grant an enforcement capability.
    let d = decide(&fixture_policy(), &fixture_context());
    assert_decision("CASE-033", &d, DecisionOutcome::Permit);
    assert_eq!(
        d.reasons.iter().map(|r| r.code).collect::<Vec<_>>(),
        vec![ReasonCode::ExplicitAllow, ReasonCode::RequirementSatisfied]
    );
}

#[test]
fn claimed_coverage_is_not_an_independent_trust_attestation() {
    // A positive decision is pure data. Claims of external verification do
    // not authenticate the caller or enforce an operation.
    let mut p = fixture_policy();
    let mut context = fixture_context();
    context.facts[0].verified = false;
    context.facts[0].properties.as_mut().unwrap().source_quality =
        Some(cryptopolicy::EvidenceQuality::Unverified);
    let d = decide(&p, &context);
    assert_ne!(d.outcome, DecisionOutcome::Permit);
    p.rules.reverse();
    assert_ne!(decide(&p, &context).outcome, DecisionOutcome::Permit);
}
