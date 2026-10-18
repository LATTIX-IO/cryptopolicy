//! FOSS-459 runtime bindings to the immutable, specification-only security corpus.
//! These tests cover a declared subset; pending cases remain intentionally unverified.
#![allow(clippy::unwrap_used)]

use cryptopolicy::{
    AdvancedSelector, ContractError, CryptoContext, CryptoOperation, DataSensitivity,
    DecisionOutcome, EvaluationTime, PolicyDecision, PolicyDocument, ReasonCode, RuleEffect,
    RuleId, RuleTemporal, evaluate,
};
use serde_json::Value;

const CORPUS: &[u8] = include_bytes!("../../../tests/fixtures/security/contract-v1.json");
const POLICY: &[u8] = include_bytes!("fixtures/evaluator-policy-v1.json");
const CONTEXT: &[u8] = include_bytes!("fixtures/evaluator-context-v1.json");

fn spec_expected(id: &str) -> Value {
    let corpus: Value = serde_json::from_slice(CORPUS).unwrap();
    corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing normative fixture: {id}"))["expected"]
        .clone()
}

fn fixture_policy() -> PolicyDocument {
    PolicyDocument::parse_json(POLICY).unwrap()
}
fn fixture_context() -> CryptoContext {
    CryptoContext::parse_json(CONTEXT).unwrap()
}
fn at(millis: i64) -> EvaluationTime {
    EvaluationTime {
        unix_millis: millis,
    }
}
fn decide(policy: &PolicyDocument, context: &CryptoContext) -> PolicyDecision {
    evaluate(policy, context, context.evaluation_time).unwrap()
}

fn assert_decision(id: &str, decision: &PolicyDecision, outcome: DecisionOutcome) {
    let expected = spec_expected(id);
    assert_eq!(
        expected["kind"], "Decision",
        "fixture must be normative Decision: {id}"
    );
    let status = match outcome {
        DecisionOutcome::Permit => "Permit",
        DecisionOutcome::Deny => "Deny",
        DecisionOutcome::Indeterminate => "Indeterminate",
    };
    assert_eq!(decision.outcome, outcome, "runtime result differs: {id}");
    assert_eq!(
        expected["status"], status,
        "normative outcome differs: {id}"
    );
    assert_eq!(
        expected["enforcement"],
        if outcome == DecisionOutcome::Permit {
            "allow"
        } else {
            "block"
        },
        "downstream enforcement envelope not normative: {id}"
    );
    let actual_reasons: Vec<_> = decision
        .reasons
        .iter()
        .map(|r| format!("{:?}", r.code))
        .collect();
    for expected_code in expected["reason_codes"].as_array().unwrap() {
        assert!(
            actual_reasons
                .iter()
                .any(|code| Some(code.as_str()) == expected_code.as_str()),
            "{id}: normative required reason {expected_code} absent from actual {actual_reasons:?}"
        );
    }
    // The specification lists controlling reasons; the current runtime also
    // returns supplementary reasons. This subset does not claim exact ordered
    // golden conformance for all 33 cases.
}

fn hard_deny(id: &str) -> cryptopolicy::PolicyRule {
    let mut rule = fixture_policy()
        .rules
        .iter()
        .find(|r| r.effect == RuleEffect::Warn)
        .unwrap()
        .clone();
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
    assert!(
        !d.reasons
            .iter()
            .any(|r| r.code == ReasonCode::ExplicitAllow)
    );
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
    let rule = p
        .rules
        .iter_mut()
        .find(|r| r.effect == RuleEffect::Allow)
        .unwrap();
    rule.temporal = Some(RuleTemporal {
        effective_from: Some(at(200)),
        expires_at: Some(at(150)),
        deprecated_from: None,
        required_from: None,
        prohibited_from: None,
    });
    assert_eq!(spec_expected("CASE-011")["kind"], "Error");
    assert_eq!(spec_expected("CASE-011")["error_code"], "InvalidPolicy");
    assert!(matches!(
        p.validate(),
        Err(ContractError::InvalidDocument(_))
    ));
}

#[test]
fn case_027_reordered_deny_is_semantically_identical() {
    let mut p = fixture_policy();
    p.rules.push(hard_deny("runtime-case-027"));
    let expected = decide(&p, &fixture_context());
    p.rules.reverse();
    let result = decide(&p, &fixture_context());
    assert_decision("CASE-027", &result, DecisionOutcome::Deny);
    assert_eq!(
        result, expected,
        "permutation must preserve reasons and policy digest"
    );
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

// FOSS-492: direct normative error/temporal/import runtime checks.
// The published specification uses ABSTRACT error names. This suite checks the
// actual strongly typed Rust error first; it does not claim an exact runtime
// vocabulary mapping for unimplemented policy conflict / trust surfaces.

fn assert_spec_error(id: &str, expected_code: &str) {
    let expected = spec_expected(id);
    assert_eq!(expected["kind"], "Error", "{id}: not a normative error");
    assert_eq!(expected["error_code"], expected_code);
    assert_eq!(expected["enforcement"], "block");
}

#[test]
fn case_001_missing_explicit_default_effect_rejected() {
    let mut source = serde_json::to_value(fixture_policy()).unwrap();
    source.as_object_mut().unwrap().remove("default_effect");
    source["rules"] = serde_json::json!([]);
    let bytes = serde_json::to_vec(&source).unwrap();
    let error = PolicyDocument::parse_json(&bytes).unwrap_err();
    assert!(
        matches!(error, ContractError::InvalidJson(_)),
        "missing required default effect must fail parsing: {error:?}"
    );
    assert_spec_error("CASE-001", "InvalidPolicy");
}

#[test]
fn case_005_invalid_effect_type_cannot_produce_a_decision() {
    let mut source = serde_json::to_value(fixture_policy()).unwrap();
    source["rules"][0]["effect"] = serde_json::json!("permit_all");
    let error = PolicyDocument::parse_json(&serde_json::to_vec(&source).unwrap()).unwrap_err();
    assert!(matches!(error, ContractError::InvalidJson(_)));
    assert_spec_error("CASE-005", "InvalidPolicy");
}

#[test]
fn case_012_legacy_rsa_prohibition_is_inclusive_at_cutover() {
    use cryptopolicy::{AlgorithmId, ProfileId};

    let mut policy = fixture_policy();
    policy.created_at = at(0);
    policy.effective_at = None;
    policy.expires_at = None;
    let mut deny = hard_deny("foss-492-legacy-rsa-cutover");
    deny.selector.match_all = false;
    deny.selector.operation = Some(CryptoOperation::Verify);
    deny.selector.algorithm_id = None;
    deny.selector.profile_id = Some(ProfileId::parse("RSA-legacy").unwrap());
    deny.temporal = Some(RuleTemporal {
        effective_from: None,
        expires_at: None,
        deprecated_from: None,
        required_from: None,
        prohibited_from: Some(at(400)),
    });
    policy.rules.push(deny);
    let mut context = fixture_context();
    context.operation = CryptoOperation::Verify;
    context.facts[0].algorithm_id = Some(AlgorithmId::parse("RSA-legacy").unwrap());
    context.facts[0].profile_id = Some(ProfileId::parse("RSA-legacy").unwrap());

    context.evaluation_time = at(399);
    let before = decide(&policy, &context);
    assert!(
        !before
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::ExplicitDeny),
        "a time-gated prohibition must not apply before activation"
    );
    for moment in [400, 401, 800] {
        context.evaluation_time = at(moment);
        let decision = decide(&policy, &context);
        assert_decision("CASE-012", &decision, DecisionOutcome::Deny);
        assert!(decision.reasons.iter().any(|r| {
            r.code == ReasonCode::ExplicitDeny
                && r.rule_id
                    .as_ref()
                    .is_some_and(|id| id.as_str() == "foss-492-legacy-rsa-cutover")
        }));
        let before_permutation = decision.clone();
        policy.rules.reverse();
        assert_eq!(decide(&policy, &context), before_permutation);
    }
}

#[test]
fn case_022_cyclic_pinned_policy_imports_fail_before_decision() {
    use cryptopolicy::{
        CompositionError, Limits, PolicyId, PolicyNode, PolicyReference, PolicySet, SchemaVersion,
        compile_policy_set,
    };
    let document_a = fixture_policy();
    let mut document_b = fixture_policy();
    document_b.policy_id = PolicyId::parse("foss-492-policy-b").unwrap();
    let reference_a = PolicyReference::from_document(&document_a).unwrap();
    let reference_b = PolicyReference::from_document(&document_b).unwrap();
    let set = PolicySet {
        schema_version: SchemaVersion::V1,
        baseline: reference_a.clone(),
        overlays: vec![],
    };
    let node_a = PolicyNode {
        schema_version: SchemaVersion::V1,
        document: document_a,
        imports: vec![reference_b.clone()],
    };
    let node_b = PolicyNode {
        schema_version: SchemaVersion::V1,
        document: document_b,
        imports: vec![reference_a.clone()],
    };
    let resolver = |r: &PolicyReference| {
        Ok::<Option<PolicyNode>, CompositionError>(if *r == reference_a {
            Some(node_a.clone())
        } else if *r == reference_b {
            Some(node_b.clone())
        } else {
            None
        })
    };
    let failure = compile_policy_set(&set, &resolver, &Limits::default()).unwrap_err();
    assert_eq!(failure, CompositionError::CycleDetected);
    assert_spec_error("CASE-022", "ImportCycle");
}

#[test]
fn case_024_oversized_policy_input_exceeds_bounded_parser_budget() {
    use cryptopolicy::Limits;
    let bytes = serde_json::to_vec(&fixture_policy()).unwrap();
    let limits = Limits {
        max_json_bytes: bytes.len() - 1,
        ..Limits::default()
    };
    assert_eq!(bytes.len(), limits.max_json_bytes + 1);
    let failure = PolicyDocument::parse_json_with_limits(&bytes, &limits).unwrap_err();
    assert_eq!(failure, ContractError::PayloadTooLarge);
    assert_spec_error("CASE-024", "ResourceLimitExceeded");
}

#[test]
fn case_025_overdeep_import_graph_fails_before_effective_policy() {
    use cryptopolicy::{
        CompositionError, Limits, PolicyId, PolicyNode, PolicyReference, PolicySet, SchemaVersion,
        compile_policy_set,
    };
    let policies: Vec<_> = (0..3)
        .map(|i| {
            let mut policy = fixture_policy();
            policy.policy_id = PolicyId::parse(&format!("foss-492-node-{i}")).unwrap();
            policy
        })
        .collect();
    let references: Vec<_> = policies
        .iter()
        .map(|p| PolicyReference::from_document(p).unwrap())
        .collect();
    let nodes: Vec<_> = policies
        .into_iter()
        .enumerate()
        .map(|(i, document)| PolicyNode {
            schema_version: SchemaVersion::V1,
            document,
            imports: references.get(i + 1).cloned().into_iter().collect(),
        })
        .collect();
    let set = PolicySet {
        schema_version: SchemaVersion::V1,
        baseline: references[0].clone(),
        overlays: vec![],
    };
    let limits = Limits {
        max_import_depth: 1,
        ..Limits::default()
    };
    let resolver = |r: &PolicyReference| {
        Ok::<Option<PolicyNode>, CompositionError>(
            nodes
                .iter()
                .find(|node| node.document.policy_id == r.policy_id)
                .cloned(),
        )
    };
    let failure = compile_policy_set(&set, &resolver, &limits).unwrap_err();
    assert_eq!(failure, CompositionError::ResourceLimit("import_depth"));
    assert_spec_error("CASE-025", "ResourceLimitExceeded");
}

#[test]
fn unknown_critical_policy_field_fails_closed_but_error_vocabulary_is_not_yet_exact() {
    // CASE-030 expects UnsupportedSchema. The runtime currently returns
    // InvalidJson for unknown fields, so CASE-030 remains deliberately pending.
    let mut source = serde_json::to_value(fixture_policy()).unwrap();
    source["override_deny_silently"] = serde_json::json!(true);
    assert!(matches!(
        PolicyDocument::parse_json(&serde_json::to_vec(&source).unwrap()),
        Err(ContractError::InvalidJson(_))
    ));
}
