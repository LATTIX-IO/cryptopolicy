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

// FOSS-493/A: real library assessments and typed, non-authorizing reason
// projections for the exact missing-evidence vocabulary. These projections
// are not policy authorization tokens, signatures or proof of source trust.

fn assert_spec_indeterminate(id: &str, actual: DecisionOutcome, code: ReasonCode) {
    let expected = spec_expected(id);
    assert_eq!(expected["kind"], "Decision");
    assert_eq!(expected["status"], "Indeterminate");
    assert_eq!(expected["enforcement"], "block");
    assert_eq!(actual, DecisionOutcome::Indeterminate);
    let expected_reasons = expected["reason_codes"].as_array().unwrap();
    let code_name = format!("{code:?}");
    assert!(
        expected_reasons
            .iter()
            .any(|r| r.as_str() == Some(code_name.as_str()))
    );
}

#[test]
fn case_014_unknown_vendor_alias_is_indeterminate() {
    use cryptopolicy::AlgorithmId;

    let unknown = AlgorithmId::parse("AES-256-GCM-vendor-unknown").unwrap();
    let mut policy = fixture_policy();
    let allow = policy
        .rules
        .iter_mut()
        .find(|r| r.effect == RuleEffect::Allow)
        .unwrap();
    allow.selector.algorithm_id = Some(unknown.clone());
    for requirement in &mut allow.requirements {
        if let cryptopolicy::Requirement::Algorithm(algorithm) = requirement {
            *algorithm = unknown.clone();
        }
    }
    let mut c = fixture_context();
    c.facts[0].algorithm_id = Some(unknown);
    let d = decide(&policy, &c);
    assert_decision("CASE-014", &d, DecisionOutcome::Indeterminate);
    assert!(
        d.reasons
            .iter()
            .any(|r| r.code == ReasonCode::UnsupportedProfile)
    );
}

#[test]
fn case_016_installed_dependency_is_not_executed_crypto() {
    use cryptopolicy::{
        AssessmentContext, AssessmentReason, ObservationKind, UnverifiedEvidence, assess,
        assessment_missing_required_attribute,
    };
    let context =
        AssessmentContext::parse_json(include_bytes!("fixtures/assessment-dependency-v1.json"))
            .unwrap();
    assert_eq!(context.observations.len(), 1);
    assert_eq!(
        context.observations[0].kind,
        ObservationKind::InstalledDependency
    );
    assert!(!context.observations[0].kind.is_operational());
    let report = assess(
        &fixture_policy(),
        &context,
        context.evaluation_time,
        &UnverifiedEvidence,
    )
    .unwrap();
    assert_eq!(report.outcome, DecisionOutcome::Indeterminate);
    assert!(
        report
            .reasons
            .contains(&AssessmentReason::NoOperationalObservation)
    );
    let projection = assessment_missing_required_attribute(&report);
    assert_eq!(projection, Some(ReasonCode::MissingRequiredAttribute));
    assert_spec_indeterminate("CASE-016", report.outcome, projection.unwrap());

    let mut forged = report.clone();
    forged.outcome = DecisionOutcome::Permit;
    assert_eq!(assessment_missing_required_attribute(&forged), None);
}

#[test]
fn case_017_partial_inventory_with_no_observations_is_incomplete() {
    use cryptopolicy::{
        AssessmentContext, AssessmentCoverage, AssessmentReason, UnverifiedEvidence, assess,
        assessment_missing_required_attribute,
    };
    let mut context =
        AssessmentContext::parse_json(include_bytes!("fixtures/assessment-partial-v1.json"))
            .unwrap();
    context.observations.clear();
    context.uninspected_sources.clear();
    assert_eq!(context.coverage, AssessmentCoverage::Partial);
    assert!(context.observations.is_empty());
    let report = assess(
        &fixture_policy(),
        &context,
        context.evaluation_time,
        &UnverifiedEvidence,
    )
    .unwrap();
    assert_eq!(report.outcome, DecisionOutcome::Indeterminate);
    assert!(
        report
            .reasons
            .contains(&AssessmentReason::CoverageIncomplete)
    );
    assert!(
        report
            .reasons
            .contains(&AssessmentReason::NoOperationalObservation)
    );
    let projection = assessment_missing_required_attribute(&report);
    assert_eq!(projection, Some(ReasonCode::MissingRequiredAttribute));
    assert_spec_indeterminate("CASE-017", report.outcome, projection.unwrap());
}

#[test]
fn case_018_configured_tls_suite_is_not_a_negotiated_session() {
    use cryptopolicy::{
        AssessmentContext, AssessmentReason, ObservationKind, ProfileId, UnverifiedEvidence,
        assess, assessment_missing_required_attribute,
    };
    let mut context =
        AssessmentContext::parse_json(include_bytes!("fixtures/assessment-configured-v1.json"))
            .unwrap();
    assert_eq!(context.observations.len(), 1);
    context.observations[0].profile_id = Some(ProfileId::parse("TLS_AES_256_GCM_SHA384").unwrap());
    assert_eq!(context.observations[0].kind, ObservationKind::Configuration);
    assert!(!context.observations[0].kind.is_operational());
    let report = assess(
        &fixture_policy(),
        &context,
        context.evaluation_time,
        &UnverifiedEvidence,
    )
    .unwrap();
    assert_eq!(report.outcome, DecisionOutcome::Indeterminate);
    assert!(
        report
            .reasons
            .contains(&AssessmentReason::NoOperationalObservation)
    );
    let projection = assessment_missing_required_attribute(&report);
    assert_eq!(projection, Some(ReasonCode::MissingRequiredAttribute));
    assert_spec_indeterminate("CASE-018", report.outcome, projection.unwrap());
}

#[test]
fn case_019_hsm_provider_claim_without_attestation_is_not_verified() {
    use cryptopolicy::{
        AssuranceClaim, CapabilityReason, KeyRequest, ProviderCapabilityClaim,
        ProviderCapabilitySnapshot, ProviderVerification, assess_key_capabilities,
        capability_missing_required_attribute,
    };
    let request = KeyRequest::parse_json(include_bytes!("fixtures/request-v1.json")).unwrap();
    let mut snapshot = ProviderCapabilitySnapshot::parse_json(include_bytes!(
        "fixtures/provider-supported-v1.json"
    ))
    .unwrap();
    assert_eq!(snapshot.claims.len(), 1);
    snapshot.claims[0].assurance = Some(AssuranceClaim::ProviderAsserted);
    snapshot.claims[0].assurance_ref = None;
    // Exercise the missing independent HSM attestation AFTER the source
    // authentication gate. A test verifier is not production proof.
    let authenticated_source_without_assurance =
        |_: &KeyRequest, _: &ProviderCapabilitySnapshot, _: &ProviderCapabilityClaim| {
            Ok(ProviderVerification {
                source_authenticated: true,
                assurance_authenticated: false,
            })
        };
    let report =
        assess_key_capabilities(&request, &snapshot, &authenticated_source_without_assurance)
            .unwrap();
    assert_eq!(report.outcome, DecisionOutcome::Indeterminate);
    assert!(
        report
            .reasons
            .contains(&CapabilityReason::AssuranceNotVerified)
    );
    assert!(report.findings[0].source_authenticated);
    assert!(!report.findings[0].assurance_authenticated);
    let projection = capability_missing_required_attribute(&report);
    assert_eq!(projection, Some(ReasonCode::MissingRequiredAttribute));
    assert_spec_indeterminate("CASE-019", report.outcome, projection.unwrap());

    let mut forged = report.clone();
    forged.outcome = DecisionOutcome::Deny;
    assert_eq!(capability_missing_required_attribute(&forged), None);
}

#[test]
fn malformed_unnamed_hybrid_shapes_fail_closed_without_claiming_case_029() {
    let mut source = serde_json::to_value(fixture_policy()).unwrap();
    source["profile"] = serde_json::json!({"hybrid":true,"construction":null});
    assert!(matches!(
        PolicyDocument::parse_json(&serde_json::to_vec(&source).unwrap()),
        Err(ContractError::InvalidJson(_))
    ));

    // Even when the author chooses the declared named_hybrid requirement
    // discriminator, an absent exact profile value cannot validate.
    let mut malformed = serde_json::to_value(fixture_policy()).unwrap();
    malformed["rules"][0]["requirements"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"kind":"named_hybrid","value":null}));
    assert!(matches!(
        PolicyDocument::parse_json(&serde_json::to_vec(&malformed).unwrap()),
        Err(ContractError::InvalidJson(_))
    ));
    // CASE-029 is not counted by FOSS-493/A: the schema has no generic
    // hybrid policy DTO and so cannot yet prove the exact normative scenario.
}


// FOSS-501/A: three exact negative-path security cases with real policy
// execution, typed E0 approval validation, and immutable blocked receipts.
// Synthetic test policy and UTC fixtures carry NO production signing claims.

fn legacy_rsa_denial_fixture() -> (
    cryptopolicy::EffectivePolicy,
    cryptopolicy::CryptoContext,
    cryptopolicy::ExceptionReference,
    cryptopolicy::PolicyWaiverGrant,
) {
    use cryptopolicy::{
        AlgorithmId, CompositionError, EvidenceId, ExceptionDeviation,
        ExceptionReference, PolicyNode, PolicyReference, PolicySet, PolicyWaiverGrant,
        SchemaVersion, compile_policy_set,
    };
    let mut policy = fixture_policy();
    policy.effective_at = None;
    policy.expires_at = None;
    let mut rule = hard_deny("r-normative-rsa-deny");
    rule.selector.match_all = false;
    rule.selector.operation = Some(CryptoOperation::Verify);
    rule.selector.algorithm_id = Some(AlgorithmId::parse("RSA-legacy").unwrap());
    policy.rules.push(rule);
    let reference = PolicyReference::from_document(&policy).unwrap();
    let node = PolicyNode {
        schema_version: SchemaVersion::V1,
        document: policy,
        imports: vec![],
    };
    let set = PolicySet {
        schema_version: SchemaVersion::V1,
        baseline: reference.clone(),
        overlays: vec![],
    };
    let resolver = |r: &PolicyReference| {
        Ok::<Option<PolicyNode>, CompositionError>(
            if *r == reference { Some(node.clone()) } else { None },
        )
    };
    let effective = compile_policy_set(&set, &resolver, &cryptopolicy::Limits::default()).unwrap();
    let mut context = fixture_context();
    context.operation = CryptoOperation::Verify;
    context.evaluation_time = at(1_792_108_800_000); // 2026-10-16T00:00:00Z
    context.facts[0].algorithm_id = Some(AlgorithmId::parse("RSA-legacy").unwrap());
    let mut exception = ExceptionReference::parse_json(include_bytes!(
        "fixtures/exception-reference-v1.json"
    )).unwrap();
    exception.policy = reference.clone();
    exception.target_rule = RuleId::parse("r-normative-rsa-deny").unwrap();
    exception.scope.operation = CryptoOperation::Verify;
    exception.scope.algorithm_id = AlgorithmId::parse("RSA-legacy").unwrap();
    exception.deviation = ExceptionDeviation::RuleDeny;
    exception.issued_at = at(1_735_689_600_000); // 2025-01-01
    exception.effective_at = at(1_735_689_600_000);
    exception.expires_at = at(1_798_761_600_000); // 2027-01-01
    let grant = PolicyWaiverGrant {
        schema_version: SchemaVersion::V1,
        policy: reference,
        target_rule: exception.target_rule.clone(),
        exception_id: exception.exception_id.clone(),
        exception_digest: exception.correlation_digest().unwrap(),
        policy_authority_ref: EvidenceId::parse("owner:approval:synthetic").unwrap(),
        deviation: ExceptionDeviation::RuleDeny,
        scope: exception.scope.clone(),
        compensating_controls: exception.compensating_controls.clone(),
        authorized_at: at(1_735_689_600_000),
        expires_at: at(1_798_761_600_000),
    };
    (effective, context, exception, grant)
}
fn audited_negative(
    graph: &cryptopolicy::EffectivePolicy,
    context: &CryptoContext,
    exception: &cryptopolicy::ExceptionReference,
    grant: &cryptopolicy::PolicyWaiverGrant,
    actual_scope: &cryptopolicy::ExceptionScope,
) -> cryptopolicy::BlockedExceptionAuditReceipt {
    use cryptopolicy::{
        ExceptionBoundContext, Limits, UnverifiedExceptionReferences,
        UnverifiedPolicyWaiverAuthority, WaiverCandidateRequest,
        build_blocked_exception_audit_receipt, evaluate_deny_waiver_candidate,
    };
    let report = evaluate_deny_waiver_candidate(
        WaiverCandidateRequest {
            effective: graph, context, actual_scope,
            time: context.evaluation_time,
            exception, grant, limits: &Limits::default(),
        },
        &UnverifiedExceptionReferences, &UnverifiedPolicyWaiverAuthority,
    ).unwrap();
    let bound = ExceptionBoundContext {
        policy: exception.policy.clone(),
        target_rule: exception.target_rule.clone(),
        scope: actual_scope.clone(),
        evaluation_time: context.evaluation_time,
    };
    build_blocked_exception_audit_receipt(
        &report, exception, &bound, &Limits::default()
    ).unwrap()
}

#[test]
fn case_008_expired_exception_preserves_legacy_rsa_explicit_deny() {
    use cryptopolicy::{
        BlockedExceptionEnforcement, ExceptionReferenceFinding,
    };
    let (graph, context, mut exception, mut grant) = legacy_rsa_denial_fixture();
    exception.expires_at = at(1_767_225_600_000); // 2026-01-01T00:00:00Z
    grant.exception_digest = exception.correlation_digest().unwrap();
    let receipt = audited_negative(&graph, &context, &exception, &grant, &exception.scope);
    let original = graph.evaluate(&context, context.evaluation_time,
                                  &cryptopolicy::Limits::default()).unwrap();
    assert_decision("CASE-008", &original.components[0].decision, DecisionOutcome::Deny);
    assert_eq!(receipt.reference_finding, ExceptionReferenceFinding::Expired);
    assert_eq!(receipt.enforcement, BlockedExceptionEnforcement::Block);
    assert_eq!(receipt.original_outcome, DecisionOutcome::Deny);
    assert_eq!(receipt.candidate_outcome, DecisionOutcome::Deny);
    assert!(receipt.blocking_reasons.iter().any(|r| {
        r.code == ReasonCode::ExplicitDeny
            && r.rule_id.as_ref() == Some(&exception.target_rule)
    }));
    assert_eq!(receipt.correlation_digest().unwrap(), receipt.correlation_digest().unwrap());
}

#[test]
fn case_009_other_tenant_exception_cannot_waive_explicit_deny() {
    use cryptopolicy::{
        BlockedExceptionEnforcement, ExceptionReferenceFinding, PolicyId,
    };
    let (graph, context, exception, grant) = legacy_rsa_denial_fixture();
    let mut requested_scope = exception.scope.clone();
    requested_scope.tenant_id = PolicyId::parse("tenant-b").unwrap();
    let receipt = audited_negative(&graph, &context, &exception, &grant, &requested_scope);
    let original = graph.evaluate(&context, context.evaluation_time,
                                  &cryptopolicy::Limits::default()).unwrap();
    assert_decision("CASE-009", &original.components[0].decision, DecisionOutcome::Deny);
    assert_eq!(receipt.reference_finding, ExceptionReferenceFinding::OutOfScope);
    assert_eq!(receipt.enforcement, BlockedExceptionEnforcement::Block);
    assert_eq!(receipt.candidate_outcome, DecisionOutcome::Deny);
    assert!(receipt.blocking_reasons.iter().any(|r| r.code == ReasonCode::ExplicitDeny));
}

#[test]
fn case_010_unverified_approver_missing_evidence_is_typed_invalid_exception() {
    use cryptopolicy::{
        ExceptionAuditError, ExceptionBoundContext, Limits,
        UnverifiedExceptionReferences, validate_verified_exception_reference,
    };
    let (_, context, exception, _) = legacy_rsa_denial_fixture();
    let mut input = serde_json::to_value(&exception).unwrap();
    input["approver"] = serde_json::json!("unverified-string");
    input["approval_ref"] = serde_json::Value::Null;
    let bound = ExceptionBoundContext {
        policy: exception.policy.clone(),
        target_rule: exception.target_rule.clone(),
        scope: exception.scope.clone(),
        evaluation_time: context.evaluation_time,
    };
    let outcome = validate_verified_exception_reference(
        &serde_json::to_vec(&input).unwrap(), &bound,
        &UnverifiedExceptionReferences, &Limits::default(),
    );
    assert_eq!(outcome, Err(ExceptionAuditError::InvalidException));
    assert_spec_error("CASE-010", "InvalidException");

    // An apparently valid identifier without independent approval also fails.
    input["approval_ref"] = serde_json::json!("approval:unverified");
    let result = validate_verified_exception_reference(
        &serde_json::to_vec(&input).unwrap(), &bound,
        &UnverifiedExceptionReferences, &Limits::default(),
    );
    assert_eq!(result, Err(ExceptionAuditError::InvalidException));
}
