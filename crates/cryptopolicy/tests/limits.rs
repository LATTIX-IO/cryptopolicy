//! Boundary and adversarial regressions for resource limits.
#![allow(clippy::unwrap_used)] // Explicitly test fallible setup paths.

use cryptopolicy::*;

fn document() -> PolicyDocument {
    PolicyDocument::parse_json(include_bytes!("fixtures/policy-v1.json")).unwrap()
}

#[test]
fn default_limits_are_valid_and_bounded() {
    let limits = Limits::default();
    limits.validate().unwrap();
    assert_eq!(limits.max_json_bytes, MAX_CONTRACT_BYTES);
    assert!(limits.max_nesting_depth <= 128);
    assert!(limits.max_json_bytes <= ABSOLUTE_MAX_JSON_BYTES);
}

#[test]
fn exact_byte_boundary_passes_and_one_above_fails() {
    let limits = Limits {
        max_json_bytes: 6,
        ..Limits::default()
    };
    limits.check_json(b"  {}  ").unwrap();
    assert_eq!(
        limits.check_json(b"  {}   "),
        Err(ContractError::PayloadTooLarge),
    );
}

#[test]
fn exact_nested_container_boundary_and_escaped_text() {
    let mut limits = Limits {
        max_nesting_depth: 3,
        ..Limits::default()
    };
    limits.check_json(b"[[[]]]").unwrap();
    limits.max_nesting_depth = 2;
    assert_eq!(
        limits.check_json(b"[[[]]]"),
        Err(ContractError::ResourceLimitExceeded("json nesting")),
    );
    limits.max_nesting_depth = 1;
    limits
        .check_json(br#"{"text":"escaped \" { [ ] }"}"#)
        .unwrap();
}

#[test]
fn invalid_or_infinite_budget_overrides_rejected() {
    let mut limits = Limits {
        max_rules: 0,
        ..Limits::default()
    };
    assert_eq!(limits.validate(), Err(ContractError::InvalidLimit("rules")));
    limits = Limits::default();
    limits.max_json_bytes = ABSOLUTE_MAX_JSON_BYTES + 1;
    assert_eq!(
        limits.validate(),
        Err(ContractError::InvalidLimit("json bytes"))
    );
    limits = Limits::default();
    limits.max_nesting_depth = 129;
    assert_eq!(
        limits.validate(),
        Err(ContractError::InvalidLimit("nesting"))
    );
}

#[test]
fn policy_rule_count_at_limit_and_over_limit() {
    let mut value = document();
    let rule = PolicyRule {
        rule_id: RuleId::parse("r1").unwrap(),
        effect: RuleEffect::Deny,
        selector: RuleSelector {
            match_all: true,
            operation: None,
            algorithm_id: None,
            profile_id: None,
            environment: None,
        },
        requirements: vec![],
    };
    value.rules.push(rule.clone());
    let limits = Limits {
        max_rules: 1,
        ..Limits::default()
    };
    value.validate_with_limits(&limits).unwrap();
    value.rules.push(PolicyRule {
        rule_id: RuleId::parse("r2").unwrap(),
        ..rule
    });
    assert_eq!(
        value.validate_with_limits(&limits),
        Err(ContractError::ResourceLimitExceeded("policy rules")),
    );
}

#[test]
fn per_rule_requirements_and_metadata_limits() {
    let mut doc = document();
    let mut limits = Limits {
        max_requirements_per_rule: 1,
        ..Limits::default()
    };
    doc.rules.push(PolicyRule {
        rule_id: RuleId::parse("r").unwrap(),
        effect: RuleEffect::Require,
        selector: RuleSelector {
            match_all: true,
            operation: None,
            algorithm_id: None,
            profile_id: None,
            environment: None,
        },
        requirements: vec![
            Requirement::NonExportable,
            Requirement::MinSecurityCategory(3),
        ],
    });
    assert_eq!(
        doc.validate_with_limits(&limits),
        Err(ContractError::ResourceLimitExceeded(
            "requirements per rule"
        )),
    );
    doc.rules[0].requirements.pop();
    doc.validate_with_limits(&limits).unwrap();
    limits.max_metadata = 1;
    doc.metadata.push(MetadataEntry {
        key: PolicyId::parse("a").unwrap(),
        value: "1".into(),
    });
    doc.metadata.push(MetadataEntry {
        key: PolicyId::parse("b").unwrap(),
        value: "2".into(),
    });
    assert_eq!(
        doc.validate_with_limits(&limits),
        Err(ContractError::ResourceLimitExceeded("policy metadata")),
    );
}

#[test]
fn context_fact_limit_controls_deserialization() {
    let payload = br#"{"schema_version":"1","request_id":"x","operation":"sign","evaluation_time":{"unix_millis":1},"facts":[{"fact_id":"a","origin":"requested","algorithm_id":null,"profile_id":null,"evidence_ref":null,"verified":false},{"fact_id":"b","origin":"observed","algorithm_id":null,"profile_id":null,"evidence_ref":null,"verified":true}]}"#;
    let mut limits = Limits {
        max_facts: 2,
        ..Limits::default()
    };
    CryptoContext::parse_json_with_limits(payload, &limits).unwrap();
    limits.max_facts = 1;
    assert_eq!(
        CryptoContext::parse_json_with_limits(payload, &limits),
        Err(ContractError::ResourceLimitExceeded("context facts")),
    );
}

#[test]
fn decision_reason_and_evidence_count_limits() {
    let decision = PolicyDecision {
        schema_version: SchemaVersion::V1,
        policy_id: PolicyId::parse("p").unwrap(),
        policy_version: PolicyVersion::parse("1.0.0").unwrap(),
        policy_digest: PolicyDigest::try_from("a".repeat(64)).unwrap(),
        evaluated_at: EvaluationTime { unix_millis: 0 },
        outcome: DecisionOutcome::Deny,
        matched_rules: vec![RuleId::parse("r1").unwrap(), RuleId::parse("r2").unwrap()],
        reasons: vec![
            DecisionReason {
                code: ReasonCode::ExplicitDeny,
                rule_id: Some(RuleId::parse("r1").unwrap()),
            },
            DecisionReason {
                code: ReasonCode::DefaultDenied,
                rule_id: None,
            },
        ],
        evidence: vec![
            EvidenceId::parse("e1").unwrap(),
            EvidenceId::parse("e2").unwrap(),
        ],
    };
    let json = serde_json::to_vec(&decision).unwrap();
    let mut limits = Limits {
        max_decision_reasons: 2,
        ..Limits::default()
    };
    PolicyDecision::parse_json_with_limits(&json, &limits).unwrap();
    limits.max_decision_reasons = 1;
    assert_eq!(
        PolicyDecision::parse_json_with_limits(&json, &limits),
        Err(ContractError::ResourceLimitExceeded("decision reasons")),
    );
}

#[test]
fn deterministic_corrupt_input_mutations_do_not_panic() {
    let bytes = document().canonical_json().unwrap();
    let limits = Limits::default();
    for index in 0..bytes.len().min(300) {
        let mut changed = bytes.clone();
        changed[index] = 0xff;
        let _ = PolicyDocument::parse_json_with_limits(&changed, &limits);
    }
}

#[test]
fn huge_nested_payload_fails_without_unbounded_deserialization() {
    let input = format!("{}0{}", "[".repeat(100), "]".repeat(100));
    assert_eq!(
        PolicyDocument::parse_json(input.as_bytes()),
        Err(ContractError::ResourceLimitExceeded("json nesting")),
    );
}

#[test]
fn programmatically_constructed_huge_metadata_is_rejected_before_clone() {
    let mut policy = document();
    policy.metadata.push(MetadataEntry {
        key: PolicyId::parse("large").unwrap(),
        value: "x".repeat(MAX_CONTRACT_BYTES + 1),
    });
    assert_eq!(policy.canonical_json(), Err(ContractError::PayloadTooLarge),);
}
