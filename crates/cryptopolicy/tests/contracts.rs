//! Integration and regression tests for the versioned cryptographic policy contract.
#![allow(clippy::unwrap_used)] // Test fixtures use fallible construction deliberately.

use cryptopolicy::*;

fn sample() -> PolicyDocument {
    PolicyDocument {
        schema_version: SchemaVersion::V1,
        policy_id: PolicyId::parse("org:baseline").unwrap(),
        version: PolicyVersion::parse("1.0.0").unwrap(),
        issuer: Issuer {
            subject: "test-organization".into(),
            assurance_ref: None,
        },
        created_at: EvaluationTime { unix_millis: 0 },
        effective_at: None,
        expires_at: Some(EvaluationTime { unix_millis: 200 }),
        default_effect: DefaultEffect::Deny,
        rules: vec![
            PolicyRule {
                rule_id: RuleId::parse("rule-z").unwrap(),
                effect: RuleEffect::Deny,
                selector: RuleSelector {
                    match_all: false,
                    operation: Some(CryptoOperation::Encrypt),
                    algorithm_id: None,
                    profile_id: None,
                    environment: None,
                    advanced: None,
                },
                requirements: vec![Requirement::NonExportable],
                temporal: None,
            },
            PolicyRule {
                rule_id: RuleId::parse("rule-a").unwrap(),
                effect: RuleEffect::Require,
                selector: RuleSelector {
                    match_all: true,
                    operation: None,
                    algorithm_id: None,
                    profile_id: None,
                    environment: None,
                    advanced: None,
                },
                requirements: vec![
                    Requirement::MinSecurityCategory(3),
                    Requirement::Algorithm(AlgorithmId::parse("ML-KEM-1024").unwrap()),
                ],
                temporal: None,
            },
        ],
        metadata: vec![
            MetadataEntry {
                key: PolicyId::parse("z").unwrap(),
                value: "last".into(),
            },
            MetadataEntry {
                key: PolicyId::parse("a").unwrap(),
                value: "first".into(),
            },
        ],
    }
}

#[test]
fn canonical_round_trip_and_fixed_policy_identity() {
    let before = sample();
    let encoded = before.canonical_json().unwrap();
    let after = PolicyDocument::parse_json(&encoded).unwrap();
    assert_eq!(after.policy_id, before.policy_id);
    assert_eq!(after.default_effect, DefaultEffect::Deny);
    assert_eq!(after.canonical_digest(), before.canonical_digest());
    assert_eq!(after.rules.len(), 2);
}

#[test]
fn order_of_rules_metadata_and_conjunctive_requirements_does_not_change_digest() {
    let before = sample();
    let mut shuffled = before.clone();
    shuffled.rules.reverse();
    shuffled.metadata.reverse();
    shuffled.rules[1].requirements.reverse();
    assert_eq!(
        before.canonical_json().unwrap(),
        shuffled.canonical_json().unwrap()
    );
    assert_eq!(
        before.canonical_digest().unwrap(),
        shuffled.canonical_digest().unwrap()
    );
}

#[test]
fn semantic_change_changes_policy_digest() {
    let before = sample();
    let mut after = before.clone();
    after.default_effect = DefaultEffect::Allow;
    assert_ne!(
        before.canonical_digest().unwrap(),
        after.canonical_digest().unwrap()
    );
}

#[test]
fn reject_missing_default_unknown_fields_and_duplicate_json_keys() {
    let encoded = String::from_utf8(sample().canonical_json().unwrap()).unwrap();
    let removed = encoded.replace("\"default_effect\":\"deny\",", "");
    assert!(PolicyDocument::parse_json(removed.as_bytes()).is_err());
    let extra = encoded.replace(
        "\"default_effect\":\"deny\"",
        "\"default_effect\":\"deny\",\"bypass_denial\":true",
    );
    assert!(PolicyDocument::parse_json(extra.as_bytes()).is_err());
    let duplicate = encoded.replace(
        "\"default_effect\":\"deny\"",
        "\"default_effect\":\"deny\",\"default_effect\":\"allow\"",
    );
    assert!(PolicyDocument::parse_json(duplicate.as_bytes()).is_err());
}

#[test]
fn reject_unknown_schema_and_unknown_enum_variant() {
    let encoded = String::from_utf8(sample().canonical_json().unwrap()).unwrap();
    let version = encoded.replace("\"schema_version\":\"1\"", "\"schema_version\":\"2\"");
    assert!(PolicyDocument::parse_json(version.as_bytes()).is_err());
    let bogus = encoded.replace(
        "\"default_effect\":\"deny\"",
        "\"default_effect\":\"magic\"",
    );
    assert!(PolicyDocument::parse_json(bogus.as_bytes()).is_err());
}

#[test]
fn reject_invalid_identifiers_and_versions() {
    for id in ["", " bad", "-start", "policy:🐱"] {
        assert!(PolicyId::parse(id).is_err());
    }
    assert!(PolicyId::parse(&"a".repeat(129)).is_err());
    for version in [
        "1.0",
        "01.0.0",
        "+1.0.0",
        "1.+1.0",
        "1.0.+2",
        "1.0.0-beta",
        "1.0.4294967296",
    ] {
        assert!(PolicyVersion::parse(version).is_err());
    }
}

#[test]
fn reject_bad_time_range_duplicate_rule_and_ambiguous_selectors() {
    let mut invalid_time = sample();
    invalid_time.expires_at = Some(EvaluationTime { unix_millis: 0 });
    assert!(invalid_time.validate().is_err());
    let mut duplicate = sample();
    duplicate.rules[0].rule_id = duplicate.rules[1].rule_id.clone();
    assert_eq!(
        duplicate.validate(),
        Err(ContractError::DuplicateIdentifier)
    );
    let mut ambiguous = sample();
    ambiguous.rules[0].selector.match_all = true;
    assert!(ambiguous.validate().is_err());
}

#[test]
fn reject_invalid_category_and_oversized_json() {
    let mut invalid = sample();
    invalid.rules[0]
        .requirements
        .push(Requirement::MinSecurityCategory(6));
    assert!(invalid.validate().is_err());
    let attack = vec![b'a'; MAX_CONTRACT_BYTES + 1];
    assert_eq!(
        PolicyDocument::parse_json(&attack).unwrap_err(),
        ContractError::PayloadTooLarge,
    );
}

#[test]
fn preserve_fact_origin_without_equating_capability_to_usage() {
    let context = CryptoContext {
        schema_version: SchemaVersion::V1,
        request_id: RequestId::parse("req:1").unwrap(),
        operation: CryptoOperation::Encrypt,
        evaluation_time: EvaluationTime { unix_millis: 100 },
        environment: None,
        facts: vec![
            CryptoFact {
                fact_id: EvidenceId::parse("e1").unwrap(),
                origin: FactOrigin::Configured,
                algorithm_id: Some(AlgorithmId::parse("AES-256-GCM").unwrap()),
                profile_id: None,
                evidence_ref: None,
                verified: false,
                properties: None,
            },
            CryptoFact {
                fact_id: EvidenceId::parse("e2").unwrap(),
                origin: FactOrigin::ProviderCapability,
                algorithm_id: None,
                profile_id: None,
                evidence_ref: None,
                verified: false,
                properties: None,
            },
        ],
    };
    let serialized = serde_json::to_vec(&context).unwrap();
    let round_trip = CryptoContext::parse_json(&serialized).unwrap();
    assert_eq!(round_trip.facts[0].origin, FactOrigin::Configured);
    assert_eq!(round_trip.facts[1].origin, FactOrigin::ProviderCapability);
    assert!(!round_trip.facts[0].verified);
}

#[test]
fn context_duplicate_evidence_id_rejected() {
    let raw = br#"{"schema_version":"1","request_id":"req","operation":"sign","evaluation_time":{"unix_millis":1},"facts":[{"fact_id":"same","origin":"observed","algorithm_id":null,"profile_id":null,"evidence_ref":null,"verified":true},{"fact_id":"same","origin":"inferred","algorithm_id":null,"profile_id":null,"evidence_ref":null,"verified":false}]}"#;
    assert_eq!(
        CryptoContext::parse_json(raw),
        Err(ContractError::DuplicateIdentifier)
    );
}

#[test]
fn parse_versioned_golden_example() {
    let document = PolicyDocument::parse_json(include_bytes!("fixtures/policy-v1.json")).unwrap();
    assert_eq!(document.default_effect, DefaultEffect::Deny);
    assert_eq!(document.canonical_digest().unwrap().as_str().len(), 64);
}

#[test]
fn golden_canonical_wire_encoding_and_sha256_are_stable() {
    let parsed = PolicyDocument::parse_json(include_bytes!("fixtures/policy-v1.json")).unwrap();
    let expected = concat!(
        "{\"schema_version\":\"1\",\"policy_id\":\"org:bootstrap\",",
        "\"version\":\"1.0.0\",\"issuer\":{\"subject\":\"example-org\",",
        "\"assurance_ref\":null},\"created_at\":{\"unix_millis\":0},",
        "\"effective_at\":null,\"expires_at\":null,\"default_effect\":\"deny\",",
        "\"rules\":[],\"metadata\":[]}"
    );
    assert_eq!(parsed.canonical_json().unwrap(), expected.as_bytes());
    assert_eq!(
        parsed.canonical_digest().unwrap().as_str(),
        "8a5e04fa8462ff436d721debef9d659194c4fa6e121887bc4a3690a0ef628823",
    );
}

#[test]
fn malformed_utf8_rejected_without_panicking() {
    let mut broken = sample().canonical_json().unwrap();
    broken.push(0xff);
    assert!(PolicyDocument::parse_json(&broken).is_err());
}
