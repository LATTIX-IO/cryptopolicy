//! FOSS-514: exact v1 public schema-admission failure families.
//! All inputs are synthetic and all error paths are non-authorizing.
#![allow(clippy::unwrap_used)]

use cryptopolicy::{
    ContractError, Limits, PolicyAdmissionError, PolicyDocument, parse_policy_for_admission,
    parse_policy_for_admission_with_limits,
};

const VALID: &[u8] = include_bytes!("fixtures/evaluator-policy-v1.json");

fn mutate(mutator: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(VALID).unwrap();
    mutator(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn accepted_policies_are_exactly_the_legacy_parser_outputs() {
    let legacy = PolicyDocument::parse_json(VALID).unwrap();
    let admitted = parse_policy_for_admission(VALID).unwrap();
    assert_eq!(admitted, legacy);
    assert_eq!(
        admitted.canonical_digest().unwrap(),
        legacy.canonical_digest().unwrap()
    );
    assert_eq!(
        parse_policy_for_admission_with_limits(VALID, &Limits::default()).unwrap(),
        legacy
    );
}

#[test]
fn unsupported_root_key_fails_closed_with_a_stable_payload_free_code() {
    let bytes = mutate(|doc| {
        doc["override_deny_silently"] = serde_json::json!(true);
        doc["issuer"]["subject"] = serde_json::json!("REDACT_THIS_ISSUER");
    });
    assert!(matches!(
        PolicyDocument::parse_json(&bytes),
        Err(ContractError::InvalidJson(_))
    ));
    for _ in 0..2 {
        let error = parse_policy_for_admission(&bytes).unwrap_err();
        assert_eq!(error, PolicyAdmissionError::UnsupportedSchema);
        assert_eq!(error.to_string(), "UnsupportedSchema");
        assert!(!format!("{error:?}").contains("REDACT_THIS"));
        assert!(!error.to_string().contains("override_deny_silently"));
    }
}

#[test]
fn unknown_schemas_and_type_changes_are_not_accepted() {
    for version in [serde_json::json!("2"), serde_json::json!(2)] {
        let bytes = mutate(|doc| doc["schema_version"] = version);
        assert_eq!(
            parse_policy_for_admission(&bytes),
            Err(PolicyAdmissionError::UnsupportedSchema)
        );
        assert!(PolicyDocument::parse_json(&bytes).is_err());
    }
}

#[test]
fn nested_structure_and_missing_required_fields_remain_invalid_policy() {
    let nested = mutate(|doc| {
        doc["issuer"]["unknown_critical"] = serde_json::json!("REDACT_THIS");
    });
    assert_eq!(
        parse_policy_for_admission(&nested),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    let missing = mutate(|doc| {
        doc.as_object_mut().unwrap().remove("default_effect");
    });
    assert_eq!(
        parse_policy_for_admission(&missing),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    assert_eq!(
        parse_policy_for_admission(br#"{"schema_version":"1","schema_version":"1"}"#),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    assert_eq!(
        parse_policy_for_admission(b"{not valid JSON"),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
}

#[test]
fn duplicate_root_keys_are_invalid_policy_regardless_of_order() {
    let duplicates: [&[u8]; 3] = [
        br#"{"schema_version":"1","schema_version":"2","override_deny_silently":true}"#,
        br#"{"schema_version":"2","schema_version":"1","override_deny_silently":true}"#,
        br#"{"schema_version":"1","override_deny_silently":true,"override_deny_silently":false}"#,
    ];
    for raw in duplicates {
        assert_eq!(
            parse_policy_for_admission(raw),
            Err(PolicyAdmissionError::InvalidPolicy)
        );
        assert!(PolicyDocument::parse_json(raw).is_err());
    }
}

#[test]
fn input_budget_and_nesting_limits_are_enforced_before_admission() {
    let bytes = mutate(|doc| {
        doc["override_deny_silently"] = serde_json::json!(true);
    });
    let tiny = Limits {
        max_json_bytes: bytes.len() - 1,
        ..Limits::default()
    };
    assert_eq!(
        parse_policy_for_admission_with_limits(&bytes, &tiny),
        Err(PolicyAdmissionError::ResourceLimit)
    );
    let shallow = Limits {
        max_nesting_depth: 1,
        ..Limits::default()
    };
    assert_eq!(
        parse_policy_for_admission_with_limits(VALID, &shallow),
        Err(PolicyAdmissionError::ResourceLimit)
    );
    let invalid_limits = Limits {
        max_json_bytes: 0,
        ..Limits::default()
    };
    assert_eq!(
        parse_policy_for_admission_with_limits(VALID, &invalid_limits),
        Err(PolicyAdmissionError::ResourceLimit)
    );
}
