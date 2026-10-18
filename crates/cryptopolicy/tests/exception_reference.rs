//! FOSS-499 strict reference/parser and trust-boundary security regressions.
#![allow(clippy::unwrap_used)]

use cryptopolicy::*;
use serde_json::{Value, json};

fn reference() -> ExceptionReference {
    ExceptionReference::parse_json(include_bytes!("fixtures/exception-reference-v1.json"))
        .unwrap()
}
fn context(reference: &ExceptionReference, time: i64) -> ExceptionBoundContext {
    ExceptionBoundContext {
        policy: reference.policy.clone(),
        target_rule: reference.target_rule.clone(),
        scope: reference.scope.clone(),
        evaluation_time: EvaluationTime { unix_millis: time },
    }
}
fn external_test_verifier(
    e: &ExceptionReference,
    c: &ExceptionBoundContext,
) -> Result<ExceptionVerification, ContractError> {
    // A synthetic test-only stand-in. Actual deployments MUST authenticate
    // the original signed approval, issuer delegation and current revocation.
    Ok(ExceptionVerification {
        source_authenticated: e.source_ref.as_str() == "source:alpha:1",
        approver_authorized: e.approver.as_str() == "tenant:security:approver"
            && e.owner.as_str() == "tenant:security:owner"
            && e.scope.tenant_id == c.scope.tenant_id,
        approval_verified: e.approval_ref.as_str() == "approval:alpha:1",
        revocation_checked: true,
    })
}
fn status(
    reference: &ExceptionReference,
    time: i64,
) -> ExceptionReferenceFinding {
    let c = context(reference, time);
    assess_exception_reference(reference, &c, &external_test_verifier)
        .unwrap()
        .finding
}
fn mutate(mutator: impl FnOnce(&mut Value)) -> Result<ExceptionReference, ContractError> {
    let mut json: Value = serde_json::from_slice(include_bytes!(
        "fixtures/exception-reference-v1.json"
    ))
    .unwrap();
    mutator(&mut json);
    ExceptionReference::parse_json(&serde_json::to_vec(&json).unwrap())
}

#[test]
fn strict_fixture_binds_actual_canonical_policy_and_roundtrips() {
    let source = reference();
    let policy =
        PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap();
    assert_eq!(source.policy, PolicyReference::from_document(&policy).unwrap());
    let canonical = serde_json::to_vec(&source).unwrap();
    assert_eq!(ExceptionReference::parse_json(&canonical).unwrap(), source);
    assert_eq!(source.compensating_controls.len(), 1);
    assert_eq!(source.deviation, ExceptionDeviation::RuleRequirement);
    assert_eq!(source.schema_version, SchemaVersion::V1);
    assert_eq!(source.correlation_digest().unwrap().as_str().len(), 64);
}

#[test]
fn default_is_never_authenticated_despite_apparent_active_and_approval_refs() {
    let e = reference();
    let c = context(&e, 150);
    let report = assess_exception_reference(&e, &c, &UnverifiedExceptionReferences).unwrap();
    assert_eq!(report.finding, ExceptionReferenceFinding::Unverified);
    assert_eq!(report.verification, ExceptionVerification::default());
    assert_eq!(report.exception_digest, e.correlation_digest().unwrap());
    // Even "ready" is a metadata result; no DecisionOutcome::Permit is exposed.
}

#[test]
fn synthetic_fully_verified_reference_is_only_ready_for_future_policy_admission() {
    let e = reference();
    let c = context(&e, 150);
    let report = assess_exception_reference(&e, &c, &external_test_verifier).unwrap();
    assert_eq!(
        report.finding,
        ExceptionReferenceFinding::ReferenceReadyForPolicyAdmission
    );
    assert!(report.verification.source_authenticated);
    assert!(report.verification.approval_verified);
    assert!(report.verification.revocation_checked);
    assert_eq!(report.evaluated_at.unix_millis, 150);
}

#[test]
fn exact_inclusive_activation_and_exclusive_expiration() {
    let e = reference();
    assert_eq!(status(&e, 149), ExceptionReferenceFinding::NotEffective);
    assert_eq!(status(&e, 150), ExceptionReferenceFinding::ReferenceReadyForPolicyAdmission);
    assert_eq!(status(&e, 299), ExceptionReferenceFinding::ReferenceReadyForPolicyAdmission);
    assert_eq!(status(&e, 300), ExceptionReferenceFinding::Expired);
    assert_eq!(status(&e, 301), ExceptionReferenceFinding::Expired);
}

#[test]
fn revoked_or_suspended_never_invokes_verifier() {
    let mut e = reference();
    let bomb = |_: &ExceptionReference, _: &ExceptionBoundContext| {
        panic!("verifier must not be invoked for revoked or suspended");
        #[allow(unreachable_code)]
        Ok(ExceptionVerification::default())
    };
    for (new_status, expected) in [
        (ExceptionStatus::Revoked, ExceptionReferenceFinding::Revoked),
        (ExceptionStatus::Suspended, ExceptionReferenceFinding::Suspended),
    ] {
        e.status = new_status;
        let c = context(&e, 200);
        assert_eq!(assess_exception_reference(&e, &c, &bomb).unwrap().finding, expected);
    }
}

#[test]
fn exact_policy_rule_tenant_environment_operation_algorithm_and_key() {
    let e = reference();
    let mut c = context(&e, 200);
    c.policy.digest = PolicyDigest::try_from("0".repeat(64)).unwrap();
    assert_eq!(
        assess_exception_reference(&e, &c, &external_test_verifier).unwrap().finding,
        ExceptionReferenceFinding::WrongTarget
    );
    c = context(&e, 200);
    c.target_rule = RuleId::parse("other-target").unwrap();
    assert_eq!(
        assess_exception_reference(&e, &c, &external_test_verifier).unwrap().finding,
        ExceptionReferenceFinding::WrongTarget
    );
    c = context(&e, 200);
    c.scope.tenant_id = PolicyId::parse("tenant:other").unwrap();
    assert_eq!(
        assess_exception_reference(&e, &c, &external_test_verifier).unwrap().finding,
        ExceptionReferenceFinding::OutOfScope
    );
    c = context(&e, 200);
    c.scope.environment = "staging".into();
    assert_eq!(
        assess_exception_reference(&e, &c, &external_test_verifier).unwrap().finding,
        ExceptionReferenceFinding::OutOfScope
    );
    c = context(&e, 200);
    c.scope.operation = CryptoOperation::Decrypt;
    assert_eq!(
        assess_exception_reference(&e, &c, &external_test_verifier).unwrap().finding,
        ExceptionReferenceFinding::OutOfScope
    );
    c = context(&e, 200);
    c.scope.algorithm_id = AlgorithmId::parse("AES-128-GCM").unwrap();
    assert_eq!(
        assess_exception_reference(&e, &c, &external_test_verifier).unwrap().finding,
        ExceptionReferenceFinding::OutOfScope
    );
    c = context(&e, 200);
    c.scope.key_ref = EvidenceId::parse("key:other").unwrap();
    assert_eq!(
        assess_exception_reference(&e, &c, &external_test_verifier).unwrap().finding,
        ExceptionReferenceFinding::OutOfScope
    );
}

#[test]
fn every_external_proof_flag_is_independently_mandatory() {
    let e = reference();
    let c = context(&e, 200);
    for fail in 0..4 {
        let verifier = move |_: &ExceptionReference, _: &ExceptionBoundContext| {
            let mut flags = ExceptionVerification {
                source_authenticated: true,
                approver_authorized: true,
                approval_verified: true,
                revocation_checked: true,
            };
            match fail {
                0 => flags.source_authenticated = false,
                1 => flags.approver_authorized = false,
                2 => flags.approval_verified = false,
                _ => flags.revocation_checked = false,
            }
            Ok(flags)
        };
        let r = assess_exception_reference(&e, &c, &verifier).unwrap();
        assert_eq!(r.finding, ExceptionReferenceFinding::Unverified);
    }
    let rejected = |_: &ExceptionReference, _: &ExceptionBoundContext| {
        Err(ContractError::InvalidDocument("external_verifier_failed"))
    };
    assert_eq!(
        assess_exception_reference(&e, &c, &rejected),
        Err(ContractError::InvalidDocument("external_verifier_failed"))
    );
}

#[test]
fn malformed_time_status_and_self_approval_are_rejected() {
    let mut e = reference();
    e.effective_at = e.expires_at;
    assert!(matches!(e.validate(&Limits::default()), Err(ContractError::InvalidDocument(_))));
    e = reference();
    e.issued_at = EvaluationTime { unix_millis: 200 };
    assert!(matches!(e.validate(&Limits::default()), Err(ContractError::InvalidDocument(_))));
    e = reference();
    e.approver = e.owner.clone();
    assert_eq!(
        e.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("exception_self_approval"))
    );
    assert!(mutate(|v| v["status"] = json!("magic_active")).is_err());
}

#[test]
fn no_wildcards_missing_scope_unknown_fields_or_duplicate_json_properties() {
    assert!(mutate(|v| v["scope"]["environment"] = json!("*")).is_err());
    assert!(mutate(|v| v["scope"]["tenant_id"] = json!("*")).is_err());
    assert!(mutate(|v| v["scope"]["key_ref"] = Value::Null).is_err());
    assert!(mutate(|v| v["scope"]["operation"] = Value::Null).is_err());
    assert!(mutate(|v| v["unknown_approval_override"] = json!(true)).is_err());
    assert!(mutate(|v| v["schema_version"] = json!("2")).is_err());
    assert!(mutate(|v| v["policy"]["digest"] = json!("not-a-sha")).is_err());
    let duplicate = br#"{"schema_version":"1","schema_version":"1"}"#;
    assert!(ExceptionReference::parse_json(duplicate).is_err());
    assert!(mutate(|v| v["source_ref"] = json!("")).is_err());
}

#[test]
fn compensation_and_justification_cannot_silently_weaken_controls() {
    let mut e = reference();
    e.compensating_controls.clear();
    assert!(e.validate(&Limits::default()).is_err());
    e = reference();
    e.compensating_controls.push(e.compensating_controls[0].clone());
    assert_eq!(e.validate(&Limits::default()), Err(ContractError::DuplicateIdentifier));
    e = reference();
    e.compensating_controls = vec![
        RuleId::parse("z-rule").unwrap(),
        RuleId::parse("a-rule").unwrap(),
    ];
    assert_eq!(
        e.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("exception_unsorted_compensating_controls"))
    );
    e = reference();
    e.compensating_controls[0] = e.target_rule.clone();
    assert_eq!(
        e.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("exception_self_compensation"))
    );
    e = reference();
    e.justification = "x".repeat(513);
    assert!(e.validate(&Limits::default()).is_err());
    e.justification = "secret\nprompt".to_owned();
    assert!(e.validate(&Limits::default()).is_err());
}

#[test]
fn bounded_json_caller_limits_and_hostile_fields() {
    let value = serde_json::to_vec(&reference()).unwrap();
    let max = Limits {
        max_json_bytes: value.len() - 1,
        ..Limits::default()
    };
    assert!(matches!(
        ExceptionReference::parse_json_with_limits(&value, &max),
        Err(ContractError::PayloadTooLarge)
    ));
    let oversized = vec![b' '; MAX_EXCEPTION_REFERENCE_JSON_BYTES + 1];
    assert_eq!(ExceptionReference::parse_json(&oversized), Err(ContractError::PayloadTooLarge));
    assert_eq!(reference().correlation_digest().unwrap(), reference().correlation_digest().unwrap());
}

#[test]
fn content_digest_is_stable_and_changes_when_critical_fields_change() {
    let baseline = reference();
    let expected = baseline.correlation_digest().unwrap();
    let from_wire = ExceptionReference::parse_json(
        &serde_json::to_vec(&baseline).unwrap()
    ).unwrap();
    assert_eq!(expected, from_wire.correlation_digest().unwrap());
    for index in 0..5 {
        let mut altered = baseline.clone();
        match index {
            0 => altered.scope.environment = "staging".into(),
            1 => altered.approval_ref = EvidenceId::parse("approval:other").unwrap(),
            2 => altered.status = ExceptionStatus::Suspended,
            3 => altered.expires_at = EvaluationTime { unix_millis: 350 },
            _ => altered.justification = "New approved justification".into(),
        }
        assert_ne!(expected, altered.correlation_digest().unwrap());
    }
}
