//! FOSS-500/A: conservative exact-scope Deny waiver admission simulation.
//! Synthetic verifiers are test-only and NOT production cryptographic proof.
#![allow(clippy::unwrap_used)]

use cryptopolicy::*;
use serde_json::Value;

fn at(ms: i64) -> EvaluationTime {
    EvaluationTime { unix_millis: ms }
}
fn policy(name: &str) -> PolicyDocument {
    let mut p = PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json"))
        .unwrap();
    p.policy_id = PolicyId::parse(name).unwrap();
    p
}
fn request() -> CryptoContext {
    CryptoContext::parse_json(include_bytes!("fixtures/evaluator-context-v1.json")).unwrap()
}
fn deny(id: &str) -> PolicyRule {
    PolicyRule {
        rule_id: RuleId::parse(id).unwrap(),
        effect: RuleEffect::Deny,
        selector: RuleSelector {
            match_all: true,
            operation: None,
            algorithm_id: None,
            profile_id: None,
            environment: None,
            advanced: None,
        },
        requirements: Vec::new(),
        temporal: None,
    }
}
fn compile(policies: &[PolicyDocument]) -> EffectivePolicy {
    let refs: Vec<_> = policies
        .iter()
        .map(|p| PolicyReference::from_document(p).unwrap())
        .collect();
    let nodes: Vec<_> = policies.iter().cloned().map(|document| PolicyNode {
        schema_version: SchemaVersion::V1,
        document,
        imports: vec![],
    }).collect();
    let set = PolicySet {
        schema_version: SchemaVersion::V1,
        baseline: refs[0].clone(),
        overlays: refs[1..].to_vec(),
    };
    let resolver = |r: &PolicyReference| {
        Ok::<Option<PolicyNode>, CompositionError>(
            nodes.iter().find(|n| n.document.policy_id == r.policy_id).cloned()
        )
    };
    compile_policy_set(&set, &resolver, &Limits::default()).unwrap()
}
fn exception_for(policy: &PolicyDocument, rule_id: &str) -> ExceptionReference {
    let mut e = ExceptionReference::parse_json(include_bytes!(
        "fixtures/exception-reference-v1.json"
    )).unwrap();
    e.policy = PolicyReference::from_document(policy).unwrap();
    e.target_rule = RuleId::parse(rule_id).unwrap();
    e.deviation = ExceptionDeviation::RuleDeny;
    e
}
fn grant_for(e: &ExceptionReference) -> PolicyWaiverGrant {
    PolicyWaiverGrant {
        schema_version: SchemaVersion::V1,
        policy: e.policy.clone(),
        target_rule: e.target_rule.clone(),
        exception_id: e.exception_id.clone(),
        exception_digest: e.correlation_digest().unwrap(),
        policy_authority_ref: EvidenceId::parse("policy-owner:approval:1").unwrap(),
        deviation: ExceptionDeviation::RuleDeny,
        scope: e.scope.clone(),
        compensating_controls: e.compensating_controls.clone(),
        authorized_at: at(120),
        expires_at: at(250),
    }
}
// Two DISTINCT external-verification fixtures. These intentionally hardcode
// synthetic fixture identities: production must independently validate the
// real signed source/approval, policy owner and revocation for every request.
fn exception_verifier(
    e: &ExceptionReference,
    c: &ExceptionBoundContext,
) -> Result<ExceptionVerification, ContractError> {
    Ok(ExceptionVerification {
        source_authenticated: e.source_ref.as_str() == "source:alpha:1",
        approver_authorized: e.approver.as_str() == "tenant:security:approver"
            && e.scope.tenant_id == c.scope.tenant_id,
        approval_verified: e.approval_ref.as_str() == "approval:alpha:1",
        revocation_checked: true,
    })
}
fn owner_verifier(
    grant: &PolicyWaiverGrant,
    reference: &ExceptionReference,
    effective: &EffectivePolicy,
    context: &CryptoContext,
) -> Result<bool, ContractError> {
    Ok(grant.policy_authority_ref.as_str() == "policy-owner:approval:1"
        && grant.policy == reference.policy
        && grant.exception_digest == reference.correlation_digest().unwrap()
        && effective.components().iter().any(|node| node.reference == grant.policy)
        && context.operation == grant.scope.operation)
}

fn ready() -> (EffectivePolicy, ExceptionReference, PolicyWaiverGrant, CryptoContext) {
    let mut p = policy("org:evaluator-preview");
    p.rules.push(deny("r-deny-waivable"));
    let graph = compile(&[p.clone()]);
    let exception = exception_for(&p, "r-deny-waivable");
    let grant = grant_for(&exception);
    (graph, exception, grant, request())
}
fn evaluate(
    graph: &EffectivePolicy,
    e: &ExceptionReference,
    grant: &PolicyWaiverGrant,
    c: &CryptoContext,
    time: i64,
) -> WaiverAdmissionReport {
    evaluate_deny_waiver_candidate(
        graph, c, &e.scope, at(time), e, grant,
        &exception_verifier, &owner_verifier, &Limits::default(),
    ).unwrap()
}

#[test]
fn exact_waiver_is_only_a_distinct_non_authorizing_candidate() {
    let (graph, e, grant, context) = ready();
    let original = graph.evaluate(&context, context.evaluation_time, &Limits::default()).unwrap();
    assert_eq!(original.outcome, DecisionOutcome::Deny);
    let report = evaluate(&graph, &e, &grant, &context, 150);
    assert_eq!(report.original, original);
    assert_eq!(report.original_effective_digest, *graph.digest());
    assert_eq!(report.disposition, WaiverAdmissionDisposition::CandidateEvaluated);
    assert_eq!(report.candidate_outcome, DecisionOutcome::Permit);
    let simulated = report.candidate_target_layer.as_ref().unwrap();
    assert_eq!(simulated.outcome, DecisionOutcome::Permit);
    assert_ne!(simulated.policy_digest, e.policy.digest);
    assert!(simulated.reasons.iter().any(|reason| {
        reason.code == ReasonCode::RequirementSatisfied
            && reason.rule_id.as_ref().is_some_and(|id| id.as_str() == "r-require-protection")
    }));
    // No mutation and no privilege from a subsequent untrusted evaluation.
    assert_eq!(graph.evaluate(&context, at(150), &Limits::default()).unwrap(), original);
}

#[test]
fn safe_defaults_and_missing_independent_trust_never_produce_candidate_permit() {
    let (graph, e, grant, context) = ready();
    let report = evaluate_deny_waiver_candidate(
        &graph, &context, &e.scope, at(150), &e, &grant,
        &UnverifiedExceptionReferences, &owner_verifier, &Limits::default(),
    ).unwrap();
    assert_eq!(report.disposition, WaiverAdmissionDisposition::ExceptionNotReady);
    assert_eq!(report.candidate_outcome, DecisionOutcome::Deny);
    assert!(report.candidate_target_layer.is_none());
    let report = evaluate_deny_waiver_candidate(
        &graph, &context, &e.scope, at(150), &e, &grant,
        &exception_verifier, &UnverifiedPolicyWaiverAuthority, &Limits::default(),
    ).unwrap();
    assert_eq!(report.disposition, WaiverAdmissionDisposition::GrantNotAuthorized);
    assert_eq!(report.candidate_outcome, DecisionOutcome::Deny);
}

#[test]
fn revoked_suspended_expired_unverified_wrong_tenant_and_approval_are_blocked() {
    let (graph, mut e, mut grant, context) = ready();
    for (status, expected) in [
        (ExceptionStatus::Revoked, WaiverAdmissionDisposition::ExceptionNotReady),
        (ExceptionStatus::Suspended, WaiverAdmissionDisposition::ExceptionNotReady),
    ] {
        e.status = status;
        assert_eq!(evaluate(&graph, &e, &grant, &context, 150).disposition, expected);
    }
    e.status = ExceptionStatus::Active;
    e.approval_ref = EvidenceId::parse("approval:forged").unwrap();
    grant.exception_digest = e.correlation_digest().unwrap();
    assert_eq!(evaluate(&graph, &e, &grant, &context, 150).disposition,
               WaiverAdmissionDisposition::ExceptionNotReady);
    e = ready().1;
    grant = grant_for(&e);
    let expired = evaluate(&graph, &e, &grant, &context, 300);
    // At an expired evaluation context, the E0 gate is fail closed.
    assert_eq!(expired.disposition, WaiverAdmissionDisposition::ExceptionNotReady);
    assert_ne!(expired.candidate_outcome, DecisionOutcome::Permit);
    e.scope.tenant_id = PolicyId::parse("tenant:other").unwrap();
    grant = grant_for(&e);
    let mismatch = evaluate_deny_waiver_candidate(
        &graph, &context, &ready().1.scope, at(150), &e, &grant,
        &exception_verifier, &owner_verifier, &Limits::default(),
    ).unwrap();
    assert_eq!(mismatch.disposition, WaiverAdmissionDisposition::ScopeMismatch);
    assert_eq!(mismatch.candidate_outcome, DecisionOutcome::Deny);
}

#[test]
fn policy_digest_rule_grant_and_key_bindings_cannot_be_substituted() {
    let (graph, e, mut grant, context) = ready();
    grant.policy.digest = PolicyDigest::try_from("0".repeat(64)).unwrap();
    assert_eq!(evaluate(&graph, &e, &grant, &context, 150).disposition,
               WaiverAdmissionDisposition::GrantNotAuthorized);
    grant = grant_for(&e);
    grant.policy_authority_ref = EvidenceId::parse("forged:owner").unwrap();
    assert_eq!(evaluate(&graph, &e, &grant, &context, 150).disposition,
               WaiverAdmissionDisposition::GrantNotAuthorized);
    grant = grant_for(&e);
    grant.target_rule = RuleId::parse("r-other").unwrap();
    assert_eq!(evaluate(&graph, &e, &grant, &context, 150).disposition,
               WaiverAdmissionDisposition::GrantNotAuthorized);
    grant = grant_for(&e);
    grant.scope.key_ref = EvidenceId::parse("key:forged").unwrap();
    assert_eq!(evaluate(&graph, &e, &grant, &context, 150).disposition,
               WaiverAdmissionDisposition::GrantNotAuthorized);
    grant = grant_for(&e);
    grant.exception_digest = PolicyDigest::try_from("1".repeat(64)).unwrap();
    assert_eq!(evaluate(&graph, &e, &grant, &context, 150).disposition,
               WaiverAdmissionDisposition::GrantNotAuthorized);
    grant = grant_for(&e);
    grant.expires_at = at(150);
    assert_eq!(evaluate(&graph, &e, &grant, &context, 150).disposition,
               WaiverAdmissionDisposition::GrantNotAuthorized);
}

#[test]
fn deny_in_other_mandatory_layer_is_never_overridden() {
    let mut baseline = policy("org:another-baseline");
    baseline.rules.push(deny("r-other-baseline-deny"));
    let mut overlay = policy("org:waivable-overlay");
    overlay.rules.push(deny("r-deny-waivable"));
    let graph = compile(&[baseline, overlay.clone()]);
    let e = exception_for(&overlay, "r-deny-waivable");
    let grant = grant_for(&e);
    let c = request();
    let report = evaluate(&graph, &e, &grant, &c, 150);
    assert_eq!(report.disposition, WaiverAdmissionDisposition::CandidateEvaluated);
    assert_eq!(report.candidate_target_layer.as_ref().unwrap().outcome,
               DecisionOutcome::Permit);
    assert_eq!(report.candidate_outcome, DecisionOutcome::Deny);
    assert!(report.original.components.iter().any(|layer| {
        layer.reference != e.policy && layer.decision.outcome == DecisionOutcome::Deny
    }));
}

#[test]
fn missing_failed_or_irrelevant_compensation_never_elevates_original_deny() {
    let (graph, mut e, mut grant, mut c) = ready();
    e.compensating_controls = vec![RuleId::parse("no-such-require-rule").unwrap()];
    grant = grant_for(&e);
    let report = evaluate(&graph, &e, &grant, &c, 150);
    assert_eq!(report.disposition, WaiverAdmissionDisposition::CompensationNotSatisfied);
    assert_eq!(report.candidate_outcome, DecisionOutcome::Deny);

    e = ready().1;
    grant = grant_for(&e);
    c.facts[0].properties.as_mut().unwrap().key_protection = None;
    assert_eq!(evaluate(&graph, &e, &grant, &c, 150).disposition,
               WaiverAdmissionDisposition::CompensationNotSatisfied);
    c = request();
    c.facts[0].properties.as_mut().unwrap().key_exportable = Some(true);
    let result = evaluate(&graph, &e, &grant, &c, 150);
    assert_ne!(result.candidate_outcome, DecisionOutcome::Permit);
    assert!(result.candidate_target_layer.is_none());
}

#[test]
fn unrelated_or_inactive_target_rule_is_not_a_waivable_matched_deny() {
    let (graph, e, grant, mut c) = ready();
    c.operation = CryptoOperation::Verify;
    let r = evaluate_deny_waiver_candidate(
        &graph, &c, &e.scope, at(150), &e, &grant,
        &exception_verifier, &owner_verifier, &Limits::default(),
    ).unwrap();
    assert_eq!(r.disposition, WaiverAdmissionDisposition::ScopeMismatch);
    let mut p = policy("org:evaluator-preview");
    let mut unrelated = deny("r-deny-waivable");
    unrelated.selector.match_all = false;
    unrelated.selector.operation = Some(CryptoOperation::Decrypt);
    p.rules.push(unrelated);
    let graph = compile(&[p.clone()]);
    let e = exception_for(&p, "r-deny-waivable");
    let grant = grant_for(&e);
    assert_eq!(evaluate(&graph, &e, &grant, &request(), 150).disposition,
               WaiverAdmissionDisposition::NoMatchingExplicitDeny);
}

#[test]
fn reason_and_hypothetical_policy_fingerprints_are_order_stable() {
    let (graph, e, grant, c) = ready();
    let a = evaluate(&graph, &e, &grant, &c, 150);
    let b = evaluate(&graph, &e, &grant, &c, 150);
    assert_eq!(a, b);
    let mut p = policy("org:evaluator-preview");
    p.rules.push(deny("r-deny-waivable"));
    p.rules.reverse();
    let reordered = compile(&[p.clone()]);
    let e2 = exception_for(&p, "r-deny-waivable");
    let grant2 = grant_for(&e2);
    let d = evaluate(&reordered, &e2, &grant2, &c, 150);
    assert_eq!(a.original, d.original);
    assert_eq!(a.candidate_target_layer, d.candidate_target_layer);
    assert_eq!(a.original_effective_digest, d.original_effective_digest);
}

#[test]
fn bound_grant_rejects_unsupported_deviation_malformed_json_and_oversize() {
    let (_, e, mut grant, _) = ready();
    grant.deviation = ExceptionDeviation::RuleRequirement;
    assert_eq!(grant.validate(&Limits::default()),
               Err(ContractError::InvalidDocument("unsupported_waiver_deviation")));
    grant = grant_for(&e);
    grant.compensating_controls.push(grant.compensating_controls[0].clone());
    assert_eq!(grant.validate(&Limits::default()), Err(ContractError::DuplicateIdentifier));
    grant = grant_for(&e);
    let json = serde_json::to_vec(&grant).unwrap();
    let small = Limits { max_json_bytes: json.len()-1, ..Limits::default() };
    assert_eq!(PolicyWaiverGrant::parse_json_with_limits(&json,&small),
               Err(ContractError::PayloadTooLarge));
    let mut raw: Value = serde_json::from_slice(&json).unwrap();
    raw["grant_as_superuser"] = serde_json::json!(true);
    assert!(PolicyWaiverGrant::parse_json_with_limits(
        &serde_json::to_vec(&raw).unwrap(),&Limits::default()).is_err());
    assert!(PolicyWaiverGrant::parse_json_with_limits(
        br#"{"schema_version":"1","schema_version":"1"}"#,
        &Limits::default()).is_err());
}
