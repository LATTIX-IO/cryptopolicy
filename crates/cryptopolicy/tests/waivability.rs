//! FOSS-502 owner waivability, actual key/profile and mandatory Require regressions.
#![allow(clippy::unwrap_used)]

use cryptopolicy::*;

fn at(ms: i64) -> EvaluationTime {
    EvaluationTime { unix_millis: ms }
}
fn policy(name: &str) -> PolicyDocument {
    let mut p =
        PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap();
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
    let nodes: Vec<_> = policies
        .iter()
        .cloned()
        .map(|document| PolicyNode {
            schema_version: SchemaVersion::V1,
            document,
            imports: vec![],
        })
        .collect();
    let set = PolicySet {
        schema_version: SchemaVersion::V1,
        baseline: refs[0].clone(),
        overlays: refs[1..].to_vec(),
    };
    let resolver = |r: &PolicyReference| {
        Ok::<Option<PolicyNode>, CompositionError>(
            nodes
                .iter()
                .find(|n| n.document.policy_id == r.policy_id)
                .cloned(),
        )
    };
    compile_policy_set(&set, &resolver, &Limits::default()).unwrap()
}
fn exception_for(policy: &PolicyDocument, rule_id: &str) -> ExceptionReference {
    let mut e =
        ExceptionReference::parse_json(include_bytes!("fixtures/exception-reference-v1.json"))
            .unwrap();
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
    Ok(
        grant.policy_authority_ref.as_str() == "policy-owner:approval:1"
            && grant.policy == reference.policy
            && grant.exception_digest == reference.correlation_digest().unwrap()
            && effective
                .components()
                .iter()
                .any(|node| node.reference == grant.policy)
            && context.operation == grant.scope.operation,
    )
}

fn ready() -> (
    EffectivePolicy,
    ExceptionReference,
    PolicyWaiverGrant,
    CryptoContext,
) {
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
        WaiverCandidateRequest {
            effective: graph,
            context: c,
            actual_scope: &e.scope,
            time: at(time),
            exception: e,
            grant,
            limits: &Limits::default(),
        },
        &exception_verifier,
        &owner_verifier,
    )
    .unwrap()
}


const PROFILE: &str = "AES-256-GCM:profile-a";

fn registry_for(e: &ExceptionReference) -> WaivabilityRegistry {
    WaivabilityRegistry {
        schema_version: SchemaVersion::V1,
        policy: e.policy.clone(),
        registry_ref: EvidenceId::parse("owner-registry:1").unwrap(),
        authority_ref: EvidenceId::parse("signed-policy-owner:1").unwrap(),
        revision: 12,
        nonce: EvidenceId::parse("registry-nonce:12").unwrap(),
        status: ExceptionStatus::Active,
        issued_at: at(100),
        effective_at: at(120),
        expires_at: at(190),
        entries: vec![WaivableRuleEntry {
            target_rule: e.target_rule.clone(),
            deviation: e.deviation,
            scope: e.scope.clone(),
            profile_id: ProfileId::parse(PROFILE).unwrap(),
            compensating_controls: e.compensating_controls.clone(),
        }],
    }
}
fn binding_for(e: &ExceptionReference) -> KeyProfileBinding {
    KeyProfileBinding {
        scope: e.scope.clone(),
        profile_id: ProfileId::parse(PROFILE).unwrap(),
        evidence_ref: EvidenceId::parse("verified-key-profile:1").unwrap(),
        key_version_ref: EvidenceId::parse("key-version:42").unwrap(),
    }
}
fn source_registry_verifier(
    registry: &WaivabilityRegistry, request: &WaiverCandidateRequest<'_>,
) -> Result<RegistryVerification, ContractError> {
    Ok(RegistryVerification {
        registry_authenticated: registry.registry_ref.as_str() == "owner-registry:1",
        owner_delegation_verified: registry.authority_ref.as_str() == "signed-policy-owner:1"
            && registry.policy == request.exception.policy,
        revocation_fresh: registry.status == ExceptionStatus::Active,
        replay_fresh: registry.revision == 12 && registry.nonce.as_str() == "registry-nonce:12",
    })
}
fn source_key_verifier(
    binding: &KeyProfileBinding, context: &CryptoContext,
) -> Result<bool, ContractError> {
    Ok(binding.evidence_ref.as_str() == "verified-key-profile:1"
        && binding.key_version_ref.as_str() == "key-version:42"
        && binding.scope.key_ref.as_str() == "key:alpha:1"
        && context.facts[0].profile_id.as_ref() == Some(&binding.profile_id))
}
fn reviewed(
    graph: &EffectivePolicy, e: &ExceptionReference, grant: &PolicyWaiverGrant,
    registry: &WaivabilityRegistry, binding: &KeyProfileBinding, c: &CryptoContext,
) -> WaiverAdmissionReport {
    evaluate_reviewed_waiver_candidate(
        ReviewedWaiverRequest {
            request: WaiverCandidateRequest {
                effective: graph,
                context: c,
                actual_scope: &e.scope,
                time: c.evaluation_time,
                exception: e,
                grant,
                limits: &Limits::default(),
            },
            registry,
            key_binding: binding,
        },
        &exception_verifier,
        &owner_verifier,
        &source_registry_verifier,
        &source_key_verifier,
    ).unwrap()
}
fn prepared_deny() -> (
    EffectivePolicy, ExceptionReference, PolicyWaiverGrant,
    WaivabilityRegistry, KeyProfileBinding, CryptoContext
) {
    let (graph, e, grant, mut c) = ready();
    c.facts[0].profile_id = Some(ProfileId::parse(PROFILE).unwrap());
    let registry = registry_for(&e);
    let binding = binding_for(&e);
    (graph, e, grant, registry, binding, c)
}

#[test]
fn exact_profile_bound_deny_candidate_needs_four_independent_trust_gates() {
    let (graph, e, grant, registry, binding, c) = prepared_deny();
    // Old E1 cannot waive profile-bearing facts at all.
    let old = evaluate(&graph, &e, &grant, &c, 150);
    assert_eq!(old.disposition, WaiverAdmissionDisposition::ScopeMismatch);

    let result = reviewed(&graph, &e, &grant, &registry, &binding, &c);
    assert_eq!(result.disposition, WaiverAdmissionDisposition::CandidateEvaluated);
    assert_eq!(result.original.outcome, DecisionOutcome::Deny);
    assert_eq!(result.candidate_outcome, DecisionOutcome::Permit);
    assert!(result.candidate_target_layer.as_ref().is_some_and(|d| {
        d.policy_digest != e.policy.digest
    }));
    assert_eq!(graph.evaluate(&c, at(150), &Limits::default()).unwrap(),
               result.original);
}

#[test]
fn default_rejecting_registry_or_key_verifier_never_yields_candidate() {
    let (graph, e, grant, registry, binding, c) = prepared_deny();
    let mk_request = || ReviewedWaiverRequest {
        request: WaiverCandidateRequest {
            effective: &graph,
            context: &c,
            actual_scope: &e.scope,
            time: at(150),
            exception: &e,
            grant: &grant,
            limits: &Limits::default(),
        },
        registry: &registry, key_binding: &binding,
    };
    let reject_registry = evaluate_reviewed_waiver_candidate(
        mk_request(), &exception_verifier, &owner_verifier,
        &UnverifiedWaivabilityRegistry, &source_key_verifier,
    ).unwrap();
    assert_eq!(reject_registry.disposition, WaiverAdmissionDisposition::RegistryNotAuthorized);
    assert_eq!(reject_registry.candidate_outcome, DecisionOutcome::Deny);
    let reject_key = evaluate_reviewed_waiver_candidate(
        mk_request(), &exception_verifier, &owner_verifier,
        &source_registry_verifier, &UnverifiedKeyProfileBinding,
    ).unwrap();
    assert_eq!(reject_key.disposition, WaiverAdmissionDisposition::KeyBindingUnverified);
    assert_eq!(reject_key.candidate_outcome, DecisionOutcome::Deny);
}

#[test]
fn profile_change_never_inherits_approval_for_other_profile() {
    let (graph, e, grant, registry, binding, mut c) = prepared_deny();
    c.facts[0].profile_id = Some(ProfileId::parse("AES-256-GCM:profile-b").unwrap());
    let decision = reviewed(&graph, &e, &grant, &registry, &binding, &c);
    assert_eq!(decision.disposition, WaiverAdmissionDisposition::ScopeMismatch);
    assert_eq!(decision.candidate_outcome, DecisionOutcome::Deny);
    c.facts[0].profile_id = None;
    assert_eq!(reviewed(&graph, &e, &grant, &registry, &binding, &c).disposition,
               WaiverAdmissionDisposition::ScopeMismatch);
}

#[test]
fn revoked_expired_stale_nonce_and_wrong_owner_registry_fail_closed() {
    let (graph, e, grant, mut registry, binding, c) = prepared_deny();
    registry.status = ExceptionStatus::Revoked;
    assert_eq!(reviewed(&graph, &e, &grant, &registry, &binding, &c).disposition,
               WaiverAdmissionDisposition::RegistryNotAuthorized);
    registry.status = ExceptionStatus::Active;
    registry.expires_at = at(150);
    assert_eq!(reviewed(&graph, &e, &grant, &registry, &binding, &c).disposition,
               WaiverAdmissionDisposition::RegistryNotAuthorized);
    registry.expires_at = at(190);
    registry.nonce = EvidenceId::parse("registry-nonce:replayed").unwrap();
    assert_eq!(reviewed(&graph, &e, &grant, &registry, &binding, &c).disposition,
               WaiverAdmissionDisposition::RegistryNotAuthorized);
    registry.nonce = EvidenceId::parse("registry-nonce:12").unwrap();
    registry.authority_ref = EvidenceId::parse("wrong-policy-owner").unwrap();
    assert_eq!(reviewed(&graph, &e, &grant, &registry, &binding, &c).disposition,
               WaiverAdmissionDisposition::RegistryNotAuthorized);
}

#[test]
fn wrong_scope_deviation_or_compensation_is_not_owner_waivable() {
    let (graph, e, grant, mut registry, binding, c) = prepared_deny();
    registry.entries[0].scope.key_ref = EvidenceId::parse("key:other").unwrap();
    assert_eq!(reviewed(&graph, &e, &grant, &registry, &binding, &c).disposition,
               WaiverAdmissionDisposition::RuleNotWaivable);
    registry = registry_for(&e);
    registry.entries[0].deviation = ExceptionDeviation::RuleRequirement;
    assert_eq!(reviewed(&graph, &e, &grant, &registry, &binding, &c).disposition,
               WaiverAdmissionDisposition::RuleNotWaivable);
    registry = registry_for(&e);
    registry.entries[0].compensating_controls =
        vec![RuleId::parse("other-compensation").unwrap()];
    assert_eq!(reviewed(&graph, &e, &grant, &registry, &binding, &c).disposition,
               WaiverAdmissionDisposition::RuleNotWaivable);
}

#[test]
fn duplicate_unknown_oversized_and_unsorted_registry_entries_fail() {
    let (_, e, _, mut r, _, _) = prepared_deny();
    r.entries.push(r.entries[0].clone());
    assert_eq!(r.validate(&Limits::default()), Err(ContractError::DuplicateIdentifier));
    r = registry_for(&e);
    r.revision = 0;
    assert!(r.validate(&Limits::default()).is_err());
    r = registry_for(&e);
    let bytes = serde_json::to_vec(&r).unwrap();
    let tiny = Limits { max_json_bytes: bytes.len() - 1, ..Limits::default() };
    assert_eq!(WaivabilityRegistry::parse_json_with_limits(&bytes, &tiny),
               Err(ContractError::PayloadTooLarge));
    let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["implicit_grant"] = serde_json::json!(true);
    assert!(WaivabilityRegistry::parse_json_with_limits(
        &serde_json::to_vec(&json).unwrap(), &Limits::default()).is_err());
}

#[test]
fn explicitly_waivable_failed_require_is_simulated_only_when_compensation_satisfied() {
    let mut p = policy("org:evaluator-preview");
    let mut rule = p.rules.iter().find(|r| r.rule_id.as_str() == "r-require-protection")
        .unwrap().clone();
    rule.rule_id = RuleId::parse("r-waivable-require").unwrap();
    rule.effect = RuleEffect::Require;
    rule.requirements = vec![Requirement::KeyExportable(true)];
    p.rules.push(rule);
    let graph = compile(&[p.clone()]);
    let mut e = exception_for(&p, "r-waivable-require");
    e.deviation = ExceptionDeviation::RuleRequirement;
    let mut grant = grant_for(&e);
    grant.deviation = ExceptionDeviation::RuleRequirement;
    let registry = registry_for(&e);
    let binding = binding_for(&e);
    let mut c = request();
    c.facts[0].profile_id = Some(ProfileId::parse(PROFILE).unwrap());
    let original = graph.evaluate(&c, at(150), &Limits::default()).unwrap();
    assert_eq!(original.outcome, DecisionOutcome::Deny);
    assert!(original.components[0].decision.reasons.iter().any(|reason| {
        reason.rule_id.as_ref().is_some_and(|id| id.as_str() == "r-waivable-require")
            && reason.code == ReasonCode::RequirementNotSatisfied
    }));
    // The legacy E1 API still rejects the unapproved Require waiver.
    assert_eq!(evaluate(&graph, &e, &grant, &c, 150).disposition,
               WaiverAdmissionDisposition::ScopeMismatch);
    let assessed = reviewed(&graph, &e, &grant, &registry, &binding, &c);
    assert_eq!(assessed.disposition, WaiverAdmissionDisposition::CandidateEvaluated);
    assert_eq!(assessed.candidate_outcome, DecisionOutcome::Permit);
    assert_eq!(assessed.original, original);
    assert_eq!(graph.evaluate(&c, at(150), &Limits::default()).unwrap(), original);

    // Missing compensation means no candidate; the original Deny remains.
    c.facts[0].properties.as_mut().unwrap().source_quality = None;
    let negative = reviewed(&graph, &e, &grant, &registry, &binding, &c);
    assert_ne!(negative.candidate_outcome, DecisionOutcome::Permit);
    assert!(negative.candidate_target_layer.is_none());
}

#[test]
fn other_mandatory_policy_denial_still_dominates_reviewed_waiver() {
    let mut baseline = policy("baseline-owner");
    baseline.rules.push(deny("r-unrelated-deny"));
    let mut overlay = policy("waivable-owner");
    overlay.rules.push(deny("r-deny-waivable"));
    let graph = compile(&[baseline, overlay.clone()]);
    let e = exception_for(&overlay, "r-deny-waivable");
    let grant = grant_for(&e);
    let r = registry_for(&e);
    let b = binding_for(&e);
    let mut c = request();
    c.facts[0].profile_id = Some(ProfileId::parse(PROFILE).unwrap());
    let d = reviewed(&graph, &e, &grant, &r, &b, &c);
    assert_eq!(d.disposition, WaiverAdmissionDisposition::CandidateEvaluated);
    assert_eq!(d.candidate_outcome, DecisionOutcome::Deny);
    assert_eq!(d.original.outcome, DecisionOutcome::Deny);
}
