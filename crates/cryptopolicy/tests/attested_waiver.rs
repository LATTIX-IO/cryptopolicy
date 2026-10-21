//! FOSS-508: source-qualified, non-authorizing targeted Deny/Require waivers.
//! All positive verifiers are synthetic TEST-ONLY trust stand-ins.
#![allow(clippy::unwrap_used)]

use cryptopolicy::*;

fn at(ms: i64) -> EvaluationTime {
    EvaluationTime { unix_millis: ms }
}

fn source_policy(name: &str) -> PolicyDocument {
    let mut policy =
        PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap();
    policy.policy_id = PolicyId::parse(name).unwrap();
    policy
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
        requirements: vec![],
        temporal: None,
    }
}
fn mandatory_require(id: &str) -> PolicyRule {
    PolicyRule {
        effect: RuleEffect::Require,
        requirements: vec![Requirement::KeyExportable(true)],
        ..deny(id)
    }
}
fn compile(policies: &[PolicyDocument]) -> EffectivePolicy {
    let references: Vec<_> = policies
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
        baseline: references[0].clone(),
        overlays: references[1..].to_vec(),
    };
    let resolver = |reference: &PolicyReference| {
        Ok::<Option<PolicyNode>, CompositionError>(
            nodes
                .iter()
                .find(|node| node.document.policy_id == reference.policy_id)
                .cloned(),
        )
    };
    compile_policy_set(&set, &resolver, &Limits::default()).unwrap()
}

fn exception_for(
    policy: &PolicyDocument,
    target: &str,
    deviation: ExceptionDeviation,
) -> ExceptionReference {
    let mut e =
        ExceptionReference::parse_json(include_bytes!("fixtures/exception-reference-v1.json"))
            .unwrap();
    e.policy = PolicyReference::from_document(policy).unwrap();
    e.target_rule = RuleId::parse(target).unwrap();
    e.deviation = deviation;
    e
}

fn grant_for(exception: &ExceptionReference) -> PolicyWaiverGrant {
    PolicyWaiverGrant {
        schema_version: SchemaVersion::V1,
        policy: exception.policy.clone(),
        target_rule: exception.target_rule.clone(),
        exception_id: exception.exception_id.clone(),
        exception_digest: exception.correlation_digest().unwrap(),
        policy_authority_ref: EvidenceId::parse("owner-grant:alpha:1").unwrap(),
        deviation: exception.deviation,
        scope: exception.scope.clone(),
        compensating_controls: exception.compensating_controls.clone(),
        authorized_at: at(120),
        expires_at: at(250),
    }
}

fn registry_for(exception: &ExceptionReference) -> WaivabilityRegistry {
    WaivabilityRegistry {
        schema_version: SchemaVersion::V1,
        policy: exception.policy.clone(),
        registry_ref: EvidenceId::parse("registry:alpha:12").unwrap(),
        authority_ref: EvidenceId::parse("owner-registry:verified:alpha").unwrap(),
        revision: 12,
        nonce: EvidenceId::parse("registry-nonce:12").unwrap(),
        status: ExceptionStatus::Active,
        issued_at: at(100),
        effective_at: at(120),
        expires_at: at(250),
        entries: vec![WaivableRuleEntry {
            target_rule: exception.target_rule.clone(),
            deviation: exception.deviation,
            scope: exception.scope.clone(),
            profile_id: ProfileId::parse("AES-256-GCM").unwrap(),
            compensating_controls: exception.compensating_controls.clone(),
        }],
    }
}
fn binding_for(exception: &ExceptionReference) -> KeyProfileBinding {
    KeyProfileBinding {
        scope: exception.scope.clone(),
        profile_id: ProfileId::parse("AES-256-GCM").unwrap(),
        evidence_ref: EvidenceId::parse("attest:1").unwrap(),
        key_version_ref: EvidenceId::parse("key-version:3").unwrap(),
    }
}
fn context() -> CryptoContext {
    let mut ctx =
        CryptoContext::parse_json(include_bytes!("fixtures/evaluator-context-v1.json")).unwrap();
    ctx.facts[0].profile_id = Some(ProfileId::parse("AES-256-GCM").unwrap());
    ctx
}

fn exception_verifier(
    exception: &ExceptionReference,
    bound: &ExceptionBoundContext,
) -> Result<ExceptionVerification, ContractError> {
    Ok(ExceptionVerification {
        source_authenticated: exception.source_ref.as_str() == "source:alpha:1",
        approver_authorized: exception.approver.as_str() == "tenant:security:approver"
            && exception.scope.tenant_id == bound.scope.tenant_id,
        approval_verified: exception.approval_ref.as_str() == "approval:alpha:1",
        revocation_checked: true,
    })
}
fn owner_verifier(
    grant: &PolicyWaiverGrant,
    exception: &ExceptionReference,
    effective: &EffectivePolicy,
    context: &CryptoContext,
) -> Result<bool, ContractError> {
    Ok(grant.policy_authority_ref.as_str() == "owner-grant:alpha:1"
        && grant.exception_digest == exception.correlation_digest().unwrap()
        && effective
            .components()
            .iter()
            .any(|node| node.reference == grant.policy)
        && context.operation == grant.scope.operation)
}
fn registry_verifier(
    registry: &WaivabilityRegistry,
    request: &WaiverCandidateRequest<'_>,
) -> Result<RegistryVerification, ContractError> {
    Ok(RegistryVerification {
        registry_authenticated: registry.registry_ref.as_str() == "registry:alpha:12",
        owner_delegation_verified: registry.authority_ref.as_str()
            == "owner-registry:verified:alpha"
            && registry.policy == request.exception.policy,
        revocation_fresh: registry.status == ExceptionStatus::Active,
        replay_fresh: registry.revision == 12 && registry.nonce.as_str() == "registry-nonce:12",
    })
}
fn key_verifier(
    binding: &KeyProfileBinding,
    context: &CryptoContext,
) -> Result<bool, ContractError> {
    Ok(binding.scope.tenant_id.as_str() == "tenant:alpha"
        && binding.scope.key_ref.as_str() == "key:alpha:1"
        && binding.key_version_ref.as_str() == "key-version:3"
        && binding.evidence_ref.as_str() == "attest:1"
        && context.operation == binding.scope.operation
        && context.facts[0].profile_id.as_ref() == Some(&binding.profile_id))
}
fn source_verifier(
    request: &ProfileQualificationRequest<'_>,
) -> Result<ProfileEvidenceVerification, ContractError> {
    let fact = &request.context.facts[0];
    let props = fact.properties.as_ref();
    Ok(ProfileEvidenceVerification {
        source_authenticated: fact.evidence_ref.as_ref() == Some(&request.binding.evidence_ref)
            && request.binding.evidence_ref.as_str() == "attest:1"
            && fact.origin == FactOrigin::Observed
            && fact.verified,
        provider_attested: props
            .and_then(|p| p.provider_id.as_ref())
            .is_some_and(|v| v.as_str() == "provider:alpha")
            && props.and_then(|p| p.key_protection) == Some(KeyProtection::HardwareSecurityModule)
            && props.and_then(|p| p.source_quality) == Some(EvidenceQuality::ExternallyVerified),
        parameters_attested: *request.parameter == ProfileParameterWitness::KeyBits(256)
            && props.and_then(|p| p.key_size_bits) == Some(256)
            && props.and_then(|p| p.security_category) == Some(5),
        revocation_fresh: request.binding.key_version_ref.as_str() == "key-version:3",
    })
}

/// Complete fixture: original matching block with an otherwise Permit-ready
/// qualified AES fact; immutable source and all signed-looking references are
/// explicitly synthetic, not suitable for production trust.
struct Prepared {
    graph: EffectivePolicy,
    exception: ExceptionReference,
    grant: PolicyWaiverGrant,
    registry: WaivabilityRegistry,
    key: KeyProfileBinding,
    context: CryptoContext,
    parameter: ProfileParameterWitness,
}
impl Prepared {
    fn from(
        policies: &[PolicyDocument],
        targeted: &PolicyDocument,
        deviation: ExceptionDeviation,
    ) -> Self {
        let target_rule = match deviation {
            ExceptionDeviation::RuleDeny => "r-target-deny",
            ExceptionDeviation::RuleRequirement => "r-target-require",
        };
        let exception = exception_for(targeted, target_rule, deviation);
        Self {
            graph: compile(policies),
            grant: grant_for(&exception),
            registry: registry_for(&exception),
            key: binding_for(&exception),
            exception,
            context: context(),
            parameter: ProfileParameterWitness::KeyBits(256),
        }
    }

    fn deny() -> Self {
        let mut policy = source_policy("owner:baseline");
        policy.rules.push(deny("r-target-deny"));
        Self::from(&[policy.clone()], &policy, ExceptionDeviation::RuleDeny)
    }
    fn require() -> Self {
        let mut policy = source_policy("owner:baseline");
        policy.rules.push(mandatory_require("r-target-require"));
        Self::from(
            &[policy.clone()],
            &policy,
            ExceptionDeviation::RuleRequirement,
        )
    }

    fn run(&self) -> WaiverAdmissionReport {
        self.run_with(
            &exception_verifier,
            &owner_verifier,
            &registry_verifier,
            &key_verifier,
            &source_verifier,
        )
    }
    fn run_with<
        E: ExceptionSourceVerifier,
        A: PolicyWaiverAuthorityVerifier,
        R: WaivabilityRegistryVerifier,
        K: KeyProfileBindingVerifier,
        P: ProfileEvidenceVerifier,
    >(
        &self,
        e: &E,
        a: &A,
        r: &R,
        k: &K,
        p: &P,
    ) -> WaiverAdmissionReport {
        let limits = Limits::default();
        evaluate_attested_waiver_candidate(
            AttestedWaiverRequest {
                reviewed: ReviewedWaiverRequest {
                    request: WaiverCandidateRequest {
                        effective: &self.graph,
                        context: &self.context,
                        actual_scope: &self.exception.scope,
                        time: self.context.evaluation_time,
                        exception: &self.exception,
                        grant: &self.grant,
                        limits: &limits,
                    },
                    registry: &self.registry,
                    key_binding: &self.key,
                },
                parameter: &self.parameter,
            },
            e,
            a,
            r,
            k,
            p,
        )
        .unwrap()
    }
}

#[test]
fn owner_approved_matching_deny_uses_qualified_policy_not_profile_stripping() {
    let prepared = Prepared::deny();
    let original = prepared
        .graph
        .evaluate(&prepared.context, at(150), &Limits::default())
        .unwrap();
    assert_eq!(original.outcome, DecisionOutcome::Deny);
    assert_eq!(
        prepared
            .run_with(
                &UnverifiedExceptionReferences,
                &owner_verifier,
                &registry_verifier,
                &key_verifier,
                &source_verifier,
            )
            .disposition,
        WaiverAdmissionDisposition::ExceptionNotReady
    );

    let report = prepared.run();
    assert_eq!(
        report.disposition,
        WaiverAdmissionDisposition::CandidateEvaluated
    );
    assert_eq!(report.original, original);
    assert_eq!(report.original_effective_digest, *prepared.graph.digest());
    assert_eq!(report.candidate_outcome, DecisionOutcome::Permit);
    let candidate = report.candidate_target_layer.as_ref().unwrap();
    assert_eq!(candidate.outcome, DecisionOutcome::Permit);
    assert_ne!(candidate.policy_digest, prepared.exception.policy.digest);
    assert!(candidate.reasons.iter().any(|reason| {
        reason.code == ReasonCode::RequirementSatisfied
            && reason
                .rule_id
                .as_ref()
                .is_some_and(|r| r.as_str() == "r-require-protection")
    }));
    assert_eq!(
        prepared
            .graph
            .evaluate(&prepared.context, at(150), &Limits::default())
            .unwrap(),
        original
    );
    assert_eq!(report, prepared.run());
}

#[test]
fn specifically_approved_failed_mandatory_require_is_only_hypothetically_removed() {
    let prepared = Prepared::require();
    let original = prepared
        .graph
        .evaluate(&prepared.context, at(150), &Limits::default())
        .unwrap();
    assert_eq!(original.outcome, DecisionOutcome::Deny);
    assert!(original.components[0].decision.reasons.iter().any(|r| {
        r.rule_id
            .as_ref()
            .is_some_and(|id| id.as_str() == "r-target-require")
            && r.code == ReasonCode::RequirementNotSatisfied
    }));
    // The original FOSS-500/A evaluator remains reject-by-default for Require.
    assert!(
        evaluate_deny_waiver_candidate(
            WaiverCandidateRequest {
                effective: &prepared.graph,
                context: &prepared.context,
                actual_scope: &prepared.exception.scope,
                time: at(150),
                exception: &prepared.exception,
                grant: &prepared.grant,
                limits: &Limits::default(),
            },
            &exception_verifier,
            &owner_verifier,
        )
        .is_err()
    );
    let result = prepared.run();
    assert_eq!(
        result.disposition,
        WaiverAdmissionDisposition::CandidateEvaluated
    );
    assert_eq!(result.candidate_outcome, DecisionOutcome::Permit);
    assert_eq!(result.original, original);
    assert!(
        result
            .candidate_target_layer
            .as_ref()
            .unwrap()
            .matched_rules
            .iter()
            .all(|id| id.as_str() != "r-target-require")
    );
}

#[test]
fn missing_or_untrusted_source_and_actual_key_never_become_candidate_permit() {
    let fixture = Prepared::deny();
    let missing_source = fixture.run_with(
        &exception_verifier,
        &owner_verifier,
        &registry_verifier,
        &key_verifier,
        &UnverifiedProfileEvidence,
    );
    assert_eq!(
        missing_source.disposition,
        WaiverAdmissionDisposition::ProfileQualificationNotReady
    );
    assert_eq!(missing_source.candidate_outcome, DecisionOutcome::Deny);
    assert!(missing_source.candidate_target_layer.is_none());

    let wrong_key = fixture.run_with(
        &exception_verifier,
        &owner_verifier,
        &registry_verifier,
        &UnverifiedKeyProfileBinding,
        &source_verifier,
    );
    assert_eq!(
        wrong_key.disposition,
        WaiverAdmissionDisposition::KeyBindingUnverified
    );
    assert_eq!(wrong_key.candidate_outcome, DecisionOutcome::Deny);
    let wrong_owner = fixture.run_with(
        &exception_verifier,
        &UnverifiedPolicyWaiverAuthority,
        &registry_verifier,
        &key_verifier,
        &source_verifier,
    );
    assert_eq!(
        wrong_owner.disposition,
        WaiverAdmissionDisposition::GrantNotAuthorized
    );
    let wrong_registry = fixture.run_with(
        &exception_verifier,
        &owner_verifier,
        &UnverifiedWaivabilityRegistry,
        &key_verifier,
        &source_verifier,
    );
    assert_eq!(
        wrong_registry.disposition,
        WaiverAdmissionDisposition::RegistryNotAuthorized
    );
}

#[test]
fn altered_profile_key_tenant_operation_nonce_grant_and_expiry_fail_closed() {
    let mut f = Prepared::deny();
    f.context.facts[0].profile_id = Some(ProfileId::parse("AES-128-GCM").unwrap());
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::ScopeMismatch
    );

    f = Prepared::deny();
    f.key.key_version_ref = EvidenceId::parse("key-version:replayed").unwrap();
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::KeyBindingUnverified
    );

    f = Prepared::deny();
    f.exception.scope.tenant_id = PolicyId::parse("tenant:other").unwrap();
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::ScopeMismatch
    );

    f = Prepared::deny();
    f.context.operation = CryptoOperation::Decrypt;
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::ScopeMismatch
    );

    f = Prepared::deny();
    f.registry.nonce = EvidenceId::parse("registry-nonce:replayed").unwrap();
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::RegistryNotAuthorized
    );

    f = Prepared::deny();
    f.grant.policy_authority_ref = EvidenceId::parse("owner-grant:forged").unwrap();
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::GrantNotAuthorized
    );

    f = Prepared::deny();
    // A well-formed exception expires *after* activation, but before the
    // explicit evaluation time; malformed 150..150 is a typed error instead.
    f.exception.expires_at = at(151);
    f.grant.exception_digest = f.exception.correlation_digest().unwrap();
    f.context.evaluation_time = at(151);
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::ExceptionNotReady
    );

    f = Prepared::deny();
    f.context.evaluation_time = at(199);
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::CandidateEvaluated
    );
    f.context.evaluation_time = at(250);
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::RegistryNotAuthorized
    );
}

#[test]
fn nonmatching_target_and_wrong_owner_rule_can_never_be_waived() {
    let mut policy = source_policy("owner:baseline");
    let mut inactive = deny("r-target-deny");
    inactive.selector.match_all = false;
    inactive.selector.operation = Some(CryptoOperation::Decrypt);
    policy.rules.push(inactive);
    let original = Prepared::from(&[policy.clone()], &policy, ExceptionDeviation::RuleDeny);
    assert_eq!(
        original.run().disposition,
        WaiverAdmissionDisposition::NoMatchingExplicitDeny
    );
    let mut wrong = Prepared::deny();
    wrong.exception.target_rule = RuleId::parse("r-unknown-rule").unwrap();
    assert_ne!(wrong.run().candidate_outcome, DecisionOutcome::Permit);
}

#[test]
fn failed_compensation_blocks_even_if_target_deny_could_be_removed() {
    let mut source = source_policy("owner:baseline");
    source
        .rules
        .iter_mut()
        .find(|rule| rule.rule_id.as_str() == "r-require-protection")
        .unwrap()
        .requirements
        .push(Requirement::KeyExportable(true));
    source.rules.push(deny("r-target-deny"));
    let f = Prepared::from(&[source.clone()], &source, ExceptionDeviation::RuleDeny);
    let report = f.run();
    assert_eq!(report.original.outcome, DecisionOutcome::Deny);
    assert_eq!(
        report.disposition,
        WaiverAdmissionDisposition::CompensationNotSatisfied
    );
    assert_eq!(report.candidate_outcome, DecisionOutcome::Deny);
    assert!(report.candidate_target_layer.is_none());
}

#[test]
fn unrelated_mandatory_baseline_deny_still_dominates_qualified_overlay_candidate() {
    let mut baseline = source_policy("org:independent-baseline");
    baseline.rules.push(deny("r-independent-hard-deny"));
    let mut overlay = source_policy("org:waivable-overlay");
    overlay.rules.push(deny("r-target-deny"));
    let f = Prepared::from(
        &[baseline, overlay.clone()],
        &overlay,
        ExceptionDeviation::RuleDeny,
    );
    let report = f.run();
    assert_eq!(
        report.disposition,
        WaiverAdmissionDisposition::CandidateEvaluated
    );
    assert_eq!(
        report.candidate_target_layer.as_ref().unwrap().outcome,
        DecisionOutcome::Permit
    );
    assert_eq!(report.candidate_outcome, DecisionOutcome::Deny);
    assert_eq!(report.original.outcome, DecisionOutcome::Deny);
    assert_eq!(report.original.components.len(), 2);
}

#[test]
fn unrelated_indeterminate_baseline_remains_indeterminate_after_qualified_waiver() {
    // The original legacy evaluator cannot qualify a profile-bearing fact.
    // Even when the exact target overlay passes the independently attested
    // hypothetical waiver, a different layer's Indeterminate must survive.
    let baseline = source_policy("org:indeterminate-baseline");
    let mut overlay = source_policy("org:waivable-overlay");
    overlay.rules.push(deny("r-target-deny"));
    let fixture = Prepared::from(
        &[baseline.clone(), overlay.clone()],
        &overlay,
        ExceptionDeviation::RuleDeny,
    );
    let original = fixture
        .graph
        .evaluate(&fixture.context, at(150), &Limits::default())
        .unwrap();
    let original_baseline = original
        .components
        .iter()
        .find(|component| component.reference.policy_id == baseline.policy_id)
        .unwrap();
    assert_eq!(original_baseline.decision.outcome, DecisionOutcome::Indeterminate);
    assert!(original_baseline
        .decision
        .reasons
        .iter()
        .any(|reason| reason.code == ReasonCode::UnsupportedProfile));

    let report = fixture.run();
    assert_eq!(report.disposition, WaiverAdmissionDisposition::CandidateEvaluated);
    assert_eq!(
        report.candidate_target_layer.as_ref().unwrap().outcome,
        DecisionOutcome::Permit
    );
    assert_eq!(report.candidate_outcome, DecisionOutcome::Indeterminate);
    assert_eq!(report.original, original);
    assert_eq!(report.original_effective_digest, fixture.graph.digest().clone());
    let unchanged_baseline = report
        .original
        .components
        .iter()
        .find(|component| component.reference.policy_id == baseline.policy_id)
        .unwrap();
    assert_eq!(unchanged_baseline.decision, original_baseline.decision);
}

#[test]
fn policy_expiry_cannot_be_bypassed_by_a_permitted_target_rule_exception() {
    let mut policy = source_policy("owner:baseline");
    policy.expires_at = Some(at(150));
    policy.rules.push(deny("r-target-deny"));
    let f = Prepared::from(&[policy.clone()], &policy, ExceptionDeviation::RuleDeny);
    assert_eq!(
        f.run().disposition,
        WaiverAdmissionDisposition::NoMatchingExplicitDeny
    );
    assert_eq!(f.run().candidate_outcome, DecisionOutcome::Deny);
}

fn pqc_source_verifier(
    request: &ProfileQualificationRequest<'_>,
) -> Result<ProfileEvidenceVerification, ContractError> {
    let fact = &request.context.facts[0];
    let props = fact.properties.as_ref();
    Ok(ProfileEvidenceVerification {
        source_authenticated: fact.origin == FactOrigin::Observed
            && fact.verified
            && fact.evidence_ref.as_ref() == Some(&request.binding.evidence_ref)
            && request.binding.evidence_ref.as_str() == "attest:1",
        provider_attested: props
            .and_then(|p| p.provider_id.as_ref())
            .is_some_and(|id| id.as_str() == "provider:alpha")
            && props.and_then(|p| p.source_quality) == Some(EvidenceQuality::ExternallyVerified),
        parameters_attested: matches!(
            request.parameter,
            ProfileParameterWitness::NamedSet(p) if p.as_str() == "ML-DSA-65"
        ) && props.and_then(|p| p.key_size_bits).is_none()
            && props.and_then(|p| p.security_category) == Some(3),
        revocation_fresh: request.binding.key_version_ref.as_str() == "key-version:3",
    })
}

#[test]
fn qualified_ml_dsa_profile_can_only_simulate_exact_owner_approved_deny() {
    let mut policy = source_policy("owner:pqc");
    let require = policy
        .rules
        .iter_mut()
        .find(|r| r.rule_id.as_str() == "r-require-protection")
        .unwrap();
    require.requirements = vec![
        Requirement::MinSecurityCategory(3),
        Requirement::SourceQuality(EvidenceQuality::ExternallyVerified),
    ];
    let allow = policy
        .rules
        .iter_mut()
        .find(|r| r.rule_id.as_str() == "r-allow-aes")
        .unwrap();
    allow.rule_id = RuleId::parse("r-allow-mldsa").unwrap();
    allow.selector.operation = Some(CryptoOperation::Verify);
    allow.selector.algorithm_id = Some(AlgorithmId::parse("ML-DSA-65").unwrap());
    allow.selector.profile_id = Some(ProfileId::parse("ML-DSA-65").unwrap());
    allow.requirements = vec![
        Requirement::Algorithm(AlgorithmId::parse("ML-DSA-65").unwrap()),
        Requirement::Profile(ProfileId::parse("ML-DSA-65").unwrap()),
        Requirement::SourceOrigin(FactOrigin::Observed),
    ];
    policy.rules.push(deny("r-target-deny"));
    let mut f = Prepared::from(&[policy.clone()], &policy, ExceptionDeviation::RuleDeny);
    f.context.operation = CryptoOperation::Verify;
    f.context.facts[0].algorithm_id = Some(AlgorithmId::parse("ML-DSA-65").unwrap());
    f.context.facts[0].profile_id = Some(ProfileId::parse("ML-DSA-65").unwrap());
    let props = f.context.facts[0].properties.as_mut().unwrap();
    props.key_size_bits = None;
    props.security_category = Some(3);
    f.exception.scope.operation = CryptoOperation::Verify;
    f.exception.scope.algorithm_id = AlgorithmId::parse("ML-DSA-65").unwrap();
    f.grant = grant_for(&f.exception);
    f.registry = registry_for(&f.exception);
    f.registry.entries[0].profile_id = ProfileId::parse("ML-DSA-65").unwrap();
    f.key = binding_for(&f.exception);
    f.key.profile_id = ProfileId::parse("ML-DSA-65").unwrap();
    f.parameter = ProfileParameterWitness::NamedSet(ProfileId::parse("ML-DSA-65").unwrap());
    let report = f.run_with(
        &exception_verifier,
        &owner_verifier,
        &registry_verifier,
        &key_verifier,
        &pqc_source_verifier,
    );
    assert_eq!(report.original.outcome, DecisionOutcome::Deny);
    assert_eq!(
        report.disposition,
        WaiverAdmissionDisposition::CandidateEvaluated
    );
    assert_eq!(report.candidate_outcome, DecisionOutcome::Permit);
    assert_ne!(
        report
            .candidate_target_layer
            .as_ref()
            .unwrap()
            .policy_digest,
        f.exception.policy.digest
    );

    // An otherwise identical source with a wrong attested named parameter
    // cannot inherit the approved ML-DSA-65 profile or obtain a candidate.
    f.parameter = ProfileParameterWitness::NamedSet(ProfileId::parse("ML-DSA-44").unwrap());
    let wrong_named_set = f.run_with(
        &exception_verifier,
        &owner_verifier,
        &registry_verifier,
        &key_verifier,
        &pqc_source_verifier,
    );
    assert_eq!(
        wrong_named_set.disposition,
        WaiverAdmissionDisposition::ProfileQualificationNotReady
    );
    assert_eq!(wrong_named_set.candidate_outcome, DecisionOutcome::Deny);
}

#[test]
fn unsupported_named_hybrid_cannot_be_granted_by_valid_owner_registry() {
    let mut policy = source_policy("owner:hybrid");
    let allow = policy
        .rules
        .iter_mut()
        .find(|r| r.rule_id.as_str() == "r-allow-aes")
        .unwrap();
    allow.requirements.push(Requirement::NamedHybrid(
        ProfileId::parse("fake-hybrid-construction").unwrap(),
    ));
    policy.rules.push(deny("r-target-deny"));
    let f = Prepared::from(&[policy.clone()], &policy, ExceptionDeviation::RuleDeny);
    let report = f.run();
    assert_eq!(report.original.outcome, DecisionOutcome::Deny);
    assert_eq!(
        report.disposition,
        WaiverAdmissionDisposition::CompensationNotSatisfied
    );
    assert_eq!(report.candidate_outcome, DecisionOutcome::Deny);
    assert!(report.candidate_target_layer.is_none());
}

#[test]
fn original_unknown_mandatory_requirement_requires_exact_owner_waiver() {
    // Unknown source sensitivity is not silently assumed to match a Require.
    // Only a fresh separately approved exact waiver, with all verified
    // compensators, may yield hypothetical policy data, never PEP authority.
    let mut policy = source_policy("owner:unknown-require");
    let mut target = mandatory_require("r-target-require");
    target.requirements = vec![Requirement::Sensitivity(DataSensitivity::Restricted)];
    policy.rules.push(target);
    let mut f = Prepared::from(
        &[policy.clone()],
        &policy,
        ExceptionDeviation::RuleRequirement,
    );
    f.context.facts[0]
        .properties
        .as_mut()
        .unwrap()
        .data_sensitivity = None;
    let original = f
        .graph
        .evaluate(&f.context, at(150), &Limits::default())
        .unwrap();
    assert_eq!(original.outcome, DecisionOutcome::Indeterminate);
    assert!(
        original.components[0]
            .decision
            .reasons
            .iter()
            .any(|reason| {
                reason.rule_id.as_ref() == Some(&f.exception.target_rule)
                    && reason.code == ReasonCode::MissingRequiredAttribute
            })
    );
    let report = f.run();
    assert_eq!(
        report.disposition,
        WaiverAdmissionDisposition::CandidateEvaluated
    );
    assert_eq!(report.original, original);
    assert_eq!(report.candidate_outcome, DecisionOutcome::Permit);
    assert_eq!(
        f.graph
            .evaluate(&f.context, at(150), &Limits::default())
            .unwrap(),
        original
    );
}

#[test]
fn same_rule_id_in_an_independent_baseline_is_never_waived_by_overlay_authority() {
    let mut baseline = source_policy("org:same-id-baseline");
    baseline.rules.push(deny("r-target-deny"));
    let mut overlay = source_policy("org:target-overlay");
    overlay.rules.push(deny("r-target-deny"));
    let f = Prepared::from(
        &[baseline.clone(), overlay.clone()],
        &overlay,
        ExceptionDeviation::RuleDeny,
    );
    let report = f.run();
    assert_eq!(
        report.disposition,
        WaiverAdmissionDisposition::CandidateEvaluated
    );
    assert_eq!(
        report.candidate_target_layer.as_ref().unwrap().outcome,
        DecisionOutcome::Permit
    );
    assert_eq!(report.original.components.len(), 2);
    assert_eq!(report.candidate_outcome, DecisionOutcome::Deny);
    let remaining = report
        .original
        .components
        .iter()
        .find(|c| c.reference.policy_id == baseline.policy_id)
        .unwrap();
    assert_eq!(remaining.decision.outcome, DecisionOutcome::Deny);
    assert!(remaining.decision.reasons.iter().any(|r| {
        r.rule_id
            .as_ref()
            .is_some_and(|id| id.as_str() == "r-target-deny")
            && r.code == ReasonCode::ExplicitDeny
    }));
}
