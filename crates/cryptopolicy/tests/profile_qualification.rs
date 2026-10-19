//! FOSS-505 exact embedded-catalog and external profile-evidence regressions.
#![allow(clippy::unwrap_used)]

use cryptopolicy::*;

const PIN: &str = pqc_kit::EMBEDDED_CATALOG_SHA256_V1;

struct SyntheticEvidenceSource;
impl ProfileEvidenceVerifier for SyntheticEvidenceSource {
    fn verify(
        &self,
        request: &ProfileQualificationRequest<'_>,
    ) -> Result<ProfileEvidenceVerification, ContractError> {
        let fact = &request.context.facts[0];
        let provider_ok = fact
            .properties
            .as_ref()
            .and_then(|p| p.provider_id.as_ref())
            .is_some_and(|id| id.as_str() == "provider:alpha");
        let parameter_ok = match request.parameter {
            ProfileParameterWitness::KeyBits(bits) => *bits == 256,
            ProfileParameterWitness::NamedSet(name) => {
                matches!(name.as_str(), "ML-DSA-65" | "ML-KEM-1024" | "FALCON-512")
            }
        };
        Ok(ProfileEvidenceVerification {
            source_authenticated: request.binding.evidence_ref.as_str() == "attest:1",
            provider_attested: provider_ok,
            parameters_attested: parameter_ok,
            revocation_fresh: request.binding.key_version_ref.as_str() == "key-version:3",
        })
    }
}
struct SyntheticKeyOwner;
impl KeyProfileBindingVerifier for SyntheticKeyOwner {
    fn verify(
        &self,
        binding: &KeyProfileBinding,
        context: &CryptoContext,
    ) -> Result<bool, ContractError> {
        Ok(binding.scope.tenant_id.as_str() == "tenant:alpha"
            && binding.scope.key_ref.as_str() == "key:alpha:1"
            && binding.key_version_ref.as_str() == "key-version:3"
            && context.operation == binding.scope.operation)
    }
}
fn prepare(
    name: &str,
    operation: CryptoOperation,
) -> (CryptoContext, ExceptionScope, KeyProfileBinding) {
    let mut c =
        CryptoContext::parse_json(include_bytes!("fixtures/evaluator-context-v1.json")).unwrap();
    c.operation = operation;
    c.facts[0].algorithm_id = Some(AlgorithmId::parse(name).unwrap());
    c.facts[0].profile_id = Some(ProfileId::parse(name).unwrap());
    let e = ExceptionReference::parse_json(include_bytes!("fixtures/exception-reference-v1.json"))
        .unwrap();
    let mut scope = e.scope;
    scope.operation = operation;
    scope.algorithm_id = AlgorithmId::parse(name).unwrap();
    let binding = KeyProfileBinding {
        scope: scope.clone(),
        profile_id: ProfileId::parse(name).unwrap(),
        evidence_ref: EvidenceId::parse("attest:1").unwrap(),
        key_version_ref: EvidenceId::parse("key-version:3").unwrap(),
    };
    (c, scope, binding)
}
fn qualify(
    c: &CryptoContext,
    scope: &ExceptionScope,
    binding: &KeyProfileBinding,
    parameter: &ProfileParameterWitness,
) -> ProfileQualificationReport {
    qualify_embedded_profile(
        ProfileQualificationRequest {
            context: c,
            actual_scope: scope,
            binding,
            parameter,
            time: c.evaluation_time,
            limits: &Limits::default(),
        },
        &SyntheticEvidenceSource,
        &SyntheticKeyOwner,
    )
    .unwrap()
}
fn named(profile: &str) -> ProfileParameterWitness {
    ProfileParameterWitness::NamedSet(ProfileId::parse(profile).unwrap())
}

#[test]
fn aes_exact_key_bits_and_source_evidence_qualify_without_policy_permit() {
    let (c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let w = ProfileParameterWitness::KeyBits(256);
    let result = qualify(&c, &scope, &binding, &w);
    assert_eq!(
        result.finding,
        ProfileQualificationFinding::ReadyForVerifiedEvaluator
    );
    assert_eq!(result.catalog_digest.as_str(), PIN);
    assert_eq!(result.profile_id.as_str(), "AES-256-GCM");
    assert_eq!(result.evaluated_at, c.evaluation_time);
    assert_eq!(result, qualify(&c, &scope, &binding, &w));

    // Existing public evaluator MUST remain conservative when a profile is
    // present: qualification is not policy authority.
    let policy =
        PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap();
    let original = evaluate(&policy, &c, c.evaluation_time).unwrap();
    assert_eq!(original.outcome, DecisionOutcome::Indeterminate);
}

#[test]
fn pq_named_set_profile_uses_exact_canonical_catalog_identity() {
    for (name, operation) in [
        ("ML-DSA-65", CryptoOperation::Verify),
        ("ML-KEM-1024", CryptoOperation::Encapsulate),
    ] {
        let (mut c, scope, binding) = prepare(name, operation);
        c.facts[0].properties.as_mut().unwrap().key_size_bits = None;
        c.facts[0].properties.as_mut().unwrap().security_category =
            Some(if name == "ML-DSA-65" { 3 } else { 5 });
        let result = qualify(&c, &scope, &binding, &named(name));
        assert_eq!(
            result.finding,
            ProfileQualificationFinding::ReadyForVerifiedEvaluator
        );
        assert_eq!(result.catalog_digest.as_str(), PIN);
    }
}

#[test]
fn aliases_unknown_profiles_and_deprecated_draft_parameters_never_qualify() {
    let (mut c, scope, binding) = prepare("FALCON-512", CryptoOperation::Sign);
    c.facts[0].properties.as_mut().unwrap().key_size_bits = None;
    assert_eq!(
        qualify(&c, &scope, &binding, &named("FALCON-512")).finding,
        ProfileQualificationFinding::NonStandardProfile
    );
    let (mut c, scope, binding) = prepare("DILITHIUM3", CryptoOperation::Sign);
    c.facts[0].properties.as_mut().unwrap().key_size_bits = None;
    assert_eq!(
        qualify(&c, &scope, &binding, &named("DILITHIUM3")).finding,
        ProfileQualificationFinding::UnknownOrAliasProfile
    );
    // SHA-256 of the checked-in JSON is not interchangeable with any claimed
    // external snapshot hash, release version, or vendor alias.
    assert_eq!(pqc_kit::Catalog::embedded_v1().unwrap().fingerprint(), PIN);
}

#[test]
fn wrong_operations_key_bits_or_named_set_fail_before_source_authentication() {
    let (mut c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Sign);
    assert_eq!(
        qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(256)).finding,
        ProfileQualificationFinding::OperationUnsupported
    );
    c.operation = CryptoOperation::Encrypt;
    let mut scope = scope;
    scope.operation = CryptoOperation::Encrypt;
    let mut binding = binding;
    binding.scope.operation = CryptoOperation::Encrypt;
    assert_eq!(
        qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(128)).finding,
        ProfileQualificationFinding::ParameterMismatch
    );
    c.facts[0].properties.as_mut().unwrap().key_size_bits = Some(128);
    assert_eq!(
        qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(128)).finding,
        ProfileQualificationFinding::ParameterMismatch
    );
    let (mut pq, scope, binding) = prepare("ML-DSA-65", CryptoOperation::Verify);
    pq.facts[0].properties.as_mut().unwrap().key_size_bits = None;
    pq.facts[0].properties.as_mut().unwrap().security_category = Some(3);
    assert_eq!(
        qualify(&pq, &scope, &binding, &named("ML-DSA-44")).finding,
        ProfileQualificationFinding::ParameterMismatch
    );
}

#[test]
fn unsupported_key_agreement_and_derivation_never_coerce_to_kem_usage() {
    for operation in [CryptoOperation::KeyAgreement, CryptoOperation::DeriveKey] {
        let (mut context, scope, binding) = prepare("ML-KEM-1024", operation);
        context.facts[0].properties.as_mut().unwrap().key_size_bits = None;
        let result = qualify(&context, &scope, &binding, &named("ML-KEM-1024"));
        assert_eq!(
            result.finding,
            ProfileQualificationFinding::OperationUnsupported
        );
    }
}

#[test]
fn inflated_pqc_category_cannot_relabel_a_standardized_profile() {
    let (mut c, scope, binding) = prepare("ML-DSA-65", CryptoOperation::Verify);
    c.facts[0].properties.as_mut().unwrap().key_size_bits = None;
    c.facts[0].properties.as_mut().unwrap().security_category = Some(5);
    let result = qualify(&c, &scope, &binding, &named("ML-DSA-65"));
    assert_eq!(
        result.finding,
        ProfileQualificationFinding::ParameterMismatch
    );
    c.facts[0].properties.as_mut().unwrap().security_category = Some(3);
    assert_eq!(
        qualify(&c, &scope, &binding, &named("ML-DSA-65")).finding,
        ProfileQualificationFinding::ReadyForVerifiedEvaluator
    );
}

#[test]
fn swapped_profile_algorithm_key_environment_operation_and_time_fail_closed() {
    let (mut c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    c.facts[0].profile_id = Some(ProfileId::parse("AES-128-GCM").unwrap());
    assert_eq!(
        qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(256)).finding,
        ProfileQualificationFinding::ScopeMismatch
    );
    c.facts[0].profile_id = Some(ProfileId::parse("AES-256-GCM").unwrap());
    let mut other = scope.clone();
    other.key_ref = EvidenceId::parse("key:forged").unwrap();
    assert_eq!(
        qualify(&c, &other, &binding, &ProfileParameterWitness::KeyBits(256)).finding,
        ProfileQualificationFinding::ScopeMismatch
    );
    c.environment = Some("dev".to_owned());
    assert_eq!(
        qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(256)).finding,
        ProfileQualificationFinding::ScopeMismatch
    );
    c.environment = Some("prod".to_owned());
    c.operation = CryptoOperation::Decrypt;
    assert_eq!(
        qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(256)).finding,
        ProfileQualificationFinding::ScopeMismatch
    );
    c.operation = CryptoOperation::Encrypt;
    c.evaluation_time = EvaluationTime { unix_millis: 152 };
    let req = ProfileQualificationRequest {
        context: &c,
        actual_scope: &scope,
        binding: &binding,
        parameter: &ProfileParameterWitness::KeyBits(256),
        time: EvaluationTime { unix_millis: 150 },
        limits: &Limits::default(),
    };
    assert_eq!(
        qualify_embedded_profile(req, &SyntheticEvidenceSource, &SyntheticKeyOwner)
            .unwrap()
            .finding,
        ProfileQualificationFinding::ScopeMismatch
    );
}

#[test]
fn source_quality_missing_attestation_and_nonobserved_facts_never_qualify() {
    let (mut c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    c.facts[0].origin = FactOrigin::Configured;
    assert_eq!(
        qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(256)).finding,
        ProfileQualificationFinding::EvidenceIncomplete
    );
    c.facts[0].origin = FactOrigin::Observed;
    c.facts[0].verified = false;
    // A claimed ExternallyVerified source with a false fact-verification flag
    // is internally contradictory, and must fail structural validation
    // with an error rather than reaching a normal evidence finding.
    let witness = ProfileParameterWitness::KeyBits(256);
    let direct = ProfileQualificationRequest {
        context: &c,
        actual_scope: &scope,
        binding: &binding,
        parameter: &witness,
        time: c.evaluation_time,
        limits: &Limits::default(),
    };
    assert_eq!(
        qualify_embedded_profile(direct, &SyntheticEvidenceSource, &SyntheticKeyOwner),
        Err(ContractError::InvalidDocument(
            "inconsistent_source_quality"
        ))
    );
    c.facts[0].properties.as_mut().unwrap().source_quality = None;
    assert_eq!(
        qualify(&c, &scope, &binding, &witness).finding,
        ProfileQualificationFinding::EvidenceIncomplete
    );
    c.facts[0].verified = true;
    c.facts[0].properties.as_mut().unwrap().source_quality = None;
    assert_eq!(
        qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(256)).finding,
        ProfileQualificationFinding::EvidenceIncomplete
    );
    c.facts[0].properties.as_mut().unwrap().source_quality =
        Some(EvidenceQuality::ExternallyVerified);
    let mut forged = binding.clone();
    forged.key_version_ref = EvidenceId::parse("key-version:replayed").unwrap();
    let key = qualify(&c, &scope, &forged, &ProfileParameterWitness::KeyBits(256));
    assert_eq!(
        key.finding,
        ProfileQualificationFinding::KeyNotAuthenticated
    );
    c.facts[0].properties.as_mut().unwrap().provider_id =
        Some(ProviderId::parse("provider:wrong").unwrap());
    let source = qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(256));
    assert_eq!(
        source.finding,
        ProfileQualificationFinding::SourceNotAuthenticated
    );
}

#[test]
fn every_source_verification_flag_and_default_key_verifier_is_required() {
    let (c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let param = ProfileParameterWitness::KeyBits(256);
    let req = ProfileQualificationRequest {
        context: &c,
        actual_scope: &scope,
        binding: &binding,
        parameter: &param,
        time: c.evaluation_time,
        limits: &Limits::default(),
    };
    let missing_source =
        qualify_embedded_profile(req, &UnverifiedProfileEvidence, &SyntheticKeyOwner).unwrap();
    assert_eq!(
        missing_source.finding,
        ProfileQualificationFinding::SourceNotAuthenticated
    );
    let missing_key =
        qualify_embedded_profile(req, &SyntheticEvidenceSource, &UnverifiedKeyProfileBinding)
            .unwrap();
    assert_eq!(
        missing_key.finding,
        ProfileQualificationFinding::KeyNotAuthenticated
    );
    for blocked_flag in 0..4 {
        let checker = move |_: &ProfileQualificationRequest<'_>| {
            let mut flags = ProfileEvidenceVerification {
                source_authenticated: true,
                provider_attested: true,
                parameters_attested: true,
                revocation_fresh: true,
            };
            match blocked_flag {
                0 => flags.source_authenticated = false,
                1 => flags.provider_attested = false,
                2 => flags.parameters_attested = false,
                _ => flags.revocation_fresh = false,
            }
            Ok(flags)
        };
        let result = qualify_embedded_profile(req, &checker, &SyntheticKeyOwner).unwrap();
        assert_eq!(
            result.finding,
            ProfileQualificationFinding::SourceNotAuthenticated
        );
    }
}

#[test]
fn malformed_multiple_fact_and_bounded_contexts_never_upgrade_evidence() {
    let (mut c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    c.facts.push(c.facts[0].clone());
    let res = qualify(&c, &scope, &binding, &ProfileParameterWitness::KeyBits(256));
    assert_eq!(res.finding, ProfileQualificationFinding::ScopeMismatch);
    c.facts.remove(1);
    let bytes = serde_json::to_vec(&c).unwrap();
    let short = Limits {
        max_json_bytes: bytes.len() - 1,
        ..Limits::default()
    };
    let par = ProfileParameterWitness::KeyBits(256);
    let req = ProfileQualificationRequest {
        context: &c,
        actual_scope: &scope,
        binding: &binding,
        parameter: &par,
        time: c.evaluation_time,
        limits: &short,
    };
    assert!(matches!(
        qualify_embedded_profile(req, &SyntheticEvidenceSource, &SyntheticKeyOwner),
        Err(ContractError::PayloadTooLarge)
    ));
}

#[test]
fn caller_constructed_oversize_context_is_checked_before_json_allocation() {
    let (mut context, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    context.facts = vec![context.facts[0].clone(); 2049];
    let witness = ProfileParameterWitness::KeyBits(256);
    let limit = Limits::default();
    let too_many = ProfileQualificationRequest {
        context: &context,
        actual_scope: &scope,
        binding: &binding,
        parameter: &witness,
        time: context.evaluation_time,
        limits: &limit,
    };
    assert_eq!(
        qualify_embedded_profile(too_many, &SyntheticEvidenceSource, &SyntheticKeyOwner),
        Err(ContractError::ResourceLimitExceeded("context facts"))
    );
    context.facts.truncate(1);
    context.environment = Some("x".repeat(limit.max_json_bytes + 1));
    // The malformed environment cannot cause a JSON allocation of
    // an unbounded caller-created string before exact scope mismatch.
    let huge_environment = ProfileQualificationRequest {
        context: &context,
        actual_scope: &scope,
        binding: &binding,
        parameter: &witness,
        time: context.evaluation_time,
        limits: &limit,
    };
    assert_eq!(
        qualify_embedded_profile(
            huge_environment,
            &SyntheticEvidenceSource,
            &SyntheticKeyOwner
        )
        .unwrap()
        .finding,
        ProfileQualificationFinding::ScopeMismatch
    );
}

// FOSS-507: the separately qualified evaluator is never a PEP authorization
// token. These tests exercise the actual v1 evaluator's original rule/deny
// precedence, not reconstructed fixture expectations or a Permit shortcut.

fn fixture_policy() -> PolicyDocument {
    PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap()
}
fn verified_policy_evaluation(
    policy: &PolicyDocument,
    context: &CryptoContext,
    scope: &ExceptionScope,
    binding: &KeyProfileBinding,
    witness: &ProfileParameterWitness,
) -> QualifiedProfilePolicyDecision {
    evaluate_qualified_profile_with_limits(
        policy,
        ProfileQualificationRequest {
            context,
            actual_scope: scope,
            binding,
            parameter: witness,
            time: context.evaluation_time,
            limits: &Limits::default(),
        },
        &SyntheticEvidenceSource,
        &SyntheticKeyOwner,
    )
    .unwrap()
}

#[test]
fn verified_profile_evaluator_interprets_exact_allow_without_changing_legacy() {
    let (c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let witness = ProfileParameterWitness::KeyBits(256);
    let mut p = fixture_policy();
    let allow = p
        .rules
        .iter_mut()
        .find(|rule| rule.rule_id.as_str() == "r-allow-aes")
        .unwrap();
    allow.selector.profile_id = Some(ProfileId::parse("AES-256-GCM").unwrap());
    allow.requirements.push(Requirement::Profile(
        ProfileId::parse("AES-256-GCM").unwrap(),
    ));
    let before = evaluate_with_limits(&p, &c, c.evaluation_time, &Limits::default()).unwrap();
    assert_eq!(before.outcome, DecisionOutcome::Indeterminate);
    let after = verified_policy_evaluation(&p, &c, &scope, &binding, &witness);
    assert_eq!(
        after.qualification.finding,
        ProfileQualificationFinding::ReadyForVerifiedEvaluator
    );
    assert_eq!(after.decision.outcome, DecisionOutcome::Permit);
    assert_eq!(after.decision.policy_digest, p.canonical_digest().unwrap());
    assert_eq!(before.policy_digest, after.decision.policy_digest);
    assert!(
        after
            .decision
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::ExplicitAllow)
    );
    assert!(
        after
            .decision
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::RequirementSatisfied)
    );
    assert_eq!(
        after,
        verified_policy_evaluation(&p, &c, &scope, &binding, &witness)
    );
    // No caller flag has changed the meaning of the original entrypoint.
    assert_eq!(
        before,
        evaluate_with_limits(&p, &c, c.evaluation_time, &Limits::default()).unwrap()
    );
}

#[test]
fn canonical_pqc_signature_profile_requires_real_source_binding_and_explicit_allow() {
    let (mut c, scope, binding) = prepare("ML-DSA-65", CryptoOperation::Verify);
    c.facts[0].properties.as_mut().unwrap().key_size_bits = None;
    c.facts[0].properties.as_mut().unwrap().security_category = Some(3);
    let mut p = fixture_policy();
    p.rules.clear();
    let profile = ProfileId::parse("ML-DSA-65").unwrap();
    p.rules.push(PolicyRule {
        rule_id: RuleId::parse("allow-attested-ml-dsa").unwrap(),
        effect: RuleEffect::Allow,
        selector: RuleSelector {
            match_all: false,
            operation: Some(CryptoOperation::Verify),
            algorithm_id: Some(AlgorithmId::parse("ML-DSA-65").unwrap()),
            profile_id: Some(profile.clone()),
            environment: Some("prod".to_string()),
            advanced: None,
        },
        requirements: vec![
            Requirement::Profile(profile.clone()),
            Requirement::SourceQuality(EvidenceQuality::ExternallyVerified),
        ],
        temporal: None,
    });
    let named = ProfileParameterWitness::NamedSet(profile);
    assert_eq!(
        evaluate(&p, &c, c.evaluation_time).unwrap().outcome,
        DecisionOutcome::Indeterminate
    );
    let evaluated = verified_policy_evaluation(&p, &c, &scope, &binding, &named);
    assert_eq!(
        evaluated.qualification.finding,
        ProfileQualificationFinding::ReadyForVerifiedEvaluator
    );
    assert_eq!(evaluated.decision.outcome, DecisionOutcome::Permit);
    assert_eq!(
        evaluated.decision.policy_digest,
        p.canonical_digest().unwrap()
    );
}

#[test]
fn qualified_fact_never_overrides_explicit_deny_or_unsatisfied_mandatory_require() {
    let (mut c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let witness = ProfileParameterWitness::KeyBits(256);
    let mut p = fixture_policy();
    p.rules.push(PolicyRule {
        rule_id: RuleId::parse("x-foss-507-deny").unwrap(),
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
    });
    for order in 0..2 {
        if order == 1 {
            p.rules.reverse();
        }
        let d = verified_policy_evaluation(&p, &c, &scope, &binding, &witness).decision;
        assert_eq!(d.outcome, DecisionOutcome::Deny);
        assert!(d.reasons.iter().any(|r| r.code == ReasonCode::ExplicitDeny));
        assert!(
            !d.reasons
                .iter()
                .any(|r| r.code == ReasonCode::ExplicitAllow)
        );
    }
    p = fixture_policy();
    p.rules
        .iter_mut()
        .find(|r| r.rule_id.as_str() == "r-require-protection")
        .unwrap()
        .requirements
        .push(Requirement::KeyExportable(true));
    let denied = verified_policy_evaluation(&p, &c, &scope, &binding, &witness).decision;
    assert_eq!(denied.outcome, DecisionOutcome::Deny);
    assert!(
        denied
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::RequirementNotSatisfied)
    );
    c.facts[0].properties.as_mut().unwrap().key_exportable = None;
    let uncertain = verified_policy_evaluation(&p, &c, &scope, &binding, &witness).decision;
    assert_eq!(uncertain.outcome, DecisionOutcome::Indeterminate);
    assert!(
        uncertain
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::MissingRequiredAttribute)
    );
}

#[test]
fn qualified_fact_without_explicit_allow_is_still_denied() {
    let (c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let mut p = fixture_policy();
    p.rules.retain(|r| r.effect != RuleEffect::Allow);
    // Even an explicit default Allow cannot authorize an unmatched context.
    p.default_effect = DefaultEffect::Allow;
    let d = verified_policy_evaluation(
        &p,
        &c,
        &scope,
        &binding,
        &ProfileParameterWitness::KeyBits(256),
    );
    assert_eq!(
        d.qualification.finding,
        ProfileQualificationFinding::ReadyForVerifiedEvaluator
    );
    assert_eq!(d.decision.outcome, DecisionOutcome::Deny);
    assert!(
        d.decision
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::DefaultDenied)
    );
}

#[test]
fn default_deny_verifiers_cannot_promote_a_spoofed_qualification_report() {
    let (c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let p = fixture_policy();
    let witness = ProfileParameterWitness::KeyBits(256);
    let req = ProfileQualificationRequest {
        context: &c,
        actual_scope: &scope,
        binding: &binding,
        parameter: &witness,
        time: c.evaluation_time,
        limits: &Limits::default(),
    };
    for untrusted in 0..2 {
        let checked = if untrusted == 0 {
            evaluate_qualified_profile_with_limits(
                &p,
                req,
                &UnverifiedProfileEvidence,
                &SyntheticKeyOwner,
            )
            .unwrap()
        } else {
            evaluate_qualified_profile_with_limits(
                &p,
                req,
                &SyntheticEvidenceSource,
                &UnverifiedKeyProfileBinding,
            )
            .unwrap()
        };
        assert_eq!(checked.decision.outcome, DecisionOutcome::Indeterminate);
        assert_ne!(
            checked.qualification.finding,
            ProfileQualificationFinding::ReadyForVerifiedEvaluator
        );
    }
    // A forged/mutated public metadata report is not accepted as proof by
    // evaluate_qualified_profile_with_limits, which accepts ONLY the actual
    // verified source/key callbacks and re-runs qualification on every call.
    let mut forged =
        qualify_embedded_profile(req, &UnverifiedProfileEvidence, &SyntheticKeyOwner).unwrap();
    forged.finding = ProfileQualificationFinding::ReadyForVerifiedEvaluator;
    assert_eq!(
        forged.finding,
        ProfileQualificationFinding::ReadyForVerifiedEvaluator
    );
    let denied = evaluate_qualified_profile_with_limits(
        &p,
        req,
        &UnverifiedProfileEvidence,
        &SyntheticKeyOwner,
    )
    .unwrap();
    assert_eq!(denied.decision.outcome, DecisionOutcome::Indeterminate);
}

#[test]
fn named_hybrid_remains_unsupported_even_with_verified_canonical_profile() {
    let (c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let mut p = fixture_policy();
    p.rules
        .iter_mut()
        .find(|r| r.rule_id.as_str() == "r-allow-aes")
        .unwrap()
        .requirements
        .push(Requirement::NamedHybrid(
            ProfileId::parse("AES-256-GCM").unwrap(),
        ));
    let d = verified_policy_evaluation(
        &p,
        &c,
        &scope,
        &binding,
        &ProfileParameterWitness::KeyBits(256),
    );
    assert_eq!(
        d.qualification.finding,
        ProfileQualificationFinding::ReadyForVerifiedEvaluator
    );
    assert_eq!(d.decision.outcome, DecisionOutcome::Indeterminate);
    assert!(
        d.decision
            .reasons
            .iter()
            .any(|r| r.code == ReasonCode::UnsupportedProfile)
    );
}

#[test]
fn verified_profile_policy_expiry_and_activation_use_only_explicit_utc() {
    let (mut c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let p = fixture_policy();
    let witness = ProfileParameterWitness::KeyBits(256);
    for (time, expected) in [
        (99, DecisionOutcome::Deny),
        (100, DecisionOutcome::Permit),
        (199, DecisionOutcome::Permit),
        (200, DecisionOutcome::Deny),
    ] {
        c.evaluation_time = EvaluationTime { unix_millis: time };
        let d = verified_policy_evaluation(&p, &c, &scope, &binding, &witness);
        assert_eq!(d.decision.outcome, expected, "boundary {time}");
        assert_eq!(d.decision.evaluated_at, c.evaluation_time);
        assert_eq!(d.decision.policy_digest, p.canonical_digest().unwrap());
    }
}

#[test]
fn changed_source_or_exact_profile_identity_reverts_to_conservative_result() {
    let (mut c, scope, binding) = prepare("AES-256-GCM", CryptoOperation::Encrypt);
    let p = fixture_policy();
    let witness = ProfileParameterWitness::KeyBits(256);
    c.facts[0].profile_id = Some(ProfileId::parse("AES-128-GCM").unwrap());
    let d = verified_policy_evaluation(&p, &c, &scope, &binding, &witness);
    assert_eq!(
        d.qualification.finding,
        ProfileQualificationFinding::ScopeMismatch
    );
    assert_ne!(d.decision.outcome, DecisionOutcome::Permit);
    c.facts[0].profile_id = Some(ProfileId::parse("AES-256-GCM").unwrap());
    c.facts[0].evidence_ref = Some(EvidenceId::parse("attest:forged").unwrap());
    let d = verified_policy_evaluation(&p, &c, &scope, &binding, &witness);
    assert_eq!(
        d.qualification.finding,
        ProfileQualificationFinding::EvidenceIncomplete
    );
    assert_ne!(d.decision.outcome, DecisionOutcome::Permit);
}
