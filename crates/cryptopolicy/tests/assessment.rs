//! FOSS-447 provenance-safe assessment contract and adversarial regression tests.
#![allow(clippy::unwrap_used)] // Fixture helpers deliberately exercise fallible APIs.

use cryptopolicy::*;

fn policy() -> PolicyDocument {
    PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap()
}
fn input(name: &str) -> AssessmentContext {
    let bytes: &[u8] = match name {
        "observed" => include_bytes!("fixtures/assessment-observed-v1.json"),
        "negotiated" => include_bytes!("fixtures/assessment-negotiated-v1.json"),
        "configured" => include_bytes!("fixtures/assessment-configured-v1.json"),
        "dependency" => include_bytes!("fixtures/assessment-dependency-v1.json"),
        "uninspected" => include_bytes!("fixtures/assessment-uninspected-v1.json"),
        "partial" => include_bytes!("fixtures/assessment-partial-v1.json"),
        "conflict" => include_bytes!("fixtures/assessment-conflict-v1.json"),
        _ => panic!("unknown test fixture"),
    };
    AssessmentContext::parse_json(bytes).unwrap()
}
fn trust(ctx: &AssessmentContext, record: &AssessmentObservation) -> Result<bool, ContractError> {
    // An explicit pre-authenticated fixture binding. In production a secure
    // provider must cryptographically verify the actual signed source/evidence.
    let base = ctx.snapshot_id.as_str() == "snapshot:cryptomap:01"
        && ctx.scope.asset_id.as_str() == "asset:app"
        && ctx.scope.use_site_id.as_str() == "use:tls-egress"
        && ctx.scope.activity_id.as_str() == "session:42";
    let pair = match record.observation_id.as_str() {
        "obs:tls:1" => {
            record.source_id.as_str() == "collector:tls"
                && record
                    .evidence_ref
                    .as_ref()
                    .is_some_and(|id| id.as_str() == "evidence:tls:1")
        }
        "obs:tls:2" => {
            record.source_id.as_str() == "collector:wire"
                && record
                    .evidence_ref
                    .as_ref()
                    .is_some_and(|id| id.as_str() == "evidence:wire:2")
        }
        _ => false,
    };
    Ok(base && pair && record.scope == ctx.scope)
}
fn report(ctx: &AssessmentContext) -> AssessmentReport {
    assess(&policy(), ctx, ctx.evaluation_time, &trust).unwrap()
}
fn has(report: &AssessmentReport, reason: AssessmentReason) -> bool {
    report.reasons.contains(&reason)
}
fn rid(text: &str) -> EvidenceId {
    EvidenceId::parse(text).unwrap()
}
fn mut_json(f: impl FnOnce(&mut serde_json::Value)) -> Result<AssessmentContext, ContractError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/assessment-observed-v1.json")).unwrap();
    f(&mut value);
    AssessmentContext::parse_json(&serde_json::to_vec(&value).unwrap())
}

#[test]
fn high_confidence_externally_authenticated_direct_observation_can_permit() {
    let ctx = input("observed");
    let r = report(&ctx);
    assert_eq!(r.outcome, DecisionOutcome::Permit);
    assert_eq!(r.snapshot_id.as_str(), "snapshot:cryptomap:01");
    assert_eq!(r.scope, ctx.scope);
    assert_eq!(r.evidence_confidence, Some(AssessmentConfidence::High));
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].kind, ObservationKind::DirectOperation);
    assert!(r.findings[0].externally_authenticated);
    assert_eq!(r.findings[0].source_id.as_str(), "collector:tls");
    assert_eq!(
        r.findings[0].evidence_ref.as_ref().unwrap().as_str(),
        "evidence:tls:1"
    );
    assert_eq!(
        r.findings[0].core_decision.as_ref().unwrap().outcome,
        DecisionOutcome::Permit
    );
    assert_eq!(
        r.findings[0].core_decision.as_ref().unwrap().evidence,
        vec![rid("evidence:tls:1"), rid("obs:tls:1")]
    );
}

#[test]
fn explicit_structured_report_matches_checked_in_golden() {
    let r = report(&input("observed"));
    let expected: serde_json::Value = serde_json::from_slice(include_bytes!(
        "fixtures/assessment-result-observed-v1.json"
    ))
    .unwrap();
    assert_eq!(serde_json::to_value(&r).unwrap(), expected);
    let bytes = serde_json::to_vec(&r).unwrap();
    assert_eq!(
        AssessmentReport::parse_json_with_limits(&bytes, &Limits::default()).unwrap(),
        r
    );
    assert_eq!(r.policy_digest, policy().canonical_digest().unwrap());
}

#[test]
fn source_quality_and_claimed_high_confidence_cannot_self_authenticate() {
    let c = input("observed");
    let r = assess(&policy(), &c, c.evaluation_time, &UnverifiedEvidence).unwrap();
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::EvidenceNotAuthenticated));
    assert!(!r.findings[0].externally_authenticated);
    assert_eq!(
        r.findings[0].disposition,
        AssessmentDisposition::Unauthenticated
    );
    assert_eq!(
        r.findings[0].source_quality_claim,
        Some(EvidenceQuality::ExternallyVerified)
    );
    assert_eq!(r.findings[0].core_decision, None);
}

#[test]
fn original_snapshot_source_and_evidence_binding_cannot_be_substituted() {
    let mut c = input("observed");
    c.observations[0].evidence_ref = Some(rid("evidence:forged"));
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(!r.findings[0].externally_authenticated);
    assert_eq!(r.findings[0].evidence_ref, Some(rid("evidence:forged")));
    assert!(r.findings[0].core_decision.is_none());
    c.observations[0].evidence_ref = Some(rid("evidence:tls:1"));
    c.snapshot_id = rid("snapshot:forged");
    assert_eq!(report(&c).outcome, DecisionOutcome::Indeterminate);
}

#[test]
fn negotiated_tls_is_preserved_as_negotiated_not_observed() {
    let c = input("negotiated");
    let mut p = policy();
    let allow = p
        .rules
        .iter_mut()
        .find(|r| r.effect == RuleEffect::Allow)
        .unwrap();
    for constraint in &mut allow.requirements {
        if let Requirement::SourceOrigin(origin) = constraint {
            *origin = FactOrigin::Negotiated;
        }
    }
    let r = assess(&p, &c, c.evaluation_time, &trust).unwrap();
    assert_eq!(r.outcome, DecisionOutcome::Permit);
    assert_eq!(r.findings[0].kind.origin(), FactOrigin::Negotiated);
    assert_eq!(
        r.findings[0].core_decision.as_ref().unwrap().outcome,
        DecisionOutcome::Permit
    );
    // An observed-only requirement does not accidentally match a negotiated fact.
    assert_ne!(report(&c).outcome, DecisionOutcome::Permit);
}

#[test]
fn serialized_report_preserves_operation_parameters_and_sorted_coverage_gap_ids() {
    let mut c = input("partial");
    c.uninspected_sources.push(rid("collector:backup"));
    let a = report(&c);
    assert_eq!(a.operation, CryptoOperation::Encrypt);
    assert_eq!(a.findings[0].algorithm_id, Some(AlgorithmId::parse("AES-256-GCM").unwrap()));
    assert_eq!(a.findings[0].parameter, Some(ObservedParameter {
        kind: ObservedParameterKind::KeyBits,
        value: ObservedParameterValue::Bits(256),
    }));
    assert_eq!(a.findings[0].observed_at, EvaluationTime { unix_millis: 140 });
    assert_eq!(a.uninspected_sources, vec![rid("collector:backup"), rid("collector:uninspected")]);
    c.uninspected_sources.reverse();
    let b = report(&c);
    assert_eq!(serde_json::to_vec(&a).unwrap(), serde_json::to_vec(&b).unwrap());
}

#[test]
fn configured_cipher_cannot_be_promoted_into_operational_use() {
    let c = input("configured");
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::NoOperationalObservation));
    assert_eq!(
        r.findings[0].disposition,
        AssessmentDisposition::NotOperational
    );
    assert_eq!(r.findings[0].kind.origin(), FactOrigin::Configured);
    assert!(r.findings[0].core_decision.is_none());
}

#[test]
fn installed_crypto_capable_dependency_never_proves_algorithm_use() {
    let c = input("dependency");
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::NoOperationalObservation));
    assert_eq!(r.findings[0].kind.origin(), FactOrigin::Inferred);
    assert_eq!(
        r.findings[0].disposition,
        AssessmentDisposition::NotOperational
    );
    assert_eq!(r.findings[0].core_decision, None);
}

#[test]
fn provider_capability_and_inferred_claims_are_nonoperational() {
    let mut c = input("configured");
    c.observations[0].kind = ObservationKind::ProviderCapability;
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert_eq!(r.findings[0].kind.origin(), FactOrigin::ProviderCapability);
    c.observations[0].kind = ObservationKind::Inferred;
    let inferred = report(&c);
    assert_eq!(inferred.outcome, DecisionOutcome::Indeterminate);
    assert!(inferred.findings[0].core_decision.is_none());
}

#[test]
fn uninspected_context_never_invents_absence_or_permit() {
    let c = input("uninspected");
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::CoverageIncomplete));
    assert!(has(&r, AssessmentReason::UninspectedSources));
    assert!(has(&r, AssessmentReason::NoOperationalObservation));
    assert!(r.findings.is_empty());
    assert_eq!(r.evidence_confidence, None);
}

#[test]
fn fully_claimed_coverage_without_observation_is_still_indeterminate() {
    let mut c = input("uninspected");
    c.coverage = AssessmentCoverage::Complete;
    c.uninspected_sources.clear();
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::NoOperationalObservation));
    assert!(!has(&r, AssessmentReason::CoverageIncomplete));
}

#[test]
fn partial_scan_with_an_approved_single_observation_cannot_permit() {
    let c = input("partial");
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::CoverageIncomplete));
    assert!(has(&r, AssessmentReason::UninspectedSources));
    assert_eq!(
        r.findings[0].core_decision.as_ref().unwrap().outcome,
        DecisionOutcome::Permit
    );
}

#[test]
fn conflicting_provider_observations_remain_separate_and_block_permit() {
    let c = input("conflict");
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert_eq!(r.conflicts.len(), 1);
    assert_eq!(r.conflicts[0].field, ConflictField::Provider);
    assert_eq!(r.conflicts[0].first, rid("obs:tls:1"));
    assert_eq!(r.conflicts[0].second, rid("obs:tls:2"));
    assert!(has(&r, AssessmentReason::ConflictingObservations));
    assert!(
        r.findings
            .iter()
            .all(|f| f.core_decision.as_ref().unwrap().outcome == DecisionOutcome::Permit)
    );
    assert_eq!(r.findings[0].source_id.as_str(), "collector:tls");
    assert_eq!(r.findings[1].source_id.as_str(), "collector:wire");
}

#[test]
fn differing_sensitivity_blocks_permit_even_when_each_core_fact_permits() {
    let mut c = input("conflict");
    c.observations[1].properties.as_mut().unwrap().provider_id =
        Some(ProviderId::parse("provider:alpha").unwrap());
    c.observations[1].properties.as_mut().unwrap().data_sensitivity =
        Some(DataSensitivity::Restricted);
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert_eq!(r.conflicts.len(), 1);
    assert_eq!(r.conflicts[0].field, ConflictField::DataSensitivity);
    assert!(r.findings.iter().all(|f| {
        f.core_decision.as_ref().unwrap().outcome == DecisionOutcome::Permit
    }));
}

#[test]
fn known_denial_dominates_otherwise_permitting_evidence_and_conflict() {
    let mut c = input("conflict");
    let weak = &mut c.observations[1];
    weak.algorithm_id = Some(AlgorithmId::parse("AES-128-GCM").unwrap());
    weak.parameter = Some(ObservedParameter {
        kind: ObservedParameterKind::KeyBits,
        value: ObservedParameterValue::Bits(128),
    });
    weak.properties.as_mut().unwrap().key_size_bits = Some(128);
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Deny);
    assert!(has(&r, AssessmentReason::CoreDenied));
    assert!(has(&r, AssessmentReason::ConflictingObservations));
    assert_eq!(
        r.findings[0].core_decision.as_ref().unwrap().outcome,
        DecisionOutcome::Permit
    );
    assert_eq!(
        r.findings[1].core_decision.as_ref().unwrap().outcome,
        DecisionOutcome::Deny
    );
}

#[test]
fn valid_independent_same_activity_observations_must_each_permit() {
    let mut c = input("conflict");
    c.observations[1].properties.as_mut().unwrap().provider_id =
        Some(ProviderId::parse("provider:alpha").unwrap());
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Permit);
    assert!(r.conflicts.is_empty());
    assert_eq!(r.findings.len(), 2);
    assert_eq!(r.findings[0].observation_id, rid("obs:tls:1"));
    assert_eq!(r.findings[1].observation_id, rid("obs:tls:2"));
}

#[test]
fn confidence_is_explicit_and_cannot_replace_verified_evidence() {
    let mut c = input("observed");
    c.observations[0].confidence = AssessmentConfidence::Low;
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::InsufficientConfidence));
    assert_eq!(r.evidence_confidence, Some(AssessmentConfidence::Low));
    assert!(r.findings[0].externally_authenticated);
    assert_eq!(
        r.findings[0].core_decision.as_ref().unwrap().outcome,
        DecisionOutcome::Permit
    );
}

#[test]
fn missing_evidence_reference_blocks_even_when_other_fields_match() {
    let mut c = input("observed");
    c.observations[0].evidence_ref = None;
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::MissingEvidenceReference));
    assert_eq!(
        r.findings[0].disposition,
        AssessmentDisposition::MissingEvidence
    );
    assert!(r.findings[0].core_decision.is_none());
}

#[test]
fn missing_algorithm_and_parameter_are_not_completed_from_other_observations() {
    let mut c = input("conflict");
    c.observations[1].properties.as_mut().unwrap().provider_id =
        Some(ProviderId::parse("provider:alpha").unwrap());
    c.observations[0].algorithm_id = None;
    c.observations[0].parameter = None;
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert!(has(&r, AssessmentReason::MissingOperationalFields));
    assert_eq!(
        r.findings[0].disposition,
        AssessmentDisposition::MissingAlgorithm
    );
    assert!(r.findings[0].core_decision.is_none());
    c.observations[0].algorithm_id = Some(AlgorithmId::parse("AES-256-GCM").unwrap());
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert_eq!(
        r.findings[0].disposition,
        AssessmentDisposition::MissingParameter
    );
}

#[test]
fn mismatched_algorithm_parameter_cannot_be_laundered() {
    let mut c = input("observed");
    c.observations[0].parameter = Some(ObservedParameter {
        kind: ObservedParameterKind::KeyBits,
        value: ObservedParameterValue::Bits(128),
    });
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("contradictory_key_bits"))
    );
    c = input("observed");
    c.observations[0].parameter = Some(ObservedParameter {
        kind: ObservedParameterKind::NamedSet,
        value: ObservedParameterValue::Name(AlgorithmId::parse("ML-KEM-1024").unwrap()),
    });
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::InvalidDocument(
            "named_set_identity_mismatch"
        ))
    );
}

#[test]
fn wrong_sha3_output_bits_are_rejected_without_catalog_shortcuts() {
    let mut c = input("observed");
    c.operation = CryptoOperation::Hash;
    c.observations[0].operation = Some(CryptoOperation::Hash);
    c.observations[0].algorithm_id = Some(AlgorithmId::parse("SHA3-256").unwrap());
    c.observations[0].parameter = Some(ObservedParameter {
        kind: ObservedParameterKind::HashOutputBits,
        value: ObservedParameterValue::Bits(512),
    });
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::InvalidDocument(
            "contradictory_hash_output_bits"
        ))
    );
}

#[test]
fn wrong_operation_is_preserved_without_authorization() {
    let mut c = input("observed");
    c.observations[0].operation = Some(CryptoOperation::Decrypt);
    let r = report(&c);
    assert_eq!(r.outcome, DecisionOutcome::Indeterminate);
    assert_eq!(
        r.findings[0].disposition,
        AssessmentDisposition::DifferentOperation
    );
    assert!(r.findings[0].core_decision.is_none());
}

#[test]
fn expired_and_globally_denied_policies_apply_even_without_evidence() {
    let c = input("uninspected");
    let mut expired = policy();
    expired.expires_at = Some(EvaluationTime { unix_millis: 150 });
    let r = assess(&expired, &c, c.evaluation_time, &trust).unwrap();
    assert_eq!(r.outcome, DecisionOutcome::Deny);
    assert!(has(&r, AssessmentReason::GlobalPolicyDeny));
    let mut hard = policy();
    hard.rules.push(PolicyRule {
        rule_id: RuleId::parse("global:deny").unwrap(),
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
    });
    let d = assess(&hard, &c, c.evaluation_time, &trust).unwrap();
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(has(&d, AssessmentReason::GlobalPolicyDeny));
}

#[test]
fn observation_order_and_rule_order_do_not_change_serialized_result() {
    let c = input("conflict");
    let baseline = report(&c);
    let bytes = serde_json::to_vec(&baseline).unwrap();
    let mut reordered = c.clone();
    reordered.observations.reverse();
    let r = report(&reordered);
    assert_eq!(serde_json::to_vec(&r).unwrap(), bytes);
    for index in 0..32 {
        if index % 2 == 0 {
            reordered.observations.reverse();
        }
        assert_eq!(serde_json::to_vec(&report(&reordered)).unwrap(), bytes);
    }
}

#[test]
fn duplicate_observations_and_coverage_source_ids_reject_atomically() {
    let mut c = input("observed");
    c.observations.push(c.observations[0].clone());
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::DuplicateIdentifier)
    );
    let mut c = input("partial");
    c.uninspected_sources.push(c.uninspected_sources[0].clone());
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::DuplicateIdentifier)
    );
}

#[test]
fn cross_scope_asset_site_or_activity_laundering_is_rejected() {
    let mut c = input("observed");
    c.observations[0].scope.asset_id = PolicyId::parse("asset:other").unwrap();
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("assessment_scope_mismatch"))
    );
    c = input("observed");
    c.observations[0].scope.use_site_id = PolicyId::parse("use:other").unwrap();
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("assessment_scope_mismatch"))
    );
    c = input("observed");
    c.observations[0].scope.activity_id = rid("session:forged");
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("assessment_scope_mismatch"))
    );
}

#[test]
fn complete_coverage_with_known_uninspected_sources_is_invalid() {
    let mut c = input("partial");
    c.coverage = AssessmentCoverage::Complete;
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::InvalidDocument(
            "complete_coverage_with_gaps"
        ))
    );
}

#[test]
fn future_observations_and_mismatched_clock_fail() {
    let mut c = input("observed");
    c.observations[0].observed_at = EvaluationTime { unix_millis: 151 };
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("future_observation"))
    );
    let c = input("observed");
    assert_eq!(
        assess(&policy(), &c, EvaluationTime { unix_millis: 151 }, &trust),
        Err(ContractError::InvalidDocument("assessment_time_mismatch"))
    );
}

#[test]
fn untrusted_external_verifier_error_never_silently_authorizes() {
    let c = input("observed");
    let fails = |_: &AssessmentContext, _: &AssessmentObservation| {
        Err(ContractError::InvalidDocument(
            "verification_service_unavailable",
        ))
    };
    assert_eq!(
        assess(&policy(), &c, c.evaluation_time, &fails),
        Err(ContractError::InvalidDocument(
            "verification_service_unavailable"
        ))
    );
}

#[test]
fn strict_json_rejects_extra_critical_fields_duplicate_and_unknown_schema() {
    let valid = include_bytes!("fixtures/assessment-observed-v1.json");
    let text = std::str::from_utf8(valid).unwrap();
    let extra = text.replacen(
        "\"confidence\": \"high\"",
        "\"confidence\": \"high\", \"override_deny\": true",
        1,
    );
    assert_ne!(text, extra);
    assert!(AssessmentContext::parse_json(extra.as_bytes()).is_err());
    let duplicate = text.replacen(
        "\"schema_version\": \"1\"",
        "\"schema_version\": \"1\", \"schema_version\": \"1\"",
        1,
    );
    assert_ne!(text, duplicate);
    assert!(AssessmentContext::parse_json(duplicate.as_bytes()).is_err());
    assert!(mut_json(|v| v["schema_version"] = "2".into()).is_err());
    assert!(
        mut_json(|v| v["observations"][0]["parameter"]["kind"] = "never_trust".into()).is_err()
    );
    assert!(mut_json(|v| v["observations"][0]["parameter"]["permit"] = true.into()).is_err());
}

#[test]
fn byte_budget_and_observation_budget_bound_untrusted_inputs() {
    let c = input("observed");
    let bytes = serde_json::to_vec(&c).unwrap();
    let small = Limits {
        max_json_bytes: bytes.len() - 1,
        ..Limits::default()
    };
    assert_eq!(
        AssessmentContext::parse_json_with_limits(&bytes, &small),
        Err(ContractError::PayloadTooLarge)
    );
    let mut c = input("conflict");
    let low = Limits {
        max_facts: 1,
        ..Limits::default()
    };
    assert_eq!(
        c.validate(&low),
        Err(ContractError::ResourceLimitExceeded(
            "assessment observations"
        ))
    );
    while c.observations.len() <= MAX_ASSESSMENT_OBSERVATIONS {
        let mut item = c.observations[0].clone();
        item.observation_id = rid(&format!("obs:large:{}", c.observations.len()));
        c.observations.push(item);
    }
    assert_eq!(
        c.validate(&Limits::default()),
        Err(ContractError::ResourceLimitExceeded(
            "assessment observations"
        ))
    );
}

#[test]
fn conflicting_observation_budget_is_enforced() {
    let c = input("conflict");
    let quota = Limits {
        max_diagnostics: 1,
        ..Limits::default()
    };
    assert!(assess_with_limits(&policy(), &c, c.evaluation_time, &trust, &quota).is_ok());
    let mut c = c.clone();
    c.observations[1].algorithm_id = Some(AlgorithmId::parse("AES-128-GCM").unwrap());
    c.observations[1].parameter = Some(ObservedParameter {
        kind: ObservedParameterKind::KeyBits,
        value: ObservedParameterValue::Bits(128),
    });
    c.observations[1].properties.as_mut().unwrap().key_size_bits = Some(128);
    assert_eq!(
        assess_with_limits(&policy(), &c, c.evaluation_time, &trust, &quota),
        Err(ContractError::ResourceLimitExceeded("assessment conflicts"))
    );
}

#[test]
fn report_parser_cannot_accept_unknown_fields_or_oversized_output() {
    let r = report(&input("observed"));
    let bytes = serde_json::to_vec(&r).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    let invalid = text.replacen(
        "\"outcome\":\"permit\"",
        "\"outcome\":\"permit\",\"bypass\":true",
        1,
    );
    assert_ne!(text, invalid);
    assert!(
        AssessmentReport::parse_json_with_limits(invalid.as_bytes(), &Limits::default()).is_err()
    );
    let small = Limits {
        max_json_bytes: bytes.len() - 1,
        ..Limits::default()
    };
    assert_eq!(
        AssessmentReport::parse_json_with_limits(&bytes, &small),
        Err(ContractError::PayloadTooLarge)
    );
}
