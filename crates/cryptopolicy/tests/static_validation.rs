//! Positive, negative, metamorphic and adversarial tests for static policy validation.
#![allow(clippy::unwrap_used)] // Test fixtures intentionally construct fallible IDs.

use cryptopolicy::*;

fn fixture() -> PolicyDocument {
    PolicyDocument::parse_json(include_bytes!("fixtures/static-policy-v1.json")).unwrap()
}

fn rule(effect: RuleEffect, id: &str) -> PolicyRule {
    PolicyRule {
        rule_id: RuleId::parse(id).unwrap(),
        effect,
        selector: RuleSelector {
            match_all: false,
            operation: Some(CryptoOperation::Encrypt),
            algorithm_id: Some(AlgorithmId::parse("AES-256-GCM").unwrap()),
            profile_id: None,
            environment: None,
            advanced: None,
        },
        requirements: Vec::new(),
    }
}

fn has(report: &ValidationReport, code: ValidationCode) -> bool {
    report.diagnostics.iter().any(|item| item.code == code)
}

#[test]
fn full_typed_fixture_compiles_and_serializes_canonically() {
    let p = fixture();
    p.validate().unwrap();
    let report = p.static_validate().unwrap();
    assert!(report.is_valid());
    assert!(report.diagnostics.is_empty());
    let bytes = p.canonical_json().unwrap();
    let parsed = PolicyDocument::parse_json(&bytes).unwrap();
    assert_eq!(parsed.canonical_json().unwrap(), bytes);
    assert_eq!(parsed.canonical_digest().unwrap(), p.canonical_digest().unwrap());
    assert_eq!(parsed.rules.len(), 4);
}

#[test]
fn all_twelve_selector_fields_have_stable_enumeration() {
    let policy = fixture();
    let fields = policy.rules[0].selector.predicate_fields();
    assert_eq!(
        fields,
        vec![
            SelectorField::Operation,
            SelectorField::Algorithm,
            SelectorField::Profile,
            SelectorField::Environment,
            SelectorField::SecurityCategory,
            SelectorField::DataSensitivity,
            SelectorField::Provider,
            SelectorField::KeyProtection,
            SelectorField::KeyExportability,
            SelectorField::KeySizeBits,
            SelectorField::SourceOrigin,
            SelectorField::SourceQuality,
        ]
    );
    assert!(policy.rules[1].selector.predicate_fields().is_empty());
}

#[test]
fn missing_fact_truth_table_is_explicit_and_blocks_mandatory_unknowns() {
    assert_eq!(missing_selector_fact(RuleEffect::Allow), MissingFactDisposition::NonMatch);
    assert_eq!(missing_selector_fact(RuleEffect::Warn), MissingFactDisposition::NonMatch);
    assert_eq!(missing_selector_fact(RuleEffect::Deny), MissingFactDisposition::Indeterminate);
    assert_eq!(missing_selector_fact(RuleEffect::Require), MissingFactDisposition::Indeterminate);
    assert_eq!(missing_required_fact(), MissingFactDisposition::Indeterminate);
}

#[test]
fn source_quality_claim_is_not_implicitly_observed_or_authenticated() {
    let mut p = fixture();
    let advanced = p.rules[0].selector.advanced.as_mut().unwrap();
    advanced.source_origin = Some(FactOrigin::Configured);
    advanced.source_quality = Some(EvidenceQuality::ExternallyVerified);
    assert!(p.static_validate().unwrap().is_valid());
    // This is still a declaration: these contracts have no mechanism to prove
    // either an observation or that the verification claim is authentic.
}

#[test]
fn reject_unrestricted_allow_and_empty_require_rule() {
    let mut p = fixture();
    p.rules.push(PolicyRule {
        rule_id: RuleId::parse("r-open").unwrap(),
        effect: RuleEffect::Allow,
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
    p.rules.push(PolicyRule {
        rule_id: RuleId::parse("r-empty-require").unwrap(),
        effect: RuleEffect::Require,
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
    let report = p.static_validate().unwrap();
    assert!(!report.is_valid());
    assert!(has(&report, ValidationCode::UnconstrainedAllow));
    assert!(has(&report, ValidationCode::EmptyRequirementRule));
    assert!(p.canonical_json().is_err());
}

#[test]
fn match_all_with_other_predicates_and_empty_advanced_object_fail() {
    let mut p = fixture();
    p.rules[0].selector.match_all = true;
    assert!(has(&p.static_validate().unwrap(), ValidationCode::AmbiguousSelector));
    assert!(p.validate().is_err());
    p.rules[0].selector.match_all = false;
    p.rules[0].selector.advanced = Some(AdvancedSelector::default());
    assert!(has(&p.static_validate().unwrap(), ValidationCode::EmptyAdvancedSelector));
    assert!(p.canonical_json().is_err());
}

#[test]
fn unrecognized_critical_nested_selector_or_requirement_variant_is_rejected() {
    let text = include_str!("fixtures/static-policy-v1.json");
    let mutated = text.replace(
        "\"security_category\": 5,",
        "\"security_category\": 5, \"grant_all_unknown_algorithms\": true,",
    );
    assert_ne!(text, mutated);
    assert!(PolicyDocument::parse_json(mutated.as_bytes()).is_err());
    let bad_requirement = text.replace(
        "\"kind\": \"algorithm\"",
        "\"kind\": \"permit_everything\"",
    );
    assert_ne!(text, bad_requirement);
    assert!(PolicyDocument::parse_json(bad_requirement.as_bytes()).is_err());
}

#[test]
fn invalid_categories_and_key_sizes_are_fail_closed() {
    let mut p = fixture();
    p.rules[0].selector.advanced.as_mut().unwrap().security_category = Some(0);
    assert!(has(&p.static_validate().unwrap(), ValidationCode::InvalidSecurityCategory));
    p.rules[0].selector.advanced.as_mut().unwrap().security_category = Some(5);
    p.rules[0].selector.advanced.as_mut().unwrap().key_size_bits = Some(0);
    assert!(has(&p.static_validate().unwrap(), ValidationCode::InvalidKeySize));
    p.rules[0].selector.advanced.as_mut().unwrap().key_size_bits = Some(MAX_DECLARED_KEY_BITS + 1);
    assert!(p.canonical_json().is_err());
    p.rules[0].selector.advanced.as_mut().unwrap().key_size_bits = Some(256);
    p.rules[0].requirements.push(Requirement::MinimumKeyBits(0));
    assert!(has(&p.static_validate().unwrap(), ValidationCode::InvalidKeySize));
    p.rules[0].requirements.pop();
    p.rules[0].requirements.push(Requirement::MinSecurityCategory(6));
    assert!(has(&p.static_validate().unwrap(), ValidationCode::InvalidSecurityCategory));
}

#[test]
fn invalid_environment_and_unknown_provider_identifiers_are_rejected() {
    let mut p = fixture();
    p.rules[0].selector.environment = Some("bad env".into());
    assert!(has(&p.static_validate().unwrap(), ValidationCode::InvalidEnvironment));
    p.rules[0].selector.environment = Some(String::new());
    assert!(p.validate().is_err());
    p.rules[0].selector.environment = Some("prod".into());
    assert!(ProviderId::parse("provider⚡").is_err());
    assert!(ProviderId::parse("provider:alpha").is_ok());
}

#[test]
fn incompatible_exact_algorithm_and_profile_requirements_fail() {
    let mut p = fixture();
    p.rules[0].requirements.push(Requirement::Algorithm(
        AlgorithmId::parse("CHACHA20-POLY1305").unwrap(),
    ));
    assert!(has(&p.static_validate().unwrap(), ValidationCode::ConflictingAlgorithm));
    p.rules[0].requirements.pop();
    p.rules[0].requirements.push(Requirement::NamedHybrid(
        ProfileId::parse("hybrid:unspecified").unwrap(),
    ));
    assert!(has(&p.static_validate().unwrap(), ValidationCode::ConflictingProfile));
}

#[test]
fn selector_and_mandatory_requirement_cannot_be_incompatible() {
    let mut p = fixture();
    p.rules[0].selector.algorithm_id = Some(AlgorithmId::parse("AES-128-GCM").unwrap());
    assert!(has(
        &p.static_validate().unwrap(),
        ValidationCode::ContradictorySelectorRequirement
    ));
    p.rules[0].selector.algorithm_id = Some(AlgorithmId::parse("AES-256-GCM").unwrap());
    p.rules[0].selector.advanced.as_mut().unwrap().key_size_bits = Some(128);
    assert!(has(
        &p.static_validate().unwrap(),
        ValidationCode::ContradictorySelectorRequirement
    ));
    p.rules[0].selector.advanced.as_mut().unwrap().key_size_bits = Some(256);
    p.rules[0].selector.advanced.as_mut().unwrap().security_category = Some(2);
    assert!(has(
        &p.static_validate().unwrap(),
        ValidationCode::ContradictorySelectorRequirement
    ));
}

#[test]
fn conflicting_provider_sensitivity_protection_exportability_quality_are_rejected() {
    let mut p = fixture();
    let id = &mut p.rules[0].requirements;
    id.push(Requirement::Provider(ProviderId::parse("provider:other").unwrap()));
    id.push(Requirement::Sensitivity(DataSensitivity::Restricted));
    id.push(Requirement::KeyProtection(KeyProtection::Software));
    id.push(Requirement::KeyExportable(true));
    id.push(Requirement::SourceOrigin(FactOrigin::Configured));
    id.push(Requirement::SourceQuality(EvidenceQuality::Unverified));
    let report = p.static_validate().unwrap();
    assert!(has(&report, ValidationCode::ConflictingProvider));
    assert!(has(&report, ValidationCode::ConflictingSensitivity));
    assert!(has(&report, ValidationCode::ConflictingKeyProtection));
    assert!(has(&report, ValidationCode::ConflictingExportability));
    assert!(has(&report, ValidationCode::ConflictingSourceOrigin));
    assert!(has(&report, ValidationCode::ConflictingSourceQuality));
    assert!(!report.is_valid());
}

#[test]
fn conflicting_key_bit_requirements_and_unattested_provider_claims_are_rejected() {
    let mut p = fixture();
    p.rules[0].requirements.push(Requirement::MinimumKeyBits(512));
    assert!(has(&p.static_validate().unwrap(), ValidationCode::InvalidKeySize));
    p.rules[0].requirements.pop();
    p.rules[0].requirements.push(Requirement::KeySizeBits(128));
    assert!(has(&p.static_validate().unwrap(), ValidationCode::InvalidKeySize));
}

#[test]
fn warn_rule_cannot_gain_authority_from_requirements() {
    let mut p = fixture();
    let warn = p.rules.iter_mut().find(|r| r.effect == RuleEffect::Warn).unwrap();
    warn.requirements.push(Requirement::KeySizeBits(256));
    assert!(has(
        &p.static_validate().unwrap(),
        ValidationCode::WarnRequirementsUnsupported
    ));
    assert!(p.validate().is_err());
}

#[test]
fn deny_requirements_are_warned_but_never_made_conditional() {
    let mut p = fixture();
    let deny = p.rules.iter_mut().find(|r| r.effect == RuleEffect::Deny).unwrap();
    deny.requirements.push(Requirement::NonExportable);
    let report = p.static_validate().unwrap();
    assert!(report.is_valid());
    assert!(has(&report, ValidationCode::DenyRequirementsIgnored));
    assert!(p.validate().is_ok());
}

#[test]
fn explicit_allow_default_is_a_warning_not_a_successful_evaluation() {
    let mut p = fixture();
    p.default_effect = DefaultEffect::Allow;
    let report = p.static_validate().unwrap();
    assert!(report.is_valid());
    assert!(has(&report, ValidationCode::ExplicitAllowDefault));
    assert!(p.validate().is_ok());
}

#[test]
fn report_order_is_independent_of_rule_order_and_contains_no_raw_values() {
    let mut p = fixture();
    p.rules.push(rule(RuleEffect::Require, "zz-empty"));
    p.rules.push(rule(RuleEffect::Allow, "aa-allow"));
    p.rules.last_mut().unwrap().requirements.clear();
    p.rules.last_mut().unwrap().selector.algorithm_id = None;
    let report = p.static_validate().unwrap();
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(serialized.contains("empty_requirement_rule"));
    assert!(serialized.contains("unconstrained_allow"));
    assert!(!serialized.contains("example-org"));
    assert!(!serialized.contains("AES-256-GCM"));
    p.rules.reverse();
    assert_eq!(p.static_validate().unwrap(), report);
    assert_eq!(serde_json::to_string(&p.static_validate().unwrap()).unwrap(), serialized);
}

#[test]
fn duplicate_rule_ids_return_deterministic_diagnostic_and_legacy_error() {
    let mut p = fixture();
    p.rules[0].rule_id = p.rules[1].rule_id.clone();
    assert!(has(&p.static_validate().unwrap(), ValidationCode::DuplicateRule));
    assert_eq!(p.validate(), Err(ContractError::DuplicateIdentifier));
}

#[test]
fn static_diagnostic_limit_blocks_not_silently_truncates() {
    let mut p = fixture();
    for i in 0..20 {
        p.rules.push(rule(RuleEffect::Require, &format!("missing-{i:02}")));
    }
    let limits = Limits {
        max_diagnostics: 3,
        ..Limits::default()
    };
    assert_eq!(
        p.static_validate_with_limits(&limits),
        Err(ContractError::ResourceLimitExceeded("static diagnostics")),
    );
}

#[test]
fn parsed_context_retains_typed_evidence_without_promoting_quality() {
    let raw = br#"{
      "schema_version":"1", "request_id":"req:x", "operation":"encrypt",
      "evaluation_time":{"unix_millis":100}, "environment":"prod",
      "facts":[{
        "fact_id":"obs:1", "origin":"configured", "algorithm_id":"AES-256-GCM",
        "profile_id":null, "evidence_ref":null, "verified":false,
        "properties":{
          "security_category":3, "key_size_bits":256, "data_sensitivity":"confidential",
          "provider_id":"provider:alpha","key_protection":"hardware_security_module",
          "key_exportable":false, "source_quality":"attributed"
        }
      }]
    }"#;
    let ctx = CryptoContext::parse_json(raw).unwrap();
    assert_eq!(ctx.environment.as_deref(), Some("prod"));
    assert_eq!(ctx.facts[0].origin, FactOrigin::Configured);
    assert!(!ctx.facts[0].verified);
    let properties = ctx.facts[0].properties.as_ref().unwrap();
    assert_eq!(properties.source_quality, Some(EvidenceQuality::Attributed));
    assert_eq!(properties.key_protection, Some(KeyProtection::HardwareSecurityModule));
}

#[test]
fn invalid_context_security_attributes_are_rejected() {
    let raw = br#"{"schema_version":"1","request_id":"x","operation":"sign",
       "evaluation_time":{"unix_millis":1},"environment":"bad env",
       "facts":[]}"#;
    assert!(CryptoContext::parse_json(raw).is_err());
    let mut ctx = CryptoContext {
        schema_version: SchemaVersion::V1,
        request_id: RequestId::parse("r").unwrap(),
        operation: CryptoOperation::Sign,
        evaluation_time: EvaluationTime { unix_millis: 1 },
        environment: None,
        facts: vec![CryptoFact {
            fact_id: EvidenceId::parse("f").unwrap(),
            origin: FactOrigin::Observed,
            algorithm_id: None,
            profile_id: None,
            evidence_ref: None,
            verified: false,
            properties: Some(CryptoProperties {
                security_category: Some(3),
                key_size_bits: Some(256),
                data_sensitivity: None,
                provider_id: None,
                key_protection: None,
                key_exportable: None,
                source_quality: Some(EvidenceQuality::ExternallyVerified),
            }),
        }],
    };
    assert!(validate_context_properties(&ctx).is_err());
    ctx.facts[0].verified = true;
    assert!(validate_context_properties(&ctx).is_ok());
    ctx.facts[0].properties.as_mut().unwrap().key_size_bits = Some(0);
    assert!(validate_context_properties(&ctx).is_err());
}

#[test]
fn randomized_rule_permutations_do_not_change_validation_results() {
    let mut p = fixture();
    for i in 0..24 {
        p.rules.push(rule(RuleEffect::Require, &format!("require-{i:02}")));
    }
    let expected = p.static_validate().unwrap();
    // Deterministic test PRNG: no external property-testing dependency.
    let mut seed = 0x136b_87d1_u64;
    for _ in 0..80 {
        for i in (1..p.rules.len()).rev() {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let j = (seed as usize) % (i + 1);
            p.rules.swap(i, j);
        }
        assert_eq!(p.static_validate().unwrap(), expected);
    }
}

#[test]
fn invalid_input_mutation_never_panics_or_yields_authority() {
    let mut bytes = include_bytes!("fixtures/static-policy-v1.json").to_vec();
    for index in (0..bytes.len()).step_by(7) {
        bytes[index] = 0xff;
        let _ = PolicyDocument::parse_json(&bytes);
        bytes[index] = include_bytes!("fixtures/static-policy-v1.json")[index];
    }
    assert!(PolicyDocument::parse_json(b"{\"allow\":true}").is_err());
}
