//! FOSS-449 offline key/provider capability preflight security regressions.
#![allow(clippy::unwrap_used)] // Test fixtures intentionally construct fallible DTOs.

use cryptopolicy::*;

fn request() -> KeyRequest {
    KeyRequest::parse_json(include_bytes!("fixtures/request-v1.json")).unwrap()
}
fn snapshot(name: &str) -> ProviderCapabilitySnapshot {
    let input: &[u8] = match name {
        "supported" => include_bytes!("fixtures/provider-supported-v1.json"),
        "unknown" => include_bytes!("fixtures/provider-unknown-v1.json"),
        "unsupported" => include_bytes!("fixtures/provider-unsupported-v1.json"),
        "downgrade" => include_bytes!("fixtures/provider-downgrade-v1.json"),
        "stale" => include_bytes!("fixtures/provider-stale-v1.json"),
        "conflict" => include_bytes!("fixtures/provider-conflict-v1.json"),
        "empty" => include_bytes!("fixtures/provider-empty-v1.json"),
        _ => panic!("unknown fixture"),
    };
    ProviderCapabilitySnapshot::parse_json(input).unwrap()
}

// THIS IS A TEST STUB, NOT PRODUCTION CRYPTOGRAPHIC VERIFICATION.
// Only deliberately constructed test fixture source identities are accepted.
// The actual signed payload/provider attestation must be cryptographically
// validated by the caller in any production integration.
fn fixture_verifier(
    request: &KeyRequest,
    snapshot: &ProviderCapabilitySnapshot,
    claim: &ProviderCapabilityClaim,
) -> Result<ProviderVerification, ContractError> {
    let base = request.provider_id.as_str() == "provider:alpha"
        && snapshot.provider_id == request.provider_id
        && snapshot.snapshot_id.as_str() == "snapshot:keymesh:01"
        && request.request_id.as_str() == "keyreq:one";
    let named = match claim.claim_id.as_str() {
        "cap:one" => claim.source_id.as_str() == "provider:metadata"
            && claim.evidence_ref.as_ref().is_some_and(|x| x.as_str() == "evidence:cap:one"),
        "cap:two" => claim.source_id.as_str() == "provider:secondary"
            && claim.evidence_ref.as_ref().is_some_and(|x| x.as_str() == "evidence:cap:two"),
        _ => false,
    };
    Ok(ProviderVerification {
        source_authenticated: base && named && request.key_ref == claim.key_ref,
        assurance_authenticated: base && named && request.key_ref == claim.key_ref
            && claim.assurance == Some(AssuranceClaim::IndependentAssessment)
            && claim.assurance_ref.as_ref().is_some_and(|id| {
                id.as_str() == "attestation:cap:one" || id.as_str() == "attestation:cap:two"
            }),
    })
}
fn verify(req: &KeyRequest, snap: &ProviderCapabilitySnapshot) -> CapabilityReport {
    assess_key_capabilities(req, snap, &fixture_verifier).unwrap()
}
fn reason(report: &CapabilityReport, expected: CapabilityReason) -> bool {
    report.reasons.contains(&expected)
}
fn rid(value: &str) -> EvidenceId { EvidenceId::parse(value).unwrap() }
fn aid(value: &str) -> AlgorithmId { AlgorithmId::parse(value).unwrap() }
fn mutate_request(f: impl FnOnce(&mut serde_json::Value)) -> Result<KeyRequest, ContractError> {
    let mut raw: serde_json::Value = serde_json::from_slice(include_bytes!("fixtures/request-v1.json")).unwrap();
    f(&mut raw);
    KeyRequest::parse_json(&serde_json::to_vec(&raw).unwrap())
}
fn mutate_snapshot(f: impl FnOnce(&mut serde_json::Value)) -> Result<ProviderCapabilitySnapshot, ContractError> {
    let mut raw: serde_json::Value = serde_json::from_slice(include_bytes!("fixtures/provider-supported-v1.json")).unwrap();
    f(&mut raw);
    ProviderCapabilitySnapshot::parse_json(&serde_json::to_vec(&raw).unwrap())
}

#[test]
fn independently_checked_exact_supported_aes_hsm_request_is_compatible() {
    let req=request();let cap=snapshot("supported");let result=verify(&req,&cap);
    assert_eq!(result.outcome,DecisionOutcome::Permit);
    assert_eq!(result.catalog_digest,req.catalog_digest);
    assert_eq!(result.provider_id,req.provider_id);
    assert_eq!(result.snapshot_id,cap.snapshot_id);
    assert_eq!(result.reasons,vec![CapabilityReason::CompatibleCapability]);
    assert_eq!(result.findings.len(),1);
    assert!(result.findings[0].source_authenticated);
    assert!(result.findings[0].assurance_authenticated);
    assert_eq!(result.findings[0].disposition,CapabilityDisposition::Evaluated);
    assert_eq!(result.findings[0].source_id,rid("provider:metadata"));
    assert_eq!(result.findings[0].evidence_ref,Some(rid("evidence:cap:one")));
}

#[test]
fn golden_report_matches_exact_source_and_reason_identity() {
    let output=verify(&request(),&snapshot("supported"));
    let expected:serde_json::Value=serde_json::from_slice(include_bytes!("fixtures/provider-result-supported-v1.json")).unwrap();
    assert_eq!(serde_json::to_value(&output).unwrap(),expected);
    let bytes=serde_json::to_vec(&output).unwrap();
    assert_eq!(CapabilityReport::parse_json_with_limits(&bytes,&Limits::default()).unwrap(),output);
}

#[test]
fn default_verifier_does_not_promote_provider_self_assertion() {
    let req=request();let cap=snapshot("supported");
    let r=assess_key_capabilities(&req,&cap,&UnverifiedProviderClaims).unwrap();
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&r,CapabilityReason::UnauthenticatedSource));
    assert!(!r.findings[0].source_authenticated);
    assert!(!r.findings[0].assurance_authenticated);
}

#[test]
fn source_authenticated_does_not_automatically_authenticate_hsm_assurance() {
    let req=request();let cap=snapshot("supported");
    let weak=|_:&KeyRequest,_:&ProviderCapabilitySnapshot,_:&ProviderCapabilityClaim| {
        Ok(ProviderVerification{source_authenticated:true,assurance_authenticated:false})
    };
    let r=assess_key_capabilities(&req,&cap,&weak).unwrap();
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&r,CapabilityReason::AssuranceNotVerified));
    assert!(!r.findings[0].assurance_authenticated);
}

#[test]
fn missing_assurance_reference_blocks_even_when_verifier_says_true() {
    let req=request();let mut cap=snapshot("supported");
    cap.claims[0].assurance_ref=None;
    let fake=|_:&KeyRequest,_:&ProviderCapabilitySnapshot,_:&ProviderCapabilityClaim| {
        Ok(ProviderVerification{source_authenticated:true,assurance_authenticated:true})
    };
    let r=assess_key_capabilities(&req,&cap,&fake).unwrap();
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(!r.findings[0].assurance_authenticated);
    assert!(reason(&r,CapabilityReason::AssuranceNotVerified));
}

#[test]
fn missing_source_evidence_ref_is_never_passed_to_verifier() {
    let mut cap=snapshot("supported");cap.claims[0].evidence_ref=None;
    let panics=|_:&KeyRequest,_:&ProviderCapabilitySnapshot,_:&ProviderCapabilityClaim| -> Result<ProviderVerification,ContractError> {
        panic!("unverifiable missing source must never be treated as verified")
    };
    let r=assess_key_capabilities(&request(),&cap,&panics).unwrap();
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&r,CapabilityReason::MissingEvidence));
}

#[test]
fn unknown_provider_support_is_indeterminate_not_a_negative_assumption() {
    let r=verify(&request(),&snapshot("unknown"));
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&r,CapabilityReason::CapabilityUnknown));
    assert_eq!(r.findings[0].disposition,CapabilityDisposition::Unknown);
}

#[test]
fn independently_authenticated_unsupported_capability_denies() {
    let r=verify(&request(),&snapshot("unsupported"));
    assert_eq!(r.outcome,DecisionOutcome::Deny);
    assert!(reason(&r,CapabilityReason::ProviderUnsupported));
}

#[test]
fn absent_snapshot_capabilities_do_not_mean_denied_or_permitted() {
    let r=verify(&request(),&snapshot("empty"));
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&r,CapabilityReason::MissingCapability));
    assert!(r.findings.is_empty());
}

#[test]
fn expired_and_stale_assurance_are_indeterminate() {
    let r=verify(&request(),&snapshot("stale"));
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&r,CapabilityReason::StaleOrFutureEvidence));
    let mut req=request();req.evaluation_time.unix_millis=200;
    let expired=verify(&req,&snapshot("supported"));
    assert_eq!(expired.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&expired,CapabilityReason::StaleOrFutureEvidence));
}

#[test]
fn evidence_age_exact_boundary_is_inclusive_but_next_millisecond_stale() {
    let mut req=request();req.evaluation_time.unix_millis=170;
    assert_eq!(verify(&req,&snapshot("supported")).outcome,DecisionOutcome::Permit);
    req.evaluation_time.unix_millis=171;
    assert_eq!(verify(&req,&snapshot("supported")).outcome,DecisionOutcome::Indeterminate);
}

#[test]
fn future_issued_claim_cannot_authorize_and_checked_sub_cannot_overflow() {
    let mut req=request();req.evaluation_time.unix_millis=119;
    let r=verify(&req,&snapshot("supported"));
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    let mut cap=snapshot("supported");
    cap.claims[0].asserted_at.unix_millis=i64::MIN;
    cap.claims[0].expires_at.unix_millis=i64::MAX;
    assert_eq!(verify(&request(),&cap).outcome,DecisionOutcome::Indeterminate);
}

#[test]
fn exact_key_parameter_profile_downgrade_is_denied() {
    let r=verify(&request(),&snapshot("downgrade"));
    assert_eq!(r.outcome,DecisionOutcome::Deny);
    assert!(reason(&r,CapabilityReason::DowngradeDetected));
    assert_eq!(r.findings[0].disposition,CapabilityDisposition::Downgrade);
}

#[test]
fn ml_kem_category_5_cannot_be_replaced_by_category_3_or_by_bit_count() {
    let mut req=request();let mut cap=snapshot("supported");
    req.algorithm_id=aid("ML-KEM-1024");
    req.operation=CryptoOperation::Encapsulate;
    req.parameter=KeyParameter::NamedSet(aid("ML-KEM-1024"));
    cap.claims[0].algorithm_id=aid("ML-KEM-768");
    cap.claims[0].operation=CryptoOperation::Encapsulate;
    cap.claims[0].parameter=KeyParameter::NamedSet(aid("ML-KEM-768"));
    let result=verify(&req,&cap);
    assert_eq!(result.outcome,DecisionOutcome::Deny);
    assert!(reason(&result,CapabilityReason::DowngradeDetected));
    req.parameter=KeyParameter::KeyBits(1024);
    let invalid=verify(&req,&cap);
    assert_eq!(invalid.outcome,DecisionOutcome::Deny);
    assert!(reason(&invalid,CapabilityReason::InvalidRequestedParameter));
}

#[test]
fn exact_ml_kem_set_and_verified_claim_can_be_compatible_preflight_only() {
    let mut req=request();let mut cap=snapshot("supported");
    req.algorithm_id=aid("ML-KEM-1024");
    req.operation=CryptoOperation::Encapsulate;
    req.parameter=KeyParameter::NamedSet(aid("ML-KEM-1024"));
    cap.claims[0].algorithm_id=aid("ML-KEM-1024");
    cap.claims[0].operation=CryptoOperation::Encapsulate;
    cap.claims[0].parameter=KeyParameter::NamedSet(aid("ML-KEM-1024"));
    assert_eq!(verify(&req,&cap).outcome,DecisionOutcome::Permit);
}

#[test]
fn unknown_draft_or_alias_algorithm_never_becomes_approved() {
    for name in ["Kyber-1024","AES256-GCM","ML-KEM-999","FALCON-512","TDEA-3KEY","RSA-PSS-1024"] {
        let mut req=request();req.algorithm_id=aid(name);
        let r=verify(&req,&snapshot("supported"));
        assert_eq!(r.outcome,DecisionOutcome::Deny, "name={name}");
        assert!(reason(&r,CapabilityReason::UnsupportedRequestedAlgorithm)
            || reason(&r,CapabilityReason::InvalidRequestedParameter)
            || reason(&r,CapabilityReason::UnsupportedRequestedOperation));
    }
}

#[test]
fn unsupported_operation_and_parameter_for_known_profile_deny() {
    let mut req=request();req.operation=CryptoOperation::Sign;
    let r=verify(&req,&snapshot("supported"));
    assert_eq!(r.outcome,DecisionOutcome::Deny);
    assert!(reason(&r,CapabilityReason::UnsupportedRequestedOperation));
    req=request();req.parameter=KeyParameter::KeyBits(128);
    let x=verify(&req,&snapshot("supported"));
    assert_eq!(x.outcome,DecisionOutcome::Deny);
    assert!(reason(&x,CapabilityReason::InvalidRequestedParameter));
    req=request();req.operation=CryptoOperation::Hash;
    let x=verify(&req,&snapshot("supported"));
    assert_eq!(x.outcome,DecisionOutcome::Deny);
    assert!(reason(&x,CapabilityReason::UnsupportedRequestedOperation));
}

#[test]
fn conflicting_support_and_exportability_claims_cannot_authorize() {
    let r=verify(&request(),&snapshot("conflict"));
    assert_eq!(r.outcome,DecisionOutcome::Deny);
    assert!(reason(&r,CapabilityReason::ConflictingClaims));
    assert!(reason(&r,CapabilityReason::ForbiddenCapabilityPresent));
    assert_eq!(r.findings.len(),2);
    assert_eq!(r.findings[0].claim_id,rid("cap:one"));
    assert_eq!(r.findings[1].claim_id,rid("cap:two"));
}

#[test]
fn claim_order_and_requirement_order_never_change_serialized_output() {
    let req=request();let cap=snapshot("conflict");
    let expected=serde_json::to_vec(&verify(&req,&cap)).unwrap();
    let mut other=cap.clone();other.claims.reverse();
    let mut reverse=req.clone();reverse.required.reverse();reverse.forbidden.reverse();
    for i in 0..32 {
        if i%2==0 { other.claims.reverse(); reverse.required.reverse(); }
        assert_eq!(serde_json::to_vec(&verify(&reverse,&other)).unwrap(),expected);
    }
}

#[test]
fn known_exportable_and_imported_key_claims_fail_forbidden_requirements() {
    let mut cap=snapshot("supported");cap.claims[0].key_exportable=Some(true);
    let r=verify(&request(),&cap);
    assert_eq!(r.outcome,DecisionOutcome::Deny);
    assert!(reason(&r,CapabilityReason::ForbiddenCapabilityPresent));
    cap=snapshot("supported");cap.claims[0].key_origin=Some(KeyOrigin::Imported);
    let result=verify(&request(),&cap);
    assert_eq!(result.outcome,DecisionOutcome::Deny);
    assert!(reason(&result,CapabilityReason::ForbiddenCapabilityPresent));
}

#[test]
fn missing_origin_or_exportability_is_unknown_not_safe() {
    let mut cap=snapshot("supported");cap.claims[0].key_origin=None;
    let result=verify(&request(),&cap);
    assert_eq!(result.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&result,CapabilityReason::MissingRequiredCapability));
    cap=snapshot("supported");cap.claims[0].key_exportable=None;
    assert_eq!(verify(&request(),&cap).outcome,DecisionOutcome::Indeterminate);
}

#[test]
fn software_protection_is_confirmed_rejection_not_hsm_assurance() {
    let mut cap=snapshot("supported");cap.claims[0].protection=Some(KeyProtection::Software);
    let result=verify(&request(),&cap);
    assert_eq!(result.outcome,DecisionOutcome::Deny);
    assert!(reason(&result,CapabilityReason::RequiredCapabilityFailed));
    assert!(reason(&result,CapabilityReason::ForbiddenCapabilityPresent));
}

#[test]
fn no_hsm_attestation_cannot_satisfy_hardware_backed_requirement() {
    let mut req=request();
    req.required.retain(|c| !matches!(c,RequiredCapability::IndependentAssurance));
    let weak=|_:&KeyRequest,_:&ProviderCapabilitySnapshot,_:&ProviderCapabilityClaim| {
        Ok(ProviderVerification{source_authenticated:true,assurance_authenticated:false})
    };
    let r=assess_key_capabilities(&req,&snapshot("supported"),&weak).unwrap();
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&r,CapabilityReason::AssuranceNotVerified));
}

#[test]
fn nonmatching_stronger_family_profile_does_not_authorize_exact_request() {
    let mut cap=snapshot("supported");
    cap.claims[0].algorithm_id=aid("AES-192-GCM");
    cap.claims[0].parameter=KeyParameter::KeyBits(192);
    let r=verify(&request(),&cap);
    assert_eq!(r.outcome,DecisionOutcome::Deny);
    assert!(reason(&r,CapabilityReason::DowngradeDetected));
}

#[test]
fn unrelated_provider_capability_cannot_fill_missing_exact_request() {
    let mut cap=snapshot("supported");
    cap.claims[0].algorithm_id=aid("ML-DSA-87");
    cap.claims[0].operation=CryptoOperation::Sign;
    cap.claims[0].parameter=KeyParameter::NamedSet(aid("ML-DSA-87"));
    let r=verify(&request(),&cap);
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert_eq!(r.findings[0].disposition,CapabilityDisposition::Unrelated);
    assert!(reason(&r,CapabilityReason::MissingCapability));
}

#[test]
fn supported_claim_wrong_parameter_cannot_be_accepted() {
    let mut cap=snapshot("supported");cap.claims[0].parameter=KeyParameter::KeyBits(128);
    let r=verify(&request(),&cap);
    assert_eq!(r.outcome,DecisionOutcome::Deny);
    assert!(reason(&r,CapabilityReason::ParameterMismatch));
}

#[test]
fn source_spoof_and_assurance_issuer_confusion_does_not_authenticate() {
    let mut cap=snapshot("supported");
    cap.claims[0].evidence_ref=Some(rid("evidence:forged"));
    assert_eq!(verify(&request(),&cap).outcome,DecisionOutcome::Indeterminate);
    cap=snapshot("supported");cap.snapshot_id=rid("snapshot:wrong");
    assert_eq!(verify(&request(),&cap).outcome,DecisionOutcome::Indeterminate);
    cap=snapshot("supported");cap.claims[0].assurance_ref=Some(rid("attestation:wrong"));
    assert_eq!(verify(&request(),&cap).outcome,DecisionOutcome::Indeterminate);
}

#[test]
fn existing_key_requires_exact_attested_key_reference_binding() {
    let mut req=request();
    req.key_ref=Some(rid("key:existing:one"));
    let missing=verify(&req,&snapshot("supported"));
    assert_eq!(missing.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&missing,CapabilityReason::KeyBindingMismatch));
    assert_eq!(missing.key_ref,req.key_ref);
    assert_eq!(missing.findings[0].disposition,CapabilityDisposition::KeyBindingMismatch);
    assert!(!missing.findings[0].source_authenticated);
    let mut cap=snapshot("supported");
    cap.claims[0].key_ref=req.key_ref.clone();
    let trusted=verify(&req,&cap);
    assert_eq!(trusted.outcome,DecisionOutcome::Permit);
    assert_eq!(trusted.findings[0].key_ref,req.key_ref);
    cap.claims[0].key_ref=Some(rid("key:existing:other"));
    assert_eq!(verify(&req,&cap).outcome,DecisionOutcome::Indeterminate);
}

#[test]
fn generic_new_key_capability_cannot_claim_a_specific_existing_key() {
    let req=request();
    let mut cap=snapshot("supported");
    cap.claims[0].key_ref=Some(rid("key:existing:one"));
    let report=verify(&req,&cap);
    assert_eq!(report.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&report,CapabilityReason::KeyBindingMismatch));
}

#[test]
fn provider_and_catalog_mismatch_reject_before_verifier() {
    let req=request();let mut cap=snapshot("supported");
    cap.provider_id=ProviderId::parse("provider:beta").unwrap();
    assert_eq!(assess_key_capabilities(&req,&cap,&UnverifiedProviderClaims),
        Err(ContractError::InvalidDocument("provider_identity_mismatch")));
    let mut cap=snapshot("supported");
    cap.catalog_version=PolicyVersion::parse("1.0.1").unwrap();
    assert_eq!(assess_key_capabilities(&req,&cap,&UnverifiedProviderClaims),
        Err(ContractError::InvalidDocument("catalog_binding_mismatch")));
    let mut req=request();let mut cap=snapshot("supported");
    let digest=PolicyDigest::try_from("f".repeat(64)).unwrap();
    req.catalog_digest=digest.clone();cap.catalog_digest=digest;
    assert_eq!(assess_key_capabilities(&req,&cap,&UnverifiedProviderClaims),
        Err(ContractError::InvalidDocument("unreviewed_catalog_binding")));
}

#[test]
fn duplicate_claim_id_and_invalid_claim_interval_are_rejected() {
    let mut cap=snapshot("supported");cap.claims.push(cap.claims[0].clone());
    assert_eq!(cap.validate(&Limits::default()),Err(ContractError::DuplicateIdentifier));
    let mut cap=snapshot("supported");
    cap.claims[0].expires_at=cap.claims[0].asserted_at;
    assert_eq!(cap.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("invalid_claim_validity")));
}

#[test]
fn nonsupport_status_with_key_security_properties_is_invalid() {
    let cap=mutate_snapshot(|v|v["claims"][0]["availability"]="unknown".into());
    assert_eq!(cap,Err(ContractError::InvalidDocument("nonsupport_with_key_attributes")));
}

#[test]
fn unknown_origin_requirement_is_rejected_at_construction() {
    let mut req=request();req.required.push(RequiredCapability::KeyOrigin(KeyOrigin::Unknown));
    assert_eq!(req.validate(&Limits::default()),Err(ContractError::InvalidDocument("requirement_unknown_origin")));
    req=request();req.forbidden.push(ForbiddenCapability::KeyOrigin(KeyOrigin::Unknown));
    assert_eq!(req.validate(&Limits::default()),Err(ContractError::InvalidDocument("forbid_unknown_origin")));
}

#[test]
fn duplicate_contraint_and_unconstrained_request_fail_closed() {
    let mut req=request();req.required.push(req.required[0].clone());
    assert_eq!(req.validate(&Limits::default()),Err(ContractError::DuplicateIdentifier));
    req=request();req.required.clear();req.forbidden.clear();
    assert_eq!(req.validate(&Limits::default()),
        Err(ContractError::InvalidDocument("unconstrained_key_request")));
}

#[test]
fn oversized_age_budget_zero_age_and_invalid_key_bits_are_rejected() {
    let mut req=request();req.max_evidence_age_ms=0;
    assert_eq!(req.validate(&Limits::default()),Err(ContractError::InvalidDocument("invalid_evidence_age_budget")));
    req.max_evidence_age_ms=MAX_CAPABILITY_AGE_MS+1;
    assert_eq!(req.validate(&Limits::default()),Err(ContractError::InvalidDocument("invalid_evidence_age_budget")));
    req=request();req.parameter=KeyParameter::KeyBits(0);
    assert_eq!(req.validate(&Limits::default()),Err(ContractError::InvalidDocument("invalid_key_parameter")));
    req.parameter=KeyParameter::KeyBits(u32::MAX);
    assert_eq!(req.validate(&Limits::default()),Err(ContractError::InvalidDocument("invalid_key_parameter")));
}

#[test]
fn incompatible_schema_unknown_fields_and_critical_extensions_are_rejected() {
    assert!(mutate_request(|v|v["schema_version"]="2".into()).is_err());
    assert!(mutate_request(|v|v["allow_any_provider"]=true.into()).is_err());
    assert!(mutate_snapshot(|v|v["catalog_digest"]="bad".into()).is_err());
    assert!(mutate_snapshot(|v|v["claims"][0]["override_forbidden"]=true.into()).is_err());
    let input=String::from_utf8(include_bytes!("fixtures/request-v1.json").to_vec()).unwrap();
    let duplicated=input.replacen("\"schema_version\": \"1\"", "\"schema_version\": \"1\", \"schema_version\": \"1\"",1);
    assert_ne!(input,duplicated);
    assert!(KeyRequest::parse_json(duplicated.as_bytes()).is_err());
}

#[test]
fn byte_and_count_budgets_apply_even_for_in_memory_objects() {
    let req=request();
    let bytes=serde_json::to_vec(&req).unwrap();
    let small=Limits{max_adapter_bytes:bytes.len()-1,..Limits::default()};
    assert_eq!(KeyRequest::parse_json_with_limits(&bytes,&small),Err(ContractError::PayloadTooLarge));
    assert_eq!(req.validate(&small),Err(ContractError::PayloadTooLarge));
    let mut cap=snapshot("supported");
    let small=Limits{max_facts:1,..Limits::default()};
    cap.claims.push({let mut c=cap.claims[0].clone();c.claim_id=rid("cap:two");c});
    assert_eq!(cap.validate(&small),Err(ContractError::ResourceLimitExceeded("provider claims")));
    while cap.claims.len()<=MAX_PROVIDER_CAPABILITY_CLAIMS {
        let mut c=cap.claims[0].clone();c.claim_id=rid(&format!("cap:{}",cap.claims.len()));cap.claims.push(c);
    }
    assert_eq!(cap.validate(&Limits::default()),Err(ContractError::ResourceLimitExceeded("provider claims")));
}

#[test]
fn verifier_transport_failure_cannot_be_inferred_as_support() {
    let bad=|_:&KeyRequest,_:&ProviderCapabilitySnapshot,_:&ProviderCapabilityClaim| {
        Err(ContractError::InvalidDocument("provider_verifier_unavailable"))
    };
    assert_eq!(assess_key_capabilities(&request(),&snapshot("supported"),&bad),
        Err(ContractError::InvalidDocument("provider_verifier_unavailable")));
}

#[test]
fn compatibility_report_never_contains_key_material_or_opaque_ref_value_when_absent() {
    let result=verify(&request(),&snapshot("supported"));
    let data=serde_json::to_string(&result).unwrap();
    assert!(!data.contains("private_key"));
    assert!(!data.contains("secret"));
    assert!(!data.contains("key_material"));
    assert_eq!(result.outcome,DecisionOutcome::Permit);
    // This was only a provider capability preflight. The FOSS-435 policy and
    // its independently authenticated issuer have NOT been evaluated here.
}

#[test]
fn generated_report_parser_is_strict_and_bounded() {
    let report=verify(&request(),&snapshot("supported"));
    let bytes=serde_json::to_vec(&report).unwrap();
    let data=String::from_utf8(bytes.clone()).unwrap();
    let injected=data.replacen("\"outcome\":\"permit\"","\"outcome\":\"permit\",\"allow_anything\":true",1);
    assert_ne!(data,injected);
    assert!(CapabilityReport::parse_json_with_limits(injected.as_bytes(),&Limits::default()).is_err());
    let small=Limits{max_json_bytes:bytes.len()-1,..Limits::default()};
    assert_eq!(CapabilityReport::parse_json_with_limits(&bytes,&small),Err(ContractError::PayloadTooLarge));
}

#[test]
fn explicit_forbiddens_can_be_checked_without_an_independent_assurance_rule() {
    let mut req=request();
    req.required=vec![RequiredCapability::NonExportable];
    req.forbidden=vec![ForbiddenCapability::KeyOrigin(KeyOrigin::Imported)];
    assert_eq!(verify(&req,&snapshot("supported")).outcome,DecisionOutcome::Permit);
    let mut cap=snapshot("supported");cap.claims[0].key_origin=Some(KeyOrigin::Imported);
    assert_eq!(verify(&req,&cap).outcome,DecisionOutcome::Deny);
}

#[test]
fn conditionally_unknown_attribute_cannot_satisfy_forbidden_absence() {
    let mut req=request();req.required=vec![RequiredCapability::KeyOrigin(KeyOrigin::ProviderGenerated)];
    req.forbidden=vec![ForbiddenCapability::Exportable];
    let mut cap=snapshot("supported");cap.claims[0].key_exportable=None;
    let r=verify(&req,&cap);
    assert_eq!(r.outcome,DecisionOutcome::Indeterminate);
    assert!(reason(&r,CapabilityReason::MissingRequiredCapability));
}
