//! Exact RFC 10024 registration, negotiation boundary and downgrade tests.
#![allow(clippy::unwrap_used)]
use pqc_kit::tls_hybrid::{
    HybridShareOrder, RFC10024_HYBRID_GROUPS, TlsEvidenceOrigin, TlsGroupClass, TlsHybridError,
    TlsHybridFinding, TlsHybridObservation, TlsTransitionRequirement, assess_tls_hybrid,
    classify_tls_group, named_tls_hybrid, validate_tls_hybrid_components,
};
use serde_json::Value;

fn observed(code: u16, client: usize, server: usize) -> TlsHybridObservation {
    TlsHybridObservation {
        configured_groups: vec![code],
        negotiated_group: Some(code),
        claimed_name: None,
        origin: TlsEvidenceOrigin::Negotiated,
        client_share_octets: Some(client),
        server_share_octets: Some(server),
        source_id: "source:tls".to_owned(),
        evidence_ref: "evidence:tls:1".to_owned(),
    }
}

fn assessment(
    observation: &TlsHybridObservation,
    requirement: TlsTransitionRequirement,
) -> TlsHybridFinding {
    assess_tls_hybrid(observation, &requirement)
        .unwrap()
        .finding
}

#[test]
fn all_three_registered_groups_match_exact_normative_json_vectors() {
    let cases: Vec<Value> =
        serde_json::from_slice(include_bytes!("fixtures/rfc10024-tls-groups-v1.json")).unwrap();
    assert_eq!(cases.len(), RFC10024_HYBRID_GROUPS.len());
    for (row, actual) in cases.iter().zip(RFC10024_HYBRID_GROUPS.iter()) {
        assert_eq!(actual.codepoint as u64, row["codepoint"].as_u64().unwrap());
        assert_eq!(actual.name, row["name"].as_str().unwrap());
        assert_eq!(
            actual.classical_component,
            row["classical"].as_str().unwrap()
        );
        assert_eq!(actual.kem_component, row["kem"].as_str().unwrap());
        assert_eq!(
            actual.client_share_octets as u64,
            row["client_share"].as_u64().unwrap()
        );
        assert_eq!(
            actual.server_share_octets as u64,
            row["server_share"].as_u64().unwrap()
        );
        assert_eq!(
            actual.shared_secret_octets as u64,
            row["shared_secret"].as_u64().unwrap()
        );
        assert_eq!(
            actual.iana_recommended,
            row["recommended"].as_bool().unwrap()
        );
        assert_eq!(actual.standard, "RFC 10024");
        assert_eq!(
            actual.share_order == HybridShareOrder::KemThenEcdhe,
            row["kem_first"].as_bool().unwrap()
        );
        validate_tls_hybrid_components(actual).unwrap();
        assert_eq!(named_tls_hybrid(actual.name), Some(actual));
        assert_eq!(
            classify_tls_group(actual.codepoint),
            TlsGroupClass::Finalized(actual)
        );
    }
}

#[test]
fn standardized_client_and_server_sizes_are_component_sums() {
    for group in &RFC10024_HYBRID_GROUPS {
        assert_eq!(
            group.classical_public_octets + group.kem_public_octets,
            group.client_share_octets
        );
        assert_eq!(
            group.classical_public_octets + group.kem_ciphertext_octets,
            group.server_share_octets
        );
    }
    assert_eq!(
        RFC10024_HYBRID_GROUPS[1].share_order,
        HybridShareOrder::KemThenEcdhe
    );
    assert_eq!(
        RFC10024_HYBRID_GROUPS[2].share_order,
        HybridShareOrder::EcdheThenKem
    );
}

#[test]
fn exact_finalized_hybrid_is_structural_only() {
    for group in &RFC10024_HYBRID_GROUPS {
        let obs = observed(
            group.codepoint,
            group.client_share_octets,
            group.server_share_octets,
        );
        let output = assess_tls_hybrid(
            &obs,
            &TlsTransitionRequirement::ExactHybridGroup(group.codepoint),
        )
        .unwrap();
        assert_eq!(
            output.finding,
            TlsHybridFinding::StructurallyConsistentHybrid
        );
        assert_eq!(output.origin, TlsEvidenceOrigin::Negotiated);
        assert_eq!(output.group, Some(*group));
        assert_eq!(
            assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
            TlsHybridFinding::StructurallyConsistentHybrid
        );
    }
}

#[test]
fn configuration_or_inference_alone_cannot_imply_negotiated_hybrid() {
    let group = &RFC10024_HYBRID_GROUPS[1];
    let mut obs = observed(
        group.codepoint,
        group.client_share_octets,
        group.server_share_octets,
    );
    obs.negotiated_group = None;
    assert_eq!(
        assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
        TlsHybridFinding::NotNegotiated
    );
    obs.negotiated_group = Some(group.codepoint);
    for phase in [TlsEvidenceOrigin::Configured, TlsEvidenceOrigin::Inferred] {
        obs.origin = phase;
        assert_eq!(
            assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
            TlsHybridFinding::UnverifiedOrigin
        );
    }
}

#[test]
fn old_kyber_drafts_unknown_groups_and_classical_groups_never_upgrade() {
    for (code, name) in [
        (25497, "X25519Kyber768Draft00"),
        (25498, "SecP256r1Kyber768Draft00"),
    ] {
        assert_eq!(
            classify_tls_group(code),
            TlsGroupClass::ObsoletedDraft {
                codepoint: code,
                name
            }
        );
        let obs = observed(code, 1216, 1120);
        assert_eq!(
            assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
            TlsHybridFinding::ObsoletedDraft
        );
    }
    for code in [0, 29, 23, 24, 0xffff, 4600, 25499] {
        assert_eq!(classify_tls_group(code), TlsGroupClass::Unknown(code));
        assert_eq!(
            assessment(
                &observed(code, 1216, 1120),
                TlsTransitionRequirement::AnyFinalizedHybrid
            ),
            TlsHybridFinding::UnknownGroup
        );
    }
    assert_eq!(named_tls_hybrid("x25519mlkem768"), None);
    assert_eq!(named_tls_hybrid("X25519Kyber768Draft00"), None);
}

#[test]
fn name_mismatch_and_unoffered_selection_detect_downgrade() {
    let group = &RFC10024_HYBRID_GROUPS[1];
    let mut obs = observed(
        group.codepoint,
        group.client_share_octets,
        group.server_share_octets,
    );
    obs.claimed_name = Some("SecP256r1MLKEM768".to_owned());
    assert_eq!(
        assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
        TlsHybridFinding::NameMismatch
    );
    obs.claimed_name = Some(group.name.to_owned());
    obs.configured_groups = vec![4587];
    assert_eq!(
        assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
        TlsHybridFinding::UnofferedGroup
    );
    obs.configured_groups = vec![4587, group.codepoint];
    assert_eq!(
        assessment(&obs, TlsTransitionRequirement::ExactHybridGroup(4587)),
        TlsHybridFinding::RequirementMismatch
    );
}

#[test]
fn missing_and_mismatched_key_share_lengths_are_not_compliance() {
    let group = &RFC10024_HYBRID_GROUPS[2];
    let mut obs = observed(
        group.codepoint,
        group.client_share_octets,
        group.server_share_octets,
    );
    obs.client_share_octets = None;
    assert_eq!(
        assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
        TlsHybridFinding::IncompleteShareEvidence
    );
    obs.client_share_octets = Some(group.client_share_octets - 1);
    assert_eq!(
        assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
        TlsHybridFinding::ShareMismatch
    );
    obs.client_share_octets = Some(group.client_share_octets);
    obs.server_share_octets = Some(0);
    assert_eq!(
        assessment(&obs, TlsTransitionRequirement::AnyFinalizedHybrid),
        TlsHybridFinding::ShareMismatch
    );
}

#[test]
fn single_pq_component_never_satisfies_hybrid_requirement() {
    let group = &RFC10024_HYBRID_GROUPS[0];
    let obs = observed(
        group.codepoint,
        group.client_share_octets,
        group.server_share_octets,
    );
    assert_eq!(
        assessment(
            &obs,
            TlsTransitionRequirement::PqcComponentOnly("ML-KEM-768".to_owned())
        ),
        TlsHybridFinding::ComponentOnlyMatch
    );
    assert_eq!(
        assessment(
            &obs,
            TlsTransitionRequirement::PqcComponentOnly("ML-KEM-1024".to_owned())
        ),
        TlsHybridFinding::RequirementMismatch
    );
    let single_pq = observed(0x0201, 1184, 1088);
    assert_eq!(
        assessment(&single_pq, TlsTransitionRequirement::AnyFinalizedHybrid),
        TlsHybridFinding::UnknownGroup
    );
}

#[test]
fn duplicate_oversized_and_invalid_provenance_rejected() {
    let group = &RFC10024_HYBRID_GROUPS[1];
    let mut obs = observed(
        group.codepoint,
        group.client_share_octets,
        group.server_share_octets,
    );
    obs.configured_groups = vec![4588, 4588];
    assert_eq!(
        assess_tls_hybrid(&obs, &TlsTransitionRequirement::AnyFinalizedHybrid),
        Err(TlsHybridError::DuplicateGroup)
    );
    obs.configured_groups = (0..65).collect();
    assert_eq!(
        assess_tls_hybrid(&obs, &TlsTransitionRequirement::AnyFinalizedHybrid),
        Err(TlsHybridError::ResourceLimit)
    );
    obs.configured_groups = vec![4588];
    obs.source_id = "untrusted\nsource".to_owned();
    assert_eq!(
        assess_tls_hybrid(&obs, &TlsTransitionRequirement::AnyFinalizedHybrid),
        Err(TlsHybridError::InvalidIdentifier)
    );
}

#[test]
fn future_codepoint_fuzz_cannot_map_to_finalized_group() {
    for code in 0_u16..=u16::MAX {
        if let TlsGroupClass::Finalized(p) = classify_tls_group(code) {
            assert!([4587, 4588, 4589].contains(&code));
            assert_eq!(p.codepoint, code);
        }
    }
}
