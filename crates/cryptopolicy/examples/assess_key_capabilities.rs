//! FOSS-449 offline Keymesh-style capability preflight demonstration.
//! The fixture verifier is NOT production cryptographic provider authentication.
use cryptopolicy::{
    CapabilityReason, ContractError, DecisionOutcome, EvidenceId, KeyRequest,
    ProviderCapabilityClaim, ProviderCapabilitySnapshot, ProviderVerification,
    UnverifiedProviderClaims, assess_key_capabilities,
};

fn fixture_proof(
    request: &KeyRequest,
    snapshot: &ProviderCapabilitySnapshot,
    claim: &ProviderCapabilityClaim,
) -> Result<ProviderVerification, ContractError> {
    let known = request.provider_id == snapshot.provider_id
        && snapshot.snapshot_id == EvidenceId::parse("snapshot:keymesh:01")?
        && claim.claim_id == EvidenceId::parse("cap:one")?
        && claim.source_id == EvidenceId::parse("provider:metadata")?
        && claim.evidence_ref == Some(EvidenceId::parse("evidence:cap:one")?);
    Ok(ProviderVerification {
        source_authenticated: known,
        assurance_authenticated: known
            && claim.assurance_ref == Some(EvidenceId::parse("attestation:cap:one")?),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let request = KeyRequest::parse_json(include_bytes!("../tests/fixtures/request-v1.json"))?;
    let supported = ProviderCapabilitySnapshot::parse_json(
        include_bytes!("../tests/fixtures/provider-supported-v1.json"),
    )?;
    let unknown_trust = assess_key_capabilities(&request, &supported, &UnverifiedProviderClaims)?;
    assert_eq!(unknown_trust.outcome, DecisionOutcome::Indeterminate);
    assert!(unknown_trust.reasons.contains(&CapabilityReason::UnauthenticatedSource));

    // Test-only fixture identity matching. This is NOT signature verification
    // or a production proof of a provider's HSM/CMVP authorization.
    let compatible = assess_key_capabilities(&request, &supported, &fixture_proof)?;
    assert_eq!(compatible.outcome, DecisionOutcome::Permit);
    println!("catalog={} digest={}", compatible.catalog_version, compatible.catalog_digest.as_str());
    println!("unverified={:?}, fixture_bound={:?}", unknown_trust.outcome, compatible.outcome);

    let stale = ProviderCapabilitySnapshot::parse_json(
        include_bytes!("../tests/fixtures/provider-stale-v1.json"),
    )?;
    let stale_report = assess_key_capabilities(&request, &stale, &fixture_proof)?;
    assert_eq!(stale_report.outcome, DecisionOutcome::Indeterminate);
    println!("stale evidence={:?}", stale_report.outcome);

    let weaker = ProviderCapabilitySnapshot::parse_json(
        include_bytes!("../tests/fixtures/provider-downgrade-v1.json"),
    )?;
    let weak_report = assess_key_capabilities(&request, &weaker, &fixture_proof)?;
    assert_eq!(weak_report.outcome, DecisionOutcome::Deny);
    println!("downgraded provider claim={:?}", weak_report.outcome);
    println!("Capability preflight ONLY: no key operation, issuer approval or enforcement.");
    Ok(())
}
