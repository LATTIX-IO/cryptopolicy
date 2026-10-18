//! Inspect a synthetic TLS group negotiation without authenticating transcripts.
use pqc_kit::tls_hybrid::{
    RFC10024_HYBRID_GROUPS, TlsEvidenceOrigin, TlsHybridObservation,
    TlsTransitionRequirement, assess_tls_hybrid, classify_tls_group,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let group = RFC10024_HYBRID_GROUPS[1];
    let observation = TlsHybridObservation {
        configured_groups: vec![group.codepoint, 29],
        negotiated_group: Some(group.codepoint),
        claimed_name: Some(group.name.to_owned()),
        origin: TlsEvidenceOrigin::Negotiated,
        client_share_octets: Some(group.client_share_octets),
        server_share_octets: Some(group.server_share_octets),
        source_id: "example:tls".to_owned(),
        evidence_ref: "evidence:tls:example".to_owned(),
    };
    let assessment = assess_tls_hybrid(
        &observation,
        &TlsTransitionRequirement::ExactHybridGroup(group.codepoint),
    )?;
    println!("group={:?} finding={:?}", classify_tls_group(group.codepoint), assessment.finding);
    println!("Structural consistency is NOT cryptographic proof, handshake verification or Permit.");
    Ok(())
}
