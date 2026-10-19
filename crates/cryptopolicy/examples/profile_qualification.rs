//! FOSS-505: classify a named AES profile without authorizing its use.
//! No real key or source attestations are performed in this example.
use cryptopolicy::{
    CryptoContext, EvidenceId, ExceptionReference, KeyProfileBinding, Limits, ProfileId,
    ProfileParameterWitness, ProfileQualificationFinding, ProfileQualificationRequest,
    UnverifiedKeyProfileBinding, UnverifiedProfileEvidence, qualify_embedded_profile,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut context = CryptoContext::parse_json(include_bytes!(
        "../tests/fixtures/evaluator-context-v1.json"
    ))?;
    context.facts[0].profile_id = Some(ProfileId::parse("AES-256-GCM")?);
    let exception = ExceptionReference::parse_json(include_bytes!(
        "../tests/fixtures/exception-reference-v1.json"
    ))?;
    let binding = KeyProfileBinding {
        scope: exception.scope.clone(),
        profile_id: ProfileId::parse("AES-256-GCM")?,
        evidence_ref: EvidenceId::parse("attest:1")?,
        key_version_ref: EvidenceId::parse("key-version:example")?,
    };
    let parameter = ProfileParameterWitness::KeyBits(256);
    let result = qualify_embedded_profile(
        ProfileQualificationRequest {
            context: &context,
            actual_scope: &exception.scope,
            binding: &binding,
            parameter: &parameter,
            time: context.evaluation_time,
            limits: &Limits::default(),
        },
        &UnverifiedProfileEvidence,
        &UnverifiedKeyProfileBinding,
    )?;
    assert_eq!(result.finding, ProfileQualificationFinding::KeyNotAuthenticated);
    println!(
        "catalog={} profile={} finding={:?}",
        result.catalog_digest.as_str(),
        result.profile_id.as_str(),
        result.finding
    );
    println!("This is metadata, NOT a policy Permit or cryptographic authorization.");
    Ok(())
}
