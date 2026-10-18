//! RFC 9964 synthetic public AKP identity normalization. NOT signature verification.
use cryptopolicy::{EvaluationTime, RequestId};
use pqc_jose::{JoseEvidenceSource, normalize_ml_dsa_jwk};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Synthetic all-zero public key encoding: structural test only, not a valid ML-DSA key.
    let jwk = format!(
        "{{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"pub\":\"{}\"}}",
        "A".repeat(1750)
    );
    let protected = br#"{"alg":"ML-DSA-44"}"#;
    let evidence = JoseEvidenceSource {
        source_id: "example:synthetic".to_owned(),
        evidence_ref: "example:jwk:1".to_owned(),
    };
    let identity = normalize_ml_dsa_jwk(jwk.as_bytes(), protected, &evidence)?;
    assert!(!identity.signature_verified && !identity.key_validated);
    let projected = identity.to_untrusted_context(
        RequestId::parse("example:request:1")?,
        EvaluationTime { unix_millis: 100 },
    )?;
    assert!(!projected.facts[0].verified);
    println!(
        "profile={} source={} public_bytes={} digest={}",
        identity.profile_id,
        identity.standards_profile,
        identity.public_key_octets,
        identity.input_json_sha256
    );
    println!("Projection remains inferred/unverified and never authorizes a key operation.");
    Ok(())
}
