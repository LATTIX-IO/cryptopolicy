//! Synthetic COSE ML-DSA public-key normalization without key or signature validation.
use cryptopolicy::{EvaluationTime, RequestId};
use pqc_cose::{CoseEvidenceSource, normalize_ml_dsa_cose_key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // COSE_Key {1:7, 3:-48, -1:h'00...'}: synthetic bytes, not a valid ML-DSA key.
    let mut key = vec![0xa3, 0x01, 0x07, 0x03, 0x38, 0x2f, 0x20, 0x59, 0x05, 0x20];
    key.extend(vec![0_u8; 1312]);
    // Protected COSE header map {1:-48}, extracted by a separate COSE parser.
    let protected = [0xa1, 0x01, 0x38, 0x2f];
    let source = CoseEvidenceSource {
        source_id: "example:cose".to_owned(),
        evidence_ref: "evidence:synthetic:1".to_owned(),
    };
    let identity = normalize_ml_dsa_cose_key(&key, &protected, &source)?;
    assert!(!identity.signature_verified && !identity.key_validated);
    let time = EvaluationTime { unix_millis: 150 };
    let context = identity.to_untrusted_context(
        RequestId::parse("example:cose:1")?,
        time,
    )?;
    assert!(!context.facts[0].verified);
    println!(
        "alg={} profile={} public_octets={} sha256={}",
        identity.alg, identity.profile_id, identity.public_key_octets, identity.input_cbor_sha256
    );
    println!("The result is unverified structural metadata, never a Permit.");
    Ok(())
}
