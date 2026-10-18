//! Offline RFC 9881/9935 identity normalization example (NOT certificate validation).
use pqc_x509::{
    CriticalExtensions, MlKemKeyUsage, X509EvidenceSource, normalize_ml_dsa_certificate_signature,
    normalize_ml_kem_spki,
};
fn len(value: usize) -> Vec<u8> {
    if value < 128 {
        vec![value as u8]
    } else if value <= 255 {
        vec![0x81, value as u8]
    } else {
        vec![0x82, (value >> 8) as u8, value as u8]
    }
}
fn synthetic_spki() -> Vec<u8> {
    let mut body = vec![
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02,
    ];
    let mut payload = vec![0u8; 1185];
    payload[1..].fill(0xa5);
    body.push(0x03);
    body.extend(len(payload.len()));
    body.extend(payload);
    let mut result = vec![0x30];
    result.extend(len(body.len()));
    result.extend(body);
    result
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = X509EvidenceSource {
        source_id: "parser:example".into(),
        evidence_ref: "sample:synthetic".into(),
    };
    let signature = [
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
    ];
    let a = normalize_ml_dsa_certificate_signature(
        &signature,
        &signature,
        CriticalExtensions::CheckedNoUnknownCritical,
        &source,
    )?;
    let b = normalize_ml_kem_spki(
        &synthetic_spki(),
        CriticalExtensions::CheckedNoUnknownCritical,
        MlKemKeyUsage::KeyEnciphermentOnly,
        &source,
    )?;
    assert_eq!(a.profile_id, "ML-DSA-65");
    assert_eq!(b.profile_id, "ML-KEM-768");
    assert!(!a.signature_verified && !a.certificate_validated);
    assert!(!b.signature_verified && !b.certificate_validated);
    println!("{}", serde_json::to_string_pretty(&b)?);
    println!("Result: identity metadata only, no certificate validation or policy decision");
    Ok(())
}
