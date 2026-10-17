//! Compile-tested static validation; no cryptographic operation is authorized.
use cryptopolicy::{
    AlgorithmId, PolicyDocument, Requirement, ValidationCode,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_bytes!("../tests/fixtures/static-policy-v1.json");
    let policy = PolicyDocument::parse_json(source)?;
    let good = policy.static_validate()?;
    println!("static_valid={} diagnostics={}", good.is_valid(), good.diagnostics.len());
    assert!(good.is_valid());

    let mut invalid = policy.clone();
    invalid.rules[0].requirements.push(Requirement::Algorithm(
        AlgorithmId::parse("CHACHA20-POLY1305")?,
    ));
    let report = invalid.static_validate()?;
    assert!(!report.is_valid());
    assert!(report.diagnostics.iter().any(|d| d.code == ValidationCode::ConflictingAlgorithm));
    println!("static_valid={} code=conflicting_algorithm", report.is_valid());
    println!("Only syntax/semantics were validated. No runtime decision was made.");
    Ok(())
}
