//! Offline NIST algorithm-profile catalog demo; no cryptography performed.
use pqc_kit::{Catalog, CatalogError, OperationClass, UsageParameter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = Catalog::embedded_v1()?;
    println!(
        "catalog={} sha256={}",
        catalog.snapshot().catalog_version,
        catalog.fingerprint()
    );
    let name = catalog.resolve_name("AES256-GCM")?;
    println!(
        "parsing_alias={} canonical={}",
        name.via_alias, name.canonical_id
    );
    assert_eq!(name.canonical_id, "AES-256-GCM");
    let aes = catalog.validate_usage(
        "AES-256-GCM",
        OperationClass::Encrypt,
        UsageParameter::KeyBits(256),
    )?;
    println!("name={} status={:?}", aes.id, aes.status);
    let ml_kem = catalog.validate_usage(
        "ML-KEM-768",
        OperationClass::Encapsulate,
        UsageParameter::NamedSet("ML-KEM-768"),
    )?;
    assert_eq!(ml_kem.security.pqc_category, Some(3));
    println!(
        "name={} pqc_category={:?}",
        ml_kem.id, ml_kem.security.pqc_category
    );
    assert_eq!(
        catalog.validate_usage(
            "ML-KEM-768",
            OperationClass::Encapsulate,
            UsageParameter::KeyBits(768)
        ),
        Err(CatalogError::ParameterMismatch),
    );
    println!("Named sets are NOT key bit lengths; catalog membership is NOT a policy Permit.");
    Ok(())
}
