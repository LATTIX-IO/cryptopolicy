//! FOSS-445 registry contract, adversarial parser, and parameter-set regression tests.
#![allow(clippy::unwrap_used)] // Test fixtures deliberately exercise fallible APIs.

use pqc_kit::*;

fn catalog() -> Catalog {
    Catalog::embedded_v1().unwrap()
}

fn fixture() -> Vec<u8> {
    include_bytes!("../data/catalog-v1.json").to_vec()
}

fn mutated(f: impl FnOnce(&mut serde_json::Value)) -> Result<Catalog, CatalogError> {
    let mut value: serde_json::Value = serde_json::from_slice(&fixture()).unwrap();
    f(&mut value);
    Catalog::parse_untrusted_json(&serde_json::to_vec(&value).unwrap())
}

fn named<'a>(id: &'a str) -> UsageParameter<'a> {
    UsageParameter::NamedSet(id)
}

#[test]
fn exact_immutable_v1_snapshot_is_pinned_and_sorted() {
    let c = catalog();
    assert_eq!(c.snapshot().schema_version, CATALOG_SCHEMA_V1);
    assert_eq!(c.snapshot().catalog_version, CATALOG_VERSION_V1);
    assert_eq!(c.snapshot().as_of, "2026-10-17");
    assert_eq!(c.snapshot().entries.len(), 36);
    assert_eq!(c.fingerprint(), EMBEDDED_CATALOG_SHA256_V1);
    assert_eq!(c.fingerprint().len(), 64);
    assert!(c.snapshot().entries.windows(2).all(|x| x[0].id < x[1].id));
}

#[test]
fn source_metadata_and_family_counts_remain_explicit() {
    let c = catalog();
    assert_eq!(
        c.snapshot()
            .entries
            .iter()
            .filter(|p| p.status == StandardizationStatus::Standardized)
            .count(),
        33
    );
    assert_eq!(
        c.snapshot()
            .entries
            .iter()
            .filter(|p| p.family == AlgorithmFamily::SlhDsa)
            .count(),
        12
    );
    for profile in &c.snapshot().entries {
        assert!(profile.source.url.starts_with("https://csrc.nist.gov/"));
        assert!(!profile.source.revision.is_empty());
    }
}

#[test]
fn ml_kem_named_sets_have_exact_nist_pqc_categories_not_key_lengths() {
    let c = catalog();
    for (name, category) in [("ML-KEM-512", 1), ("ML-KEM-768", 3), ("ML-KEM-1024", 5)] {
        let entry = c
            .validate_usage(name, OperationClass::Encapsulate, named(name))
            .unwrap();
        assert_eq!(entry.security.pqc_category, Some(category));
        assert_eq!(entry.security.classical_bits, None);
        assert_eq!(entry.parameter.kind, ParameterKind::NamedSet);
        assert!(
            c.validate_usage(name, OperationClass::Decapsulate, named(name))
                .is_ok()
        );
        assert_eq!(
            c.validate_usage(
                name,
                OperationClass::Encapsulate,
                UsageParameter::KeyBits(name.split('-').last().unwrap().parse().unwrap())
            ),
            Err(CatalogError::ParameterMismatch),
        );
    }
}

#[test]
fn ml_dsa_sets_map_to_categories_two_three_five_only() {
    let c = catalog();
    for (name, category) in [("ML-DSA-44", 2), ("ML-DSA-65", 3), ("ML-DSA-87", 5)] {
        let e = c
            .validate_usage(name, OperationClass::Sign, named(name))
            .unwrap();
        assert_eq!(e.security.pqc_category, Some(category));
        assert!(
            c.validate_usage(name, OperationClass::Verify, named(name))
                .is_ok()
        );
    }
}

#[test]
fn all_twelve_slh_dsa_sets_have_exact_distinct_categories() {
    let c = catalog();
    for hash in ["SHA2", "SHAKE"] {
        for (strength, category) in [(128, 1), (192, 3), (256, 5)] {
            for size in ['f', 's'] {
                let id = format!("SLH-DSA-{hash}-{strength}{size}");
                let p = c
                    .validate_usage(&id, OperationClass::Verify, named(&id))
                    .unwrap();
                assert_eq!(p.security.pqc_category, Some(category));
                assert_eq!(p.parameter.value, ParameterValue::Name(id.clone()));
                assert!(
                    c.validate_usage(&id, OperationClass::Sign, named(&id))
                        .is_ok()
                );
            }
        }
    }
}

#[test]
fn aes_sha_rsa_and_ecc_parameters_remain_distinct_from_security_strength() {
    let c = catalog();
    for bits in [128, 192, 256] {
        let id = format!("AES-{bits}-GCM");
        let e = c
            .validate_usage(&id, OperationClass::Encrypt, UsageParameter::KeyBits(bits))
            .unwrap();
        assert_eq!(e.security.classical_bits, Some(bits as u16));
        assert_eq!(e.security.pqc_category, None);
    }
    assert!(
        c.validate_usage(
            "SHA-256",
            OperationClass::Hash,
            UsageParameter::HashOutputBits(256)
        )
        .is_ok()
    );
    assert!(
        c.validate_usage(
            "SHA3-512",
            OperationClass::Hash,
            UsageParameter::HashOutputBits(512)
        )
        .is_ok()
    );
    assert!(
        c.validate_usage(
            "RSA-PSS-3072",
            OperationClass::Sign,
            UsageParameter::KeyBits(3072)
        )
        .is_ok()
    );
    assert!(
        c.validate_usage(
            "ECDSA-P384",
            OperationClass::Verify,
            UsageParameter::KeyBits(384)
        )
        .is_ok()
    );
    assert_eq!(
        c.validate_usage(
            "SHA-256",
            OperationClass::Hash,
            UsageParameter::KeyBits(256)
        ),
        Err(CatalogError::ParameterMismatch)
    );
}

#[test]
fn unknown_and_prestanard_identifiers_never_become_canonical() {
    let c = catalog();
    for id in [
        "Kyber-1024",
        "Dilithium5",
        "SPHINCS+-SHA2-256s",
        "ML-KEM-999",
        "ML-DSA-1024",
        "SHA3-123",
        "ML-KEM",
        "unknown",
        "",
    ] {
        assert_eq!(c.resolve_name(id), Err(CatalogError::UnknownProfile));
        assert_eq!(
            c.validate_usage(id, OperationClass::Encapsulate, named(id)),
            Err(CatalogError::UnknownProfile)
        );
    }
}

#[test]
fn explicit_aliases_are_parsing_only_and_case_sensitive() {
    let c = catalog();
    assert_eq!(
        c.resolve_name("AES256-GCM").unwrap(),
        ResolvedName {
            canonical_id: "AES-256-GCM",
            via_alias: true
        }
    );
    assert_eq!(c.resolve_name("AES-256-GCM").unwrap().via_alias, false);
    assert_eq!(c.resolve_name("SHA3_256").unwrap().canonical_id, "SHA3-256");
    assert_eq!(
        c.resolve_name("aes256-gcm"),
        Err(CatalogError::UnknownProfile)
    );
    assert!(c.get("AES256-GCM").is_none());
    assert_eq!(
        c.validate_usage(
            "AES256-GCM",
            OperationClass::Encrypt,
            UsageParameter::KeyBits(256)
        ),
        Err(CatalogError::AliasNotCanonical)
    );
}

#[test]
fn invalid_operation_wrong_named_set_and_wrong_bits_fail_closed() {
    let c = catalog();
    assert_eq!(
        c.validate_usage("ML-KEM-768", OperationClass::Sign, named("ML-KEM-768")),
        Err(CatalogError::OperationMismatch)
    );
    assert_eq!(
        c.validate_usage("ML-DSA-65", OperationClass::Encapsulate, named("ML-DSA-65")),
        Err(CatalogError::OperationMismatch)
    );
    assert_eq!(
        c.validate_usage(
            "AES-256-GCM",
            OperationClass::Encrypt,
            UsageParameter::KeyBits(128)
        ),
        Err(CatalogError::ParameterMismatch)
    );
    assert_eq!(
        c.validate_usage(
            "ML-KEM-1024",
            OperationClass::Encapsulate,
            named("ML-KEM-768")
        ),
        Err(CatalogError::ParameterMismatch)
    );
    assert_eq!(
        c.validate_usage(
            "SLH-DSA-SHAKE-128s",
            OperationClass::Sign,
            named("SLH-DSA-SHA2-128s")
        ),
        Err(CatalogError::ParameterMismatch)
    );
}

#[test]
fn experimental_deprecated_and_unsupported_entries_cannot_pass_usage_check() {
    let c = catalog();
    for (name, op, p, status) in [
        (
            "FALCON-512",
            OperationClass::Sign,
            named("FALCON-512"),
            StandardizationStatus::Experimental,
        ),
        (
            "TDEA-3KEY",
            OperationClass::Decrypt,
            UsageParameter::KeyBits(168),
            StandardizationStatus::Deprecated,
        ),
        (
            "RSA-PSS-1024",
            OperationClass::Verify,
            UsageParameter::KeyBits(1024),
            StandardizationStatus::Unsupported,
        ),
    ] {
        assert_eq!(c.get(name).unwrap().status, status);
        assert_eq!(
            c.validate_usage(name, op, p),
            Err(CatalogError::NonStandard(status))
        );
    }
}

#[test]
fn unknown_fields_and_duplicate_json_keys_are_rejected() {
    let text = String::from_utf8(fixture()).unwrap();
    let invalid = text.replacen(
        r#""status": "standardized","#,
        r#""status": "standardized", "permit_any": true,"#,
        1,
    );
    assert_ne!(text, invalid);
    assert_eq!(
        Catalog::parse_untrusted_json(invalid.as_bytes()).err(),
        Some(CatalogError::InvalidJson)
    );
    let duplicated = text.replacen(
        r#""schema_version": "1","#,
        r#""schema_version": "1", "schema_version": "1","#,
        1,
    );
    assert_ne!(text, duplicated);
    assert_eq!(
        Catalog::parse_untrusted_json(duplicated.as_bytes()).err(),
        Some(CatalogError::InvalidJson)
    );
}

#[test]
fn payload_bound_and_future_schema_are_rejected() {
    assert_eq!(
        Catalog::parse_untrusted_json(&vec![b' '; MAX_CATALOG_BYTES + 1]).err(),
        Some(CatalogError::PayloadTooLarge)
    );
    assert_eq!(
        mutated(|v| v["catalog_version"] = "2.0.0".into()).err(),
        Some(CatalogError::InvalidSchema)
    );
    assert_eq!(
        mutated(|v| v["schema_version"] = "2".into()).err(),
        Some(CatalogError::InvalidSchema)
    );
    assert_eq!(
        mutated(|v| v["as_of"] = "2026-10-18".into()).err(),
        Some(CatalogError::InvalidSchema)
    );
}

#[test]
fn category_mutation_and_key_bits_substitution_are_rejected() {
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "ML-KEM-1024").unwrap();
            e["security"]["pqc_category"] = 3.into();
        })
        .err(),
        Some(CatalogError::InvalidProfile("pqc_category"))
    );
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "ML-KEM-768").unwrap();
            e["parameter"]["kind"] = "key_bits".into();
            e["parameter"]["value"] = 768.into();
        })
        .err(),
        Some(CatalogError::InvalidProfile("profile_parameter"))
    );
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "ML-DSA-44").unwrap();
            e["security"]["classical_bits"] = 128.into();
        })
        .err(),
        Some(CatalogError::InvalidProfile("mixed_security_dimensions"))
    );
}

#[test]
fn lifecycle_downgrade_from_unsupported_or_experimental_is_rejected() {
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "FALCON-512").unwrap();
            e["status"] = "standardized".into();
        })
        .err(),
        Some(CatalogError::InvalidProfile("family_or_status"))
    );
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "RSA-PSS-1024").unwrap();
            e["status"] = "standardized".into();
        })
        .err(),
        Some(CatalogError::InvalidProfile("family_or_status"))
    );
}

#[test]
fn unreviewed_alias_and_alias_to_canonical_collision_are_rejected() {
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "ML-KEM-1024").unwrap();
            e["aliases"] = serde_json::json!(["Kyber-1024"]);
        })
        .err(),
        Some(CatalogError::InvalidAlias)
    );
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "AES-256-GCM").unwrap();
            e["aliases"] = serde_json::json!(["AES-128-GCM"]);
        })
        .err(),
        Some(CatalogError::InvalidAlias)
    );
}

#[test]
fn wrong_operation_set_and_untrusted_source_url_fail() {
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "ML-KEM-768").unwrap();
            e["operations"] = serde_json::json!(["sign"]);
        })
        .err(),
        Some(CatalogError::InvalidProfile("operation_set"))
    );
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            let e = arr.iter_mut().find(|x| x["id"] == "ML-KEM-768").unwrap();
            e["source"]["url"] = "https://evil.example/standards".into();
        })
        .err(),
        Some(CatalogError::InvalidProfile("standards_source"))
    );
}

#[test]
fn duplicate_or_unordered_profiles_cannot_change_identity_precedence() {
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            arr.push(arr[0].clone());
        })
        .err(),
        Some(CatalogError::InvalidIdentity)
    );
    assert_eq!(
        mutated(|v| {
            let arr = v["entries"].as_array_mut().unwrap();
            arr.swap(0, 1);
        })
        .err(),
        Some(CatalogError::InvalidIdentity)
    );
}

#[test]
fn all_profiles_roundtrip_without_loss_of_parameter_type() {
    let c = catalog();
    let serial = serde_json::to_vec(c.snapshot()).unwrap();
    let parsed = Catalog::parse_untrusted_json(&serial).unwrap();
    assert_eq!(parsed.snapshot(), c.snapshot());
    assert_ne!(parsed.fingerprint(), "".to_owned());
    for e in &c.snapshot().entries {
        assert_eq!(c.get(&e.id), Some(e));
        let name = c.resolve_name(&e.id).unwrap();
        assert_eq!(name.canonical_id, e.id);
        assert!(!name.via_alias);
    }
}

#[test]
fn adversarial_invalid_utf8_mutations_do_not_parse() {
    let base = fixture();
    for i in (0..base.len()).step_by(139) {
        let mut payload = base.clone();
        payload[i] = 0xff;
        assert!(Catalog::parse_untrusted_json(&payload).is_err());
    }
}
