//! FOSS-452 deterministic RFC 9881 and RFC 9935 DER conformance tests.
#![allow(clippy::unwrap_used)] // Fixtures intentionally test fallible parsers.

use pqc_x509::*;

const CLEAN: CriticalExtensions = CriticalExtensions::CheckedNoUnknownCritical;
const EVIDENCE: &str = "sha256:input:test-fixture";

fn source() -> X509EvidenceSource {
    X509EvidenceSource {
        source_id: "collector:x509:fixture".to_owned(),
        evidence_ref: EVIDENCE.to_owned(),
    }
}
fn signature(oid_end: u8) -> Vec<u8> {
    vec![
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, oid_end,
    ]
}
fn kem_identifier(oid_end: u8) -> Vec<u8> {
    vec![
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, oid_end,
    ]
}
fn der_length(len: usize) -> Vec<u8> {
    if len <= 127 {
        vec![len as u8]
    } else if len <= 255 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}
fn spki(algorithm: &[u8], size: usize) -> Vec<u8> {
    let mut bits = vec![0xa5; size + 1];
    bits[0] = 0;
    let mut bit_string = vec![0x03];
    bit_string.extend(der_length(bits.len()));
    bit_string.extend(bits);
    let mut content = algorithm.to_vec();
    content.extend(bit_string);
    let mut result = vec![0x30];
    result.extend(der_length(content.len()));
    result.extend(content);
    result
}
fn norm_signature(tbs: &[u8], outer: &[u8]) -> Result<X509AlgorithmIdentity, X509Error> {
    normalize_ml_dsa_certificate_signature(tbs, outer, CLEAN, &source())
}
fn norm_spki(input: &[u8]) -> Result<X509AlgorithmIdentity, X509Error> {
    normalize_ml_kem_spki(input, CLEAN, MlKemKeyUsage::KeyEnciphermentOnly, &source())
}
fn golden(name: &str) -> serde_json::Value {
    let input = match name {
        "mldsa44" => include_str!("fixtures/rfc9881-ml-dsa-44-result-v1.json"),
        "mlkem768" => include_str!("fixtures/rfc9935-ml-kem-768-result-v1.json"),
        _ => panic!("bad fixture name"),
    };
    serde_json::from_str(input).unwrap()
}
fn hex_der(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn published_rfc_fixture_tables_are_consumed_as_independent_exact_oid_vectors() {
    let dsa: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/rfc9881-algorithms-v1.json")).unwrap();
    let kem: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/rfc9935-algorithms-v1.json")).unwrap();
    assert_eq!(dsa["schema_version"], "1");
    assert_eq!(kem["schema_version"], "1");
    let dsa_items = dsa["entries"].as_array().unwrap();
    let kem_items = kem["entries"].as_array().unwrap();
    assert_eq!(dsa_items.len(), 3);
    assert_eq!(kem_items.len(), 3);
    for entry in dsa_items {
        let der = hex_der(entry["algorithm_identifier_der_hex"].as_str().unwrap());
        let observed = norm_signature(&der, &der).unwrap();
        assert_eq!(observed.profile_id, entry["profile_id"].as_str().unwrap());
        assert_eq!(observed.oid, entry["oid"].as_str().unwrap());
        assert!(!observed.parameters_present);
    }
    for entry in kem_items {
        let der = hex_der(entry["algorithm_identifier_der_hex"].as_str().unwrap());
        let key_bytes = entry["public_key_octets"].as_u64().unwrap() as usize;
        let observed = norm_spki(&spki(&der, key_bytes)).unwrap();
        assert_eq!(observed.profile_id, entry["profile_id"].as_str().unwrap());
        assert_eq!(observed.oid, entry["oid"].as_str().unwrap());
        assert_eq!(observed.public_key_octets, Some(key_bytes));
    }
}

#[test]
fn checked_in_malformed_der_vectors_keep_stable_failure_codes() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/rfc9881-malformed-der-v1.json")).unwrap();
    assert_eq!(corpus["schema_version"], "1");
    let cases = corpus["cases"].as_array().unwrap();
    assert!(cases.len() >= 8);
    for record in cases {
        let label = record["id"].as_str().unwrap();
        let raw = hex_der(record["der_hex"].as_str().unwrap());
        let expected = record["expected_error"].as_str().unwrap();
        let err = norm_signature(&raw, &raw).unwrap_err();
        assert_eq!(format!("{err:?}"), expected, "case {label}");
    }
}

#[test]
fn all_three_rfc9881_mldsa_signature_oid_profiles_are_exact() {
    for (last, id, oid) in [
        (0x11, "ML-DSA-44", "2.16.840.1.101.3.4.3.17"),
        (0x12, "ML-DSA-65", "2.16.840.1.101.3.4.3.18"),
        (0x13, "ML-DSA-87", "2.16.840.1.101.3.4.3.19"),
    ] {
        let der = signature(last);
        let result = norm_signature(&der, &der).unwrap();
        assert_eq!(result.schema_version, X509SchemaVersion::V1);
        assert_eq!(result.profile_id, id);
        assert_eq!(result.oid, oid);
        assert_eq!(result.field, X509Field::CertificateSignature);
        assert_eq!(result.standards_profile, "RFC 9881");
        assert_eq!(result.public_key_octets, None);
        assert!(!result.parameters_present);
        assert!(!result.signature_verified);
        assert!(!result.certificate_validated);
        assert_eq!(result.source_id, source().source_id);
        assert_eq!(result.evidence_ref, EVIDENCE);
    }
}
#[test]
fn all_three_rfc9935_mlkem_spki_oids_have_exact_raw_public_key_lengths() {
    for (last, size, id, oid) in [
        (1, 800, "ML-KEM-512", "2.16.840.1.101.3.4.4.1"),
        (2, 1184, "ML-KEM-768", "2.16.840.1.101.3.4.4.2"),
        (3, 1568, "ML-KEM-1024", "2.16.840.1.101.3.4.4.3"),
    ] {
        let der = spki(&kem_identifier(last), size);
        let result = norm_spki(&der).unwrap();
        assert_eq!(result.profile_id, id);
        assert_eq!(result.oid, oid);
        assert_eq!(result.field, X509Field::SubjectPublicKeyInfo);
        assert_eq!(result.public_key_octets, Some(size));
        assert_eq!(result.standards_profile, "RFC 9935");
        assert!(!result.signature_verified);
        assert!(!result.certificate_validated);
        assert_eq!(result.catalog_version, "1.0.0");
        assert_eq!(
            result.catalog_sha256,
            "91cca1ed7fe8a0391045801108089bb38bee0b34fdff40e2c7e0fac4e87fb685"
        );
    }
}
#[test]
fn normative_signature_der_golden_contains_original_refs_and_stable_digest() {
    let der = signature(0x11);
    let observed = norm_signature(&der, &der).unwrap();
    assert_eq!(serde_json::to_value(&observed).unwrap(), golden("mldsa44"));
    let bytes = serde_json::to_vec(&observed).unwrap();
    assert_eq!(
        X509AlgorithmIdentity::parse_untrusted_json(&bytes).unwrap(),
        observed
    );
}
#[test]
fn normative_spki_der_golden_has_no_public_key_material_and_stable_fingerprint() {
    let der = spki(&kem_identifier(2), 1184);
    let result = norm_spki(&der).unwrap();
    assert_eq!(serde_json::to_value(&result).unwrap(), golden("mlkem768"));
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("a5a5a5a5"));
    assert!(!json.contains("private_key"));
    assert!(!json.contains("key_material"));
}
#[test]
fn external_parser_absent_key_usage_is_permitted_by_rfc9935() {
    let sample = spki(&kem_identifier(3), 1568);
    let result = normalize_ml_kem_spki(&sample, CLEAN, MlKemKeyUsage::Absent, &source()).unwrap();
    assert_eq!(result.profile_id, "ML-KEM-1024");
}
#[test]
fn any_other_key_usage_or_no_inspection_blocks_spki_normalization() {
    let sample = spki(&kem_identifier(1), 800);
    for usage in [MlKemKeyUsage::OtherBits, MlKemKeyUsage::NotInspected] {
        assert_eq!(
            normalize_ml_kem_spki(&sample, CLEAN, usage, &source()),
            Err(X509Error::InvalidKeyUsage)
        );
    }
}
#[test]
fn unknown_critical_and_malformed_critical_extensions_fail_closed() {
    let der = signature(0x11);
    let sample = spki(&kem_identifier(1), 800);
    for state in [
        CriticalExtensions::UnknownCritical,
        CriticalExtensions::MalformedCritical,
    ] {
        assert_eq!(
            normalize_ml_dsa_certificate_signature(&der, &der, state, &source()),
            Err(X509Error::UnsupportedCriticalExtension)
        );
        assert_eq!(
            normalize_ml_kem_spki(&sample, state, MlKemKeyUsage::Absent, &source()),
            Err(X509Error::UnsupportedCriticalExtension)
        );
    }
}
#[test]
fn missing_critical_extension_inspection_never_produces_supported_fact() {
    let der = signature(0x12);
    let spki = spki(&kem_identifier(2), 1184);
    assert_eq!(
        normalize_ml_dsa_certificate_signature(
            &der,
            &der,
            CriticalExtensions::NotInspected,
            &source()
        ),
        Err(X509Error::UncheckedCriticalExtensions)
    );
    assert_eq!(
        normalize_ml_kem_spki(
            &spki,
            CriticalExtensions::NotInspected,
            MlKemKeyUsage::Absent,
            &source()
        ),
        Err(X509Error::UncheckedCriticalExtensions)
    );
}
#[test]
fn tbs_and_outer_mldsa_signatures_must_match_without_fallback() {
    let tbs = signature(0x11);
    let outer = signature(0x12);
    assert_eq!(
        norm_signature(&tbs, &outer),
        Err(X509Error::SignatureAlgorithmMismatch)
    );
}
#[test]
fn unknown_future_or_legacy_oids_cannot_map_to_nearby_profiles() {
    let mut der = signature(0x11);
    for last in [0x10, 0x14, 0x15, 0x7f] {
        der[12] = last;
        assert_eq!(norm_signature(&der, &der), Err(X509Error::UnsupportedOid));
    }
    let mut der = kem_identifier(1);
    der[12] = 4;
    assert_eq!(norm_spki(&spki(&der, 800)), Err(X509Error::UnsupportedOid));
}
#[test]
fn mldsa_signature_identifier_is_not_a_kem_key_identifier() {
    let der = signature(0x11);
    let sample = spki(&der, 800);
    assert_eq!(norm_spki(&sample), Err(X509Error::WrongRole));
}
#[test]
fn mlkem_spki_identifier_is_not_a_certificate_signature() {
    let der = kem_identifier(3);
    assert_eq!(norm_signature(&der, &der), Err(X509Error::WrongRole));
}
#[test]
fn null_parameters_are_rejected_even_when_oid_is_standardized() {
    let mut sign = signature(0x11);
    sign[1] += 2;
    sign.extend([0x05, 0x00]);
    assert_eq!(
        norm_signature(&sign, &sign),
        Err(X509Error::ParametersNotAbsent)
    );
    let mut kem = kem_identifier(1);
    kem[1] += 2;
    kem.extend([0x05, 0x00]);
    assert_eq!(
        norm_spki(&spki(&kem, 800)),
        Err(X509Error::ParametersNotAbsent)
    );
}
#[test]
fn arbitrary_parameters_or_second_algorithm_oid_are_rejected() {
    let mut sign = signature(0x11);
    sign[1] += 3;
    sign.extend([0x02, 0x01, 0x01]);
    assert_eq!(
        norm_signature(&sign, &sign),
        Err(X509Error::ParametersNotAbsent)
    );
    let mut kem = kem_identifier(1);
    kem[1] += 13;
    kem.extend(kem_identifier(2));
    assert_eq!(
        norm_spki(&spki(&kem, 800)),
        Err(X509Error::ParametersNotAbsent)
    );
}
#[test]
fn indefinite_length_ber_is_not_accepted_as_der() {
    let sign = signature(0x11);
    let mut malformed = vec![0x30, 0x80];
    malformed.extend_from_slice(&sign[2..]);
    malformed.extend([0, 0]);
    assert_eq!(
        norm_signature(&malformed, &malformed),
        Err(X509Error::InvalidDer("indefinite_or_oversized_length"))
    );
}
#[test]
fn long_form_encoding_of_short_length_is_noncanonical() {
    let der = signature(0x11);
    let mut invalid = vec![0x30, 0x81, 0x0b];
    invalid.extend_from_slice(&der[2..]);
    assert_eq!(
        norm_signature(&invalid, &invalid),
        Err(X509Error::InvalidDer("noncanonical_length"))
    );
    let mut invalid = vec![0x30, 0x82, 0x00, 0x0b];
    invalid.extend_from_slice(&der[2..]);
    assert_eq!(
        norm_signature(&invalid, &invalid),
        Err(X509Error::InvalidDer("noncanonical_length"))
    );
}
#[test]
fn truncated_der_length_cannot_extend_outside_input() {
    for invalid in [
        vec![],
        vec![0x30],
        vec![0x30, 0x0b],
        vec![0x30, 0x81],
        vec![0x30, 0x82, 0x01],
        vec![0x30, 0x82, 0xff, 0xff],
    ] {
        assert!(norm_signature(&invalid, &invalid).is_err());
    }
}
#[test]
fn wrong_der_tags_and_duplicate_trailing_tlvs_are_invalid() {
    let der = signature(0x11);
    let mut tag = der.clone();
    tag[0] = 0x31;
    assert_eq!(
        norm_signature(&tag, &tag),
        Err(X509Error::InvalidDer("wrong_tag"))
    );
    let mut tag = der.clone();
    tag[2] = 0x05;
    assert_eq!(
        norm_signature(&tag, &tag),
        Err(X509Error::InvalidDer("wrong_tag"))
    );
    let mut tail = der.clone();
    tail.push(0);
    assert_eq!(
        norm_signature(&tail, &tail),
        Err(X509Error::InvalidDer("trailing_der"))
    );
}
#[test]
fn malformed_oid_base128_continuation_and_nonminimal_arc_fail() {
    let mut der = signature(0x11);
    der[12] |= 0x80;
    assert_eq!(
        norm_signature(&der, &der),
        Err(X509Error::InvalidDer("truncated_oid_subidentifier"))
    );
    let mut der = signature(0x11);
    der[4] = 0x80;
    assert_eq!(
        norm_signature(&der, &der),
        Err(X509Error::InvalidDer("noncanonical_oid_subidentifier"))
    );
}
#[test]
fn empty_or_oversized_oid_is_invalid() {
    let der = [0x30, 0x02, 0x06, 0x00];
    assert_eq!(
        norm_signature(&der, &der),
        Err(X509Error::InvalidDer("oid_size"))
    );
    let mut oid = vec![0x06, 33];
    oid.extend(std::iter::repeat_n(0x01, 33));
    let mut seq = vec![0x30, oid.len() as u8];
    seq.extend(oid);
    assert_eq!(
        norm_signature(&seq, &seq),
        Err(X509Error::InvalidDer("oid_size"))
    );
}
#[test]
fn spki_requires_bit_string_and_no_trailing_structure() {
    let mut sample = spki(&kem_identifier(1), 800);
    sample[17] = 0x04;
    assert_eq!(norm_spki(&sample), Err(X509Error::InvalidDer("wrong_tag")));
    let mut sample = spki(&kem_identifier(1), 800);
    sample.push(0x00);
    assert_eq!(
        norm_spki(&sample),
        Err(X509Error::InvalidDer("trailing_der"))
    );
}
#[test]
fn mlkem_spki_rejects_nonzero_unused_bits() {
    let mut sample = spki(&kem_identifier(2), 1184);
    sample[21] = 1;
    assert_eq!(
        norm_spki(&sample),
        Err(X509Error::InvalidDer("invalid_unused_bits"))
    );
}
#[test]
fn mlkem_key_payload_must_have_exact_rfc9935_octet_length() {
    for (last, valid_len) in [(1, 800usize), (2, 1184), (3, 1568)] {
        for delta in [-2isize, -1, 1, 2] {
            let size = valid_len.checked_add_signed(delta).unwrap();
            let wrong = spki(&kem_identifier(last), size);
            assert_eq!(norm_spki(&wrong), Err(X509Error::WrongPublicKeyLength));
        }
    }
}
#[test]
fn prefixed_octet_string_wrapper_is_not_an_accepted_raw_mlkem_key() {
    let mut nested = vec![0x04, 0x82, 0x03, 0x20];
    nested.extend(std::iter::repeat_n(0xa5, 800));
    let mut bit = vec![0x03];
    bit.extend(der_length(nested.len() + 1));
    bit.push(0);
    bit.extend(nested);
    let mut body = kem_identifier(1);
    body.extend(bit);
    let mut sample = vec![0x30];
    sample.extend(der_length(body.len()));
    sample.extend(body);
    assert_eq!(norm_spki(&sample), Err(X509Error::WrongPublicKeyLength));
}
#[test]
fn spki_missing_bit_string_and_extra_second_bit_string_fail() {
    let algorithm = kem_identifier(1);
    let mut der = vec![0x30, algorithm.len() as u8];
    der.extend_from_slice(&algorithm);
    assert!(norm_spki(&der).is_err());
    let mut original = spki(&algorithm, 800);
    // Add a trailing OCTET STRING inside a valid Sequence and re-encode.
    let mut body = original.split_off(4);
    body.extend([0x04, 0x00]);
    let mut rebuilt = vec![0x30];
    rebuilt.extend(der_length(body.len()));
    rebuilt.extend(body);
    assert_eq!(
        norm_spki(&rebuilt),
        Err(X509Error::InvalidDer("trailing_spki_field"))
    );
}
#[test]
fn input_limits_apply_before_der_allocation_or_alias_matching() {
    let d = signature(0x11);
    let small = X509Limits {
        max_algorithm_identifier_bytes: 12,
        ..X509Limits::default()
    };
    assert_eq!(
        normalize_ml_dsa_certificate_signature_with_limits(&d, &d, CLEAN, &source(), small),
        Err(X509Error::SizeLimit)
    );
    let too_large = vec![0u8; MAX_SPKI_DER_BYTES + 1];
    assert_eq!(norm_spki(&too_large), Err(X509Error::SizeLimit));
}
#[test]
fn caller_cannot_widen_der_limits() {
    for limits in [
        X509Limits {
            max_algorithm_identifier_bytes: 0,
            ..X509Limits::default()
        },
        X509Limits {
            max_algorithm_identifier_bytes: MAX_ALGORITHM_IDENTIFIER_DER_BYTES + 1,
            ..X509Limits::default()
        },
        X509Limits {
            max_spki_bytes: 0,
            ..X509Limits::default()
        },
        X509Limits {
            max_spki_bytes: MAX_SPKI_DER_BYTES + 1,
            ..X509Limits::default()
        },
    ] {
        assert_eq!(limits.validate(), Err(X509Error::InvalidLimit));
    }
}
#[test]
fn source_id_and_original_evidence_ref_are_mandatory_and_bounded() {
    let d = signature(0x11);
    for bad in ["", "/source", "contains space", "🚫", &"a".repeat(129)] {
        let evidence = X509EvidenceSource {
            source_id: bad.to_owned(),
            evidence_ref: EVIDENCE.to_owned(),
        };
        assert_eq!(
            normalize_ml_dsa_certificate_signature(&d, &d, CLEAN, &evidence),
            Err(X509Error::InvalidEvidenceIdentifier)
        );
    }
}
#[test]
fn malformed_source_ref_cannot_be_smuggled_through_spki() {
    let sample = spki(&kem_identifier(1), 800);
    let invalid = X509EvidenceSource {
        source_id: source().source_id,
        evidence_ref: "evidence:secret?key=123".to_owned(),
    };
    assert_eq!(
        normalize_ml_kem_spki(&sample, CLEAN, MlKemKeyUsage::Absent, &invalid),
        Err(X509Error::InvalidEvidenceIdentifier)
    );
}
#[test]
fn result_wire_version_fields_and_unknown_critical_flags_cannot_escalate() {
    let result = norm_signature(&signature(0x11), &signature(0x11)).unwrap();
    let mut record = serde_json::to_value(&result).unwrap();
    record["signature_verified"] = true.into();
    assert!(
        X509AlgorithmIdentity::parse_untrusted_json(&serde_json::to_vec(&record).unwrap()).is_err()
    );
    record["signature_verified"] = false.into();
    record["certificate_validated"] = true.into();
    assert!(
        X509AlgorithmIdentity::parse_untrusted_json(&serde_json::to_vec(&record).unwrap()).is_err()
    );
    record["certificate_validated"] = false.into();
    record["unknown_critical"] = true.into();
    assert!(
        X509AlgorithmIdentity::parse_untrusted_json(&serde_json::to_vec(&record).unwrap()).is_err()
    );
    record.as_object_mut().unwrap().remove("unknown_critical");
    record["schema_version"] = "2".into();
    assert!(
        X509AlgorithmIdentity::parse_untrusted_json(&serde_json::to_vec(&record).unwrap()).is_err()
    );
}
#[test]
fn versioned_dto_output_is_reproducible_after_round_trip() {
    let d = signature(0x12);
    let first = norm_signature(&d, &d).unwrap();
    let second = norm_signature(&d, &d).unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    let bytes = serde_json::to_vec(&first).unwrap();
    let decoded = X509AlgorithmIdentity::parse_untrusted_json(&bytes).unwrap();
    assert_eq!(decoded, first);
}
#[test]
fn untrusted_result_json_rejects_profile_catalog_and_original_evidence_spoofing() {
    let d = signature(0x11);
    let output = norm_signature(&d, &d).unwrap();
    let valid = serde_json::to_value(&output).unwrap();
    for (field, forged) in [
        ("profile_id", serde_json::json!("ML-DSA-87")),
        ("oid", serde_json::json!("2.16.840.1.101.3.4.4.1")),
        ("standards_profile", serde_json::json!("RFC 9935")),
        ("catalog_version", serde_json::json!("1.0.1")),
        ("catalog_sha256", serde_json::json!("f".repeat(64))),
        ("source_id", serde_json::json!("contains spaces")),
        ("evidence_ref", serde_json::json!("")),
        ("public_key_octets", serde_json::json!(800)),
        ("input_der_sha256", serde_json::json!("not-a-digest")),
    ] {
        let mut changed = valid.clone();
        changed[field] = forged;
        assert!(
            X509AlgorithmIdentity::parse_untrusted_json(&serde_json::to_vec(&changed).unwrap())
                .is_err(),
            "forged field {field} was not rejected"
        );
    }
}

#[test]
fn oversized_json_result_is_bounded() {
    let over = vec![b' '; MAX_REPORT_JSON_BYTES + 1];
    assert_eq!(
        X509AlgorithmIdentity::parse_untrusted_json(&over),
        Err(X509Error::SizeLimit)
    );
}
#[test]
fn corrupted_signature_der_never_maps_back_into_original_valid_profile() {
    let original = signature(0x11);
    for index in 0..original.len() {
        let mut mutated = original.clone();
        mutated[index] ^= 0x01;
        assert!(
            norm_signature(&mutated, &original).is_err(),
            "changed DER byte at index {index} must not be silently ignored"
        );
    }
}
#[test]
fn manipulated_spki_length_bytes_fail_without_panicking() {
    let original = spki(&kem_identifier(1), 800);
    for index in [0usize, 1, 2, 3, 17, 18, 19, 20, 21] {
        for mask in [0x01u8, 0x40, 0x80] {
            let mut mutated = original.clone();
            mutated[index] ^= mask;
            assert!(
                norm_spki(&mutated).is_err(),
                "index {index} xor mask {mask:#x} must not normalize"
            );
        }
    }
}
#[test]
fn random_well_bounded_malformed_inputs_never_panic_or_fabricate_ids() {
    // Deterministic fuzz-like corpus. Successful output, if any, is allowed
    // only with exact RFC profile identities; errors must not contain bytes.
    let mut state = 0x45d9f3bu32;
    for len in 0..300usize {
        let mut payload = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            payload.push((state >> 16) as u8);
        }
        let result = norm_signature(&payload, &payload);
        if let Ok(fact) = result {
            assert!(matches!(
                fact.profile_id.as_str(),
                "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87"
            ));
        }
        let result = norm_spki(&payload);
        if let Ok(fact) = result {
            assert!(matches!(
                fact.profile_id.as_str(),
                "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024"
            ));
        }
    }
}
#[test]
fn treating_whole_certificate_bytes_as_a_semantic_identifier_is_rejected() {
    let mut alleged_certificate = signature(0x11);
    alleged_certificate.extend(signature(0x11));
    assert!(norm_signature(&alleged_certificate, &alleged_certificate).is_err());
}
