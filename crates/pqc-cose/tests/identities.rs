//! FOSS-457: exact RFC 9964 COSE algorithm identifiers and hostile CBOR inputs.
#![allow(clippy::unwrap_used)]

use cryptopolicy::{DecisionOutcome, EvaluationTime, PolicyDocument, RequestId, evaluate};
use pqc_cose::{
    CoseAlgorithmIdentity, CoseError, CoseEvidenceSource, CoseLimits, MAX_COSE_KEY_BYTES,
    MAX_PROTECTED_CBOR_BYTES, normalize_ml_dsa_cose_key, normalize_ml_dsa_cose_key_with_limits,
};
use serde_json::{Value, json};

fn int(n: i64) -> Vec<u8> {
    if n >= 0 {
        assert!(n <= 23);
        vec![n as u8]
    } else {
        let argument = (-1 - n) as u8;
        if argument <= 23 {
            vec![0x20 + argument]
        } else {
            vec![0x38, argument]
        }
    }
}

fn count(major: u8, n: usize) -> Vec<u8> {
    if n <= 23 {
        vec![(major << 5) | n as u8]
    } else if n <= usize::from(u8::MAX) {
        vec![(major << 5) | 24, n as u8]
    } else if n <= usize::from(u16::MAX) {
        let raw = (n as u16).to_be_bytes();
        vec![(major << 5) | 25, raw[0], raw[1]]
    } else {
        panic!("synthetic test input out of bounds");
    }
}

fn bstr(bytes: &[u8]) -> Vec<u8> {
    let mut v = count(2, bytes.len());
    v.extend_from_slice(bytes);
    v
}

fn array(elements: Vec<Vec<u8>>) -> Vec<u8> {
    let mut result = count(4, elements.len());
    for item in elements {
        result.extend(item);
    }
    result
}

fn map(mut items: Vec<(i64, Vec<u8>)>) -> Vec<u8> {
    items.sort_by(|a, b| int(a.0).cmp(&int(b.0)));
    let mut out = count(5, items.len());
    for (label, content) in items {
        out.extend(int(label));
        out.extend(content);
    }
    out
}

fn key(algorithm: i64, public_octets: usize) -> Vec<u8> {
    map(vec![
        (1, int(7)),
        (3, int(algorithm)),
        (-1, bstr(&vec![0_u8; public_octets])),
    ])
}

fn header(algorithm: i64) -> Vec<u8> {
    map(vec![(1, int(algorithm))])
}

fn evidence() -> CoseEvidenceSource {
    CoseEvidenceSource {
        source_id: "source:cose:1".to_owned(),
        evidence_ref: "evidence:cose:1".to_owned(),
    }
}

#[test]
fn normative_rfc9964_mapping_with_pinned_golden_fingerprints() {
    let fixture: Vec<Value> = serde_json::from_slice(include_bytes!(
        "fixtures/rfc9964-cose-profiles-v1.json"
    )).unwrap();
    assert_eq!(fixture.len(), 3);
    for entry in fixture {
        let alg = entry["alg"].as_i64().unwrap();
        let name = entry["profile"].as_str().unwrap();
        let bytes = usize::try_from(entry["public_key_octets"].as_u64().unwrap()).unwrap();
        let output = normalize_ml_dsa_cose_key(&key(alg, bytes), &header(alg), &evidence()).unwrap();
        assert_eq!(output.alg, alg);
        assert_eq!(output.profile_id, name);
        assert_eq!(output.kty, 7);
        assert_eq!(output.standards_profile, "RFC 9964");
        assert_eq!(output.public_key_octets, bytes);
        assert_eq!(output.input_cbor_sha256, entry["synthetic_sha256"].as_str().unwrap());
        assert_eq!(output.catalog_version, "1.0.0");
        assert!(!output.signature_verified && !output.key_validated);
        let wire = serde_json::to_vec(&output).unwrap();
        assert_eq!(CoseAlgorithmIdentity::parse_untrusted_json(&wire).unwrap(), output);
    }
}

#[test]
fn algorithm_and_key_type_confusion_fails_closed() {
    let (k, h) = (key(-48, 1312), header(-48));
    assert_eq!(
        normalize_ml_dsa_cose_key(&k, &header(-49), &evidence()),
        Err(CoseError::AlgorithmMismatch)
    );
    for bad in [-47, -51, -7, 0, 1] {
        assert_eq!(
            normalize_ml_dsa_cose_key(&key(bad, 1312), &header(bad), &evidence()),
            Err(CoseError::UnsupportedAlgorithm)
        );
    }
    let bad_key = map(vec![(1, int(1)), (3, int(-48)), (-1, bstr(&vec![0; 1312]))]);
    assert_eq!(
        normalize_ml_dsa_cose_key(&bad_key, &h, &evidence()),
        Err(CoseError::UnsupportedKeyType)
    );
}

#[test]
fn private_seed_and_key_usage_confusion_rejected() {
    let h = header(-48);
    let with_seed = map(vec![
        (1, int(7)), (3, int(-48)),
        (-1, bstr(&vec![0; 1312])),
        (-2, bstr(&vec![0; 32])),
    ]);
    assert_eq!(
        normalize_ml_dsa_cose_key(&with_seed, &h, &evidence()),
        Err(CoseError::PrivateMaterialNotAccepted)
    );
    for ops in [vec![int(1)], vec![int(3)], vec![int(2), int(1)], vec![]] {
        let k = map(vec![
            (1, int(7)), (3, int(-48)), (4, array(ops)),
            (-1, bstr(&vec![0; 1312])),
        ]);
        assert_eq!(
            normalize_ml_dsa_cose_key(&k, &h, &evidence()),
            Err(CoseError::InvalidKeyUse)
        );
    }
    let verified = map(vec![
        (1, int(7)), (3, int(-48)), (4, array(vec![int(2)])),
        (-1, bstr(&vec![0; 1312])),
    ]);
    assert!(normalize_ml_dsa_cose_key(&verified, &h, &evidence()).is_ok());
}

#[test]
fn critical_unknown_and_unprotected_algorithm_headers_fail_closed() {
    let k = key(-48, 1312);
    for protected in [
        map(vec![(1, int(-48)), (2, array(vec![]))]),
        map(vec![(1, int(-48)), (2, array(vec![int(2)]))]),
        map(vec![(1, int(-48)), (3, int(7))]),
        map(vec![(4, bstr(b"untrusted-key-id"))]),
        map(vec![]),
    ] {
        assert!(normalize_ml_dsa_cose_key(&k, &protected, &evidence()).is_err());
    }
    assert_eq!(
        normalize_ml_dsa_cose_key(
            &k, &map(vec![(1, int(-48)), (2, array(vec![]))]), &evidence()
        ),
        Err(CoseError::UnsupportedCriticalHeader)
    );
}

#[test]
fn duplicate_key_and_header_labels_fail() {
    let public = bstr(&vec![0_u8; 1312]);
    let mut duplicated = vec![0xa4, 0x01, 0x07, 0x01, 0x07, 0x03, 0x38, 0x2f, 0x20];
    duplicated.extend(public);
    assert_eq!(
        normalize_ml_dsa_cose_key(&duplicated, &header(-48), &evidence()),
        Err(CoseError::DuplicateLabel)
    );
    let protected = vec![0xa2, 0x01, 0x38, 0x2f, 0x01, 0x38, 0x2f];
    assert_eq!(
        normalize_ml_dsa_cose_key(&key(-48, 1312), &protected, &evidence()),
        Err(CoseError::DuplicateLabel)
    );
}

#[test]
fn noncanonical_map_order_and_nonminimal_cbor_lengths_rejected() {
    let public = bstr(&vec![0_u8; 1312]);
    let mut unsorted = vec![0xa3, 0x03, 0x38, 0x2f, 0x01, 0x07, 0x20];
    unsorted.extend(public.clone());
    assert_eq!(
        normalize_ml_dsa_cose_key(&unsorted, &header(-48), &evidence()),
        Err(CoseError::NonCanonicalCbor)
    );
    let mut long_int = vec![0xa3, 0x01, 0x18, 0x07, 0x03, 0x38, 0x2f, 0x20];
    long_int.extend(public.clone());
    assert_eq!(
        normalize_ml_dsa_cose_key(&long_int, &header(-48), &evidence()),
        Err(CoseError::NonCanonicalCbor)
    );
    // A 1312-byte string requires 0x59 (u16), not 0x5a (u32).
    let mut long_bytes = vec![0xa3, 0x01, 0x07, 0x03, 0x38, 0x2f, 0x20, 0x5a, 0, 0, 0x05, 0x20];
    long_bytes.extend(vec![0_u8; 1312]);
    assert_eq!(
        normalize_ml_dsa_cose_key(&long_bytes, &header(-48), &evidence()),
        Err(CoseError::NonCanonicalCbor)
    );
    let mut trailing = key(-48, 1312);
    trailing.push(0);
    assert_eq!(
        normalize_ml_dsa_cose_key(&trailing, &header(-48), &evidence()),
        Err(CoseError::InvalidCbor)
    );
}

#[test]
fn wrong_lengths_and_malformed_cbor_rejected() {
    for n in [0, 1311, 1313, 1952, 2592] {
        assert_eq!(
            normalize_ml_dsa_cose_key(&key(-48, n), &header(-48), &evidence()),
            Err(CoseError::WrongPublicKeyLength)
        );
    }
    let mut truncated = key(-48, 1312);
    truncated.pop();
    assert_eq!(
        normalize_ml_dsa_cose_key(&truncated, &header(-48), &evidence()),
        Err(CoseError::InvalidCbor)
    );
    for malformed in [vec![0xbf, 0xff], vec![0xc0, 0xa0], vec![0xf6], vec![0x9f, 0xff]] {
        assert!(normalize_ml_dsa_cose_key(&malformed, &header(-48), &evidence()).is_err());
    }
    let k = map(vec![(1, int(7)), (3, int(-48)), (-1, int(7))]);
    assert_eq!(
        normalize_ml_dsa_cose_key(&k, &header(-48), &evidence()),
        Err(CoseError::UnsupportedKeyParameter)
    );
}

#[test]
fn optional_kid_is_bounded_and_must_match() {
    let key_with_kid = map(vec![
        (1, int(7)), (2, bstr(b"matching-key")), (3, int(-48)),
        (-1, bstr(&vec![0; 1312])),
    ]);
    let ok_header = map(vec![(1, int(-48)), (4, bstr(b"matching-key"))]);
    assert!(normalize_ml_dsa_cose_key(&key_with_kid, &ok_header, &evidence()).is_ok());
    let changed = map(vec![(1, int(-48)), (4, bstr(b"different-key"))]);
    assert_eq!(
        normalize_ml_dsa_cose_key(&key_with_kid, &changed, &evidence()),
        Err(CoseError::InvalidIdentifier)
    );
    let missing = key(-48, 1312);
    assert_eq!(
        normalize_ml_dsa_cose_key(&missing, &ok_header, &evidence()),
        Err(CoseError::InvalidIdentifier)
    );
}

#[test]
fn bounded_inputs_and_invalid_source_identifiers_fail() {
    let k = key(-48, 1312);
    let h = header(-48);
    assert_eq!(
        normalize_ml_dsa_cose_key_with_limits(
            &k, &h, &evidence(), CoseLimits {
                cose_key_bytes: k.len() - 1,
                protected_header_bytes: MAX_PROTECTED_CBOR_BYTES,
            }
        ), Err(CoseError::SizeLimit)
    );
    assert_eq!(
        normalize_ml_dsa_cose_key_with_limits(
            &k, &h, &evidence(), CoseLimits {
                cose_key_bytes: MAX_COSE_KEY_BYTES + 1,
                protected_header_bytes: MAX_PROTECTED_CBOR_BYTES,
            }
        ), Err(CoseError::SizeLimit)
    );
    let mut source = evidence();
    source.evidence_ref = "../../unsafe".to_owned();
    assert_eq!(
        normalize_ml_dsa_cose_key(&k, &h, &source),
        Err(CoseError::InvalidIdentifier)
    );
    source.source_id = "bad\nsource".to_owned();
    assert_eq!(
        normalize_ml_dsa_cose_key(&k, &h, &source),
        Err(CoseError::InvalidIdentifier)
    );
}

#[test]
fn externally_forged_reports_cannot_claim_verified_facts() {
    let output = normalize_ml_dsa_cose_key(&key(-48, 1312), &header(-48), &evidence()).unwrap();
    for (field, replacement) in [
        ("signature_verified", json!(true)),
        ("key_validated", json!(true)),
        ("kty", json!(2)),
        ("profile_id", json!("ML-DSA-65")),
        ("public_key_octets", json!(1952)),
        ("catalog_sha256", json!("0".repeat(64))),
        ("input_cbor_sha256", json!("not-a-digest")),
    ] {
        let mut candidate = serde_json::to_value(&output).unwrap();
        candidate[field] = replacement;
        assert!(
            CoseAlgorithmIdentity::parse_untrusted_json(&serde_json::to_vec(&candidate).unwrap())
                .is_err()
        );
    }
    let valid = serde_json::to_vec(&output).unwrap();
    let mut repeated = valid.clone();
    repeated.push(b' ');
    assert!(CoseAlgorithmIdentity::parse_untrusted_json(&repeated).is_ok());
    repeated.extend(valid);
    assert!(CoseAlgorithmIdentity::parse_untrusted_json(&repeated).is_err());
}

#[test]
fn projection_never_launders_cbor_metadata_to_permit() {
    let result = normalize_ml_dsa_cose_key(&key(-48, 1312), &header(-48), &evidence()).unwrap();
    let time = EvaluationTime { unix_millis: 150 };
    let projected =
        result.to_untrusted_context(RequestId::parse("request:cose:1").unwrap(), time).unwrap();
    assert!(!projected.facts[0].verified);
    assert_eq!(projected.facts[0].origin, cryptopolicy::FactOrigin::Inferred);
    assert_eq!(projected.operation, cryptopolicy::CryptoOperation::Verify);
    let policy = PolicyDocument::parse_json(include_bytes!(
        "../../cryptopolicy/tests/fixtures/evaluator-policy-v1.json"
    )).unwrap();
    let decision = evaluate(&policy, &projected, time).unwrap();
    assert_ne!(decision.outcome, DecisionOutcome::Permit);
}

#[test]
fn corruption_mutations_never_crash_or_produce_verified_metadata() {
    let original = key(-48, 1312);
    for index in 0..original.len() {
        if index % 17 != 0 {
            continue;
        }
        let mut mutated = original.clone();
        mutated[index] ^= 0x40;
        if let Ok(result) = normalize_ml_dsa_cose_key(&mutated, &header(-48), &evidence()) {
            assert_eq!(result.profile_id, "ML-DSA-44");
            assert!(!result.signature_verified && !result.key_validated);
        }
    }
}
