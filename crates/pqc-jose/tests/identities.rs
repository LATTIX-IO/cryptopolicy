//! FOSS-455 RFC 9964 public AKP key/header exactness and adversarial regressions.
#![allow(clippy::unwrap_used)]

use cryptopolicy::{DecisionOutcome, EvaluationTime, PolicyDocument, RequestId, evaluate};
use pqc_jose::*;
use serde_json::{Value, json};

fn evidence() -> JoseEvidenceSource {
    JoseEvidenceSource {
        source_id: "collector:jose".to_owned(),
        evidence_ref: "evidence:jose:1".to_owned(),
    }
}
fn header(alg: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"alg": alg, "typ": "JWT"})).unwrap()
}
fn jwk(alg: &str, public_octets: usize) -> Vec<u8> {
    let encoded_len = (public_octets / 3) * 4
        + match public_octets % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        };
    serde_json::to_vec(&json!({
        "kty": "AKP", "alg": alg, "pub": "A".repeat(encoded_len),
        "use": "sig", "key_ops": ["verify"], "kid": "test:key:1"
    }))
    .unwrap()
}
fn good() -> (Vec<u8>, Vec<u8>) {
    (jwk("ML-DSA-44", 1_312), header("ML-DSA-44"))
}

#[test]
fn all_rfc9964_profiles_have_exact_public_lengths_and_catalog_mapping() {
    let table: Vec<Value> =
        serde_json::from_slice(include_bytes!("fixtures/rfc9964-profiles-v1.json")).unwrap();
    assert_eq!(table.len(), 3);
    for row in table {
        let alg = row["alg"].as_str().unwrap();
        let bytes = row["public_key_octets"].as_u64().unwrap() as usize;
        let (key, hdr) = (jwk(alg, bytes), header(alg));
        let result = normalize_ml_dsa_jwk(&key, &hdr, &evidence()).unwrap();
        assert_eq!(result.alg, alg);
        assert_eq!(result.profile_id, alg);
        assert_eq!(result.public_key_octets, bytes);
        assert_eq!(result.kty, "AKP");
        assert_eq!(result.standards_profile, "RFC 9964");
        assert_eq!(result.catalog_version, "1.0.0");
        assert!(!result.signature_verified && !result.key_validated);
        assert_eq!(result.input_json_sha256.len(), 64);
        let serialized = serde_json::to_vec(&result).unwrap();
        let decoded = JoseAlgorithmIdentity::parse_untrusted_json(&serialized).unwrap();
        assert_eq!(decoded, result);
    }
}

#[test]
fn algorithm_confusion_and_unknown_profiles_reject_without_fallback() {
    let (key, _) = good();
    assert_eq!(
        normalize_ml_dsa_jwk(&key, &header("ML-DSA-65"), &evidence()),
        Err(JoseError::AlgorithmMismatch)
    );
    for bad in [
        "none",
        "RS256",
        "ML-DSA-44-legacy",
        "ML-DSA-unknown",
        "ml-dsa-44",
    ] {
        assert_eq!(
            normalize_ml_dsa_jwk(&jwk(bad, 1_312), &header(bad), &evidence()),
            Err(JoseError::UnsupportedAlgorithm)
        );
    }
    let bad_kty = json!({"kty":"RSA","alg":"ML-DSA-44","pub":"A".repeat(1750)});
    assert_eq!(
        normalize_ml_dsa_jwk(
            &serde_json::to_vec(&bad_kty).unwrap(),
            &header("ML-DSA-44"),
            &evidence()
        ),
        Err(JoseError::UnsupportedKeyType)
    );
}

#[test]
fn header_extensions_and_critical_states_fail_closed() {
    let (key, _) = good();
    for hdr in [
        json!({"alg":"ML-DSA-44","crit":["new"]}),
        json!({"alg":"ML-DSA-44","crit":[]}),
        json!({"alg":"ML-DSA-44","b64":false}),
        json!({"alg":"ML-DSA-44","b64":true}),
        json!({"alg":"ML-DSA-44","jku":"https://invalid.example/test"}),
    ] {
        let data = serde_json::to_vec(&hdr).unwrap();
        assert!(normalize_ml_dsa_jwk(&key, &data, &evidence()).is_err());
    }
}

#[test]
fn public_only_normalizer_rejects_private_seed_or_invalid_use() {
    let (key, hdr) = good();
    let mut value: Value = serde_json::from_slice(&key).unwrap();
    value["priv"] = json!("A".repeat(43));
    assert_eq!(
        normalize_ml_dsa_jwk(&serde_json::to_vec(&value).unwrap(), &hdr, &evidence()),
        Err(JoseError::PrivateMaterialNotAccepted)
    );
    for (field, replacement) in [
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("key_ops", json!(["verify", "sign"])),
    ] {
        let mut value: Value = serde_json::from_slice(&key).unwrap();
        value[field] = replacement;
        assert_eq!(
            normalize_ml_dsa_jwk(&serde_json::to_vec(&value).unwrap(), &hdr, &evidence()),
            Err(JoseError::InvalidKeyUse)
        );
    }
}

#[test]
fn malformed_padding_trailing_bits_and_wrong_key_lengths_reject() {
    let (key, hdr) = good();
    for replacement in [
        "A".repeat(1749),
        "A".repeat(1751),
        format!("{}=", "A".repeat(1749)),
        format!("{}B", "A".repeat(1749)),
        format!("{}+", "A".repeat(1749)),
    ] {
        let mut value: Value = serde_json::from_slice(&key).unwrap();
        value["pub"] = json!(replacement);
        assert!(
            normalize_ml_dsa_jwk(&serde_json::to_vec(&value).unwrap(), &hdr, &evidence()).is_err()
        );
    }
}

#[test]
fn duplicate_members_unknown_fields_and_trailing_json_reject() {
    let (key, hdr) = good();
    let with_duplicate = format!(
        "{{\"kty\":\"AKP\",\"alg\":\"ML-DSA-44\",\"alg\":\"ML-DSA-65\",\"pub\":\"{}\"}}",
        "A".repeat(1750),
    );
    assert_eq!(
        normalize_ml_dsa_jwk(with_duplicate.as_bytes(), &hdr, &evidence()),
        Err(JoseError::InvalidJson)
    );
    let extra = [key, b"{\"a\":1}".to_vec()].concat();
    assert!(normalize_ml_dsa_jwk(&extra, &hdr, &evidence()).is_err());
    let bad_header = b"{\"alg\":\"ML-DSA-44\",\"alg\":\"ML-DSA-65\"}";
    assert_eq!(
        normalize_ml_dsa_jwk(jwk("ML-DSA-44", 1_312).as_slice(), bad_header, &evidence()),
        Err(JoseError::InvalidJson)
    );
}

#[test]
fn size_limits_and_invalid_provenance_reject() {
    let (key, hdr) = good();
    assert_eq!(
        normalize_ml_dsa_jwk_with_limits(
            &key,
            &hdr,
            &evidence(),
            JoseLimits {
                jwk_bytes: key.len() - 1,
                protected_header_bytes: MAX_PROTECTED_JSON_BYTES
            }
        ),
        Err(JoseError::SizeLimit)
    );
    assert_eq!(
        normalize_ml_dsa_jwk_with_limits(
            &key,
            &hdr,
            &evidence(),
            JoseLimits {
                jwk_bytes: MAX_JWK_JSON_BYTES + 1,
                protected_header_bytes: MAX_PROTECTED_JSON_BYTES
            }
        ),
        Err(JoseError::SizeLimit)
    );
    let mut ev = evidence();
    ev.evidence_ref = ".. bad path".to_owned();
    assert_eq!(
        normalize_ml_dsa_jwk(&key, &hdr, &ev),
        Err(JoseError::InvalidIdentifier)
    );
}

#[test]
fn mismatch_kid_and_unknown_header_types_are_not_accepted() {
    let (key, _) = good();
    let h = br#"{"alg":"ML-DSA-44","kid":"wrong"}"#;
    assert_eq!(
        normalize_ml_dsa_jwk(&key, h, &evidence()),
        Err(JoseError::InvalidIdentifier)
    );
    let h = br#"{"alg":"ML-DSA-44","kid":"test:key:1","typ":"JWT"}"#;
    assert!(normalize_ml_dsa_jwk(&key, h, &evidence()).is_ok());
}

#[test]
fn report_spoofing_never_upgrades_verification() {
    let (key, hdr) = good();
    let output = normalize_ml_dsa_jwk(&key, &hdr, &evidence()).unwrap();
    for (field, change) in [
        ("signature_verified", json!(true)),
        ("key_validated", json!(true)),
        ("kty", json!("RSA")),
        ("profile_id", json!("ML-DSA-65")),
        ("catalog_sha256", json!("0".repeat(64))),
        ("input_json_sha256", json!("not-a-sha")),
    ] {
        let mut data = serde_json::to_value(&output).unwrap();
        data[field] = change;
        assert!(
            JoseAlgorithmIdentity::parse_untrusted_json(&serde_json::to_vec(&data).unwrap())
                .is_err()
        );
    }
}

#[test]
fn projection_cannot_launder_unverified_metadata_into_policy_permit() {
    let (key, hdr) = good();
    let normal = normalize_ml_dsa_jwk(&key, &hdr, &evidence()).unwrap();
    let time = EvaluationTime { unix_millis: 150 };
    let projected = normal
        .to_untrusted_context(RequestId::parse("request:jose:1").unwrap(), time)
        .unwrap();
    assert!(!projected.facts[0].verified);
    assert_eq!(
        projected.facts[0].origin,
        cryptopolicy::FactOrigin::Inferred
    );
    assert_eq!(projected.operation, cryptopolicy::CryptoOperation::Verify);
    let policy = PolicyDocument::parse_json(include_bytes!(
        "../../cryptopolicy/tests/fixtures/evaluator-policy-v1.json"
    ))
    .unwrap();
    let decision = evaluate(&policy, &projected, time).unwrap();
    assert_ne!(decision.outcome, DecisionOutcome::Permit);
}

#[test]
fn repeated_input_normalization_is_deterministic() {
    let (key, hdr) = good();
    let reference = normalize_ml_dsa_jwk(&key, &hdr, &evidence()).unwrap();
    for _ in 0..32 {
        assert_eq!(
            normalize_ml_dsa_jwk(&key, &hdr, &evidence()).unwrap(),
            reference
        );
    }
}
