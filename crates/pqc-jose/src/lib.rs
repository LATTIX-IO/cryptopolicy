//! RFC 9964 ML-DSA JOSE/JWK public-key and protected-header normalization.
//!
//! Exact metadata recognition is NOT signature verification, public-key
//! validation, authentication, authorization or cryptographic execution.
//! Unknown JOSE extensions and private JWK material are rejected conservatively.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use cryptopolicy::{
    AlgorithmId, CryptoContext, CryptoFact, CryptoOperation, CryptoProperties, EvaluationTime,
    EvidenceId, EvidenceQuality, FactOrigin, RequestId, SchemaVersion,
};
use pqc_kit::{Catalog, OperationClass, UsageParameter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Absolute size budget for a JWK JSON document.
pub const MAX_JWK_JSON_BYTES: usize = 16_384;
/// Absolute size budget for a decoded JWS protected-header JSON document.
pub const MAX_PROTECTED_JSON_BYTES: usize = 2_048;
/// Absolute size budget for a normalized identity JSON report.
pub const MAX_REPORT_JSON_BYTES: usize = 8_192;

/// Caller's bounded parsing limits; overrides can only be more restrictive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoseLimits {
    /// Maximum source JWK JSON bytes.
    pub jwk_bytes: usize,
    /// Maximum decoded, separately supplied protected-header JSON bytes.
    pub protected_header_bytes: usize,
}

impl Default for JoseLimits {
    fn default() -> Self {
        Self {
            jwk_bytes: MAX_JWK_JSON_BYTES,
            protected_header_bytes: MAX_PROTECTED_JSON_BYTES,
        }
    }
}

impl JoseLimits {
    /// Reject zero or increased caller budgets.
    pub fn validate(self) -> Result<(), JoseError> {
        if self.jwk_bytes == 0
            || self.jwk_bytes > MAX_JWK_JSON_BYTES
            || self.protected_header_bytes == 0
            || self.protected_header_bytes > MAX_PROTECTED_JSON_BYTES
        {
            return Err(JoseError::SizeLimit);
        }
        Ok(())
    }
}

/// Redaction-safe, typed parse failures. No input material is formatted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoseError {
    /// Input, report or caller-supplied budget is too large.
    SizeLimit,
    /// JSON syntax, duplicate key, unknown field or field type is invalid.
    InvalidJson,
    /// Algorithm identifier is not one of the three published RFC 9964 names.
    UnsupportedAlgorithm,
    /// Public-key type must be AKP.
    UnsupportedKeyType,
    /// Protected header and JWK algorithm identities disagree.
    AlgorithmMismatch,
    /// A JWK private seed, expanded key or other private material was supplied.
    PrivateMaterialNotAccepted,
    /// Invalid JOSE public-key purpose or use restrictions.
    InvalidKeyUse,
    /// Protected header contains unhandled extensions or critical parameters.
    UnsupportedHeader,
    /// Noncanonical base64url, padding, forbidden characters or trailing bits.
    InvalidPublicKeyEncoding,
    /// Decoded public-key size differs from the exact FIPS 204 length.
    WrongPublicKeyLength,
    /// Source/evidence reference or JOSE key ID is malformed or unbounded.
    InvalidIdentifier,
    /// Pinned algorithm catalog does not recognize the exact use.
    CatalogMismatch,
    /// Report claims unsupported verification state or contradictory fields.
    InconsistentReport,
}

impl fmt::Display for JoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for JoseError {}

/// Unauthenticated source and original evidence handles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoseEvidenceSource {
    /// Opaque ID for the independent JOSE parser or collector.
    pub source_id: String,
    /// Opaque externally retained evidence reference.
    pub evidence_ref: String,
}

impl JoseEvidenceSource {
    /// Check narrow ASCII identity grammar. Does not authenticate the source.
    pub fn validate(&self) -> Result<(), JoseError> {
        for value in [&self.source_id, &self.evidence_ref] {
            check_identifier(value)?;
        }
        Ok(())
    }
}

fn check_identifier(value: &str) -> Result<(), JoseError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(b))
    {
        return Err(JoseError::InvalidIdentifier);
    }
    Ok(())
}

/// Strict version of the normalized JOSE metadata record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum JoseSchemaVersion {
    /// Initial JSON representation.
    #[serde(rename = "1")]
    V1,
}

/// Bounded normalization metadata; NOT an authenticated policy fact or Permit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoseAlgorithmIdentity {
    /// Wire DTO version.
    pub schema_version: JoseSchemaVersion,
    /// Claimed parser/collector identity.
    pub source_id: String,
    /// Original evidence reference.
    pub evidence_ref: String,
    /// JOSE alg of the JWK and protected header.
    pub alg: String,
    /// Canonical key type, always AKP.
    pub kty: String,
    /// Exact approved catalog profile identifier.
    pub profile_id: String,
    /// RFC 9964 public-key octet count.
    pub public_key_octets: usize,
    /// Algorithm source document.
    pub standards_profile: String,
    /// Version of immutable pqc-kit catalog.
    pub catalog_version: String,
    /// SHA-256 digest of immutable pqc-kit catalog.
    pub catalog_sha256: String,
    /// Domain-separated SHA-256 of original JWK and protected JSON input.
    pub input_json_sha256: String,
    /// The parser never verifies cryptographic signature bytes.
    pub signature_verified: bool,
    /// The parser never validates the mathematical public key.
    pub key_validated: bool,
}

impl JoseAlgorithmIdentity {
    /// Parse an untrusted report without allowing flags or profile aliases
    /// to manufacture verified evidence. The caller must authenticate reports.
    pub fn parse_untrusted_json(input: &[u8]) -> Result<Self, JoseError> {
        if input.len() > MAX_REPORT_JSON_BYTES {
            return Err(JoseError::SizeLimit);
        }
        let parsed: Self = serde_json::from_slice(input).map_err(|_| JoseError::InvalidJson)?;
        JoseEvidenceSource {
            source_id: parsed.source_id.clone(),
            evidence_ref: parsed.evidence_ref.clone(),
        }
        .validate()?;
        if parsed.signature_verified || parsed.key_validated || parsed.kty != "AKP" {
            return Err(JoseError::InconsistentReport);
        }
        let expected = profile_public_size(&parsed.alg)?;
        if parsed.profile_id != parsed.alg
            || parsed.public_key_octets != expected
            || parsed.standards_profile != "RFC 9964"
        {
            return Err(JoseError::InconsistentReport);
        }
        let (version, fingerprint) = catalog_version_and_fingerprint(&parsed.alg)?;
        if parsed.catalog_version != version || parsed.catalog_sha256 != fingerprint {
            return Err(JoseError::CatalogMismatch);
        }
        if !is_lower_hex_digest(&parsed.input_json_sha256) {
            return Err(JoseError::InconsistentReport);
        }
        Ok(parsed)
    }

    /// Project ONLY untrusted, inferred metadata into CryptoContext. This can
    /// NEVER assert observed/verified evidence, even with a forged source JSON.
    ///
    /// The v1 evaluator will not promote an inferred ML-DSA identity to Permit.
    pub fn to_untrusted_context(
        &self,
        request_id: RequestId,
        evaluation_time: EvaluationTime,
    ) -> Result<CryptoContext, JoseError> {
        let encoded = serde_json::to_vec(self).map_err(|_| JoseError::InvalidJson)?;
        Self::parse_untrusted_json(&encoded)?;
        let fact_id =
            EvidenceId::parse(&self.evidence_ref).map_err(|_| JoseError::InvalidIdentifier)?;
        let algorithm_id =
            AlgorithmId::parse(&self.alg).map_err(|_| JoseError::UnsupportedAlgorithm)?;
        Ok(CryptoContext {
            schema_version: SchemaVersion::V1,
            request_id,
            operation: CryptoOperation::Verify,
            evaluation_time,
            environment: None,
            facts: vec![CryptoFact {
                fact_id: fact_id.clone(),
                origin: FactOrigin::Inferred,
                algorithm_id: Some(algorithm_id),
                profile_id: None,
                evidence_ref: Some(fact_id),
                verified: false,
                properties: Some(CryptoProperties {
                    source_quality: Some(EvidenceQuality::Unverified),
                    ..CryptoProperties::default()
                }),
            }],
        })
    }
}

fn is_lower_hex_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn catalog_version_and_fingerprint(profile: &str) -> Result<(String, String), JoseError> {
    let catalog = Catalog::embedded_v1().map_err(|_| JoseError::CatalogMismatch)?;
    catalog
        .validate_usage(
            profile,
            OperationClass::Verify,
            UsageParameter::NamedSet(profile),
        )
        .map_err(|_| JoseError::CatalogMismatch)?;
    Ok((
        catalog.snapshot().catalog_version.clone(),
        catalog.fingerprint().to_owned(),
    ))
}

fn profile_public_size(profile: &str) -> Result<usize, JoseError> {
    match profile {
        "ML-DSA-44" => Ok(1_312),
        "ML-DSA-65" => Ok(1_952),
        "ML-DSA-87" => Ok(2_592),
        _ => Err(JoseError::UnsupportedAlgorithm),
    }
}

/// Strictly supported AKP public-key JWK subset. Deliberately excludes custom
/// extensions and refuses private key input regardless of content.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicJwk {
    kty: String,
    alg: String,
    #[serde(rename = "pub")]
    public_key: String,
    #[serde(default)]
    r#priv: Option<String>,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, rename = "use")]
    purpose: Option<String>,
    #[serde(default)]
    key_ops: Option<Vec<String>>,
}

/// Only the supported, separately decoded JWS protected-header fields.
/// Unrecognized critical/remote-key/embedded-key headers are rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    cty: Option<String>,
    #[serde(default)]
    crit: Option<Vec<String>>,
    #[serde(default)]
    b64: Option<bool>,
}

fn base64url_value(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Validate exact unpadded base64url encoding without retaining raw key bytes.
/// This enforces byte length and encoding, NOT ML-DSA mathematical key validity.
fn validate_public_key_base64url(value: &str, expected: usize) -> Result<(), JoseError> {
    let needed_chars = 4 * (expected / 3)
        + match expected % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        };
    if value.len() != needed_chars {
        return Err(JoseError::WrongPublicKeyLength);
    }
    let mut bits = 0_u32;
    let mut accumulator = 0_u32;
    let mut decoded_bytes = 0_usize;
    for byte in value.bytes() {
        let next = base64url_value(byte).ok_or(JoseError::InvalidPublicKeyEncoding)?;
        accumulator = ((accumulator & ((1 << bits) - 1)) << 6) | next;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded_bytes += 1;
        }
    }
    if accumulator & ((1 << bits) - 1) != 0 {
        return Err(JoseError::InvalidPublicKeyEncoding);
    }
    if decoded_bytes != expected {
        return Err(JoseError::WrongPublicKeyLength);
    }
    Ok(())
}

/// Parse a bounded RFC 9964 ML-DSA AKP JWK with an independently extracted
/// *protected* JWS header. This is metadata-only; no signature is validated.
///
/// Both JSON documents are untrusted. Caller must obtain the decoded protected
/// header from a real JWS parser and retain original source evidence.
pub fn normalize_ml_dsa_jwk(
    jwk_json: &[u8],
    protected_header_json: &[u8],
    evidence: &JoseEvidenceSource,
) -> Result<JoseAlgorithmIdentity, JoseError> {
    normalize_ml_dsa_jwk_with_limits(
        jwk_json,
        protected_header_json,
        evidence,
        JoseLimits::default(),
    )
}

/// Identical operation with caller-selected bounded resource budgets.
pub fn normalize_ml_dsa_jwk_with_limits(
    jwk_json: &[u8],
    protected_header_json: &[u8],
    evidence: &JoseEvidenceSource,
    limits: JoseLimits,
) -> Result<JoseAlgorithmIdentity, JoseError> {
    limits.validate()?;
    evidence.validate()?;
    if jwk_json.is_empty()
        || protected_header_json.is_empty()
        || jwk_json.len() > limits.jwk_bytes
        || protected_header_json.len() > limits.protected_header_bytes
    {
        return Err(JoseError::SizeLimit);
    }
    let key: PublicJwk = serde_json::from_slice(jwk_json).map_err(|_| JoseError::InvalidJson)?;
    let header: ProtectedHeader =
        serde_json::from_slice(protected_header_json).map_err(|_| JoseError::InvalidJson)?;

    if key.kty != "AKP" {
        return Err(JoseError::UnsupportedKeyType);
    }
    let public_size = profile_public_size(&key.alg)?;
    if key.alg != header.alg {
        return Err(JoseError::AlgorithmMismatch);
    }
    if key.r#priv.is_some() {
        return Err(JoseError::PrivateMaterialNotAccepted);
    }
    if key
        .purpose
        .as_deref()
        .is_some_and(|purpose| purpose != "sig")
        || key
            .key_ops
            .as_ref()
            .is_some_and(|ops| ops.as_slice() != ["verify"])
    {
        return Err(JoseError::InvalidKeyUse);
    }
    if header.crit.is_some() || header.b64.is_some() {
        return Err(JoseError::UnsupportedHeader);
    }
    if let Some(id) = &key.kid {
        check_identifier(id)?;
    }
    if let Some(id) = &header.kid {
        check_identifier(id)?;
        if key.kid.as_ref() != Some(id) {
            return Err(JoseError::InvalidIdentifier);
        }
    }
    for optional in [header.typ.as_deref(), header.cty.as_deref()]
        .into_iter()
        .flatten()
    {
        check_identifier(optional)?;
    }
    validate_public_key_base64url(&key.public_key, public_size)?;
    let (catalog_version, catalog_sha256) = catalog_version_and_fingerprint(&key.alg)?;
    let mut hasher = Sha256::new();
    hasher.update(b"pqc-jose-ml-dsa-akp-v1\0");
    hasher.update(
        u32::try_from(jwk_json.len())
            .map_err(|_| JoseError::SizeLimit)?
            .to_be_bytes(),
    );
    hasher.update(jwk_json);
    hasher.update(
        u32::try_from(protected_header_json.len())
            .map_err(|_| JoseError::SizeLimit)?
            .to_be_bytes(),
    );
    hasher.update(protected_header_json);
    let identity = JoseAlgorithmIdentity {
        schema_version: JoseSchemaVersion::V1,
        source_id: evidence.source_id.clone(),
        evidence_ref: evidence.evidence_ref.clone(),
        alg: key.alg.clone(),
        kty: "AKP".to_owned(),
        profile_id: key.alg,
        public_key_octets: public_size,
        standards_profile: "RFC 9964".to_owned(),
        catalog_version,
        catalog_sha256,
        input_json_sha256: format!("{:x}", hasher.finalize()),
        signature_verified: false,
        key_validated: false,
    };
    let encoded = serde_json::to_vec(&identity).map_err(|_| JoseError::SizeLimit)?;
    if encoded.len() > MAX_REPORT_JSON_BYTES {
        return Err(JoseError::SizeLimit);
    }
    Ok(identity)
}
