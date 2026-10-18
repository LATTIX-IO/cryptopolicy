//! RFC 9964 bounded COSE ML-DSA public AKP key and protected-header parser.
//!
//! The normalizer never verifies signatures, keys, CWT identities or issuers.
//! Parsed identities are metadata only and never grant authorization.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cbor;

use cbor::Value;
use cryptopolicy::{
    AlgorithmId, CryptoContext, CryptoFact, CryptoOperation, CryptoProperties, EvaluationTime,
    EvidenceId, EvidenceQuality, FactOrigin, RequestId, SchemaVersion,
};
use pqc_kit::{Catalog, OperationClass, UsageParameter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Absolute maximum COSE_Key CBOR bytes (contains at most 2592 public-key bytes).
pub const MAX_COSE_KEY_BYTES: usize = 8_192;
/// Absolute maximum separately decoded protected-header map CBOR bytes.
pub const MAX_PROTECTED_CBOR_BYTES: usize = 2_048;
/// Maximum externally supplied normalized report JSON bytes.
pub const MAX_REPORT_JSON_BYTES: usize = 8_192;

/// Local configurable input limits, never exceeding hard ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoseLimits {
    /// Maximum COSE_Key input bytes.
    pub cose_key_bytes: usize,
    /// Maximum protected-header map input bytes.
    pub protected_header_bytes: usize,
}

impl Default for CoseLimits {
    fn default() -> Self {
        Self {
            cose_key_bytes: MAX_COSE_KEY_BYTES,
            protected_header_bytes: MAX_PROTECTED_CBOR_BYTES,
        }
    }
}

impl CoseLimits {
    /// Reject zero and attempted limit increases.
    pub fn validate(self) -> Result<(), CoseError> {
        if self.cose_key_bytes == 0
            || self.cose_key_bytes > MAX_COSE_KEY_BYTES
            || self.protected_header_bytes == 0
            || self.protected_header_bytes > MAX_PROTECTED_CBOR_BYTES
        {
            return Err(CoseError::SizeLimit);
        }
        Ok(())
    }
}

/// Bounded, redaction-safe parsing failures; raw key material is never logged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoseError {
    /// Input, nested array/map, or returned report exceeds a hard ceiling.
    SizeLimit,
    /// Truncated CBOR, trailing bytes or an invalid CBOR integer/length.
    InvalidCbor,
    /// Valid CBOR but unsupported major type or top-level map shape.
    UnsupportedCborType,
    /// Alternate valid but nonpreferred integer encoding or unordered map.
    NonCanonicalCbor,
    /// Repeated integer CBOR map key, which can cause interpretation confusion.
    DuplicateLabel,
    /// Unsupported unknown key parameter label or type.
    UnsupportedKeyParameter,
    /// Unknown or unsupported signed-message protected header.
    UnsupportedHeader,
    /// A critical header parameter was present but is not processed here.
    UnsupportedCriticalHeader,
    /// Algorithm is not RFC 9964's exact -48, -49 or -50.
    UnsupportedAlgorithm,
    /// COSE_Key kty is not integer 7 for AKP.
    UnsupportedKeyType,
    /// COSE_Key algorithm differs from protected-header algorithm.
    AlgorithmMismatch,
    /// Public-key byte string does not have the exact FIPS 204 public length.
    WrongPublicKeyLength,
    /// Input contains -2 (private seed) in public-key-only API.
    PrivateMaterialNotAccepted,
    /// Key operations are not absent or the verify-only operation `[2]`.
    InvalidKeyUse,
    /// Source identifiers or optional key ID are invalid or incompatible.
    InvalidIdentifier,
    /// Pinned pqc-kit catalog does not validate this standardized profile.
    CatalogMismatch,
    /// Untrusted report JSON is malformed or not the closed v1 contract.
    InvalidReport,
    /// Report attempts to upgrade verification or rewrite fixed structural data.
    InconsistentReport,
}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CoseError {}

/// Claims of source identity and original evidence reference; not authenticated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoseEvidenceSource {
    /// Independent collector/parser identifier, not a verified principal.
    pub source_id: String,
    /// Original retained evidence reference.
    pub evidence_ref: String,
}

impl CoseEvidenceSource {
    /// Validate a bounded ASCII evidence handle without checking provenance.
    pub fn validate(&self) -> Result<(), CoseError> {
        for id in [&self.source_id, &self.evidence_ref] {
            let bytes = id.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 128
                || !bytes[0].is_ascii_alphanumeric()
                || !bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(b))
            {
                return Err(CoseError::InvalidIdentifier);
            }
        }
        Ok(())
    }
}

/// Wire schema version for an unauthenticated COSE identity DTO.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CoseSchemaVersion {
    /// Version 1, JSON string "1".
    #[serde(rename = "1")]
    V1,
}

/// Strict metadata record, not cryptographic key validation or policy authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoseAlgorithmIdentity {
    /// Versioned report schema.
    pub schema_version: CoseSchemaVersion,
    /// Claim about the evidence collector.
    pub source_id: String,
    /// Original evidence reference for independent verification.
    pub evidence_ref: String,
    /// COSE Key Type, always 7 (AKP).
    pub kty: i64,
    /// Exact COSE ML-DSA identifier (-48/-49/-50).
    pub alg: i64,
    /// Exact FIPS 204 algorithm name.
    pub profile_id: String,
    /// Exact structural length of public-key bytes.
    pub public_key_octets: usize,
    /// Source standard, always "RFC 9964".
    pub standards_profile: String,
    /// Pinned, immutable pqc-kit catalog version.
    pub catalog_version: String,
    /// Pinned, immutable pqc-kit catalog fingerprint.
    pub catalog_sha256: String,
    /// Domain-separated fingerprint of original CBOR key and header bytes.
    pub input_cbor_sha256: String,
    /// Always false: this adapter never verifies a signature.
    pub signature_verified: bool,
    /// Always false: public-key encodings are not mathematically validated.
    pub key_validated: bool,
}

fn profile(code: i64) -> Result<(&'static str, usize), CoseError> {
    match code {
        -48 => Ok(("ML-DSA-44", 1_312)),
        -49 => Ok(("ML-DSA-65", 1_952)),
        -50 => Ok(("ML-DSA-87", 2_592)),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

fn pinned_catalog(name: &str) -> Result<(String, String), CoseError> {
    let catalog = Catalog::embedded_v1().map_err(|_| CoseError::CatalogMismatch)?;
    catalog
        .validate_usage(name, OperationClass::Verify, UsageParameter::NamedSet(name))
        .map_err(|_| CoseError::CatalogMismatch)?;
    Ok((
        catalog.snapshot().catalog_version.clone(),
        catalog.fingerprint().to_owned(),
    ))
}

fn digest_is_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl CoseAlgorithmIdentity {
    /// Check closed JSON report values, refusing upgrades to cryptographic trust.
    ///
    /// The report is always untrusted; a digest is not an attestation.
    pub fn parse_untrusted_json(input: &[u8]) -> Result<Self, CoseError> {
        if input.len() > MAX_REPORT_JSON_BYTES {
            return Err(CoseError::SizeLimit);
        }
        let parsed: Self = serde_json::from_slice(input).map_err(|_| CoseError::InvalidReport)?;
        CoseEvidenceSource {
            source_id: parsed.source_id.clone(),
            evidence_ref: parsed.evidence_ref.clone(),
        }
        .validate()?;
        let (canonical, public_bytes) = profile(parsed.alg)?;
        if parsed.kty != 7
            || parsed.signature_verified
            || parsed.key_validated
            || parsed.profile_id != canonical
            || parsed.public_key_octets != public_bytes
            || parsed.standards_profile != "RFC 9964"
            || !digest_is_hex(&parsed.input_cbor_sha256)
        {
            return Err(CoseError::InconsistentReport);
        }
        let (version, digest) = pinned_catalog(canonical)?;
        if parsed.catalog_version != version || parsed.catalog_sha256 != digest {
            return Err(CoseError::CatalogMismatch);
        }
        Ok(parsed)
    }

    /// Project only *unverified, inferred* metadata to CryptoContext.
    ///
    /// Neither the parsed CBOR nor an externally supplied report authorizes use.
    /// Operational evidence authentication and actual signature verification
    /// must be performed independently by the caller.
    pub fn to_untrusted_context(
        &self,
        request_id: RequestId,
        evaluation_time: EvaluationTime,
    ) -> Result<CryptoContext, CoseError> {
        let json = serde_json::to_vec(self).map_err(|_| CoseError::InvalidReport)?;
        Self::parse_untrusted_json(&json)?;
        let fact_id =
            EvidenceId::parse(&self.evidence_ref).map_err(|_| CoseError::InvalidIdentifier)?;
        let algorithm_id =
            AlgorithmId::parse(&self.profile_id).map_err(|_| CoseError::UnsupportedAlgorithm)?;
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

/// Normalize a strict canonical CBOR COSE_Key map with a separately extracted
/// **protected header map**. Neither a full COSE_Sign1 parser nor verifier.
///
/// A caller must supply actual decoded protected *map* bytes, not an untrusted
/// unprotected header or detached algorithm claim. Signature and key validity
/// are not examined.
pub fn normalize_ml_dsa_cose_key(
    cose_key_cbor: &[u8],
    protected_header_map_cbor: &[u8],
    evidence: &CoseEvidenceSource,
) -> Result<CoseAlgorithmIdentity, CoseError> {
    normalize_ml_dsa_cose_key_with_limits(
        cose_key_cbor,
        protected_header_map_cbor,
        evidence,
        CoseLimits::default(),
    )
}

/// Same public identity operation with caller-selected, hard-capped limits.
pub fn normalize_ml_dsa_cose_key_with_limits(
    cose_key_cbor: &[u8],
    protected_header_map_cbor: &[u8],
    evidence: &CoseEvidenceSource,
    limits: CoseLimits,
) -> Result<CoseAlgorithmIdentity, CoseError> {
    limits.validate()?;
    evidence.validate()?;
    if cose_key_cbor.is_empty()
        || protected_header_map_cbor.is_empty()
        || cose_key_cbor.len() > limits.cose_key_bytes
        || protected_header_map_cbor.len() > limits.protected_header_bytes
    {
        return Err(CoseError::SizeLimit);
    }

    let mut kty = None;
    let mut key_algorithm = None;
    let mut public_key = None;
    let mut key_id = None;
    for (label, value) in cbor::strict_map(cose_key_cbor)? {
        match (label, value) {
            (1, Value::Integer(7)) => kty = Some(7),
            (1, Value::Integer(_)) => return Err(CoseError::UnsupportedKeyType),
            (2, Value::Bytes(bytes)) if bytes.len() <= 128 => key_id = Some(bytes),
            (3, Value::Integer(value)) => key_algorithm = Some(value),
            (4, Value::Array(values))
                if values.len() == 1 && matches!(&values[0], Value::Integer(2)) => {}
            (-1, Value::Bytes(bytes)) => public_key = Some(bytes),
            (-2, _) => return Err(CoseError::PrivateMaterialNotAccepted),
            (4, _) => return Err(CoseError::InvalidKeyUse),
            (1 | 2 | 3 | -1, _) => return Err(CoseError::UnsupportedKeyParameter),
            _ => return Err(CoseError::UnsupportedKeyParameter),
        }
    }
    if kty != Some(7) {
        return Err(CoseError::UnsupportedKeyType);
    }
    let key_alg = key_algorithm.ok_or(CoseError::UnsupportedAlgorithm)?;
    let (name, bytes) = profile(key_alg)?;
    let public = public_key.ok_or(CoseError::UnsupportedKeyParameter)?;
    if public.len() != bytes {
        return Err(CoseError::WrongPublicKeyLength);
    }

    let mut protected_alg = None;
    let mut protected_key_id = None;
    for (label, value) in cbor::strict_map(protected_header_map_cbor)? {
        match (label, value) {
            (1, Value::Integer(value)) => protected_alg = Some(value),
            (2, _) => return Err(CoseError::UnsupportedCriticalHeader),
            (4, Value::Bytes(bytes)) if bytes.len() <= 128 => protected_key_id = Some(bytes),
            _ => return Err(CoseError::UnsupportedHeader),
        }
    }
    if protected_alg != Some(key_alg) {
        return Err(CoseError::AlgorithmMismatch);
    }
    if protected_key_id.is_some() && key_id != protected_key_id {
        return Err(CoseError::InvalidIdentifier);
    }

    let (catalog_version, catalog_sha256) = pinned_catalog(name)?;
    let mut hasher = Sha256::new();
    hasher.update(b"pqc-cose-ml-dsa-akp-v1\0");
    for raw in [cose_key_cbor, protected_header_map_cbor] {
        hasher.update(
            u32::try_from(raw.len())
                .map_err(|_| CoseError::SizeLimit)?
                .to_be_bytes(),
        );
        hasher.update(raw);
    }
    let output = CoseAlgorithmIdentity {
        schema_version: CoseSchemaVersion::V1,
        source_id: evidence.source_id.clone(),
        evidence_ref: evidence.evidence_ref.clone(),
        kty: 7,
        alg: key_alg,
        profile_id: name.to_owned(),
        public_key_octets: bytes,
        standards_profile: "RFC 9964".to_owned(),
        catalog_version,
        catalog_sha256,
        input_cbor_sha256: format!("{:x}", hasher.finalize()),
        signature_verified: false,
        key_validated: false,
    };
    let serialized = serde_json::to_vec(&output).map_err(|_| CoseError::SizeLimit)?;
    if serialized.len() > MAX_REPORT_JSON_BYTES {
        return Err(CoseError::SizeLimit);
    }
    Ok(output)
}
