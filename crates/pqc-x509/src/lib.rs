//! FOSS-452: strict, bounded RFC 9881 / RFC 9935 identity normalization.
//!
//! These are *semantic* entrypoints for independently extracted certificate
//! signature AlgorithmIdentifier fields and a complete standalone SPKI.
//! This is intentionally NOT a general ASN.1 parser, certificate validator,
//! signature verifier, critical-extension parser, or authorization decision.
//! The caller must use an independent RFC 5280 certificate parser to establish
//! field position and accurately report unknown critical extensions.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use pqc_kit::{Catalog, OperationClass, UsageParameter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Maximum individually extracted DER AlgorithmIdentifier size.
pub const MAX_ALGORITHM_IDENTIFIER_DER_BYTES: usize = 96;
/// Maximum standalone DER SubjectPublicKeyInfo size (ML-KEM max is smaller).
pub const MAX_SPKI_DER_BYTES: usize = 4096;
/// Maximum serialized normalization report size.
pub const MAX_REPORT_JSON_BYTES: usize = 8192;

/// Hard-capped caller budgets for the two intentionally narrow entrypoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X509Limits {
    /// Maximum individual AlgorithmIdentifier DER bytes.
    pub max_algorithm_identifier_bytes: usize,
    /// Maximum standalone SubjectPublicKeyInfo DER bytes.
    pub max_spki_bytes: usize,
}
impl Default for X509Limits {
    fn default() -> Self {
        Self {
            max_algorithm_identifier_bytes: MAX_ALGORITHM_IDENTIFIER_DER_BYTES,
            max_spki_bytes: MAX_SPKI_DER_BYTES,
        }
    }
}
impl X509Limits {
    /// Prevent zero or caller-widened budgets.
    pub fn validate(self) -> Result<(), X509Error> {
        if self.max_algorithm_identifier_bytes == 0
            || self.max_algorithm_identifier_bytes > MAX_ALGORITHM_IDENTIFIER_DER_BYTES
            || self.max_spki_bytes == 0
            || self.max_spki_bytes > MAX_SPKI_DER_BYTES
        {
            return Err(X509Error::InvalidLimit);
        }
        Ok(())
    }
}

/// Stable, redaction-safe error vocabulary; no raw ASN.1 or key bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum X509Error {
    /// A caller-supplied limit was zero or above the absolute limit.
    InvalidLimit,
    /// DER input or output exceeds a hard or configured byte budget.
    SizeLimit,
    /// Invalid canonical DER structure or field, with a bounded reason label.
    InvalidDer(&'static str),
    /// An AlgorithmIdentifier contains parameters (including ASN.1 NULL).
    ParametersNotAbsent,
    /// An otherwise structurally valid OID is not among the exact RFC profiles.
    UnsupportedOid,
    /// A recognized OID occurs in the wrong certificate field or role.
    WrongRole,
    /// The TBS and outer certificate signature identifiers disagree.
    SignatureAlgorithmMismatch,
    /// Critical-extension inspection was absent or not complete.
    UncheckedCriticalExtensions,
    /// An unknown or malformed critical extension was reported.
    UnsupportedCriticalExtension,
    /// Certificate key usage was uninspected or incompatible with ML-KEM.
    InvalidKeyUsage,
    /// ML-KEM SubjectPublicKey BIT STRING has an invalid payload length.
    WrongPublicKeyLength,
    /// A source or evidence identifier is missing/invalid/unbounded.
    InvalidEvidenceIdentifier,
    /// The repository-pinned FOSS-445 catalog did not verify these exact names.
    CatalogMismatch,
}
impl fmt::Display for X509Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for X509Error {}

/// Strict JSON wire version. It does not authenticate the message producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum X509SchemaVersion {
    /// The initial DTO schema.
    #[serde(rename = "1")]
    V1,
}

/// Only a caller's reported result of an external certificate extension parser.
///
/// This is NOT checked from certificate bytes by pqc-x509; callers must never
/// treat this enum as proof that an external parser was honest or competent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticalExtensions {
    /// External parser reported no unhandled/malformed critical extension.
    CheckedNoUnknownCritical,
    /// External parser found an unsupported critical extension.
    UnknownCritical,
    /// External parser found a malformed critical extension.
    MalformedCritical,
    /// No reliable critical-extension analysis has been supplied.
    NotInspected,
}

/// External X.509 parser's claim about RFC 9935 keyUsage if it is present.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlKemKeyUsage {
    /// The certificate had no keyUsage extension.
    Absent,
    /// The only set keyUsage bit is keyEncipherment.
    KeyEnciphermentOnly,
    /// Other keyUsage bits were set (forbidden for ML-KEM SPKI).
    OtherBits,
    /// Key usage was not independently extracted.
    NotInspected,
}

/// A bounded source/evidence handle; never a signature or authenticity proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509EvidenceSource {
    /// Exact source/parser or collector identifier.
    pub source_id: String,
    /// Original externally retained artifact/evidence identifier.
    pub evidence_ref: String,
}
impl X509EvidenceSource {
    /// Validate identifier grammar and resource limits prior to normalization.
    pub fn validate(&self) -> Result<(), X509Error> {
        for value in [&self.source_id, &self.evidence_ref] {
            let data = value.as_bytes();
            if data.is_empty()
                || data.len() > 128
                || !data[0].is_ascii_alphanumeric()
                || !data
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._:/".contains(byte))
            {
                return Err(X509Error::InvalidEvidenceIdentifier);
            }
        }
        Ok(())
    }
}

/// The sole input field locations recognized by these narrow adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum X509Field {
    /// Inner/outer certificate signature AlgorithmIdentifier pair.
    CertificateSignature,
    /// Complete SubjectPublicKeyInfo (not a whole certificate).
    SubjectPublicKeyInfo,
}

/// Fully typed, versioned normalization *metadata*, not a policy decision.
///
/// Both verification flags are always false from these APIs. Deserializing
/// any JSON from an untrusted source NEVER authenticates this report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X509AlgorithmIdentity {
    /// The single supported schema version.
    pub schema_version: X509SchemaVersion,
    /// Source or parser reference, unverified.
    pub source_id: String,
    /// Original evidence reference, unverified.
    pub evidence_ref: String,
    /// Which independently extracted certificate field was normalized.
    pub field: X509Field,
    /// Exact RFC/NIST dotted-decimal OID, not an alias.
    pub oid: String,
    /// Canonical reviewed FOSS-445 profile identity.
    pub profile_id: String,
    /// Whether the mandatory-absent parameters field is present (always false).
    pub parameters_present: bool,
    /// Number of raw public-key octets for a valid ML-KEM SPKI, if applicable.
    pub public_key_octets: Option<usize>,
    /// RFC defining the recognized X.509 identifier.
    pub standards_profile: String,
    /// Exact pinned FOSS-445 catalog semantic version.
    pub catalog_version: String,
    /// SHA-256 of pinned FOSS-445 catalog JSON, not an issuer signature.
    pub catalog_sha256: String,
    /// SHA-256 of domain-separated original input DER bytes.
    pub input_der_sha256: String,
    /// This crate never verifies a cryptographic certificate signature.
    pub signature_verified: bool,
    /// This crate never verifies trust paths, issuer, revocation or validity.
    pub certificate_validated: bool,
}
impl X509AlgorithmIdentity {
    /// Strict bounded JSON reader for transport. Caller MUST independently
    /// verify the report producer; JSON is not an attestation or permit.
    pub fn parse_untrusted_json(input: &[u8]) -> Result<Self, X509Error> {
        if input.len() > MAX_REPORT_JSON_BYTES {
            return Err(X509Error::SizeLimit);
        }
        let value: Self = serde_json::from_slice(input)
            .map_err(|_| X509Error::InvalidDer("result_json"))?;
        if value.parameters_present || value.signature_verified || value.certificate_validated {
            return Err(X509Error::InvalidDer("untrusted_result_verification_flags"));
        }
        X509EvidenceSource {
            source_id: value.source_id.clone(),
            evidence_ref: value.evidence_ref.clone(),
        }.validate()?;
        let canonical_oid = match value.oid.as_str() {
            "2.16.840.1.101.3.4.3.17" => OID_ML_DSA_44,
            "2.16.840.1.101.3.4.3.18" => OID_ML_DSA_65,
            "2.16.840.1.101.3.4.3.19" => OID_ML_DSA_87,
            "2.16.840.1.101.3.4.4.1" => OID_ML_KEM_512,
            "2.16.840.1.101.3.4.4.2" => OID_ML_KEM_768,
            "2.16.840.1.101.3.4.4.3" => OID_ML_KEM_1024,
            _ => return Err(X509Error::UnsupportedOid),
        };
        let profile = profile_for_oid(canonical_oid, value.field)?;
        if value.profile_id != profile.id
            || value.standards_profile != profile.source
            || value.public_key_octets != profile.pubkey_len
        {
            return Err(X509Error::InvalidDer("inconsistent_result_profile"));
        }
        let (version, fingerprint) = catalog_identity(profile, value.field)?;
        if value.catalog_version != version || value.catalog_sha256 != fingerprint {
            return Err(X509Error::CatalogMismatch);
        }
        if value.input_der_sha256.len() != 64
            || !value
                .input_der_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(X509Error::InvalidDer("invalid_der_fingerprint"));
        }
        Ok(value)
    }
}

const OID_ML_DSA_44: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
const OID_ML_DSA_65: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
const OID_ML_DSA_87: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];
const OID_ML_KEM_512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01];
const OID_ML_KEM_768: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02];
const OID_ML_KEM_1024: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03];

#[derive(Clone, Copy)]
struct ProfileRecord {
    id: &'static str,
    oid: &'static str,
    source: &'static str,
    pubkey_len: Option<usize>,
}
fn profile_for_oid(value: &[u8], field: X509Field) -> Result<ProfileRecord, X509Error> {
    let observed = if value == OID_ML_DSA_44 {
        (X509Field::CertificateSignature, "ML-DSA-44", "2.16.840.1.101.3.4.3.17", "RFC 9881", None)
    } else if value == OID_ML_DSA_65 {
        (X509Field::CertificateSignature, "ML-DSA-65", "2.16.840.1.101.3.4.3.18", "RFC 9881", None)
    } else if value == OID_ML_DSA_87 {
        (X509Field::CertificateSignature, "ML-DSA-87", "2.16.840.1.101.3.4.3.19", "RFC 9881", None)
    } else if value == OID_ML_KEM_512 {
        (X509Field::SubjectPublicKeyInfo, "ML-KEM-512", "2.16.840.1.101.3.4.4.1", "RFC 9935", Some(800))
    } else if value == OID_ML_KEM_768 {
        (X509Field::SubjectPublicKeyInfo, "ML-KEM-768", "2.16.840.1.101.3.4.4.2", "RFC 9935", Some(1184))
    } else if value == OID_ML_KEM_1024 {
        (X509Field::SubjectPublicKeyInfo, "ML-KEM-1024", "2.16.840.1.101.3.4.4.3", "RFC 9935", Some(1568))
    } else {
        return Err(X509Error::UnsupportedOid);
    };
    if observed.0 != field {
        return Err(X509Error::WrongRole);
    }
    Ok(ProfileRecord {
        id: observed.1,
        oid: observed.2,
        source: observed.3,
        pubkey_len: observed.4,
    })
}

struct Tlv<'a> {
    content: &'a [u8],
    tail: &'a [u8],
    encoded_len: usize,
}

/// Parse only definite, minimally encoded DER lengths; BER and EOC are invalid.
fn read_tlv(input: &[u8], tag: u8) -> Result<Tlv<'_>, X509Error> {
    if input.len() < 2 {
        return Err(X509Error::InvalidDer("truncated_tag_or_length"));
    }
    if input[0] != tag {
        return Err(X509Error::InvalidDer("wrong_tag"));
    }
    let (len, header) = match input[1] {
        0..=127 => (usize::from(input[1]), 2usize),
        0x81 => {
            if input.len() < 3 || input[2] < 128 {
                return Err(X509Error::InvalidDer("noncanonical_length"));
            }
            (usize::from(input[2]), 3)
        }
        0x82 => {
            if input.len() < 4 || input[2] == 0 {
                return Err(X509Error::InvalidDer("noncanonical_length"));
            }
            let value = (usize::from(input[2]) << 8) | usize::from(input[3]);
            if value < 256 {
                return Err(X509Error::InvalidDer("noncanonical_length"));
            }
            (value, 4)
        }
        _ => return Err(X509Error::InvalidDer("indefinite_or_oversized_length")),
    };
    let end = header
        .checked_add(len)
        .ok_or(X509Error::InvalidDer("length_overflow"))?;
    if end > input.len() {
        return Err(X509Error::InvalidDer("truncated_value"));
    }
    Ok(Tlv {
        content: &input[header..end],
        tail: &input[end..],
        encoded_len: end,
    })
}
fn whole_sequence(input: &[u8]) -> Result<&[u8], X509Error> {
    let seq = read_tlv(input, 0x30)?;
    if !seq.tail.is_empty() {
        return Err(X509Error::InvalidDer("trailing_der"));
    }
    Ok(seq.content)
}
fn oid_canonical(value: &[u8]) -> Result<(), X509Error> {
    if value.is_empty() || value.len() > 32 {
        return Err(X509Error::InvalidDer("oid_size"));
    }
    let mut start_of_component = true;
    for &byte in value {
        if start_of_component && byte == 0x80 {
            return Err(X509Error::InvalidDer("noncanonical_oid_subidentifier"));
        }
        start_of_component = byte & 0x80 == 0;
    }
    if !start_of_component {
        return Err(X509Error::InvalidDer("truncated_oid_subidentifier"));
    }
    Ok(())
}
fn parse_algorithm_identifier(der: &[u8], field: X509Field) -> Result<ProfileRecord, X509Error> {
    let sequence = whole_sequence(der)?;
    let identifier = read_tlv(sequence, 0x06)?;
    oid_canonical(identifier.content)?;
    if !identifier.tail.is_empty() {
        // Even DER NULL (05 00) is FORBIDDEN by both target RFCs.
        return Err(X509Error::ParametersNotAbsent);
    }
    profile_for_oid(identifier.content, field)
}
fn inspect_critical(state: CriticalExtensions) -> Result<(), X509Error> {
    match state {
        CriticalExtensions::CheckedNoUnknownCritical => Ok(()),
        CriticalExtensions::UnknownCritical | CriticalExtensions::MalformedCritical => {
            Err(X509Error::UnsupportedCriticalExtension)
        }
        CriticalExtensions::NotInspected => Err(X509Error::UncheckedCriticalExtensions),
    }
}
fn catalog_identity(profile: ProfileRecord, field: X509Field) -> Result<(String, String), X509Error> {
    let catalog = Catalog::embedded_v1().map_err(|_| X509Error::CatalogMismatch)?;
    let operation = match field {
        X509Field::CertificateSignature => OperationClass::Verify,
        X509Field::SubjectPublicKeyInfo => OperationClass::Encapsulate,
    };
    catalog
        .validate_usage(profile.id, operation, UsageParameter::NamedSet(profile.id))
        .map_err(|_| X509Error::CatalogMismatch)?;
    Ok((
        catalog.snapshot().catalog_version.clone(),
        catalog.fingerprint().to_owned(),
    ))
}
fn hex_digest(chunks: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for chunk in chunks {
        digest.update(*chunk);
    }
    digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}
fn complete_record(
    field: X509Field,
    profile: ProfileRecord,
    evidence: &X509EvidenceSource,
    public_key_octets: Option<usize>,
    digest: String,
) -> Result<X509AlgorithmIdentity, X509Error> {
    let (catalog_version, catalog_sha256) = catalog_identity(profile, field)?;
    let result = X509AlgorithmIdentity {
        schema_version: X509SchemaVersion::V1,
        source_id: evidence.source_id.clone(),
        evidence_ref: evidence.evidence_ref.clone(),
        field,
        oid: profile.oid.to_owned(),
        profile_id: profile.id.to_owned(),
        parameters_present: false,
        public_key_octets,
        standards_profile: profile.source.to_owned(),
        catalog_version,
        catalog_sha256,
        input_der_sha256: digest,
        signature_verified: false,
        certificate_validated: false,
    };
    let encoded = serde_json::to_vec(&result).map_err(|_| X509Error::SizeLimit)?;
    if encoded.len() > MAX_REPORT_JSON_BYTES {
        return Err(X509Error::SizeLimit);
    }
    Ok(result)
}

/// Normalize an externally extracted RFC 5280 TBSCertificate signature
/// AlgorithmIdentifier *and* outer Certificate signatureAlgorithm pair.
///
/// Both must be identical, parameter-free RFC 9881 ML-DSA identifiers. The
/// caller must use a real X.509 parser to extract those fields and inspect
/// all critical extensions. This method does not parse a certificate or
/// verify the signature, issuer, trust anchor, keyUsage or revocation.
pub fn normalize_ml_dsa_certificate_signature(
    tbs_identifier_der: &[u8],
    outer_identifier_der: &[u8],
    extensions: CriticalExtensions,
    evidence: &X509EvidenceSource,
) -> Result<X509AlgorithmIdentity, X509Error> {
    normalize_ml_dsa_certificate_signature_with_limits(
        tbs_identifier_der,
        outer_identifier_der,
        extensions,
        evidence,
        X509Limits::default(),
    )
}

/// Normalize extracted ML-DSA certificate signature fields with hard budgets.
pub fn normalize_ml_dsa_certificate_signature_with_limits(
    tbs_identifier_der: &[u8],
    outer_identifier_der: &[u8],
    extensions: CriticalExtensions,
    evidence: &X509EvidenceSource,
    limits: X509Limits,
) -> Result<X509AlgorithmIdentity, X509Error> {
    limits.validate()?;
    evidence.validate()?;
    if tbs_identifier_der.len() > limits.max_algorithm_identifier_bytes
        || outer_identifier_der.len() > limits.max_algorithm_identifier_bytes
    {
        return Err(X509Error::SizeLimit);
    }
    inspect_critical(extensions)?;
    let tbs = parse_algorithm_identifier(tbs_identifier_der, X509Field::CertificateSignature)?;
    let outer = parse_algorithm_identifier(outer_identifier_der, X509Field::CertificateSignature)?;
    if tbs.id != outer.id || tbs_identifier_der != outer_identifier_der {
        return Err(X509Error::SignatureAlgorithmMismatch);
    }
    let l = u32::try_from(tbs_identifier_der.len()).map_err(|_| X509Error::SizeLimit)?;
    complete_record(
        X509Field::CertificateSignature,
        tbs,
        evidence,
        None,
        hex_digest(&[
            b"pqc-x509-ml-dsa-signature-pair-v1\0",
            &l.to_be_bytes(),
            tbs_identifier_der,
            outer_identifier_der,
        ]),
    )
}

/// Normalize complete, standalone RFC 9935 ML-KEM SubjectPublicKeyInfo DER.
///
/// The caller must extract this exact SPKI field from an independently parsed
/// certificate and accurately classify critical extensions and keyUsage.
/// The BIT STRING must contain precisely 800/1184/1568 raw public-key octets,
/// with zero unused bits and NO nested OCTET STRING. This is only a structural
/// length check; it does not validate the cryptographic public key.
pub fn normalize_ml_kem_spki(
    spki_der: &[u8],
    extensions: CriticalExtensions,
    key_usage: MlKemKeyUsage,
    evidence: &X509EvidenceSource,
) -> Result<X509AlgorithmIdentity, X509Error> {
    normalize_ml_kem_spki_with_limits(
        spki_der,
        extensions,
        key_usage,
        evidence,
        X509Limits::default(),
    )
}

/// Normalize ML-KEM SPKI with a smaller caller-configurable hard-capped budget.
pub fn normalize_ml_kem_spki_with_limits(
    spki_der: &[u8],
    extensions: CriticalExtensions,
    key_usage: MlKemKeyUsage,
    evidence: &X509EvidenceSource,
    limits: X509Limits,
) -> Result<X509AlgorithmIdentity, X509Error> {
    limits.validate()?;
    evidence.validate()?;
    if spki_der.len() > limits.max_spki_bytes {
        return Err(X509Error::SizeLimit);
    }
    inspect_critical(extensions)?;
    if !matches!(
        key_usage,
        MlKemKeyUsage::Absent | MlKemKeyUsage::KeyEnciphermentOnly
    ) {
        return Err(X509Error::InvalidKeyUsage);
    }
    let subject_public_key_info = whole_sequence(spki_der)?;
    let algorithm = read_tlv(subject_public_key_info, 0x30)?;
    let der = &subject_public_key_info[..algorithm.encoded_len];
    if der.len() > limits.max_algorithm_identifier_bytes {
        return Err(X509Error::SizeLimit);
    }
    let profile = parse_algorithm_identifier(der, X509Field::SubjectPublicKeyInfo)?;
    let public_key = read_tlv(algorithm.tail, 0x03)?;
    if !public_key.tail.is_empty() {
        return Err(X509Error::InvalidDer("trailing_spki_field"));
    }
    if public_key.content.first() != Some(&0) {
        return Err(X509Error::InvalidDer("invalid_unused_bits"));
    }
    let actual = public_key.content.len().saturating_sub(1);
    if profile.pubkey_len != Some(actual) {
        return Err(X509Error::WrongPublicKeyLength);
    }
    complete_record(
        X509Field::SubjectPublicKeyInfo,
        profile,
        evidence,
        Some(actual),
        hex_digest(&[b"pqc-x509-ml-kem-spki-v1\0", spki_der]),
    )
}
