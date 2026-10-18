//! Versioned, immutable, adapter-independent algorithm/profile identification.
//!
//! **No cryptography or authorization is performed.** A standardized profile
//! describes a documented NIST *algorithm specification*, not a validated
//! implementation, approved configuration, authorized provider, or Permit.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Maximum bytes accepted from a caller-supplied catalog.
pub const MAX_CATALOG_BYTES: usize = 262_144;
/// Maximum profiles in one v1 snapshot.
pub const MAX_PROFILES: usize = 128;
/// Maximum explicit parsing aliases per profile.
pub const MAX_ALIASES_PER_PROFILE: usize = 8;
/// Exact version of this catalog's JSON contract.
pub const CATALOG_SCHEMA_V1: &str = "1";
/// Exact semantic version of the checked-in catalog snapshot.
pub const CATALOG_VERSION_V1: &str = "1.0.0";
/// SHA-256 of the *exact checked-in JSON bytes*, not a signature.
///
/// Pinned during FOSS-445 CI. Never silently regenerate in tests.
pub const EMBEDDED_CATALOG_SHA256_V1: &str =
    "91cca1ed7fe8a0391045801108089bb38bee0b34fdff40e2c7e0fac4e87fb685";

/// Algorithm family. Families are distinct from fully specified profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgorithmFamily {
    /// AES Galois/Counter Mode authenticated encryption.
    AesGcm,
    /// SHA-2 fixed-output hash functions.
    Sha2,
    /// SHA-3 fixed-output hash functions.
    Sha3,
    /// RSA Probabilistic Signature Scheme parameterized by modulus bits.
    RsaPss,
    /// Elliptic Curve Digital Signature Algorithm with named NIST curves.
    Ecdsa,
    /// Module-lattice key encapsulation.
    MlKem,
    /// Module-lattice digital signature.
    MlDsa,
    /// Stateless hash-based digital signature.
    SlhDsa,
    /// Withdrawn Triple DES; legacy decryption only.
    Tdea,
    /// Pre-standard Falcon/FN-DSA candidate, NOT an approved profile.
    Falcon,
}

/// Documentation maturity, never an authorization or CMVP claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardizationStatus {
    /// The cited standard specifies this parameter set.
    Standardized,
    /// Research/draft profile; not eligible for this registry's usage check.
    Experimental,
    /// Legacy processing only; never granted by the usage check.
    Deprecated,
    /// Explicitly blocked parameterization.
    Unsupported,
}

/// Exact cryptographic operation class. Does not execute any operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    /// Encrypt plaintext.
    Encrypt,
    /// Decrypt ciphertext.
    Decrypt,
    /// Compute a digital signature.
    Sign,
    /// Verify a digital signature.
    Verify,
    /// Produce a fixed-length hash.
    Hash,
    /// Encapsulate a shared secret.
    Encapsulate,
    /// Decapsulate a shared secret.
    Decapsulate,
}

/// The interpretation of a profile's mandatory parameter value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterKind {
    /// Number of key bits; not a PQ security category.
    KeyBits,
    /// Digest output bits; not key bits or a security-strength claim.
    HashOutputBits,
    /// Complete, literal, named NIST parameter set.
    NamedSet,
}

/// The parameter's precise value type, never inferred from its numeric name.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParameterValue {
    /// Numeric key size or fixed digest output length.
    Bits(u32),
    /// Exact named parameter set (case-sensitive).
    Name(String),
}

/// One mandatory parameter with a strict, finite JSON envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterDefinition {
    /// Interpretation of the value.
    pub kind: ParameterKind,
    /// Typed exact value.
    pub value: ParameterValue,
}

/// Classical and post-quantum security metadata MUST NOT be interchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityMetadata {
    /// Documented classical security-strength estimate, if directly known.
    pub classical_bits: Option<u16>,
    /// NIST post-quantum category 1..5, not a key length or a universal proof.
    pub pqc_category: Option<u8>,
}

/// Traceable source reference and cited revision for a *specification*.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardsSource {
    /// Public standards document name.
    pub document: String,
    /// HTTPS URL to NIST standards material.
    pub url: String,
    /// Publication revision or version at snapshot time.
    pub revision: String,
}

/// Fully specified canonical profile, not a cryptographic implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmProfile {
    /// Exact canonical ASCII profile identifier.
    pub id: String,
    /// Cryptographic primitive family.
    pub family: AlgorithmFamily,
    /// Standards lifecycle status, distinct from deployment authorization.
    pub status: StandardizationStatus,
    /// Explicit, sorted supported operations; not all operations on a family.
    pub operations: Vec<OperationClass>,
    /// Complete, mandatory parameter definition.
    pub parameter: ParameterDefinition,
    /// Security metadata with disjoint strength and category dimensions.
    pub security: SecurityMetadata,
    /// Specification provenance. This field is not independently authenticated.
    pub source: StandardsSource,
    /// Explicit parsing-only spellings; never canonical policy identifiers.
    pub aliases: Vec<String>,
}

/// Versioned catalog's exact DTO with closed fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogSnapshot {
    /// Wire contract; this library accepts v1 only.
    pub schema_version: String,
    /// Explicit semantic content version.
    pub catalog_version: String,
    /// UTC release date of the checked-in snapshot.
    pub as_of: String,
    /// Profiles, strictly sorted by canonical ID in the v1 encoding.
    pub entries: Vec<AlgorithmProfile>,
}

/// Structural/usage errors are NEVER converted to a cryptographic Permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    /// Catalog exceeds its fixed input bound.
    PayloadTooLarge,
    /// The JSON cannot be decoded by the closed DTO schema.
    InvalidJson,
    /// Unrecognized catalog schema or version.
    InvalidSchema,
    /// Invalid structural profile or parameter definition.
    InvalidProfile(&'static str),
    /// Unsorted, repeated, colliding or unreviewed alias.
    InvalidAlias,
    /// Duplicate/unsorted canonical profile IDs.
    InvalidIdentity,
    /// Embedded snapshot differs from its pinned SHA-256.
    SnapshotMismatch,
    /// Canonical name not present in this snapshot.
    UnknownProfile,
    /// Alias used in an authorization-adjacent canonical lookup.
    AliasNotCanonical,
    /// Algorithm family does not support requested operation.
    OperationMismatch,
    /// Key size, output length or named set is incomplete or incorrect.
    ParameterMismatch,
    /// Nonstandard/deprecated/unsupported profile cannot pass usage checking.
    NonStandard(StandardizationStatus),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CatalogError {}

/// Exact input parameter for a usage check; never a nullable/fuzzy guess.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageParameter<'a> {
    /// Cryptographic key length, in bits.
    KeyBits(u32),
    /// Fixed hash digest output, in bits.
    HashOutputBits(u32),
    /// Full canonical named parameter set.
    NamedSet(&'a str),
}

/// External-name parsing outcome. A result is NOT usable as an authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedName<'a> {
    /// Exact canonical profile ID from the immutable catalog.
    pub canonical_id: &'a str,
    /// Whether a parsing-only alias was used.
    pub via_alias: bool,
}

/// Parsed immutable snapshot; all mutation is internal to validation/creation.
///
/// Structural parsing of caller-provided JSON does NOT authenticate the author.
/// Only embedded_v1 pins exact bytes to this repository's reviewed snapshot.
#[derive(Clone, Debug)]
pub struct Catalog {
    snapshot: CatalogSnapshot,
    aliases: BTreeMap<String, usize>,
    fingerprint: String,
}

fn is_identifier(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(byte))
}

fn validate_source(source: &StandardsSource) -> Result<(), CatalogError> {
    if source.document.is_empty()
        || source.document.len() > 128
        || source.revision.is_empty()
        || source.revision.len() > 128
        || source.url.len() > 256
        || !source.url.starts_with("https://csrc.nist.gov/")
    {
        return Err(CatalogError::InvalidProfile("standards_source"));
    }
    Ok(())
}

fn expected_family_and_category(
    id: &str,
) -> Option<(AlgorithmFamily, Option<u8>, StandardizationStatus)> {
    use AlgorithmFamily as F;
    use StandardizationStatus as S;
    match id {
        "AES-128-GCM" | "AES-192-GCM" | "AES-256-GCM" => Some((F::AesGcm, None, S::Standardized)),
        "SHA-256" | "SHA-384" | "SHA-512" => Some((F::Sha2, None, S::Standardized)),
        "SHA3-256" | "SHA3-384" | "SHA3-512" => Some((F::Sha3, None, S::Standardized)),
        "RSA-PSS-2048" | "RSA-PSS-3072" | "RSA-PSS-4096" => {
            Some((F::RsaPss, None, S::Standardized))
        }
        "ECDSA-P256" | "ECDSA-P384" | "ECDSA-P521" => Some((F::Ecdsa, None, S::Standardized)),
        "ML-KEM-512" => Some((F::MlKem, Some(1), S::Standardized)),
        "ML-KEM-768" => Some((F::MlKem, Some(3), S::Standardized)),
        "ML-KEM-1024" => Some((F::MlKem, Some(5), S::Standardized)),
        "ML-DSA-44" => Some((F::MlDsa, Some(2), S::Standardized)),
        "ML-DSA-65" => Some((F::MlDsa, Some(3), S::Standardized)),
        "ML-DSA-87" => Some((F::MlDsa, Some(5), S::Standardized)),
        "FALCON-512" => Some((F::Falcon, None, S::Experimental)),
        "RSA-PSS-1024" => Some((F::RsaPss, None, S::Unsupported)),
        "TDEA-3KEY" => Some((F::Tdea, None, S::Deprecated)),
        _ if id.starts_with("SLH-DSA-SHA2-") || id.starts_with("SLH-DSA-SHAKE-") => {
            let suffix = id
                .strip_prefix("SLH-DSA-SHA2-")
                .or_else(|| id.strip_prefix("SLH-DSA-SHAKE-"))?;
            let cat = match suffix {
                "128f" | "128s" => 1,
                "192f" | "192s" => 3,
                "256f" | "256s" => 5,
                _ => return None,
            };
            Some((F::SlhDsa, Some(cat), S::Standardized))
        }
        _ => None,
    }
}

fn numeric_suffix(id: &str, family: AlgorithmFamily) -> Option<u32> {
    let prefix = match family {
        AlgorithmFamily::AesGcm => {
            return id.strip_prefix("AES-")?.strip_suffix("-GCM")?.parse().ok();
        }
        AlgorithmFamily::Sha2 => "SHA-",
        AlgorithmFamily::Sha3 => "SHA3-",
        AlgorithmFamily::RsaPss => "RSA-PSS-",
        AlgorithmFamily::Ecdsa => "ECDSA-P",
        AlgorithmFamily::Tdea => return Some(168),
        _ => return None,
    };
    id.strip_prefix(prefix)?.parse().ok()
}

fn allowed_ops(family: AlgorithmFamily) -> &'static [OperationClass] {
    use OperationClass as Op;
    match family {
        AlgorithmFamily::AesGcm => &[Op::Decrypt, Op::Encrypt],
        AlgorithmFamily::Sha2 | AlgorithmFamily::Sha3 => &[Op::Hash],
        AlgorithmFamily::RsaPss
        | AlgorithmFamily::Ecdsa
        | AlgorithmFamily::MlDsa
        | AlgorithmFamily::SlhDsa
        | AlgorithmFamily::Falcon => &[Op::Sign, Op::Verify],
        AlgorithmFamily::MlKem => &[Op::Decapsulate, Op::Encapsulate],
        AlgorithmFamily::Tdea => &[Op::Decrypt],
    }
}

fn aliases_allowed(id: &str, aliases: &[String]) -> bool {
    match id {
        "AES-256-GCM" => aliases.is_empty() || (aliases.len() == 1 && aliases[0] == "AES256-GCM"),
        "SHA3-256" => aliases.is_empty() || (aliases.len() == 1 && aliases[0] == "SHA3_256"),
        _ => aliases.is_empty(),
    }
}

fn validate_entry(entry: &AlgorithmProfile) -> Result<(), CatalogError> {
    if !is_identifier(&entry.id) {
        return Err(CatalogError::InvalidProfile("profile_id"));
    }
    let (family, category, status) = expected_family_and_category(&entry.id)
        .ok_or(CatalogError::InvalidProfile("unknown_canonical_profile"))?;
    if entry.family != family || entry.status != status {
        return Err(CatalogError::InvalidProfile("family_or_status"));
    }
    if entry.security.pqc_category != category {
        return Err(CatalogError::InvalidProfile("pqc_category"));
    }
    if category.is_some() && entry.security.classical_bits.is_some() {
        return Err(CatalogError::InvalidProfile("mixed_security_dimensions"));
    }
    if !allowed_ops(family).eq(entry.operations.as_slice()) {
        return Err(CatalogError::InvalidProfile("operation_set"));
    }
    let expected = numeric_suffix(&entry.id, family);
    match (&entry.parameter.kind, &entry.parameter.value, expected) {
        (ParameterKind::KeyBits, ParameterValue::Bits(actual), Some(value))
            if !matches!(family, AlgorithmFamily::Sha2 | AlgorithmFamily::Sha3)
                && *actual == value => {}
        (ParameterKind::HashOutputBits, ParameterValue::Bits(actual), Some(value))
            if matches!(family, AlgorithmFamily::Sha2 | AlgorithmFamily::Sha3)
                && *actual == value => {}
        (ParameterKind::NamedSet, ParameterValue::Name(actual), None)
            if matches!(
                family,
                AlgorithmFamily::MlKem
                    | AlgorithmFamily::MlDsa
                    | AlgorithmFamily::SlhDsa
                    | AlgorithmFamily::Falcon
            ) && *actual == entry.id => {}
        _ => return Err(CatalogError::InvalidProfile("profile_parameter")),
    }
    if entry
        .security
        .classical_bits
        .is_some_and(|value| value == 0 || value > 256)
    {
        return Err(CatalogError::InvalidProfile("classical_strength"));
    }
    if matches!(
        family,
        AlgorithmFamily::Sha2
            | AlgorithmFamily::Sha3
            | AlgorithmFamily::Tdea
            | AlgorithmFamily::Falcon
    ) && entry.security.classical_bits.is_some()
    {
        return Err(CatalogError::InvalidProfile("unsupported_strength_claim"));
    }
    validate_source(&entry.source)?;
    if entry.aliases.len() > MAX_ALIASES_PER_PROFILE
        || entry.aliases.iter().any(|name| !is_identifier(name))
        || !entry.aliases.windows(2).all(|pair| pair[0] < pair[1])
        || !aliases_allowed(&entry.id, &entry.aliases)
    {
        return Err(CatalogError::InvalidAlias);
    }
    Ok(())
}

impl Catalog {
    /// Parse a structurally checked **untrusted** v1 snapshot.
    ///
    /// This function is for fixture validation and future consumer-supplied
    /// catalogs. It cannot authenticate source identities or grant authority.
    pub fn parse_untrusted_json(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(CatalogError::PayloadTooLarge);
        }
        let snapshot: CatalogSnapshot =
            serde_json::from_slice(bytes).map_err(|_| CatalogError::InvalidJson)?;
        if snapshot.schema_version != CATALOG_SCHEMA_V1
            || snapshot.catalog_version != CATALOG_VERSION_V1
            || snapshot.as_of != "2026-10-17"
        {
            return Err(CatalogError::InvalidSchema);
        }
        if snapshot.entries.is_empty() || snapshot.entries.len() > MAX_PROFILES {
            return Err(CatalogError::InvalidProfile("profile_count"));
        }
        let mut seen = BTreeSet::new();
        let mut aliases = BTreeMap::new();
        let mut last: Option<&str> = None;
        for (index, entry) in snapshot.entries.iter().enumerate() {
            validate_entry(entry)?;
            if last.is_some_and(|prior| prior >= entry.id.as_str()) {
                return Err(CatalogError::InvalidIdentity);
            }
            last = Some(&entry.id);
            if !seen.insert(entry.id.clone()) {
                return Err(CatalogError::InvalidIdentity);
            }
            for alias in &entry.aliases {
                if aliases.insert(alias.clone(), index).is_some() {
                    return Err(CatalogError::InvalidAlias);
                }
            }
        }
        if aliases.keys().any(|alias| seen.contains(alias)) {
            return Err(CatalogError::InvalidAlias);
        }
        let fingerprint = hex_digest(bytes);
        Ok(Self {
            snapshot,
            aliases,
            fingerprint,
        })
    }

    /// Load the exact reviewed v1 bytes shipped with this crate.
    ///
    /// Pinned SHA-256 detects accidental drift within a checkout. It is NOT
    /// signature verification or an independent supply-chain trust anchor.
    pub fn embedded_v1() -> Result<Self, CatalogError> {
        let catalog = Self::parse_untrusted_json(include_bytes!("../data/catalog-v1.json"))?;
        if catalog.fingerprint != EMBEDDED_CATALOG_SHA256_V1 {
            return Err(CatalogError::SnapshotMismatch);
        }
        Ok(catalog)
    }

    /// The immutable, explicitly versioned snapshot data.
    pub fn snapshot(&self) -> &CatalogSnapshot {
        &self.snapshot
    }

    /// SHA-256 of exact original versioned JSON bytes, not a signature.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Exact canonical-ID lookup; aliases always return None.
    pub fn get(&self, canonical_id: &str) -> Option<&AlgorithmProfile> {
        self.snapshot
            .entries
            .binary_search_by(|p| p.id.as_str().cmp(canonical_id))
            .ok()
            .map(|index| &self.snapshot.entries[index])
    }

    /// Explicit, case-sensitive external-name parsing, never authorization.
    ///
    /// Unknown labels and legacy "Kyber"/"Dilithium"/"SPHINCS+" names are not
    /// automatically equated to standardized ML-KEM/ML-DSA/SLH-DSA sets.
    pub fn resolve_name(&self, input: &str) -> Result<ResolvedName<'_>, CatalogError> {
        if let Some(profile) = self.get(input) {
            return Ok(ResolvedName {
                canonical_id: &profile.id,
                via_alias: false,
            });
        }
        let index = self
            .aliases
            .get(input)
            .ok_or(CatalogError::UnknownProfile)?;
        Ok(ResolvedName {
            canonical_id: &self.snapshot.entries[*index].id,
            via_alias: true,
        })
    }

    /// Validate an exact canonical profile, operation and typed parameter.
    ///
    /// A successful check proves only membership/parameters in this **catalog
    /// snapshot**, not policy Permit, provider attestation or FIPS module status.
    pub fn validate_usage<'a>(
        &'a self,
        canonical_id: &str,
        operation: OperationClass,
        parameter: UsageParameter<'_>,
    ) -> Result<&'a AlgorithmProfile, CatalogError> {
        let profile = self.get(canonical_id).ok_or_else(|| {
            if self.aliases.contains_key(canonical_id) {
                CatalogError::AliasNotCanonical
            } else {
                CatalogError::UnknownProfile
            }
        })?;
        if profile.status != StandardizationStatus::Standardized {
            return Err(CatalogError::NonStandard(profile.status));
        }
        if !profile.operations.contains(&operation) {
            return Err(CatalogError::OperationMismatch);
        }
        let matched = match (&profile.parameter.kind, &profile.parameter.value, parameter) {
            (
                ParameterKind::KeyBits,
                ParameterValue::Bits(expected),
                UsageParameter::KeyBits(value),
            ) => *expected == value,
            (
                ParameterKind::HashOutputBits,
                ParameterValue::Bits(expected),
                UsageParameter::HashOutputBits(value),
            ) => *expected == value,
            (
                ParameterKind::NamedSet,
                ParameterValue::Name(expected),
                UsageParameter::NamedSet(value),
            ) => expected == value,
            _ => false,
        };
        if !matched {
            return Err(CatalogError::ParameterMismatch);
        }
        Ok(profile)
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Finalized RFC 10024 TLS hybrid group identity and transition metadata.
pub mod tls_hybrid;
