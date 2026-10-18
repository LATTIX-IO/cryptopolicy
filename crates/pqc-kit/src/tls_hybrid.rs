//! Finalized RFC 10024 TLS 1.3 hybrid group identity and offline transition
//! assessment. This module performs NO TLS handshake, cryptography, transcript
//! authentication, implementation approval, or policy authorization.

use crate::{Catalog, CatalogError, OperationClass, UsageParameter};
use std::{collections::BTreeSet, fmt};

/// Maximum count of caller-declared Supported Groups (not a negotiated set).
pub const MAX_CONFIGURED_TLS_GROUPS: usize = 64;

/// Exact constituent ordering for TLS KeyShareEntry payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HybridShareOrder {
    /// ML-KEM first, then classical ECDHE.
    KemThenEcdhe,
    /// Classical ECDHE first, then ML-KEM.
    EcdheThenKem,
}

/// Immutable descriptor for one finalized RFC 10024 TLS NamedGroup.
///
/// Describes a published construction, not a validated implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsHybridGroup {
    /// IANA TLS NamedGroup codepoint.
    pub codepoint: u16,
    /// Exact registered name.
    pub name: &'static str,
    /// Classical ephemeral key-agreement component.
    pub classical_component: &'static str,
    /// FIPS 203 ML-KEM parameter set; not interchangeable with the hybrid.
    pub kem_component: &'static str,
    /// Wire concatenation order for both shares.
    pub share_order: HybridShareOrder,
    /// Classical ECDHE public share octets.
    pub classical_public_octets: usize,
    /// ML-KEM encapsulation key octets in the client share.
    pub kem_public_octets: usize,
    /// ML-KEM ciphertext octets in the server share.
    pub kem_ciphertext_octets: usize,
    /// Complete client key_exchange value size.
    pub client_share_octets: usize,
    /// Complete server key_exchange value size.
    pub server_share_octets: usize,
    /// Concatenated shared secrets size, before TLS HKDF.
    pub shared_secret_octets: usize,
    /// Literal IANA registry Recommended field.
    pub iana_recommended: bool,
    /// Exact normative document identifier.
    pub standard: &'static str,
}

/// Three exact RFC 10024 published group registrations, sorted by codepoint.
/// This is a NEW construction registry; immutable FOSS-445 catalog bytes
/// and their pinned digest must not be changed by introducing these groups.
pub static RFC10024_HYBRID_GROUPS: [TlsHybridGroup; 3] = [
    TlsHybridGroup {
        codepoint: 4587, name: "SecP256r1MLKEM768",
        classical_component: "secp256r1", kem_component: "ML-KEM-768",
        share_order: HybridShareOrder::EcdheThenKem,
        classical_public_octets: 65, kem_public_octets: 1184,
        kem_ciphertext_octets: 1088, client_share_octets: 1249,
        server_share_octets: 1153, shared_secret_octets: 64,
        iana_recommended: false, standard: "RFC 10024",
    },
    TlsHybridGroup {
        codepoint: 4588, name: "X25519MLKEM768",
        classical_component: "X25519", kem_component: "ML-KEM-768",
        share_order: HybridShareOrder::KemThenEcdhe,
        classical_public_octets: 32, kem_public_octets: 1184,
        kem_ciphertext_octets: 1088, client_share_octets: 1216,
        server_share_octets: 1120, shared_secret_octets: 64,
        iana_recommended: true, standard: "RFC 10024",
    },
    TlsHybridGroup {
        codepoint: 4589, name: "SecP384r1MLKEM1024",
        classical_component: "secp384r1", kem_component: "ML-KEM-1024",
        share_order: HybridShareOrder::EcdheThenKem,
        classical_public_octets: 97, kem_public_octets: 1568,
        kem_ciphertext_octets: 1568, client_share_octets: 1665,
        server_share_octets: 1665, shared_secret_octets: 80,
        iana_recommended: false, standard: "RFC 10024",
    },
];

/// Finalized, obsoleted experimental, and otherwise unknown codepoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsGroupClass {
    /// Published, named RFC 10024 hybrid construction.
    Finalized(&'static TlsHybridGroup),
    /// Kyber-based experimental codepoint obsoleted by RFC 10024.
    ObsoletedDraft {
        /// Original codepoint, never aliased to ML-KEM.
        codepoint: u16,
        /// Original draft group name, diagnostic only.
        name: &'static str,
    },
    /// Not in finalized registry; may be classical, single-PQ, future or bogus.
    Unknown(u16),
}

/// Recognize EXACT IANA values. No aliases or silent experimental upgrade.
pub fn classify_tls_group(codepoint: u16) -> TlsGroupClass {
    match codepoint {
        4587 => TlsGroupClass::Finalized(&RFC10024_HYBRID_GROUPS[0]),
        4588 => TlsGroupClass::Finalized(&RFC10024_HYBRID_GROUPS[1]),
        4589 => TlsGroupClass::Finalized(&RFC10024_HYBRID_GROUPS[2]),
        25497 => TlsGroupClass::ObsoletedDraft {
            codepoint, name: "X25519Kyber768Draft00",
        },
        25498 => TlsGroupClass::ObsoletedDraft {
            codepoint, name: "SecP256r1Kyber768Draft00",
        },
        _ => TlsGroupClass::Unknown(codepoint),
    }
}

/// Exact name lookup; no parsing-only aliases, case folding or fuzzy mapping.
pub fn named_tls_hybrid(name: &str) -> Option<&'static TlsHybridGroup> {
    RFC10024_HYBRID_GROUPS.iter().find(|group| group.name == name)
}

/// Provenance quality of a reported TLS configuration or negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsEvidenceOrigin {
    /// Offered or configured list alone.
    Configured,
    /// Claims an actual negotiated TLS KeyShare, not transcript authentication.
    Negotiated,
    /// Inferred/guessed observation.
    Inferred,
}

/// Explicitly distinct TLS construction and constituent-only constraints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TlsTransitionRequirement {
    /// Require any of the three exact finalized TLS hybrid constructions.
    AnyFinalizedHybrid,
    /// Require one specific finalized TLS NamedGroup.
    ExactHybridGroup(u16),
    /// Check only a PQ constituent, never a complete hybrid-construction match.
    PqcComponentOnly(String),
}

/// Untrusted observation without key material or secret bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsHybridObservation {
    /// Offered Supported Groups. Offer alone is NOT a negotiation.
    pub configured_groups: Vec<u16>,
    /// Claimed selected TLS NamedGroup, if any.
    pub negotiated_group: Option<u16>,
    /// Optional human-readable group claim, which must agree with codepoint.
    pub claimed_name: Option<String>,
    /// Distinguishes configured-only, negotiated and inferred observations.
    pub origin: TlsEvidenceOrigin,
    /// Length of decoded client KeyShareEntry key_exchange, if inspected.
    pub client_share_octets: Option<usize>,
    /// Length of decoded server KeyShareEntry key_exchange, if inspected.
    pub server_share_octets: Option<usize>,
    /// Opaque unverified observation source identifier.
    pub source_id: String,
    /// Opaque retained evidence identifier.
    pub evidence_ref: String,
}

/// A consistency finding, never a Permit, attestation or handshake proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsHybridFinding {
    /// Exact published hybrid satisfies structural constraints as claimed.
    StructurallyConsistentHybrid,
    /// Only ML-KEM constituent matched a primitive-only requirement.
    ComponentOnlyMatch,
    /// No selected group was observed.
    NotNegotiated,
    /// Declared source does not claim a negotiated observation.
    UnverifiedOrigin,
    /// Selected group absent from offered list, indicating downgrade/conflict.
    UnofferedGroup,
    /// Known obsoleted experimental Kyber codepoint.
    ObsoletedDraft,
    /// Unknown/future/single-primitive codepoint, not a finalized hybrid.
    UnknownGroup,
    /// Claimed string name mismatches codepoint.
    NameMismatch,
    /// Missing share size evidence prevents a structural hybrid match.
    IncompleteShareEvidence,
    /// Share sizes do not match RFC 10024 for the claimed group.
    ShareMismatch,
    /// Requirement disagrees with selected construction or PQ component.
    RequirementMismatch,
}

/// Assessment metadata with no authority to authorize cryptographic operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsHybridAssessment {
    /// Conservative finding.
    pub finding: TlsHybridFinding,
    /// Recognized finalized descriptor, even on mismatch.
    pub group: Option<TlsHybridGroup>,
    /// Source-provided origin retained for the consuming security system.
    pub origin: TlsEvidenceOrigin,
    /// Source-provided selected codepoint, possibly unknown.
    pub negotiated_group: Option<u16>,
}

/// Failed input validation; no partial successful result is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsHybridError {
    /// Oversized advertised groups list or name.
    ResourceLimit,
    /// Duplicated configured codepoint.
    DuplicateGroup,
    /// Invalid unbounded or non-ASCII provenance identifier.
    InvalidIdentifier,
    /// Referenced ML-KEM catalog entry is not a recognized approved standard.
    CatalogMismatch,
}
impl fmt::Display for TlsHybridError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TlsHybridError {}

fn valid_handle(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty() && bytes.len() <= 128 && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(b))
}

/// Validate a finalized group's PQ component against immutable pqc-kit v1.
///
/// Does NOT validate a real provider, classical ECDHE or TLS 1.3 implementation.
pub fn validate_tls_hybrid_components(group: &TlsHybridGroup) -> Result<(), CatalogError> {
    let catalog = Catalog::embedded_v1()?;
    catalog.validate_usage(
        group.kem_component,
        OperationClass::Encapsulate,
        UsageParameter::NamedSet(group.kem_component),
    )
}

/// Evaluate only structural consistency of claimed TLS metadata.
///
/// A matching constituent does not imply the hybrid construction was used.
/// A successful-looking result does not authenticate transcripts or validate
/// KEM ciphertexts, ECDHE points, HKDF, certificates or negotiated secrets.
pub fn assess_tls_hybrid(
    evidence: &TlsHybridObservation,
    requirement: &TlsTransitionRequirement,
) -> Result<TlsHybridAssessment, TlsHybridError> {
    if evidence.configured_groups.len() > MAX_CONFIGURED_TLS_GROUPS
        || evidence.claimed_name.as_ref().is_some_and(|n| n.len() > 64)
    {
        return Err(TlsHybridError::ResourceLimit);
    }
    if !valid_handle(&evidence.source_id) || !valid_handle(&evidence.evidence_ref) {
        return Err(TlsHybridError::InvalidIdentifier);
    }
    let offered: BTreeSet<_> = evidence.configured_groups.iter().copied().collect();
    if offered.len() != evidence.configured_groups.len() {
        return Err(TlsHybridError::DuplicateGroup);
    }
    let mut result = TlsHybridAssessment {
        finding: TlsHybridFinding::NotNegotiated,
        group: None,
        origin: evidence.origin,
        negotiated_group: evidence.negotiated_group,
    };
    let Some(codepoint) = evidence.negotiated_group else { return Ok(result); };
    let profile = match classify_tls_group(codepoint) {
        TlsGroupClass::Finalized(profile) => profile,
        TlsGroupClass::ObsoletedDraft { .. } => {
            result.finding = TlsHybridFinding::ObsoletedDraft;
            return Ok(result);
        }
        TlsGroupClass::Unknown(_) => {
            result.finding = TlsHybridFinding::UnknownGroup;
            return Ok(result);
        }
    };
    result.group = Some(*profile);
    result.finding = if evidence.claimed_name.as_deref().is_some_and(|n| n != profile.name) {
        TlsHybridFinding::NameMismatch
    } else if !offered.contains(&codepoint) {
        TlsHybridFinding::UnofferedGroup
    } else if evidence.origin != TlsEvidenceOrigin::Negotiated {
        TlsHybridFinding::UnverifiedOrigin
    } else if evidence.client_share_octets.is_none() || evidence.server_share_octets.is_none() {
        TlsHybridFinding::IncompleteShareEvidence
    } else if evidence.client_share_octets != Some(profile.client_share_octets)
        || evidence.server_share_octets != Some(profile.server_share_octets)
    {
        TlsHybridFinding::ShareMismatch
    } else {
        validate_tls_hybrid_components(profile).map_err(|_| TlsHybridError::CatalogMismatch)?;
        match requirement {
            TlsTransitionRequirement::AnyFinalizedHybrid => {
                TlsHybridFinding::StructurallyConsistentHybrid
            }
            TlsTransitionRequirement::ExactHybridGroup(required) if *required == codepoint => {
                TlsHybridFinding::StructurallyConsistentHybrid
            }
            TlsTransitionRequirement::PqcComponentOnly(required)
                if required == profile.kem_component => {
                TlsHybridFinding::ComponentOnlyMatch
            }
            _ => TlsHybridFinding::RequirementMismatch,
        }
    };
    Ok(result)
}
