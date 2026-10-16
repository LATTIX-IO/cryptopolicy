//! Validated wire identities and stable classification enums.
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Maximum input bytes accepted by initial contract parsing. FOSS-433
/// replaces this with a configurable central limit policy.
pub const MAX_CONTRACT_BYTES: usize = 1_048_576;

/// An invalid contract is not the same as an evaluated Deny.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    /// Identifier is malformed or contains ambiguous characters.
    InvalidIdentifier,
    /// Version is not a canonical MAJOR.MINOR.PATCH triple.
    InvalidVersion,
    /// Input is not valid strict JSON for the declared schema.
    InvalidJson(String),
    /// Input exceeds its configured byte budget.
    PayloadTooLarge,
    /// Duplicate policy rule, metadata key or fact identifier.
    DuplicateIdentifier,
    /// A structural or temporal invariant failed.
    InvalidDocument(&'static str),
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ContractError {}

fn validate_identifier(value: &str) -> Result<(), ContractError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes.iter().all(|c| c.is_ascii_alphanumeric() || b"-._:/".contains(c))
    {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(())
}

macro_rules! identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            /// Validate and construct an ASCII-safe identifier.
            pub fn parse(value: &str) -> Result<Self, ContractError> {
                validate_identifier(value)?;
                Ok(Self(value.to_owned()))
            }
            /// Return its validated representation.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = ContractError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(&value)
            }
        }
        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
        impl FromStr for $name {
            type Err = ContractError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

identifier!(PolicyId, "Stable identity of a policy.");
identifier!(RuleId, "Stable identity of a rule.");
identifier!(AlgorithmId, "Exact algorithm identity.");
identifier!(ProfileId, "Exact algorithm or protocol profile identity.");
identifier!(EvidenceId, "Opaque external evidence identity.");
identifier!(RequestId, "Opaque evaluation request identity.");

/// Canonical semantic-version triplet. Prereleases are not in this initial wire schema.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PolicyVersion(String);
impl PolicyVersion {
    /// Validate the strict MAJOR.MINOR.PATCH policy version.
    pub fn parse(value: &str) -> Result<Self, ContractError> {
        let parts: Vec<_> = value.split('.').collect();
        if parts.len() != 3
            || parts.iter().any(|part| {
                part.is_empty()
                    || (part.len() > 1 && part.starts_with('0'))
                    || part.parse::<u32>().is_err()
            })
        {
            return Err(ContractError::InvalidVersion);
        }
        Ok(Self(value.to_owned()))
    }
    /// Return its canonical representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for PolicyVersion {
    type Error = ContractError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}
impl From<PolicyVersion> for String {
    fn from(value: PolicyVersion) -> Self {
        value.0
    }
}
impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Strict wire version independent of the semantic policy version.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SchemaVersion {
    /// First JSON contract.
    #[serde(rename = "1")]
    V1,
}

/// Explicit UTC Unix timestamp in milliseconds. No hidden system clock is used.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationTime {
    /// Milliseconds relative to 1970-01-01T00:00:00Z.
    pub unix_millis: i64,
}

/// Explicit fallback behavior, never inferred from a missing field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultEffect {
    /// Deny unmatched requests.
    Deny,
    /// Explicit default permission requiring deliberate policy authorship.
    Allow,
}

/// Operations to be described in policy facts. No execution occurs in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoOperation {
    /// Encrypt data.
    Encrypt,
    /// Decrypt data.
    Decrypt,
    /// Create a signature.
    Sign,
    /// Verify a signature.
    Verify,
    /// Encapsulate key material.
    Encapsulate,
    /// Decapsulate key material.
    Decapsulate,
    /// Hash data.
    Hash,
    /// Agree on a shared key.
    KeyAgreement,
    /// Derive a key.
    DeriveKey,
}

/// Typed rule effect; evaluation is deferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Matching rule forbids an operation.
    Deny,
    /// Matching rule allows an operation only when requirements hold.
    Allow,
    /// Matching rule contributes mandatory constraints.
    Require,
    /// Advisory effect, never an authorization.
    Warn,
}

/// Origin of a fact, without accidental promotion of configuration to observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactOrigin {
    /// Caller requested use.
    Requested,
    /// Algorithm or protocol is configured.
    Configured,
    /// Algorithm or protocol was negotiated.
    Negotiated,
    /// Operation was directly observed.
    Observed,
    /// Claim was inferred from other evidence.
    Inferred,
    /// Provider asserts support, not proven use.
    ProviderCapability,
}

/// Outcome of a future validated evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    /// Permit is the only authorizing result and must be trusted.
    Permit,
    /// Evaluation denies the request.
    Deny,
    /// Reliable authorization is unavailable; caller must block.
    Indeterminate,
}

/// Wire reason vocabulary. Adding variants needs a compatibility review.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// No applicable authorization under default deny.
    DefaultDenied,
    /// An explicit Deny matched.
    ExplicitDeny,
    /// A required attribute is absent.
    MissingRequiredAttribute,
    /// Unknown or unsupported algorithm profile.
    UnsupportedProfile,
    /// Known profile is not approved.
    ProfileNotApproved,
    /// A mandatory requirement was satisfied.
    RequirementSatisfied,
}

/// SHA-256 fingerprint of canonical policy JSON; not a signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PolicyDigest(String);
impl PolicyDigest {
    /// Return lowercase hexadecimal content digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for PolicyDigest {
    type Error = ContractError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err(ContractError::InvalidIdentifier);
        }
        Ok(Self(value))
    }
}
impl From<PolicyDigest> for String {
    fn from(value: PolicyDigest) -> Self {
        value.0
    }
}
