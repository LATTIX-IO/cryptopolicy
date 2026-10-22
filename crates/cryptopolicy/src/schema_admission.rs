//! FOSS-514: bounded, fail-closed public policy-admission error vocabulary.
//!
//! This is a *classification of parser failures*, not authentication,
//! enforcement or permission. The existing strict policy parser is the sole
//! authority for accepting documents; no compatibility fallback is possible.

use crate::{ContractError, Limits, PolicyDocument};
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use std::{collections::BTreeSet, fmt};

/// Closed, payload-free admission failure families for an untrusted document.
///
/// No attacker-supplied JSON, field name, issuer string or parser message is
/// preserved in this error type. All variants prevent policy admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyAdmissionError {
    /// Unknown top-level policy schema field or unsupported declared version.
    UnsupportedSchema,
    /// Policy JSON, structure or requirements are invalid under strict v1.
    InvalidPolicy,
    /// A configured size, depth or resource budget was exceeded or invalid.
    ResourceLimit,
}

impl fmt::Display for PolicyAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::UnsupportedSchema => "UnsupportedSchema",
            Self::InvalidPolicy => "InvalidPolicy",
            Self::ResourceLimit => "ResourceLimit",
        };
        f.write_str(code)
    }
}

impl std::error::Error for PolicyAdmissionError {}

fn classify_failure(error: &ContractError) -> PolicyAdmissionError {
    match error {
        ContractError::PayloadTooLarge
        | ContractError::InvalidLimit(_)
        | ContractError::ResourceLimitExceeded(_) => PolicyAdmissionError::ResourceLimit,
        _ => PolicyAdmissionError::InvalidPolicy,
    }
}

/// Recognize unsupported root keys/versions only AFTER strict parsing failed.
///
/// A second bounded JSON read is a diagnostic classifier, NEVER an alternate
/// accepted policy parser. The source parser retains ownership of all nested
/// grammar, duplicate-field and semantic validation. Root names not in this
/// closed vocabulary are security-critical and cannot be ignored.
const V1_ROOT_KEYS: &[&str] = &[
    "schema_version",
    "policy_id",
    "version",
    "issuer",
    "created_at",
    "effective_at",
    "expires_at",
    "default_effect",
    "rules",
    "metadata",
];

#[derive(Default)]
struct RootObservation {
    duplicate_key: bool,
    unsupported_schema: bool,
}

struct RootVisitor;

impl<'de> Visitor<'de> for RootVisitor {
    type Value = RootObservation;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("top-level policy JSON object")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut seen = BTreeSet::new();
        let mut result = RootObservation::default();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                result.duplicate_key = true;
            }
            if key == "schema_version" {
                let version = map.next_value::<serde_json::Value>()?;
                if version.as_str() != Some("1") {
                    result.unsupported_schema = true;
                }
            } else {
                if !V1_ROOT_KEYS.contains(&key.as_str()) {
                    result.unsupported_schema = true;
                }
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(result)
    }
}

fn unsupported_root_schema(bytes: &[u8]) -> bool {
    // A normal serde_json::Value map silently overwrites repeated keys.
    // A streaming visitor checks every root occurrence instead. A duplicate
    // root field is always InvalidPolicy, regardless of duplicate order or
    // whether one value would imply an unsupported schema.
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let Ok(root) = de.deserialize_map(RootVisitor) else {
        return false;
    };
    if de.end().is_err() {
        return false;
    }
    !root.duplicate_key && root.unsupported_schema
}

/// Parse a strict policy while exposing a stable, closed admission error code.
///
/// Success is IDENTICAL to PolicyDocument::parse_json_with_limits: this API
/// cannot admit a document rejected by the existing strict parser. On failure,
/// an explicit v1 root-key allowlist and the declared schema version classify
/// unsupported top-level extensions as UnsupportedSchema, without parsing
/// error-message text. All other invalid inputs remain non-authorizing errors.
///
/// Budget checks precede either JSON parse. No policy issuer/source trust is
/// authenticated here and no returned document is an authorization.
pub fn parse_policy_for_admission_with_limits(
    input: &[u8],
    limits: &Limits,
) -> Result<PolicyDocument, PolicyAdmissionError> {
    limits
        .check_json(input)
        .map_err(|error| classify_failure(&error))?;
    match PolicyDocument::parse_json_with_limits(input, limits) {
        Ok(document) => Ok(document),
        Err(error) => {
            if unsupported_root_schema(input) {
                Err(PolicyAdmissionError::UnsupportedSchema)
            } else {
                Err(classify_failure(&error))
            }
        }
    }
}

/// Parse with the default resource budget and the same fail-closed semantics.
pub fn parse_policy_for_admission(input: &[u8]) -> Result<PolicyDocument, PolicyAdmissionError> {
    parse_policy_for_admission_with_limits(input, &Limits::default())
}
