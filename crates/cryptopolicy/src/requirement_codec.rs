//! Strict JSON deserialization for adjacently tagged requirement values.
//! Extra sibling fields are rejected before any policy compilation.

use crate::Requirement;
use serde::de::{DeserializeOwned, Error as DeError};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Every supported v1 requirement kind is enumerated here.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Algorithm,
    Profile,
    MinSecurityCategory,
    NonExportable,
    NamedHybrid,
    Provider,
    Sensitivity,
    KeyProtection,
    KeyExportable,
    SourceOrigin,
    SourceQuality,
    KeySizeBits,
    MinimumKeyBits,
}

#[derive(Default)]
enum WireValue {
    #[default]
    Missing,
    Present(Value),
}

fn read_present<'de, D>(deserializer: D) -> Result<WireValue, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(WireValue::Present)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    kind: Kind,
    #[serde(default, deserialize_with = "read_present")]
    value: WireValue,
}

fn required<T, E>(value: WireValue) -> Result<T, E>
where
    T: DeserializeOwned,
    E: DeError,
{
    match value {
        WireValue::Present(value) if !value.is_null() => {
            serde_json::from_value(value).map_err(|_| E::custom("invalid requirement value"))
        }
        WireValue::Missing | WireValue::Present(_) => Err(E::custom("missing requirement value")),
    }
}

impl<'de> Deserialize<'de> for Requirement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = Envelope::deserialize(deserializer)?;
        match wire.kind {
            Kind::Algorithm => required(wire.value).map(Self::Algorithm),
            Kind::Profile => required(wire.value).map(Self::Profile),
            Kind::MinSecurityCategory => required(wire.value).map(Self::MinSecurityCategory),
            Kind::NamedHybrid => required(wire.value).map(Self::NamedHybrid),
            Kind::Provider => required(wire.value).map(Self::Provider),
            Kind::Sensitivity => required(wire.value).map(Self::Sensitivity),
            Kind::KeyProtection => required(wire.value).map(Self::KeyProtection),
            Kind::KeyExportable => required(wire.value).map(Self::KeyExportable),
            Kind::SourceOrigin => required(wire.value).map(Self::SourceOrigin),
            Kind::SourceQuality => required(wire.value).map(Self::SourceQuality),
            Kind::KeySizeBits => required(wire.value).map(Self::KeySizeBits),
            Kind::MinimumKeyBits => required(wire.value).map(Self::MinimumKeyBits),
            Kind::NonExportable => match wire.value {
                WireValue::Missing => Ok(Self::NonExportable),
                WireValue::Present(_) => {
                    Err(D::Error::custom("unit requirement must not contain value"))
                }
            },
        }
    }
}
