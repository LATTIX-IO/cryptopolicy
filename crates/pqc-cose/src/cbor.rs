//! Strict, allocation-bounded deterministic CBOR subset for COSE_Key and
//! separately extracted protected-header maps. Not a generic CBOR decoder.

use super::CoseError;

/// Only data types used by the supported COSE public key and header subset.
#[derive(Debug)]
pub(super) enum Value<'a> {
    Integer(i64),
    Bytes(&'a [u8]),
    Array(Vec<Value<'a>>),
    Map(Vec<(i64, Value<'a>)>),
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], CoseError> {
        let end = self.offset.checked_add(len).ok_or(CoseError::InvalidCbor)?;
        let part = self.bytes.get(self.offset..end).ok_or(CoseError::InvalidCbor)?;
        self.offset = end;
        Ok(part)
    }

    fn byte(&mut self) -> Result<u8, CoseError> {
        Ok(*self.take(1)?.first().ok_or(CoseError::InvalidCbor)?)
    }

    /// Enforces RFC 8949 preferred shortest integer/length encoding.
    fn argument(&mut self, additional: u8) -> Result<u64, CoseError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.byte()?);
                if value < 24 {
                    return Err(CoseError::NonCanonicalCbor);
                }
                Ok(value)
            }
            25 => {
                let raw = self.take(2)?;
                let value = u64::from(u16::from_be_bytes([raw[0], raw[1]]));
                if value <= u64::from(u8::MAX) {
                    return Err(CoseError::NonCanonicalCbor);
                }
                Ok(value)
            }
            26 => {
                let raw = self.take(4)?;
                let value = u64::from(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]));
                if value <= u64::from(u16::MAX) {
                    return Err(CoseError::NonCanonicalCbor);
                }
                Ok(value)
            }
            27 => {
                let raw = self.take(8)?;
                let value = u64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);
                if value <= u64::from(u32::MAX) {
                    return Err(CoseError::NonCanonicalCbor);
                }
                Ok(value)
            }
            // Indefinite lengths, reserved encodings, floats/tags are unsupported.
            _ => Err(CoseError::InvalidCbor),
        }
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>, CoseError> {
        if depth > 4 {
            return Err(CoseError::SizeLimit);
        }
        let leading = self.byte()?;
        let major = leading >> 5;
        let value = self.argument(leading & 31)?;
        match major {
            0 => Ok(Value::Integer(
                i64::try_from(value).map_err(|_| CoseError::InvalidCbor)?,
            )),
            1 => {
                let n = i64::try_from(value).map_err(|_| CoseError::InvalidCbor)?;
                Ok(Value::Integer(-1_i64 - n))
            }
            2 => {
                let len = usize::try_from(value).map_err(|_| CoseError::SizeLimit)?;
                if len > 4_096 {
                    return Err(CoseError::SizeLimit);
                }
                Ok(Value::Bytes(self.take(len)?))
            }
            4 => {
                let count = usize::try_from(value).map_err(|_| CoseError::SizeLimit)?;
                if count > 8 {
                    return Err(CoseError::SizeLimit);
                }
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(entries))
            }
            5 => {
                let count = usize::try_from(value).map_err(|_| CoseError::SizeLimit)?;
                if count > 8 {
                    return Err(CoseError::SizeLimit);
                }
                let mut entries = Vec::with_capacity(count);
                let mut previous_key: Option<&[u8]> = None;
                for _ in 0..count {
                    let begin = self.offset;
                    let key = self.item(depth + 1)?;
                    let encoded_key = &self.bytes[begin..self.offset];
                    let Value::Integer(label) = key else {
                        return Err(CoseError::UnsupportedCborType);
                    };
                    if entries.iter().any(|(existing, _)| *existing == label) {
                        return Err(CoseError::DuplicateLabel);
                    }
                    // RFC 8949 core deterministic map sorting is lexical on
                    // the canonical key encodings, not legacy length-first.
                    if previous_key.is_some_and(|prior| prior >= encoded_key) {
                        return Err(CoseError::NonCanonicalCbor);
                    }
                    previous_key = Some(encoded_key);
                    entries.push((label, self.item(depth + 1)?));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(CoseError::UnsupportedCborType),
        }
    }
}

pub(super) fn strict_map(input: &[u8]) -> Result<Vec<(i64, Value<'_>)>, CoseError> {
    let mut decoder = Decoder {
        bytes: input,
        offset: 0,
    };
    let item = decoder.item(0)?;
    if decoder.offset != input.len() {
        return Err(CoseError::InvalidCbor);
    }
    match item {
        Value::Map(entries) => Ok(entries),
        _ => Err(CoseError::UnsupportedCborType),
    }
}
