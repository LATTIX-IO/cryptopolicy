//! Strict, versioned cryptographic-policy data contracts.
//!
//! This crate provides strict DTOs, static validation and a conservative,
//! deterministic offline evaluator. It does not perform cryptography,
//! independently authenticate policy/facts or enforce its decision.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod evaluator;
mod limits;
mod policy;
mod requirement_codec;
mod types;
mod validation;

pub use evaluator::*;
pub use limits::*;
pub use policy::*;
pub use types::*;
pub use validation::*;
