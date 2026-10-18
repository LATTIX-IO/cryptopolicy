//! Strict, versioned cryptographic-policy data contracts.
//!
//! This crate provides strict DTOs, static validation and a conservative,
//! deterministic offline evaluator. It does not perform cryptography,
//! independently authenticate policy/facts or enforce its decision.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod assessment;
mod capability;
mod composition;
mod evaluator;
mod exception_admission;
mod exception_reference;
mod limits;
mod normative_projection;
mod policy;
mod requirement_codec;
mod types;
mod validation;

pub use assessment::*;
pub use capability::*;
pub use composition::*;
pub use evaluator::*;
pub use exception_admission::*;
pub use exception_reference::*;
pub use limits::*;
pub use normative_projection::*;
pub use policy::*;
pub use types::*;
pub use validation::*;
