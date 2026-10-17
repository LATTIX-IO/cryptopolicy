//! Strict, versioned cryptographic-policy data contracts.
//!
//! This crate does not yet evaluate policies, perform cryptography, or authorize
//! operations. It provides DTOs, structural validation and stable serialization.
//! Future FOSS-434 and FOSS-435 increments provide policy semantics and evaluation.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod policy;
mod types;

pub use policy::*;
pub use types::*;
