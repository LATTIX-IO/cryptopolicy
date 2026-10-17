//! Bound input sizes and structural complexity before JSON deserialization.
use crate::{ContractError, MAX_CONTRACT_BYTES};

/// Hard caps on configured limits, including for unsafe caller overrides.
pub const ABSOLUTE_MAX_JSON_BYTES: usize = 16 * 1024 * 1024;

/// Resource budgets used by all current policy/context/decision readers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum serialized JSON bytes.
    pub max_json_bytes: usize,
    /// Maximum JSON container nesting depth.
    pub max_nesting_depth: usize,
    /// Maximum policy rules.
    pub max_rules: usize,
    /// Maximum requirements in one rule.
    pub max_requirements_per_rule: usize,
    /// Maximum policy metadata items.
    pub max_metadata: usize,
    /// Maximum context facts.
    pub max_facts: usize,
    /// Maximum matched-rule references in one decision.
    pub max_matched_rules: usize,
    /// Maximum reason records in one decision.
    pub max_decision_reasons: usize,
    /// Maximum evidence identifiers in one decision.
    pub max_evidence_refs: usize,
    /// Maximum effective policy nodes and import edges (FOSS-437).
    pub max_imports: usize,
    /// Maximum dependency graph depth, counting hops from a root (FOSS-437).
    pub max_import_depth: usize,
    /// Reserved future exception count bound (FOSS-443).
    pub max_exceptions: usize,
    /// Reserved future adapter input budget (FOSS-452/455/457).
    pub max_adapter_bytes: usize,
    /// Maximum static validation diagnostic findings (FOSS-434).
    pub max_diagnostics: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_json_bytes: MAX_CONTRACT_BYTES,
            max_nesting_depth: 32,
            max_rules: 256,
            max_requirements_per_rule: 32,
            max_metadata: 128,
            max_facts: 2048,
            max_matched_rules: 256,
            max_decision_reasons: 256,
            max_evidence_refs: 2048,
            max_imports: 64,
            max_import_depth: 16,
            max_exceptions: 128,
            max_adapter_bytes: 1_048_576,
            max_diagnostics: 256,
        }
    }
}

impl Limits {
    /// Reject zero, unsupported or dangerously unbounded caller budgets.
    pub fn validate(&self) -> Result<(), ContractError> {
        const UPPER: usize = 100_000;
        let entries = [
            (self.max_json_bytes, ABSOLUTE_MAX_JSON_BYTES, "json bytes"),
            (self.max_nesting_depth, 128, "nesting"),
            (self.max_rules, UPPER, "rules"),
            (self.max_requirements_per_rule, UPPER, "rule requirements"),
            (self.max_metadata, UPPER, "metadata"),
            (self.max_facts, UPPER, "context facts"),
            (self.max_matched_rules, UPPER, "matched rules"),
            (self.max_decision_reasons, UPPER, "decision reasons"),
            (self.max_evidence_refs, UPPER, "evidence references"),
            (self.max_imports, UPPER, "imports"),
            (self.max_import_depth, 128, "import depth"),
            (self.max_exceptions, UPPER, "exceptions"),
            (
                self.max_adapter_bytes,
                ABSOLUTE_MAX_JSON_BYTES,
                "adapter bytes",
            ),
            (self.max_diagnostics, UPPER, "diagnostics"),
        ];
        for (value, hard_cap, name) in entries {
            if value == 0 || value > hard_cap {
                return Err(ContractError::InvalidLimit(name));
            }
        }
        Ok(())
    }

    /// Check bytes and nested containers before invoking the JSON parser.
    ///
    /// This O(n), allocation-free scan counts braces and brackets outside JSON
    /// quoted strings. It does not decide whether JSON is syntactically valid;
    /// serde_json remains the authoritative grammar validator.
    pub fn check_json(&self, input: &[u8]) -> Result<(), ContractError> {
        self.validate()?;
        if input.len() > self.max_json_bytes {
            return Err(ContractError::PayloadTooLarge);
        }

        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;

        for &byte in input {
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
            } else {
                match byte {
                    b'"' => quoted = true,
                    b'{' | b'[' => {
                        depth += 1;
                        if depth > self.max_nesting_depth {
                            return Err(ContractError::ResourceLimitExceeded("json nesting"));
                        }
                    }
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Validate how many bounded elements were supplied for a named category.
    pub fn check_count(
        &self,
        count: usize,
        maximum: usize,
        category: &'static str,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if count > maximum {
            return Err(ContractError::ResourceLimitExceeded(category));
        }
        Ok(())
    }
}
