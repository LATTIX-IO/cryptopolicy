//! Conservative, *non-authorizing* vocabulary projection for normative tests.
//!
//! Assessment and provider-capability reports have separate stable reason enums.
//! Only explicitly missing evidence/assurance maps to MissingRequiredAttribute.
//! This never turns a report into Permit, masks Deny, or verifies source claims.

use crate::{
    AssessmentReason, AssessmentReport, CapabilityReason, CapabilityReport, DecisionOutcome,
    ReasonCode,
};

/// Recognize missing operational evidence in an actual third-party assessment.
///
/// Only Indeterminate with a precise source/coverage gap can project to a
/// MissingRequiredAttribute explanatory reason, never a permission grant.
/// This does not authenticate external collectors or validate their claims.
pub fn assessment_missing_required_attribute(report: &AssessmentReport) -> Option<ReasonCode> {
    if report.outcome != DecisionOutcome::Indeterminate {
        return None;
    }
    const GAPS: [AssessmentReason; 6] = [
        AssessmentReason::CoverageIncomplete,
        AssessmentReason::UninspectedSources,
        AssessmentReason::NoOperationalObservation,
        AssessmentReason::MissingOperationalFields,
        AssessmentReason::MissingEvidenceReference,
        AssessmentReason::EvidenceNotAuthenticated,
    ];
    if report.reasons.iter().any(|reason| GAPS.contains(reason)) {
        Some(ReasonCode::MissingRequiredAttribute)
    } else {
        None
    }
}

/// Recognize missing independently verified provider/assurance preconditions.
///
/// A claimed HSM or provider statement remains unverified. Deny and Permit
/// outcomes are never recast as missing-attribute Indeterminate.
pub fn capability_missing_required_attribute(report: &CapabilityReport) -> Option<ReasonCode> {
    if report.outcome != DecisionOutcome::Indeterminate {
        return None;
    }
    const GAPS: [CapabilityReason; 5] = [
        CapabilityReason::MissingCapability,
        CapabilityReason::MissingEvidence,
        CapabilityReason::UnauthenticatedSource,
        CapabilityReason::AssuranceNotVerified,
        CapabilityReason::MissingRequiredCapability,
    ];
    if report.reasons.iter().any(|reason| GAPS.contains(reason)) {
        Some(ReasonCode::MissingRequiredAttribute)
    } else {
        None
    }
}
