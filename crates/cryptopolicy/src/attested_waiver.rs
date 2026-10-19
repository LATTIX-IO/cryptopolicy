//! FOSS-508: profile-attested, exact-scope hypothetical exception assessment.
//!
//! A candidate Permit is ONLY policy evaluation data. This function does not
//! authenticate a policy issuer itself, sign an authorization, execute crypto,
//! authorize a PEP, persist revocation or mutate the pinned original graph.
//!
//! Trust checks are re-executed on EVERY call, not inferred from caller-
//! constructed reports: E0 approval, E1 owner grant, current owner registry,
//! actual key generation/profile, and independently attested source evidence.

use crate::{
    CompositionError, DecisionOutcome, ExceptionDeviation, ExceptionSourceVerifier,
    KeyProfileBindingVerifier, PolicyWaiverAuthorityVerifier, ProfileEvidenceVerifier,
    ProfileParameterWitness, ProfileQualificationFinding, ProfileQualificationRequest, ReasonCode,
    ReviewedWaiverRequest, RuleEffect, WaivabilityRegistryVerifier, WaiverAdmissionDisposition,
    WaiverAdmissionReport, WaiverCandidateRequest, evaluate_qualified_profile_with_limits,
    evaluate_reviewed_waiver_candidate,
};

/// One immutable, original target and its explicitly attested profile witness.
///
/// The inner reviewed request supplies the *original* pinned EffectivePolicy,
/// current original context, exact E0/E1 references, owner registry and the
/// actual key/profile binding. No caller-provided "verified" boolean can
/// substitute for the verifier callbacks below.
pub struct AttestedWaiverRequest<'a> {
    /// Exact FOSS-502 reviewed owner registry and E0/E1 admission references.
    pub reviewed: ReviewedWaiverRequest<'a>,
    /// Independently attestable canonical key size or named parameter set.
    pub parameter: &'a ProfileParameterWitness,
}

fn reject(
    original: &WaiverAdmissionReport,
    disposition: WaiverAdmissionDisposition,
) -> WaiverAdmissionReport {
    let mut report = original.clone();
    report.disposition = disposition;
    report.candidate_outcome = report.original.outcome;
    report.candidate_target_layer = None;
    report
}

/// Assess a *hypothetical*, never enforceable, exact owner-approved waiver.
///
/// Before considering any simulation this operation executes all four FOSS-502
/// independent approval/ownership gates, requiring the status
/// ProfileEvaluatorUnsupported (the previous deliberately fail-closed result).
/// It then checks that the named target rule actually BLOCKED the original
/// runtime policy decision, and requalifies the exact canonical profile with
/// the pinned embedded catalog plus BOTH source/key verifiers.
///
/// Only after those checks does it clone ONE target policy and remove ONE
/// explicitly approved Deny or failed/unknown mandatory Require. Every
/// named compensating Require must exist in that policy AND appear matched and
/// satisfied in the newly qualified target evaluation. Other original policy
/// nodes retain their original decisions: Deny > Indeterminate > Permit.
///
/// A positive hypothetical candidate does not authenticate policy issuer or
/// issue any PEP/KMS grant. The source policy graph and original digest remain
/// unchanged and are returned separately from the derived target decision.
/// Existing unverified evaluators and blocked-audit receipt contracts are
/// untouched, and will never treat this report as an executable permission.
pub fn evaluate_attested_waiver_candidate<
    E: ExceptionSourceVerifier,
    A: PolicyWaiverAuthorityVerifier,
    R: WaivabilityRegistryVerifier,
    K: KeyProfileBindingVerifier,
    P: ProfileEvidenceVerifier,
>(
    attested: AttestedWaiverRequest<'_>,
    exception_verifier: &E,
    owner_verifier: &A,
    registry_verifier: &R,
    key_verifier: &K,
    source_verifier: &P,
) -> Result<WaiverAdmissionReport, CompositionError> {
    let AttestedWaiverRequest {
        reviewed:
            ReviewedWaiverRequest {
                request,
                registry,
                key_binding,
            },
        parameter,
    } = attested;
    let WaiverCandidateRequest {
        effective,
        context,
        actual_scope,
        time,
        exception,
        grant,
        limits,
    } = request;

    // Real FOSS-502 admission is executed afresh, not a cached report or an
    // untrusted "registry passed" bit. Its only affirmative preflight status
    // remains ProfileEvaluatorUnsupported, never a Permit.
    let preflight = evaluate_reviewed_waiver_candidate(
        ReviewedWaiverRequest {
            request,
            registry,
            key_binding,
        },
        exception_verifier,
        owner_verifier,
        registry_verifier,
        key_verifier,
    )?;
    if preflight.disposition != WaiverAdmissionDisposition::ProfileEvaluatorUnsupported {
        return Ok(preflight);
    }

    let Some(target) = effective
        .components()
        .iter()
        .find(|component| component.reference == exception.policy)
    else {
        return Ok(reject(
            &preflight,
            WaiverAdmissionDisposition::NoMatchingMandatoryRule,
        ));
    };
    let effect = match exception.deviation {
        ExceptionDeviation::RuleDeny => RuleEffect::Deny,
        ExceptionDeviation::RuleRequirement => RuleEffect::Require,
    };
    let absent = match exception.deviation {
        ExceptionDeviation::RuleDeny => WaiverAdmissionDisposition::NoMatchingExplicitDeny,
        ExceptionDeviation::RuleRequirement => WaiverAdmissionDisposition::NoMatchingMandatoryRule,
    };
    let exists = target
        .document
        .rules
        .iter()
        .any(|rule| rule.rule_id == exception.target_rule && rule.effect == effect);
    if !exists {
        return Ok(reject(&preflight, absent));
    }

    // The original EFFECTIVE decision is evaluated directly from the compiled
    // immutable graph. The targeted rule must actually have matched and
    // produced a blocking reason in the correct original policy layer.
    let blocked = preflight.original.components.iter().any(|layer| {
        layer.reference == exception.policy
            && layer.decision.outcome != DecisionOutcome::Permit
            && layer
                .decision
                .matched_rules
                .contains(&exception.target_rule)
            && layer.decision.reasons.iter().any(|reason| {
                reason.rule_id.as_ref() == Some(&exception.target_rule)
                    && match exception.deviation {
                        ExceptionDeviation::RuleDeny => reason.code == ReasonCode::ExplicitDeny,
                        ExceptionDeviation::RuleRequirement => matches!(
                            reason.code,
                            ReasonCode::RequirementNotSatisfied
                                | ReasonCode::MissingRequiredAttribute
                        ),
                    }
            })
    });
    if !blocked {
        return Ok(reject(&preflight, absent));
    }

    // Every compensator is an independently enforced, nonempty Require from
    // the EXACT source policy. An unrelated node's equal RuleId is irrelevant.
    if grant.compensating_controls.is_empty()
        || !grant.compensating_controls.iter().all(|id| {
            target.document.rules.iter().any(|rule| {
                rule.rule_id == *id
                    && rule.effect == RuleEffect::Require
                    && !rule.requirements.is_empty()
            })
        })
    {
        return Ok(reject(
            &preflight,
            WaiverAdmissionDisposition::CompensationNotSatisfied,
        ));
    }

    // Clone-only local change. The compiled source policy/reference and all
    // other baseline, overlay and import nodes remain completely immutable.
    let mut hypothetical = target.document.clone();
    let old_count = hypothetical.rules.len();
    hypothetical
        .rules
        .retain(|rule| rule.rule_id != exception.target_rule);
    if hypothetical.rules.len().checked_add(1) != Some(old_count) {
        return Ok(reject(&preflight, absent));
    }

    // FOSS-507 always calls FOSS-505 profile qualification against the pinned
    // catalog and both independent source/key proof callbacks. No caller can
    // supply a forged ProfileQualificationReport as an input.
    let qualified = evaluate_qualified_profile_with_limits(
        &hypothetical,
        ProfileQualificationRequest {
            context,
            actual_scope,
            binding: key_binding,
            parameter,
            time,
            limits,
        },
        source_verifier,
        key_verifier,
    )?;
    if qualified.qualification.finding != ProfileQualificationFinding::ReadyForVerifiedEvaluator {
        return Ok(reject(
            &preflight,
            WaiverAdmissionDisposition::ProfileQualificationNotReady,
        ));
    }
    let candidate = qualified.decision;
    if candidate.outcome != DecisionOutcome::Permit
        || !grant.compensating_controls.iter().all(|id| {
            candidate.matched_rules.contains(id)
                && candidate.reasons.iter().any(|reason| {
                    reason.rule_id.as_ref() == Some(id)
                        && reason.code == ReasonCode::RequirementSatisfied
                })
        })
    {
        return Ok(reject(
            &preflight,
            WaiverAdmissionDisposition::CompensationNotSatisfied,
        ));
    }

    // Derived decision MUST carry a distinct digest. The old canonical
    // original policy digest is preserved in the original EffectiveDecision.
    if candidate.policy_digest == target.reference.digest {
        return Ok(reject(
            &preflight,
            WaiverAdmissionDisposition::CompensationNotSatisfied,
        ));
    }
    let mut has_deny = false;
    let mut has_indeterminate = false;
    for layer in &preflight.original.components {
        let outcome = if layer.reference == exception.policy {
            candidate.outcome
        } else {
            layer.decision.outcome
        };
        match outcome {
            DecisionOutcome::Deny => has_deny = true,
            DecisionOutcome::Indeterminate => has_indeterminate = true,
            DecisionOutcome::Permit => {}
        }
    }
    let outcome = if has_deny {
        DecisionOutcome::Deny
    } else if has_indeterminate {
        DecisionOutcome::Indeterminate
    } else {
        DecisionOutcome::Permit
    };
    Ok(WaiverAdmissionReport {
        disposition: WaiverAdmissionDisposition::CandidateEvaluated,
        candidate_outcome: outcome,
        candidate_target_layer: Some(candidate),
        ..preflight
    })
}
