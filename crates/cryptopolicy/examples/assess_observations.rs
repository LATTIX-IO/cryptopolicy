//! FOSS-447 offline assessment demo. The verifier is synthetic test-only
//! binding, NOT real cryptographic signature verification.
use cryptopolicy::{
    AssessmentContext, AssessmentObservation, AssessmentReason, DecisionOutcome, EvidenceId,
    PolicyDocument, UnverifiedEvidence, assess,
};

fn fixture_binding(
    context: &AssessmentContext,
    observation: &AssessmentObservation,
) -> Result<bool, cryptopolicy::ContractError> {
    Ok(context.snapshot_id == EvidenceId::parse("snapshot:cryptomap:01")?
        && context.scope.activity_id == EvidenceId::parse("session:42")?
        && observation.observation_id == EvidenceId::parse("obs:tls:1")?
        && observation.source_id == EvidenceId::parse("collector:tls")?
        && observation.evidence_ref == Some(EvidenceId::parse("evidence:tls:1")?))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = PolicyDocument::parse_json(
        include_bytes!("../tests/fixtures/evaluator-policy-v1.json"),
    )?;
    let context = AssessmentContext::parse_json(
        include_bytes!("../tests/fixtures/assessment-observed-v1.json"),
    )?;

    let unverified = assess(&policy, &context, context.evaluation_time, &UnverifiedEvidence)?;
    assert_eq!(unverified.outcome, DecisionOutcome::Indeterminate);
    assert!(unverified.reasons.contains(&AssessmentReason::EvidenceNotAuthenticated));
    println!("unverified outcome: {:?}", unverified.outcome);

    // Synthetic only: a fixture with an already verified identity/binding.
    let verified = assess(&policy, &context, context.evaluation_time, &fixture_binding)?;
    assert_eq!(verified.outcome, DecisionOutcome::Permit);
    println!("fixture-bound outcome: {:?}", verified.outcome);
    println!(
        "source={} evidence={}",
        verified.findings[0].source_id,
        verified.findings[0].evidence_ref.as_ref().ok_or("missing evidence")?
    );
    println!("assessment is NOT an enforcement token or a policy signature");

    let partial = AssessmentContext::parse_json(
        include_bytes!("../tests/fixtures/assessment-partial-v1.json"),
    )?;
    let restricted = assess(&policy, &partial, partial.evaluation_time, &fixture_binding)?;
    assert_eq!(restricted.outcome, DecisionOutcome::Indeterminate);
    println!("partial coverage outcome: {:?}", restricted.outcome);
    Ok(())
}
