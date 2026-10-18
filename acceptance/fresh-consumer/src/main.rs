//! Independent consumer of the pinned git source of cryptopolicy.
//! No local workspace path dependency, signature checking or enforcement.
use cryptopolicy::{CryptoContext, DecisionOutcome, PolicyDocument, RuleEffect, evaluate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy = PolicyDocument::parse_json(include_bytes!("../fixtures/policy.json"))?;
    let context = CryptoContext::parse_json(include_bytes!("../fixtures/context.json"))?;

    let permit = evaluate(&policy, &context, context.evaluation_time)?;
    assert_eq!(permit.outcome, DecisionOutcome::Permit);
    assert_eq!(permit.policy_digest, policy.canonical_digest()?);

    let mut prohibited = policy.clone();
    prohibited.rules.iter_mut()
        .find(|rule| rule.effect == RuleEffect::Allow)
        .ok_or("missing allow fixture")?
        .effect = RuleEffect::Deny;
    let deny = evaluate(&prohibited, &context, context.evaluation_time)?;
    assert_eq!(deny.outcome, DecisionOutcome::Deny);

    let mut unverified = context.clone();
    unverified.facts[0].verified = false;
    unverified.facts[0].properties.as_mut().ok_or("missing fixture properties")?.source_quality =
        Some(cryptopolicy::EvidenceQuality::Unverified);
    let unknown = evaluate(&policy, &unverified, unverified.evaluation_time)?;
    assert_eq!(unknown.outcome, DecisionOutcome::Indeterminate);

    for decision in [&permit, &deny, &unknown] {
        let wire = serde_json::to_vec(decision)?;
        let decoded = cryptopolicy::PolicyDecision::parse_json(&wire)?;
        assert_eq!(decoded, *decision);
        println!("outcome={:?} digest={} reasons={:?}",
            decision.outcome, decision.policy_digest.as_str(), decision.reasons);
    }
    println!("These are untrusted decisions; a separate caller must authenticate and enforce.");
    Ok(())
}
