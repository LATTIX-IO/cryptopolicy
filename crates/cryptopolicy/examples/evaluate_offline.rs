//! Offline evaluator demonstration. No key operation or network request occurs.
use cryptopolicy::{CryptoContext, DecisionOutcome, PolicyDocument, evaluate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy =
        PolicyDocument::parse_json(include_bytes!("../tests/fixtures/evaluator-policy-v1.json"))?;
    let context = CryptoContext::parse_json(include_bytes!(
        "../tests/fixtures/evaluator-context-v1.json"
    ))?;
    let decision = evaluate(&policy, &context, context.evaluation_time)?;
    assert_eq!(decision.outcome, DecisionOutcome::Permit);
    println!(
        "policy={} result={:?}",
        decision.policy_id, decision.outcome
    );
    println!("digest={}", decision.policy_digest.as_str());
    for reason in &decision.reasons {
        println!("reason={:?} rule={:?}", reason.code, reason.rule_id);
    }

    let mut denied_policy = policy.clone();
    denied_policy.rules.push(cryptopolicy::PolicyRule {
        rule_id: cryptopolicy::RuleId::parse("hard-deny")?,
        effect: cryptopolicy::RuleEffect::Deny,
        selector: cryptopolicy::RuleSelector {
            match_all: true,
            operation: None,
            algorithm_id: None,
            profile_id: None,
            environment: None,
            advanced: None,
        },
        requirements: vec![],
        temporal: None,
    });
    let blocked = evaluate(&denied_policy, &context, context.evaluation_time)?;
    assert_eq!(blocked.outcome, DecisionOutcome::Deny);
    println!("hard_deny_result={:?}", blocked.outcome);
    println!("Decisions are data records, not authenticated enforcement tokens.");
    Ok(())
}
