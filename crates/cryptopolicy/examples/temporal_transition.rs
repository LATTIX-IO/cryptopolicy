//! Explicit UTC evaluation of a synthetic cryptographic transition.
use cryptopolicy::*;
fn at(n: i64) -> EvaluationTime {
    EvaluationTime { unix_millis: n }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut p =
        PolicyDocument::parse_json(include_bytes!("../tests/fixtures/evaluator-policy-v1.json"))?;
    let mut c = CryptoContext::parse_json(include_bytes!(
        "../tests/fixtures/evaluator-context-v1.json"
    ))?;
    p.expires_at = Some(at(1000));
    let mut template = p
        .rules
        .iter()
        .find(|r| r.effect == RuleEffect::Warn)
        .ok_or("no warning fixture")?
        .clone();
    template.selector.operation = Some(CryptoOperation::Encrypt);
    template.selector.algorithm_id = Some(AlgorithmId::parse("AES-256-GCM")?);
    let mut warn = template.clone();
    warn.rule_id = RuleId::parse("transition-warn")?;
    warn.temporal = Some(RuleTemporal {
        effective_from: None,
        expires_at: None,
        deprecated_from: Some(at(400)),
        required_from: None,
        prohibited_from: None,
    });
    p.rules.push(warn);
    let mut deny = template;
    deny.rule_id = RuleId::parse("transition-deny")?;
    deny.effect = RuleEffect::Deny;
    deny.temporal = Some(RuleTemporal {
        effective_from: None,
        expires_at: None,
        deprecated_from: None,
        required_from: None,
        prohibited_from: Some(at(600)),
    });
    p.rules.push(deny);
    for n in [399, 400, 600] {
        c.evaluation_time = at(n);
        let d = evaluate(&p, &c, at(n))?;
        println!("time={} outcome={:?} reasons={:?}", n, d.outcome, d.reasons);
        assert_eq!(
            d.outcome,
            if n >= 600 {
                DecisionOutcome::Deny
            } else {
                DecisionOutcome::Permit
            }
        );
    }
    println!("These records are not authenticated enforcement tokens.");
    Ok(())
}
