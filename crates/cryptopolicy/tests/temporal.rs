//! Temporal rule regression: boundaries and legacy compatibility.
#![allow(clippy::unwrap_used)]
use cryptopolicy::*;
fn at(n: i64) -> EvaluationTime {
    EvaluationTime { unix_millis: n }
}
fn fixture() -> PolicyDocument {
    PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap()
}
fn ctx(n: i64) -> CryptoContext {
    let mut c =
        CryptoContext::parse_json(include_bytes!("fixtures/evaluator-context-v1.json")).unwrap();
    c.evaluation_time = at(n);
    c
}
fn rule_window(
    start: Option<i64>,
    end: Option<i64>,
    warning: Option<i64>,
    required: Option<i64>,
    prohibited: Option<i64>,
) -> RuleTemporal {
    RuleTemporal {
        effective_from: start.map(at),
        expires_at: end.map(at),
        deprecated_from: warning.map(at),
        required_from: required.map(at),
        prohibited_from: prohibited.map(at),
    }
}
fn transition() -> PolicyDocument {
    let mut p = fixture();
    p.expires_at = Some(at(1000));
    let mut warning = p
        .rules
        .iter()
        .find(|r| r.effect == RuleEffect::Warn)
        .unwrap()
        .clone();
    warning.rule_id = RuleId::parse("warn-aes").unwrap();
    warning.selector.operation = Some(CryptoOperation::Encrypt);
    warning.selector.algorithm_id = Some(AlgorithmId::parse("AES-256-GCM").unwrap());
    warning.temporal = Some(rule_window(None, None, Some(400), None, None));
    p.rules.push(warning);
    let mut deny = p
        .rules
        .iter()
        .find(|r| r.effect == RuleEffect::Warn)
        .unwrap()
        .clone();
    deny.rule_id = RuleId::parse("deny-aes").unwrap();
    deny.effect = RuleEffect::Deny;
    deny.selector.operation = Some(CryptoOperation::Encrypt);
    deny.selector.algorithm_id = Some(AlgorithmId::parse("AES-256-GCM").unwrap());
    deny.temporal = Some(rule_window(None, None, None, None, Some(600)));
    p.rules.push(deny);
    p
}
fn decide(p: &PolicyDocument, n: i64) -> PolicyDecision {
    evaluate(p, &ctx(n), at(n)).unwrap()
}
#[test]
fn transition_boundaries_and_warning() {
    let p = transition();
    for n in [150, 399] {
        let d = decide(&p, n);
        assert_eq!(d.outcome, DecisionOutcome::Permit);
        assert!(
            !d.reasons
                .iter()
                .any(|r| r.code == ReasonCode::DeprecationWarning)
        );
    }
    for n in [400, 599] {
        let d = decide(&p, n);
        assert_eq!(d.outcome, DecisionOutcome::Permit);
        assert!(
            d.reasons
                .iter()
                .any(|r| r.code == ReasonCode::DeprecationWarning)
        );
    }
    for n in [600, 601] {
        let d = decide(&p, n);
        assert_eq!(d.outcome, DecisionOutcome::Deny);
        assert!(d.reasons.iter().any(|r| r.code == ReasonCode::ExplicitDeny));
    }
}
#[test]
fn activation_inclusive_expiry_exclusive() {
    let mut p = fixture();
    p.expires_at = Some(at(1000));
    let r = p
        .rules
        .iter_mut()
        .find(|r| r.effect == RuleEffect::Allow)
        .unwrap();
    r.temporal = Some(rule_window(Some(400), Some(600), None, None, None));
    assert_eq!(decide(&p, 399).outcome, DecisionOutcome::Deny);
    assert_eq!(decide(&p, 400).outcome, DecisionOutcome::Permit);
    assert_eq!(decide(&p, 599).outcome, DecisionOutcome::Permit);
    assert_eq!(decide(&p, 600).outcome, DecisionOutcome::Deny);
}
#[test]
fn mandatory_cutover_is_not_bypassable() {
    let mut p = fixture();
    p.expires_at = Some(at(1000));
    let r = p
        .rules
        .iter_mut()
        .find(|r| r.effect == RuleEffect::Require)
        .unwrap();
    r.requirements.push(Requirement::MinimumKeyBits(512));
    r.temporal = Some(rule_window(None, None, None, Some(400), None));
    assert_eq!(decide(&p, 399).outcome, DecisionOutcome::Permit);
    assert_eq!(decide(&p, 400).outcome, DecisionOutcome::Deny);
}
#[test]
fn malformed_windows_rejected() {
    let mut p = fixture();
    p.rules
        .iter_mut()
        .find(|r| r.effect == RuleEffect::Allow)
        .unwrap()
        .temporal = Some(rule_window(Some(600), Some(600), None, None, None));
    assert!(p.validate().is_err());
    p.rules
        .iter_mut()
        .find(|r| r.effect == RuleEffect::Allow)
        .unwrap()
        .temporal = Some(rule_window(Some(600), Some(601), Some(500), None, None));
    assert!(p.validate().is_err());
}
#[test]
fn canonical_legacy_digest_unchanged() {
    let p = fixture();
    assert_eq!(
        p.canonical_digest().unwrap().as_str(),
        "5eebc2f80c0fc21d7b2d065edb6f2bf095dedd546f10974078bd9c9e868af43f"
    );
    assert!(
        serde_json::to_value(&p).unwrap()["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("temporal").is_none())
    );
}
#[test]
fn order_and_historical_replay() {
    let p = transition();
    let mut q = p.clone();
    q.rules.reverse();
    assert_eq!(p.canonical_digest().unwrap(), q.canonical_digest().unwrap());
    for n in [399, 400, 599, 600] {
        assert_eq!(decide(&p, n), decide(&q, n));
    }
}
#[test]
fn absent_deny_selector_does_not_bypass() {
    let mut p = transition();
    let mut c = ctx(600);
    c.facts[0].algorithm_id = None;
    assert_ne!(
        evaluate(&p, &c, at(600)).unwrap().outcome,
        DecisionOutcome::Permit
    );
    p.rules.reverse();
    assert_ne!(
        evaluate(&p, &c, at(600)).unwrap().outcome,
        DecisionOutcome::Permit
    );
}
#[test]
fn time_mismatch_is_error() {
    assert!(evaluate(&transition(), &ctx(500), at(600)).is_err());
}
