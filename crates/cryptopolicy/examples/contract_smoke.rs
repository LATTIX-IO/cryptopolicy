//! Minimal offline contract example: parse and fingerprint an explicit-deny policy.
use cryptopolicy::{DefaultEffect, PolicyDocument};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = include_bytes!("../tests/fixtures/policy-v1.json");
    let policy = PolicyDocument::parse_json(source)?;
    assert_eq!(policy.default_effect, DefaultEffect::Deny);
    println!("policy-id: {}", policy.policy_id);
    println!("policy-digest: {}", policy.canonical_digest()?.as_str());
    println!("No decision made: runtime evaluator not yet implemented.");
    Ok(())
}
