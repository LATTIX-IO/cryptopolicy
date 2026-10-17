//! Offline policy-set compilation and intersection demonstration.
use cryptopolicy::{
    compile_policy_set, CryptoContext, DecisionOutcome, Limits, PolicyDocument, PolicyId,
    PolicyNode, PolicyReference, PolicySet, SchemaVersion,
};
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let baseline = PolicyDocument::parse_json(
        include_bytes!("../tests/fixtures/evaluator-policy-v1.json"),
    )?;
    let mut overlay = baseline.clone();
    overlay.policy_id = PolicyId::parse("org:overlay-prod")?;

    let base_ref = PolicyReference::from_document(&baseline)?;
    let overlay_ref = PolicyReference::from_document(&overlay)?;
    let set = PolicySet {
        schema_version: SchemaVersion::V1,
        baseline: base_ref,
        overlays: vec![overlay_ref],
    };
    let catalog = BTreeMap::from([
        (baseline.policy_id.clone(), PolicyNode {
            schema_version: SchemaVersion::V1,
            document: baseline,
            imports: vec![],
        }),
        (overlay.policy_id.clone(), PolicyNode {
            schema_version: SchemaVersion::V1,
            document: overlay,
            imports: vec![],
        }),
    ]);
    let limits = Limits::default();
    let compiled = compile_policy_set(
        &set,
        &|reference: &PolicyReference| Ok(catalog.get(&reference.policy_id).cloned()),
        &limits,
    )?;
    let context = CryptoContext::parse_json(
        include_bytes!("../tests/fixtures/evaluator-context-v1.json"),
    )?;
    let decision = compiled.evaluate(&context, context.evaluation_time, &limits)?;
    assert_eq!(decision.outcome, DecisionOutcome::Permit);
    assert_eq!(decision.components.len(), 2);
    println!("effective_policy_digest={}", compiled.digest().as_str());
    println!("canonical_bytes={}", compiled.canonical_bytes().len());
    println!("outcome={:?}, components={}", decision.outcome, decision.components.len());
    println!("No issuer, policy, or evidence authentication was performed.");
    Ok(())
}
