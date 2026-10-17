//! FOSS-437 atomic policy-set compilation, digest and conjunctive decision tests.
#![allow(clippy::unwrap_used)] // Fixtures deliberately construct fallible identities.

use cryptopolicy::*;
use std::collections::BTreeMap;

fn policy() -> PolicyDocument {
    PolicyDocument::parse_json(include_bytes!("fixtures/evaluator-policy-v1.json")).unwrap()
}
fn context() -> CryptoContext {
    CryptoContext::parse_json(include_bytes!("fixtures/evaluator-context-v1.json")).unwrap()
}
fn rename(mut policy: PolicyDocument, name: &str) -> PolicyDocument {
    policy.policy_id = PolicyId::parse(name).unwrap();
    policy
}
fn reference(policy: &PolicyDocument) -> PolicyReference {
    PolicyReference::from_document(policy).unwrap()
}
fn node(policy: PolicyDocument, imports: Vec<PolicyReference>) -> PolicyNode {
    PolicyNode { document: policy, imports }
}
fn catalog(nodes: Vec<PolicyNode>) -> BTreeMap<PolicyId, PolicyNode> {
    nodes.into_iter().map(|n| (n.document.policy_id.clone(), n)).collect()
}
fn compose(
    set: &PolicySet, map: &BTreeMap<PolicyId, PolicyNode>, limits: &Limits,
) -> Result<EffectivePolicy, CompositionError> {
    compile_policy_set(
        set, &|r: &PolicyReference| Ok(map.get(&r.policy_id).cloned()), limits,
    )
}
fn set(root: &PolicyDocument, overlays: &[PolicyDocument]) -> PolicySet {
    PolicySet {
        baseline: reference(root),
        overlays: overlays.iter().map(reference).collect(),
    }
}
fn limits() -> Limits { Limits::default() }
fn eval(effective: &EffectivePolicy) -> EffectiveDecision {
    let c = context();
    effective.evaluate(&c, c.evaluation_time, &limits()).unwrap()
}
fn deny(id: &str) -> PolicyRule {
    PolicyRule {
        rule_id: RuleId::parse(id).unwrap(),
        effect: RuleEffect::Deny,
        selector: RuleSelector {
            match_all: true,
            operation: None, algorithm_id: None, profile_id: None,
            environment: None, advanced: None,
        },
        requirements: vec![],
    }
}

#[test]
fn baseline_only_returns_same_evaluator_outcome() {
    let base = policy();
    let set = set(&base, &[]);
    let map = catalog(vec![node(base, vec![])]);
    let effective = compose(&set, &map, &limits()).unwrap();
    let d = eval(&effective);
    assert_eq!(d.outcome, DecisionOutcome::Permit);
    assert_eq!(d.components.len(), 1);
    assert_eq!(d.components[0].decision.outcome, DecisionOutcome::Permit);
    assert_eq!(effective.components().len(), 1);
    assert_eq!(effective.policy_set(), &set);
    assert!(effective.canonical_bytes().starts_with(EFFECTIVE_POLICY_DOMAIN_V1));
    assert_eq!(effective.digest().as_str().len(), 64);
}

#[test]
fn both_baseline_and_overlay_must_explicitly_permit() {
    let base = policy();
    let mut overlay = rename(policy(), "org:overlay");
    overlay.rules.retain(|r| r.effect == RuleEffect::Allow);
    overlay.rules[0].requirements.push(Requirement::MinSecurityCategory(5));
    let set = set(&base, &[overlay.clone()]);
    let effective = compose(&set, &catalog(vec![node(base, vec![]),node(overlay,vec![])]), &limits()).unwrap();
    let d = eval(&effective);
    assert_eq!(d.outcome, DecisionOutcome::Permit);
    assert!(d.components.iter().all(|x| x.decision.outcome == DecisionOutcome::Permit));
    assert_eq!(d.effective_policy_digest, *effective.digest());
}

#[test]
fn overlay_allow_cannot_broaden_baseline_denial() {
    let mut base = policy();
    base.rules.push(deny("deny:all"));
    let overlay = rename(policy(), "org:overlay");
    let graph = catalog(vec![node(base.clone(),vec![]),node(overlay.clone(),vec![])]);
    let effective = compose(&set(&base,&[overlay]), &graph, &limits()).unwrap();
    let d = eval(&effective);
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert!(d.components.iter().any(|x| x.decision.outcome == DecisionOutcome::Deny));
    assert!(d.components.iter().any(|x| x.decision.outcome == DecisionOutcome::Permit));
}

#[test]
fn overlay_deny_cannot_be_overridden_by_other_layer() {
    let base = policy();
    let mut overlay = rename(policy(), "org:overlay");
    overlay.rules.push(deny("deny:overlay"));
    let graph = catalog(vec![node(base.clone(),vec![]),node(overlay.clone(),vec![])]);
    let effective = compose(&set(&base,&[overlay]), &graph, &limits()).unwrap();
    let d = eval(&effective);
    assert_eq!(d.outcome, DecisionOutcome::Deny);
    assert_eq!(d.components.len(), 2);
}

#[test]
fn deny_only_overlay_cannot_implicitly_authorize() {
    let base = policy();
    let mut overlay = rename(policy(), "org:guard-only");
    overlay.rules.clear();
    overlay.default_effect = DefaultEffect::Allow;
    let graph = catalog(vec![node(base.clone(),vec![]),node(overlay.clone(),vec![])]);
    let d = eval(&compose(&set(&base,&[overlay]), &graph,&limits()).unwrap());
    assert_eq!(d.outcome, DecisionOutcome::Deny);
}

#[test]
fn indeterminate_layer_blocks_final_permit() {
    let base = policy();
    let mut overlay = rename(policy(), "org:overlay");
    overlay.rules.retain(|r| r.effect == RuleEffect::Allow);
    overlay.rules[0].requirements.push(Requirement::Provider(
        ProviderId::parse("provider:alpha").unwrap(),
    ));
    let graph = catalog(vec![node(base.clone(),vec![]),node(overlay.clone(),vec![])]);
    let effective = compose(&set(&base,&[overlay]), &graph,&limits()).unwrap();
    let mut c = context();
    c.facts[0].properties.as_mut().unwrap().provider_id = None;
    let d = effective.evaluate(&c,c.evaluation_time,&limits()).unwrap();
    assert_eq!(d.outcome, DecisionOutcome::Indeterminate);
    assert!(!d.components.iter().any(|x| x.decision.outcome == DecisionOutcome::Deny));
}

#[test]
fn definitive_deny_overrides_indeterminate_component() {
    let mut base = policy();
    base.rules.push(deny("deny:hard"));
    let mut overlay = rename(policy(), "org:overlay");
    overlay.rules.retain(|r| r.effect == RuleEffect::Allow);
    overlay.rules[0].requirements.push(Requirement::Provider(ProviderId::parse("provider:alpha").unwrap()));
    let graph = catalog(vec![node(base.clone(),vec![]),node(overlay.clone(),vec![])]);
    let effective = compose(&set(&base,&[overlay]), &graph,&limits()).unwrap();
    let mut c = context();
    c.facts[0].properties.as_mut().unwrap().provider_id = None;
    assert_eq!(effective.evaluate(&c,c.evaluation_time,&limits()).unwrap().outcome,DecisionOutcome::Deny);
}

#[test]
fn nested_imports_compose_all_layers_and_preserve_scoped_reasons() {
    let base = policy();
    let imported = rename(policy(),"org:import-a");
    let leaf = rename(policy(),"org:leaf");
    let graph = catalog(vec![
        node(base.clone(),vec![reference(&imported)]),
        node(imported.clone(),vec![reference(&leaf)]),
        node(leaf,vec![]),
    ]);
    let effective = compose(&set(&base,&[]),&graph,&limits()).unwrap();
    let d = eval(&effective);
    assert_eq!(d.outcome,DecisionOutcome::Permit);
    assert_eq!(effective.components().len(),3);
    assert_eq!(d.components.len(),3);
    for (actual,policy) in d.components.iter().zip(effective.components()) {
        assert_eq!(actual.reference,policy.reference);
        assert_eq!(actual.decision.policy_id,policy.document.policy_id);
        assert_eq!(actual.decision.outcome,DecisionOutcome::Permit);
    }
    // RuleId collisions across different policy identities are scoped.
    assert_eq!(d.components[0].decision.matched_rules,d.components[1].decision.matched_rules);
}

#[test]
fn import_and_overlay_reordering_preserves_effective_digest_and_bytes() {
    let base=policy();
    let a=rename(policy(),"org:a");
    let b=rename(policy(),"org:b");
    let c=rename(policy(),"org:c");
    let root=vec![reference(&a),reference(&b)];
    let map=catalog(vec![
        node(base.clone(),root.clone()),
        node(a.clone(),vec![reference(&c)]),
        node(b.clone(),vec![]),node(c.clone(),vec![]),
    ]);
    let set_a=set(&base,&[a.clone(),b.clone()]);
    let first=compose(&set_a,&map,&limits()).unwrap();
    let mut reversed=map.clone();
    reversed.get_mut(&base.policy_id).unwrap().imports.reverse();
    let second=compose(&set(&base,&[b,a]),&reversed,&limits()).unwrap();
    assert_eq!(first.digest(),second.digest());
    assert_eq!(first.canonical_bytes(),second.canonical_bytes());
    assert_eq!(eval(&first),eval(&second));
}

#[test]
fn rule_and_requirement_permutation_does_not_change_effective_identity() {
    let base=policy();
    let reference=reference(&base);
    let first=compose(&set(&base,&[]),&catalog(vec![node(base.clone(),vec![])]),&limits()).unwrap();
    let mut shuffled=base.clone();
    shuffled.rules.reverse();
    for r in &mut shuffled.rules {r.requirements.reverse();}
    shuffled.metadata.reverse();
    let second=compose(&set(&shuffled,&[]),&catalog(vec![node(shuffled,vec![])]),&limits()).unwrap();
    assert_eq!(reference,first.policy_set().baseline);
    assert_eq!(first.canonical_bytes(),second.canonical_bytes());
    assert_eq!(first.digest(),second.digest());
}

#[test]
fn added_import_or_modified_topology_changes_effective_digest() {
    let base=policy();
    let other=rename(policy(),"org:dependency");
    let map0=catalog(vec![node(base.clone(),vec![]),node(other.clone(),vec![])]);
    let one=compose(&set(&base,&[]),&map0,&limits()).unwrap();
    let map1=catalog(vec![node(base.clone(),vec![reference(&other)]),node(other,vec![])]);
    let two=compose(&set(&base,&[]),&map1,&limits()).unwrap();
    assert_ne!(one.digest(),two.digest());
    assert_ne!(one.canonical_bytes(),two.canonical_bytes());
}

#[test]
fn unresolved_import_is_not_a_partial_compiled_policy() {
    let base=policy();
    let other=rename(policy(),"org:absent");
    let map=catalog(vec![node(base.clone(),vec![reference(&other)])]);
    assert_eq!(compose(&set(&base,&[]),&map,&limits()),Err(CompositionError::UnresolvedReference(other.policy_id)));
}

#[test]
fn mutable_or_tampered_document_fails_pinned_digest_check() {
    let base=policy();
    let original=set(&base,&[]);
    let mut tampered=base;
    tampered.metadata[0].value.push_str("-changed");
    assert_eq!(compose(&original,&catalog(vec![node(tampered,vec![])]),&limits()),Err(CompositionError::DigestMismatch));
}

#[test]
fn version_mismatch_and_wrong_policy_id_are_rejected() {
    let base=policy();
    let set=set(&base,&[]);
    let mut changed=base.clone();
    changed.version=PolicyVersion::parse("2.0.0").unwrap();
    assert_eq!(compose(&set,&catalog(vec![node(changed,vec![])]),&limits()),Err(CompositionError::IdentityMismatch));
    let wrong=rename(base,"org:wrong");
    let map=BTreeMap::from([(set.baseline.policy_id.clone(),node(wrong,vec![]))]);
    assert_eq!(compose(&set,&map,&limits()),Err(CompositionError::IdentityMismatch));
}

#[test]
fn direct_and_indirect_cycles_fail_closed() {
    let base=policy();
    let a=rename(policy(),"org:cycle-a");
    let base_ref=reference(&base);
    let a_ref=reference(&a);
    let self_cycle=catalog(vec![node(base.clone(),vec![base_ref.clone()])]);
    assert_eq!(compose(&set(&base,&[]),&self_cycle,&limits()),Err(CompositionError::CycleDetected));
    let mutual=catalog(vec![node(base.clone(),vec![a_ref]),node(a,vec![base_ref])]);
    assert_eq!(compose(&set(&base,&[]),&mutual,&limits()),Err(CompositionError::CycleDetected));
}

#[test]
fn duplicate_direct_import_and_duplicate_overlay_roots_are_rejected() {
    let base=policy();let a=rename(policy(),"org:a");
    let same=reference(&a);
    let map=catalog(vec![node(base.clone(),vec![same.clone(),same]),node(a.clone(),vec![])]);
    assert_eq!(compose(&set(&base,&[]),&map,&limits()),Err(CompositionError::DuplicateReference));
    let s=set(&base,&[a.clone(),a]);
    assert_eq!(compose(&s,&map,&limits()),Err(CompositionError::DuplicateReference));
}

#[test]
fn conflicting_pin_same_policy_id_even_different_version_is_rejected() {
    let base=policy();let a=rename(policy(),"org:conflict");
    let mut alt=a.clone();alt.version=PolicyVersion::parse("2.0.0").unwrap();
    let graph=catalog(vec![node(base.clone(),vec![reference(&a)]),node(a.clone(),vec![])]);
    let mut set=set(&base,&[alt]);
    assert_eq!(compose(&set,&graph,&limits()),Err(CompositionError::ReferenceConflict));
    set.overlays.push(set.baseline.clone());
    assert_eq!(compose(&set,&graph,&limits()),Err(CompositionError::DuplicateReference));
}

#[test]
fn import_depth_node_count_and_edge_budgets_are_hard_limits() {
    let base=policy();let a=rename(policy(),"org:a");let b=rename(policy(),"org:b");
    let map=catalog(vec![node(base.clone(),vec![reference(&a)]),node(a.clone(),vec![reference(&b)]),node(b,vec![])]);
    let depth=Limits{max_import_depth:1,..limits()};
    assert_eq!(compose(&set(&base,&[]),&map,&depth),Err(CompositionError::ResourceLimit("import_depth")));
    let nodes=Limits{max_imports:2,..limits()};
    assert_eq!(compose(&set(&base,&[]),&map,&nodes),Err(CompositionError::ResourceLimit("import_edges")));
}

#[test]
fn total_rule_budget_is_for_entire_graph_not_per_policy() {
    let base=policy();let a=rename(policy(),"org:a");
    let graph=catalog(vec![node(base.clone(),vec![]),node(a.clone(),vec![])]);
    let quota=Limits{max_rules:base.rules.len()+a.rules.len()-1,..limits()};
    assert_eq!(compose(&set(&base,&[a]),&graph,&quota),Err(CompositionError::ResourceLimit("total_rules")));
}

#[test]
fn canonical_blob_byte_budget_rejects_one_short_without_partial_success() {
    let base=policy();let a=rename(policy(),"org:a");
    let graph=catalog(vec![node(base.clone(),vec![]),node(a.clone(),vec![])]);
    let roots=set(&base,&[a]);
    let normal=compose(&roots,&graph,&limits()).unwrap();
    let upper=normal.canonical_bytes().len();
    let near=Limits{max_json_bytes:upper-1,..limits()};
    assert_eq!(compose(&roots,&graph,&near),Err(CompositionError::ResourceLimit("effective_bytes")));
    let exact=Limits{max_json_bytes:upper,..limits()};
    assert_eq!(compose(&roots,&graph,&exact).unwrap().canonical_bytes().len(),upper);
}

#[test]
fn aggregate_evaluation_is_bounded_and_clock_mismatch_is_an_error() {
    let base=policy();let a=rename(policy(),"org:a");
    let graph=catalog(vec![node(base.clone(),vec![]),node(a.clone(),vec![])]);
    let effective=compose(&set(&base,&[a]),&graph,&limits()).unwrap();
    let c=context();
    assert_eq!(
        effective.evaluate(&c,EvaluationTime{unix_millis:c.evaluation_time.unix_millis+1},&limits()),
        Err(CompositionError::Contract(ContractError::InvalidDocument("evaluation time mismatch")))
    );
    let small=Limits{max_json_bytes:200,..limits()};
    assert!(effective.evaluate(&c,c.evaluation_time,&small).is_err());
}

#[test]
fn strict_policy_set_parser_rejects_unknown_duplicate_and_invalid_references() {
    let p=policy();let roots=set(&p,&[]);
    let valid=serde_json::to_vec(&roots).unwrap();
    assert_eq!(PolicySet::parse_json_with_limits(&valid,&limits()).unwrap(),roots);
    let text=String::from_utf8(valid).unwrap();
    let unexpected=text.replacen("\"overlays\":[]","\"overlays\":[],\"bypass_baseline\":true",1);
    assert!(PolicySet::parse_json_with_limits(unexpected.as_bytes(),&limits()).is_err());
    let duplicate=text.replacen("\"overlays\":[]","\"overlays\":[],\"overlays\":[]",1);
    assert!(PolicySet::parse_json_with_limits(duplicate.as_bytes(),&limits()).is_err());
    let malformed=text.replacen("\"version\":\"1.0.0\"","\"version\":\"01.0.0\"",1);
    assert!(PolicySet::parse_json_with_limits(malformed.as_bytes(),&limits()).is_err());
}

#[test]
fn resolver_failure_and_invalid_document_abort_compilation() {
    let base=policy();let root=set(&base,&[]);
    let down=compile_policy_set(&root,&|_:&PolicyReference| Err(CompositionError::InvalidSet("resolver_failed")),&limits());
    assert_eq!(down,Err(CompositionError::InvalidSet("resolver_failed")));
    let mut invalid=base;
    invalid.rules[0].rule_id=invalid.rules[1].rule_id.clone();
    assert!(compose(&root,&catalog(vec![node(invalid,vec![])]),&limits()).is_err());
}

#[test]
fn sorted_binary_manifest_uses_length_prefixed_fields() {
    let p=policy();
    let effective=compose(&set(&p,&[]),&catalog(vec![node(p,vec![])]),&limits()).unwrap();
    let bytes=effective.canonical_bytes();
    let domain=EFFECTIVE_POLICY_DOMAIN_V1;
    assert!(bytes.starts_with(domain));
    let n=domain.len();
    let ref_len=u32::from_be_bytes(bytes[n..n+4].try_into().unwrap()) as usize;
    let serialized_ref=&bytes[n+4..n+4+ref_len];
    assert_eq!(serialized_ref,serde_json::to_vec(&effective.policy_set().baseline).unwrap());
    let offset=n+4+ref_len;
    assert_eq!(u32::from_be_bytes(bytes[offset..offset+4].try_into().unwrap()),0);
    assert_eq!(u32::from_be_bytes(bytes[offset+4..offset+8].try_into().unwrap()),1);
}
