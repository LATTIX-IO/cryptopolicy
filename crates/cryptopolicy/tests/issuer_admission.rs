//! FOSS-515: issuer claims never substitute for source/key authentication.
//! The test verifier is synthetic, caller-owned and never a production trust root.
#![allow(clippy::unwrap_used)]

use cryptopolicy::{
    CryptoOperation, EvaluationTime, EvidenceId, IssuerAdmissionRequest, IssuerAdmissionScope,
    IssuerProvenanceClaim, IssuerVerificationContext, Limits, PolicyAdmissionError, PolicyDigest,
    PolicyDocument, PolicyId, PolicyIssuerSourceVerifier, PolicyReference, RuleEffect, RuleId,
    SchemaVersion, UnverifiedPolicyIssuerSource, admit_policy_issuer, admit_policy_issuer_json,
    evaluate,
};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

const POLICY: &[u8] = include_bytes!("fixtures/evaluator-policy-v1.json");
const CONTEXT: &[u8] = include_bytes!("fixtures/evaluator-context-v1.json");

fn at(unix_millis: i64) -> EvaluationTime {
    EvaluationTime { unix_millis }
}
fn evidence(value: &str) -> EvidenceId {
    EvidenceId::parse(value).unwrap()
}
fn policy_id(value: &str) -> PolicyId {
    PolicyId::parse(value).unwrap()
}
fn policy() -> PolicyDocument {
    let mut document = PolicyDocument::parse_json(POLICY).unwrap();
    document.issuer.subject = "trusted-org".to_owned();
    document.issuer.assurance_ref = Some(evidence("assurance:claimed"));
    document
}
fn scope() -> IssuerAdmissionScope {
    IssuerAdmissionScope {
        tenant_id: policy_id("tenant:alpha"),
        operation: CryptoOperation::Encrypt,
        challenge: evidence("challenge:one"),
    }
}
fn claim(document: &PolicyDocument, scope: &IssuerAdmissionScope) -> IssuerProvenanceClaim {
    IssuerProvenanceClaim {
        schema_version: SchemaVersion::V1,
        policy: PolicyReference::from_document(document).unwrap(),
        issuer_subject: document.issuer.subject.clone(),
        assurance_ref: evidence("assurance:claimed"),
        owner_ref: evidence("owner:alpha"),
        signer_key_ref: evidence("signer:alpha"),
        delegation_ref: Some(evidence("delegation:alpha")),
        grant_ref: evidence("grant:one"),
        scope: scope.clone(),
        issued_at: at(0),
        valid_from: at(100),
        expires_at: at(200),
    }
}

fn assess(
    document: &PolicyDocument,
    pinned: &PolicyReference,
    proof: &IssuerProvenanceClaim,
    requested_scope: &IssuerAdmissionScope,
    time: EvaluationTime,
    limits: &Limits,
    verifier: &impl PolicyIssuerSourceVerifier,
) -> Result<cryptopolicy::IssuerProvenanceAssessment, PolicyAdmissionError> {
    admit_policy_issuer(
        &IssuerAdmissionRequest {
            document,
            pinned_policy: pinned,
            claim: proof,
            scope: requested_scope,
            time,
            limits,
        },
        verifier,
    )
}

/// TEST ONLY. This simulates an independent authentication engine with exact
/// artifact matching, source revocation and one-use grant/challenge tracking.
/// There is deliberately no shipped accept-all verifier in the library.
struct SyntheticVerifier {
    expected: IssuerProvenanceClaim,
    seen_grants: RefCell<BTreeSet<EvidenceId>>,
    seen_challenges: RefCell<BTreeSet<EvidenceId>>,
    revoked: Cell<bool>,
    calls: Cell<usize>,
}
impl SyntheticVerifier {
    fn new(expected: IssuerProvenanceClaim) -> Self {
        Self {
            expected,
            seen_grants: RefCell::new(BTreeSet::new()),
            seen_challenges: RefCell::new(BTreeSet::new()),
            revoked: Cell::new(false),
            calls: Cell::new(0),
        }
    }
}
impl PolicyIssuerSourceVerifier for SyntheticVerifier {
    fn verify(&self, context: &IssuerVerificationContext<'_>) -> bool {
        self.calls.set(self.calls.get() + 1);
        if self.revoked.get()
            || context.claim != &self.expected
            || context.reference != &self.expected.policy
            || context.scope != &self.expected.scope
            || context.document.issuer.subject != self.expected.issuer_subject
            || context.time < self.expected.valid_from
            || context.time >= self.expected.expires_at
        {
            return false;
        }
        // The gate never caches a prior accepted response. The verifier must
        // enforce replay resistance in its own persisted trust domain.
        let mut grants = self.seen_grants.borrow_mut();
        let mut challenges = self.seen_challenges.borrow_mut();
        if grants.contains(&context.claim.grant_ref)
            || challenges.contains(&context.scope.challenge)
        {
            return false;
        }
        grants.insert(context.claim.grant_ref.clone());
        challenges.insert(context.scope.challenge.clone());
        true
    }
}

#[test]
fn issuer_string_and_unverified_assurance_never_admit_by_default() {
    let document = policy();
    let pinned = PolicyReference::from_document(&document).unwrap();
    let scope = scope();
    let proof = claim(&document, &scope);
    assert_eq!(
        assess(
            &document,
            &pinned,
            &proof,
            &scope,
            at(150),
            &Limits::default(),
            &UnverifiedPolicyIssuerSource,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    let mut missing_evidence = document.clone();
    missing_evidence.issuer.assurance_ref = None;
    let missing_pinned = PolicyReference::from_document(&missing_evidence).unwrap();
    let synthetic = SyntheticVerifier::new(proof.clone());
    assert_eq!(
        assess(
            &missing_evidence,
            &missing_pinned,
            &proof,
            &scope,
            at(150),
            &Limits::default(),
            &synthetic,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    assert_eq!(synthetic.calls.get(), 0);
}

#[test]
fn explicitly_synthetic_authenticated_assessment_is_not_a_permit_and_cannot_be_replayed() {
    let document = policy();
    let pinned = PolicyReference::from_document(&document).unwrap();
    let scope = scope();
    let proof = claim(&document, &scope);
    let verifier = SyntheticVerifier::new(proof.clone());

    let result = assess(
        &document,
        &pinned,
        &proof,
        &scope,
        at(150),
        &Limits::default(),
        &verifier,
    )
    .unwrap();
    assert_eq!(result.reference(), &pinned);
    assert_eq!(result.checked_at(), at(150));
    assert_eq!(verifier.calls.get(), 1);
    assert_eq!(
        assess(
            &document,
            &pinned,
            &proof,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    assert_eq!(verifier.calls.get(), 2);
}

#[test]
fn exact_policy_identity_version_and_digest_must_match_all_sources() {
    let document = policy();
    let pinned = PolicyReference::from_document(&document).unwrap();
    let scope = scope();
    let proof = claim(&document, &scope);
    let verifier = SyntheticVerifier::new(proof.clone());
    let mut wrong_version = pinned.clone();
    wrong_version.version = cryptopolicy::PolicyVersion::parse("9.9.9").unwrap();
    assert_eq!(
        assess(
            &document,
            &wrong_version,
            &proof,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    let mut wrong_digest = pinned.clone();
    wrong_digest.digest = PolicyDigest::try_from("0".repeat(64)).unwrap();
    assert_eq!(
        assess(
            &document,
            &wrong_digest,
            &proof,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    let mut modified_policy = document.clone();
    modified_policy.issuer.subject = "attacker-substituted-issuer".into();
    assert_eq!(
        assess(
            &modified_policy,
            &pinned,
            &proof,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    let mut forged_proof = proof.clone();
    forged_proof.policy.digest = PolicyDigest::try_from("f".repeat(64)).unwrap();
    assert_eq!(
        assess(
            &document,
            &pinned,
            &forged_proof,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    assert_eq!(verifier.calls.get(), 0);
}

#[test]
fn exact_tenant_operation_challenge_owner_key_and_delegation_are_checked() {
    let document = policy();
    let pinned = PolicyReference::from_document(&document).unwrap();
    let scope = scope();
    let proof = claim(&document, &scope);
    let verifier = SyntheticVerifier::new(proof.clone());

    let mut different_scope = scope.clone();
    different_scope.tenant_id = policy_id("tenant:other");
    assert_eq!(
        assess(
            &document,
            &pinned,
            &proof,
            &different_scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    different_scope = scope.clone();
    different_scope.operation = CryptoOperation::Sign;
    assert_eq!(
        assess(
            &document,
            &pinned,
            &proof,
            &different_scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    different_scope = scope.clone();
    different_scope.challenge = evidence("challenge:other");
    assert_eq!(
        assess(
            &document,
            &pinned,
            &proof,
            &different_scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    assert_eq!(verifier.calls.get(), 0);

    for mut forged in [proof.clone(), proof.clone(), proof.clone(), proof.clone()] {
        match verifier.calls.get() {
            0 => forged.owner_ref = evidence("owner:forged"),
            1 => forged.signer_key_ref = evidence("key:revoked"),
            2 => forged.delegation_ref = Some(evidence("delegation:other")),
            _ => forged.grant_ref = evidence("grant:stale"),
        }
        assert_eq!(
            assess(
                &document,
                &pinned,
                &forged,
                &scope,
                at(150),
                &Limits::default(),
                &verifier,
            ),
            Err(PolicyAdmissionError::InvalidPolicy)
        );
    }
    assert_eq!(verifier.calls.get(), 4);
    verifier.revoked.set(true);
    assert_eq!(
        assess(
            &document,
            &pinned,
            &proof,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
}

#[test]
fn utc_expiry_and_policy_effective_time_fail_closed_without_verifier() {
    let document = policy();
    let pinned = PolicyReference::from_document(&document).unwrap();
    let scope = scope();
    let proof = claim(&document, &scope);
    let verifier = SyntheticVerifier::new(proof.clone());
    for instant in [at(90), at(200), at(201)] {
        assert_eq!(
            assess(
                &document,
                &pinned,
                &proof,
                &scope,
                instant,
                &Limits::default(),
                &verifier,
            ),
            Err(PolicyAdmissionError::InvalidPolicy)
        );
    }
    let mut expired_proof = proof.clone();
    expired_proof.expires_at = at(150);
    assert_eq!(
        assess(
            &document,
            &pinned,
            &expired_proof,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    let mut invalid_window = proof.clone();
    invalid_window.valid_from = at(200);
    assert_eq!(
        assess(
            &document,
            &pinned,
            &invalid_window,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        ),
        Err(PolicyAdmissionError::InvalidPolicy)
    );
    assert_eq!(verifier.calls.get(), 0);
}

#[test]
fn invalid_input_never_reaches_verifier_and_does_not_reflect_secrets() {
    let document = policy();
    let pinned = PolicyReference::from_document(&document).unwrap();
    let scope = scope();
    let proof = claim(&document, &scope);
    let verifier = SyntheticVerifier::new(proof.clone());
    let valid_json = serde_json::to_vec(&document).unwrap();
    let mut injected: serde_json::Value = serde_json::from_slice(&valid_json).unwrap();
    injected["override_deny_silently"] = serde_json::json!("REDACT_SUPER_SECRET");
    let injected = serde_json::to_vec(&injected).unwrap();
    let inputs: &[(&[u8], PolicyAdmissionError)] = &[
        (b"{not valid", PolicyAdmissionError::InvalidPolicy),
        (&injected, PolicyAdmissionError::UnsupportedSchema),
        (
            br#"{"schema_version":"1","schema_version":"2"}"#,
            PolicyAdmissionError::InvalidPolicy,
        ),
    ];
    for (bytes, expected) in inputs {
        let error = admit_policy_issuer_json(
            bytes,
            &pinned,
            &proof,
            &scope,
            at(150),
            &Limits::default(),
            &verifier,
        )
        .unwrap_err();
        assert_eq!(&error, expected);
        assert!(!format!("{error:?}").contains("REDACT_SUPER_SECRET"));
    }
    assert_eq!(verifier.calls.get(), 0);

    // Typed policy/attestation budgets remain enforced before source checks.
    let limits = Limits {
        max_json_bytes: 1,
        ..Limits::default()
    };
    assert_eq!(
        assess(
            &document,
            &pinned,
            &proof,
            &scope,
            at(150),
            &limits,
            &verifier,
        ),
        Err(PolicyAdmissionError::ResourceLimit)
    );
    assert_eq!(verifier.calls.get(), 0);
}

#[test]
fn canonical_byte_budget_blocks_structurally_valid_policy_before_source_verifier() {
    let document = policy();
    let pinned = PolicyReference::from_document(&document).unwrap();
    let requested_scope = scope();
    let proof = claim(&document, &requested_scope);
    let verifier = SyntheticVerifier::new(proof.clone());

    // This intentionally passes structural validation but cannot fit the
    // canonical serialized policy in the caller's bounded byte budget.
    let canonical = document.canonical_json().unwrap();
    let constrained = Limits {
        max_json_bytes: canonical.len() - 1,
        ..Limits::default()
    };
    assert!(document.validate_with_limits(&constrained).is_ok());
    assert_eq!(
        assess(
            &document,
            &pinned,
            &proof,
            &requested_scope,
            at(150),
            &constrained,
            &verifier,
        ),
        Err(PolicyAdmissionError::ResourceLimit)
    );
    assert_eq!(verifier.calls.get(), 0);
}

#[test]
fn validated_issuer_provenance_cannot_override_an_explicit_policy_deny() {
    let mut document = policy();
    let mut deny = document
        .rules
        .iter()
        .find(|rule| rule.effect == RuleEffect::Warn)
        .unwrap()
        .clone();
    deny.rule_id = RuleId::parse("r:test-hard-deny").unwrap();
    deny.effect = RuleEffect::Deny;
    deny.selector.match_all = true;
    deny.selector.operation = None;
    deny.selector.algorithm_id = None;
    deny.selector.profile_id = None;
    deny.selector.environment = None;
    deny.selector.advanced = None;
    deny.requirements.clear();
    deny.temporal = None;
    document.rules.push(deny);
    let pinned = PolicyReference::from_document(&document).unwrap();
    let scope = scope();
    let proof = claim(&document, &scope);
    let verifier = SyntheticVerifier::new(proof.clone());
    let assessment = assess(
        &document,
        &pinned,
        &proof,
        &scope,
        at(150),
        &Limits::default(),
        &verifier,
    )
    .unwrap();
    assert_eq!(assessment.reference(), &pinned);
    let context = cryptopolicy::CryptoContext::parse_json(CONTEXT).unwrap();
    let decision = evaluate(&document, &context, at(150)).unwrap();
    assert_eq!(decision.outcome, cryptopolicy::DecisionOutcome::Deny);
}
