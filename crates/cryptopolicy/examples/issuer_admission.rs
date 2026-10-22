//! FOSS-515: issuer metadata cannot independently authenticate a policy.
//!
//! This example illustrates a default-reject trust boundary only. Integrators
//! must supply independent, current issuer/key/delegation/replay validation.
use cryptopolicy::{
    CryptoOperation, EvaluationTime, EvidenceId, IssuerAdmissionScope, IssuerProvenanceClaim,
    Limits, PolicyAdmissionError, PolicyDocument, PolicyId, PolicyReference, SchemaVersion,
    UnverifiedPolicyIssuerSource, admit_policy_issuer_json,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut policy =
        PolicyDocument::parse_json(include_bytes!("../tests/fixtures/evaluator-policy-v1.json"))?;
    policy.issuer.subject = "trusted-org".into();
    policy.issuer.assurance_ref = Some(EvidenceId::parse("evidence:unverified")?);
    let reference = PolicyReference::from_document(&policy)?;
    let scope = IssuerAdmissionScope {
        tenant_id: PolicyId::parse("tenant:example")?,
        operation: CryptoOperation::Encrypt,
        challenge: EvidenceId::parse("nonce:example-001")?,
    };
    let claim = IssuerProvenanceClaim {
        schema_version: SchemaVersion::V1,
        policy: reference.clone(),
        issuer_subject: policy.issuer.subject.clone(),
        assurance_ref: EvidenceId::parse("evidence:unverified")?,
        owner_ref: EvidenceId::parse("owner:claimed")?,
        signer_key_ref: EvidenceId::parse("key:claimed")?,
        delegation_ref: None,
        grant_ref: EvidenceId::parse("grant:claimed")?,
        scope: scope.clone(),
        issued_at: EvaluationTime { unix_millis: 0 },
        valid_from: EvaluationTime { unix_millis: 100 },
        expires_at: EvaluationTime { unix_millis: 200 },
    };
    let result = admit_policy_issuer_json(
        &serde_json::to_vec(&policy)?,
        &reference,
        &claim,
        &scope,
        EvaluationTime { unix_millis: 150 },
        &Limits::default(),
        &UnverifiedPolicyIssuerSource,
    );
    assert_eq!(result, Err(PolicyAdmissionError::InvalidPolicy));
    println!("unverified issuer is rejected; no Permit or enforcement token exists");
    Ok(())
}
