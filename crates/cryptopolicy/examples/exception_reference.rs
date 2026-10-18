//! FOSS-499: strictly parse a *synthetic* exception reference as untrusted data.
//! No cryptographic proof, waiver or policy authorization is created.
use cryptopolicy::{
    ExceptionBoundContext, ExceptionReference, ExceptionReferenceFinding,
    UnverifiedExceptionReferences, assess_exception_reference,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reference = ExceptionReference::parse_json(include_bytes!(
        "../tests/fixtures/exception-reference-v1.json"
    ))?;
    let context = ExceptionBoundContext {
        policy: reference.policy.clone(),
        target_rule: reference.target_rule.clone(),
        scope: reference.scope.clone(),
        evaluation_time: reference.effective_at,
    };
    let report =
        assess_exception_reference(&reference, &context, &UnverifiedExceptionReferences)?;
    assert_eq!(report.finding, ExceptionReferenceFinding::Unverified);
    println!(
        "exception={} fingerprint={} finding={:?}",
        report.exception_id, report.exception_digest, report.finding
    );
    println!("Unverified metadata grants no policy waiver, Permit or execution authority.");
    Ok(())
}
