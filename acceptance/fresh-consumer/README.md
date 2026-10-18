# External Rust consumer acceptance (FOSS-440)

This independent crate is deliberately outside the parent Cargo workspace and uses a **pinned Git dependency**, not a workspace-relative path. It demonstrates a fresh Rust client loading strict policy/context JSON, evaluating Permit/Deny/Indeterminate, preserving the canonical digest, and round-tripping typed decisions.

No cryptographic operation or enforcement occurs. Fixture provenance is synthetic and not an authenticated assertion.

To reproduce from a fresh directory, copy only `acceptance/fresh-consumer` and run:

    cargo generate-lockfile --manifest-path acceptance/fresh-consumer/Cargo.toml
    cargo run --manifest-path acceptance/fresh-consumer/Cargo.toml --locked

This is a **Git-source external consumer gate**, not a completed crates.io package acceptance. It pins the currently merged cryptopolicy Git revision and must be updated after further changes before a release candidate is approved. FOSS-464 must subsequently test actual packaged artifacts, package dependency topology, crate namespaces/owners, and fresh-consumer installation from the approved release channel; no publishing is enabled here.

Unsupported profiles, missing trust, and known-denied configurations do not grant permission. A Permit is only a data record; this smoke test does not perform source signature authentication or operation enforcement.
