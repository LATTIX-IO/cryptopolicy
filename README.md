# cryptopolicy

Policy-driven cryptographic agility and post-quantum integration.

Maintained by Lattix Technologies Corp.

Project website: https://lattix.io

## Status

This project is in early development.

Public APIs should be considered unstable until the relevant crates reach
their first stable release.

## Security contract (pre-implementation)

The [threat model](THREAT_MODEL.md) specifies fail-closed decision rules, trust
boundaries and 33 versioned golden test cases. The specification linter is
executable, but **no policy evaluator exists yet** and CI does not claim runtime
policy-conformance coverage. Future schema/evaluator increments must bind their
real outputs to these fixtures without auto-regenerating golden expectations.

Run `python3 scripts/security_contract.py --lint` and
`python3 -m unittest discover -s tests -p 'test_security_contract.py' -v`.

## Versioned Rust policy contracts (FOSS-429)

The cryptopolicy crate provides typed JSON DTOs for PolicyDocument, identifiers,
evaluation time, CryptoContext facts with source provenance, and PolicyDecision.
Parsing and SHA-256 fingerprinting do not execute a policy or authorize an
operation. The issuer is a claim, not proof of policy authenticity.

Try `cargo run -p cryptopolicy --example contract_smoke` and
`cargo test -p cryptopolicy --test contracts` once the dependency lockfile
has been generated. Inputs are strict JSON with a mandatory schema and
explicit default effect. Unknown fields, unexpected enum variants, duplicate
rule/fact IDs and oversized input are rejected. The 1 MiB limit is provisional;
FOSS-433 will supply centrally configured nested and structural limits.

Canonical encoding is versioned internally as cryptopolicy-canon-v1: ordered
typed fields; sorted rules, conjunctive requirements and metadata. It is NOT
RFC 8785 and must not be treated as interoperable signing serialization.

## Crates

- cryptopolicy
- pqc-kit
- pqc-x509
- pqc-jose
- pqc-cose

## Development

Run:

    cargo fmt --all -- --check
    cargo check --workspace --all-targets --all-features
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace --all-features

## Publishing

All five workspace packages are **unpublished bootstrap crates** with `publish = false`.
The default `main` workflow can propose a release PR but **cannot publish**.
Only `.github/workflows/release-publish.yml` contains the publication command.

Publication is disabled unless a maintainer deliberately completes the protected
release setup: a `workflow_dispatch` on `main`, exact `PUBLISH` confirmation,
repository variable `CRYPTOPOLICY_RELEASES_ENABLED=true`, and the
`crates-io-publish` GitHub environment. That environment **must** be
configured with required reviewers and main-branch deployment restrictions
before enabling the repository variable. There is no release scheduled by this PR.

CI checks all crate manifests and workflow triggers with
`scripts/release_guard.py` and adversarial regression tests. Before any
published package, a separately reviewed change must authorize that crate,
validate crates.io ownership and the public API, and update the bootstrap guard.

See [release controls and operator procedure](docs/RELEASING.md).

## License

Licensed under either:

- Apache License, Version 2.0
- MIT License

at your option.