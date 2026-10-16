# cryptopolicy

Policy-driven cryptographic agility and post-quantum integration.

Maintained by Lattix Technologies Corp.

Project website: https://lattix.io

## Status

This project is in early development.

Public APIs should be considered unstable until the relevant crates reach
their first stable release.

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