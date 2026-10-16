# Crate publication controls (FOSS-424)

Cryptopolicy is currently a five-crate bootstrap workspace. **Do not publish a placeholder package.** This document describes controls and future release prerequisites; it is not an authorization to release.

## Current invariant

- Every `crates/*/Cargo.toml` member has `publish = false`.
- Pushes to `main` run `release-plz release-pr` only. The automated workflow has **no registry token** and no release command.
- The only workflow with `release-plz release` is `.github/workflows/release-publish.yml`, triggered exclusively by a deliberate GitHub Actions `workflow_dispatch` on `main`.
- The publish job also requires exact confirmation `PUBLISH`, the repository variable `CRYPTOPOLICY_RELEASES_ENABLED` set to the string `true`, and access to the `crates-io-publish` environment.
- Until that variable is configured, the publish job is **skipped**. A GitHub environment name alone is *not* proof of reviewer protection: GitHub may create a missing environment without approval rules. An administrator must configure its protections before enabling the variable.

## Required GitHub administrator configuration (not automatic)

1. In repository **Settings > Environments**, create **crates-io-publish**.
2. Require an independent reviewer; disable self-approval where supported. Limit deployment branches to `main` only.
3. Store the least-privilege `CARGO_REGISTRY_TOKEN` in that environment, not in ordinary PR workflows. Prefer trusted publishing if supported and validated as a separate release-engineering change.
4. Confirm protected `main` PR checks, owner review of manifest/workflow changes, and `Rust checks` status. The current GitHub ruleset requires Rust checks but **does not require code-owner review**; configure that before the first real release.
5. **Only after 1-4 and an explicit release decision**, set repository variable `CRYPTOPOLICY_RELEASES_ENABLED=true`. Keep it unset/false during bootstrap. Disable it again after the authorized release window.

This increment does **not** configure environment reviewers, secrets, or repository variables; those are GitHub-side administrative settings.

## Procedure for a later deliberately authorized release

1. Verify all intended crate names and owners on crates.io, identify the dependency/publish order, and approve each published public API, version, licensing, docs and security disclosures.
2. Make a separate, owner-reviewed release PR that explicitly opts specific ready packages into publication, updates this bootstrap guard and tests to the approved immutable release allowlist, and records the change in the changelog. Unapproved crates stay `publish = false`.
3. Verify `cargo fmt --all -- --check`, `cargo check --workspace --all-targets --all-features --locked`, Clippy `-D warnings`, `cargo test --workspace --all-features --locked`, rustdoc `-D warnings`, Rust 1.85 compatibility, cargo audit/deny/semver and negative policy regressions.
4. Execute a deliberate `cargo package` / dry run for each **approved** crate; review package file lists, exact dependency versions, SBOM and provenance. Build a new Rust consumer outside this workspace from packaged artifacts.
5. Review the PR and GitHub checks. Only after merge and separate human approval, select the protected **Publish crates (manual, protected)** workflow on `main` and enter `PUBLISH`.
6. Confirm the environment approval and workflow output, crate versions, hashes, signatures/attestations, GitHub release and docs.rs. A published crates.io version cannot be overwritten; correction requires a new version.
7. Set `CRYPTOPOLICY_RELEASES_ENABLED=false` (or remove it) after release.

## Developer verification

```sh
python3 -m venv .release-guard-venv
.release-guard-venv/bin/python -m pip install -r scripts/requirements-release-guard.txt
.release-guard-venv/bin/python scripts/release_guard.py
.release-guard-venv/bin/python -m unittest discover -s tests -p 'test_release_guard.py' -v
```

The checker parses workspace manifests and all Actions workflow files, verifies that *each* crate is blocked, rejects automatic publication and registry-token references, and asserts the exact manual-release condition. It does **not** inspect GitHub's live environment settings or secret configuration.

## Threat boundary

These repository tests prevent accidental configuration regressions but cannot defend against a repository administrator deliberately changing branch rules, release environment approvals, or the guard itself. Owner review and independent environment approval are therefore mandatory controls, not substitutes for these tests.
