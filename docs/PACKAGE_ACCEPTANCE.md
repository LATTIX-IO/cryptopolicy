# FOSS-440: packaged-artifact consumer acceptance

## Scope and guarantee

The source checkout is **never publish-enabled**. The CI gate checks every workspace
manifest has `publish = false` before and after execution. Candidate crates are
copied to a disposable directory where *only* pqc-kit and cryptopolicy temporarily
gain a preview-registry allowlist. This permits cargo package to assemble genuine
distributable .crate archives without enabling publication in source control.

The test checks:
- Exact package version 0.1.0, Rust 1.85 MSRV and essential source files.
- Archive contents and size bounds; no symlinks, traversal, build outputs or .env.
- No path- or Git-only dependency in the packaged manifests.
- SHA-256 and deterministic archive bytes across two runs.
- Topological order (pqc-kit first) and exact versioned dependency.
- Ephemeral Cargo sparse registry served only on 127.0.0.1.
- Fresh consumer resolving both version-only candidate dependencies from those archives.
- Lockfile registry-source identity, three decision outcomes and wire round-trip.

The consumer uses public third-party dependencies from crates.io, but the two
candidate packages never touch crates.io and no registry credentials are read.
The server and temporary files are discarded after the run.

    python3 -m unittest discover -s tests -p test_package_acceptance.py -v
    python3 scripts/package_acceptance.py

## Remaining release gates

This is a **local registry simulation**, not a crates.io installation. It does
not establish namespace ownership, live registry availability, SBOM, signed
provenance, administrative approval, docs.rs output or publication. These
remain FOSS-464/466 requirements. The pqc-jose and pqc-cose placeholders
are excluded. Synthetic input decisions are not authenticated authority.
