# Changelog

All notable changes to this project will be documented in this file.

The project follows Semantic Versioning once its public API reaches a stable contract. Pre-1.0 releases may evolve more rapidly, with breaking changes documented here.

## [Unreleased]

### Added

- FOSS-429: strict Rust/JSON schema types, explicit fallback, context fact provenance, validated identifiers, canonical SHA-256 and negative parsing tests.

### Changed

### Fixed

### Security

- FOSS-433: bounded policy/context/decision deserialization and caller-validated structural resource budgets, including adversarial over-limit tests.

- FOSS-426: Add versioned threat model, fail-closed safety invariants, adversarial golden security fixtures, a specification linter, and an opt-in future evaluator results comparator.

- FOSS-424: Explicitly disable publication for all bootstrap crates; separate release proposals from a guarded manual publishing workflow; add manifest/workflow regression checks.
