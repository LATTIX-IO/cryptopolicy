# Changelog

All notable changes to this project will be documented in this file.

The project follows Semantic Versioning once its public API reaches a stable contract. Pre-1.0 releases may evolve more rapidly, with breaking changes documented here.

## [Unreleased]

### Added

- FOSS-435: pure deterministic single-context policy evaluator with deny-first tri-state decisions, bounded outputs, explicit-time handling, provisional strict algorithm recognition and adversarial/golden tests; source authenticity and registry approval remain external.

- FOSS-434: finite typed selector and requirement contracts, deterministic static validation/diagnostics, missing-fact dispositions, negative parser and conflict tests; no runtime evaluator.

- FOSS-429: strict Rust/JSON schema types, explicit fallback, context fact provenance, validated identifiers, canonical SHA-256 and negative parsing tests.

### Changed

### Fixed

### Security

- FOSS-433: bounded policy/context/decision deserialization and caller-validated structural resource budgets, including adversarial over-limit tests.

- FOSS-426: Add versioned threat model, fail-closed safety invariants, adversarial golden security fixtures, a specification linter, and an opt-in future evaluator results comparator.

- FOSS-424: Explicitly disable publication for all bootstrap crates; separate release proposals from a guarded manual publishing workflow; add manifest/workflow regression checks.
