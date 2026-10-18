#!/usr/bin/env python3
"""FOSS-459: fail-closed crosswalk between normative cases and real Rust tests.

This deliberately does not claim complete normative runtime conformance.
A runtime-subset result must be bound to an actual Rust integration test
that reads the pinned, unchanged normative corpus and asserts the outcome.
The existing 33-case specification remains specification-only.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/security/contract-v1.json"
MANIFEST = ROOT / "tests/fixtures/conformance/runtime-coverage-v1.json"
MAX_COVERAGE_BYTES = 65_536


class CoverageError(ValueError):
    """Crosswalk is incomplete, forged or overstates runtime evidence."""


def ensure(ok: bool, message: str) -> None:
    if not ok:
        raise CoverageError(message)


def distinct_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        ensure(key not in result, f"duplicate JSON property: {key}")
        result[key] = value
    return result


def parse_strict_json(data: bytes) -> dict:
    ensure(len(data) <= MAX_COVERAGE_BYTES, "input JSON exceeds conformance budget")
    parsed = json.loads(data, object_pairs_hook=distinct_object)
    ensure(isinstance(parsed, dict), "expected JSON map")
    return parsed


def git_blob_sha1(data: bytes) -> str:
    """Git object identity, not a signature or an approval mechanism."""
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def validate(manifest: dict, normative_bytes: bytes, rust_source: str) -> dict:
    corpus = parse_strict_json(normative_bytes)
    ensure(corpus["contract_schema"] == "cryptopolicy.security-contract.v1",
           "unknown normative contract")
    ensure(corpus.get("runtime_conformance_verified") is False,
           "specification must not be marked fully verified without whole-corpus runtime")
    ensure(corpus["implementation_status"] == "normative-specification-only",
           "normative contract maturity cannot be promoted by a partial test")
    ensure(manifest.get("schema_version") == "cryptopolicy.runtime-coverage.v1",
           "unsupported coverage manifest version")
    ensure(manifest.get("complete_normative_conformance") is False,
           "partial conformance may not claim complete verification")
    ensure(manifest.get("normative_corpus") == "tests/fixtures/security/contract-v1.json",
           "incorrect normative baseline path")
    ensure(manifest.get("runtime_tests") ==
           "crates/cryptopolicy/tests/normative_runtime.rs",
           "runtime test path is not the explicitly reviewed integration runner")
    ensure(manifest.get("check_kind") == "runtime-outcome-and-required-reasons-subset",
           "unsupported output/ordering assertion maturity")
    ensure(manifest.get("normative_git_blob_sha1") == git_blob_sha1(normative_bytes),
           "normative corpus changed without updated reviewed identity")

    normative = corpus.get("cases")
    entries = manifest.get("cases")
    ensure(isinstance(normative, list) and len(normative) == 33,
           "33-case normative contract unexpectedly changed")
    ensure(isinstance(entries, list) and len(entries) == 33,
           "coverage must enumerate every normative case")
    source_ids = [case.get("id") for case in normative]
    coverage_ids = [case.get("id") for case in entries]
    ensure(len(set(source_ids)) == len(source_ids), "duplicate source case")
    ensure(coverage_ids == source_ids, "coverage cases must match full normative order")
    ensure(all(re.fullmatch(r"CASE-\d{3}", name or "") for name in coverage_ids),
           "invalid case ID")
    ensure(len(rust_source) <= 160_000 and
           "include_bytes!(\"../../../tests/fixtures/security/contract-v1.json\")"
           in rust_source, "Rust runner does not directly consume normative source")

    tested = []
    pending = []
    test_names = set()
    for case in entries:
        ident = case["id"]
        state = case.get("status")
        if state == "runtime-subset":
            ensure(set(case) == {"id", "status", "test"}, f"{ident} extra binding fields")
            test_name = case["test"]
            ensure(isinstance(test_name, str) and
                   re.fullmatch(r"case_\d{3}_[a-z0-9_]+", test_name),
                   f"{ident} invalid Rust test symbol")
            ensure(test_name.startswith("case_" + ident[-3:] + "_"),
                   f"{ident} test ID does not match source case")
            ensure(test_name not in test_names, f"reused Rust test for {ident}")
            test_names.add(test_name)
            pattern = re.compile(
                r"(?m)^fn " + re.escape(test_name) +
                r"\s*\(\s*\)\s*\{([\s\S]*?)(?=\n#\[test\]|\Z)"
            )
            found = pattern.findall(rust_source)
            ensure(len(found) == 1, f"no unique executable Rust test for {ident}")
            ensure('"' + ident + '"' in found[0],
                   f"{ident} test does not name its own normative fixture")
            ensure(("assert_decision(" in found[0] or "spec_expected(" in found[0]),
                   f"{ident} has no normative outcome assertion")
            tested.append(ident)
        elif state == "pending":
            ensure(set(case) == {"id", "status", "reason"},
                   f"{ident} extra pending fields")
            reason = case["reason"]
            ensure(isinstance(reason, str) and 20 <= len(reason) <= 180,
                   f"{ident} missing substantive unfinished gap")
            pending.append(ident)
        else:
            raise CoverageError(f"{ident}: invalid status or unsupported completion claim")

    ensure(bool(tested) and bool(pending), "partial-integration maturity incorrectly classified")
    return {"total": len(entries), "runtime_subset": len(tested),
            "pending": len(pending), "covered_ids": tested}


def verify_files(root: Path = ROOT) -> dict:
    normative_bytes = (root / CORPUS.relative_to(ROOT)).read_bytes()
    manifest_bytes = (root / MANIFEST.relative_to(ROOT)).read_bytes()
    manifest = parse_strict_json(manifest_bytes)
    test_src = (root / manifest["runtime_tests"]).read_text(encoding="utf-8")
    return validate(manifest, normative_bytes, test_src)


def main() -> int:
    try:
        stats = verify_files()
        print("PASS partial runtime crosswalk", json.dumps(stats, sort_keys=True))
        print("NOT VERIFIED: complete 33-case normative runtime conformance")
        return 0
    except (CoverageError, ValueError, OSError, KeyError, TypeError) as exc:
        print("FAIL partial runtime crosswalk:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
