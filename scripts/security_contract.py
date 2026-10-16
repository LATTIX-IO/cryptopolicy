#!/usr/bin/env python3
"""Versioned specification corpus linter and optional real-evaluator results comparator.

This module does NOT implement or exercise the policy evaluator. Its default lint
mode checks that the threat catalog and golden expected outcomes are well formed.
Runtime conformance requires independently generated decisions from an actual
engine, passed explicitly via --results.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/security/contract-v1.json"
SCHEMA = "cryptopolicy.security-contract.v1"
BASELINE_INVARIANTS = {f"SEC-{i:03}" for i in range(1, 21)}
BASELINE_THREATS = {f"THR-{i:03}" for i in range(1, 21)}
BASELINE_CASES = {f"CASE-{i:03}" for i in range(1, 34)}
VALID_SURFACES = {"validation", "evaluation", "composition", "adapter", "enforcement"}


class ContractError(ValueError):
    """A security-contract violation, never a policy authorization result."""


def ensure(ok: bool, message: str) -> None:
    if not ok:
        raise ContractError(message)


def load_json(path: Path) -> dict:
    """Strictly load JSON, rejecting duplicate member keys at every depth."""
    def distinct_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(f"Duplicate JSON field {key!r}")
            result[key] = value
        return result

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle, object_pairs_hook=distinct_pairs)
    ensure(isinstance(data, dict), "Top-level JSON value must be an object")
    return data


def require_identifier(value: object, prefix: str) -> None:
    ensure(isinstance(value, str) and bool(re.fullmatch(prefix + r"-\d{3}", value)),
           f"Invalid identifier: {value!r}")


def validate_contract(data: dict) -> dict:
    """Validate corpus integrity without pretending to run the evaluator."""
    ensure(isinstance(data, dict), "Contract root must be an object")
    ensure(data.get("contract_schema") == SCHEMA, "Unsupported security contract schema")
    ensure(data.get("contract_version") == "1.0.0", "Unexpected contract version")
    ensure(data.get("implementation_status") == "normative-specification-only",
           "Runtime maturity requires separately verified evaluator integration")
    ensure(data.get("runtime_conformance_verified") is False,
           "A specification-only corpus may not claim runtime verification")
    ensure(data.get("decision_enforcement") ==
           "Permit-only authorization; Deny/Indeterminate/Error block",
           "Non-permit enforcement contract weakened")
    reasons = data.get("reason_vocabulary")
    errors = data.get("error_vocabulary")
    ensure(isinstance(reasons, list) and reasons and len(set(reasons)) == len(reasons),
           "Reason code vocabulary invalid")
    ensure(isinstance(errors, list) and errors and len(set(errors)) == len(errors),
           "Error code vocabulary invalid")
    ensure(all(isinstance(x, str) and re.fullmatch(r"[A-Z][a-zA-Z0-9]+", x) for x in reasons + errors),
           "Invalid reason/error code")

    invariants = data.get("invariants")
    threats = data.get("threats")
    cases = data.get("cases")
    ensure(isinstance(invariants, list) and isinstance(threats, list) and isinstance(cases, list),
           "Invariants, threats and cases must be arrays")
    inv_ids = set()
    for inv in invariants:
        ensure(isinstance(inv, dict), "Invariant must be object")
        ident = inv.get("id")
        require_identifier(ident, "SEC")
        ensure(ident not in inv_ids, f"Duplicate invariant {ident}")
        inv_ids.add(ident)
        ensure(isinstance(inv.get("requirement"), str) and len(inv["requirement"]) >= 30,
               f"{ident}: missing substantive normative requirement")
        ensure(isinstance(inv.get("implementation_issue"), str) and
               bool(re.fullmatch(r"FOSS-\d+", inv["implementation_issue"])),
               f"{ident}: missing accountable implementation issue")
        ensure(inv.get("maturity") == "pending-runtime", f"{ident}: unjustified runtime status")
    ensure(BASELINE_INVARIANTS <= inv_ids, "Baseline security invariant was removed")

    threat_ids = set()
    threat_invariants = {}
    for threat in threats:
        ensure(isinstance(threat, dict), "Threat must be object")
        ident = threat.get("id")
        require_identifier(ident, "THR")
        ensure(ident not in threat_ids, f"Duplicate threat {ident}")
        threat_ids.add(ident)
        ensure(threat.get("invariant") in inv_ids, f"{ident}: no controlling invariant")
        threat_invariants[ident] = threat["invariant"]
        ensure(threat.get("severity") in {"critical", "high", "medium"}, f"{ident}: severity")
        ensure(isinstance(threat.get("boundary"), str) and
               bool(re.fullmatch(r"TB-\d{2}", threat["boundary"])),
               f"{ident}: missing trust boundary")
        for name in ("name", "actor", "abuse"):
            ensure(isinstance(threat.get(name), str) and threat[name].strip(),
                   f"{ident}: missing {name}")
    ensure(BASELINE_THREATS <= threat_ids, "Baseline threat removed")

    case_ids = set()
    negative_inv_coverage = set()
    negative_threat_coverage = set()
    expected_by_id = {}
    for case in cases:
        ensure(isinstance(case, dict), "Case must be object")
        ident = case.get("id")
        require_identifier(ident, "CASE")
        ensure(ident not in case_ids, f"Duplicate case {ident}")
        case_ids.add(ident)
        ensure(case.get("invariant_id") in inv_ids, f"{ident}: unknown invariant")
        ensure(case.get("threat_id") in threat_ids, f"{ident}: unknown threat")
        ensure(case["invariant_id"] == threat_invariants[case["threat_id"]],
               f"{ident}: threat-invariant crosswalk mismatch")
        ensure(case.get("kind") in {"negative", "positive-control"}, f"{ident}: case kind")
        ensure(case.get("surface") in VALID_SURFACES, f"{ident}: test surface")
        ensure(case.get("runtime_status") == "pending",
               f"{ident}: runtime tests have not yet been integrated")
        ensure(isinstance(case.get("input_semantics"), dict) and case["input_semantics"],
               f"{ident}: no test input semantics")
        ensure(isinstance(case.get("scenario"), str) and len(case["scenario"]) >= 15,
               f"{ident}: missing scenario")
        ensure(isinstance(case.get("rationale"), str) and bool(case["rationale"].strip()),
               f"{ident}: missing rationale")
        ensure(isinstance(case.get("implementation_issue"), str) and
               bool(re.fullmatch(r"FOSS-\d+", case["implementation_issue"])),
               f"{ident}: missing test implementation owner")
        expected = case.get("expected")
        ensure(isinstance(expected, dict), f"{ident}: missing expected outcome")
        ensure(expected.get("kind") in {"Decision", "Error"}, f"{ident}: result kind")
        if expected["kind"] == "Error":
            ensure(set(expected) == {"kind", "error_code", "enforcement"},
                   f"{ident}: invalid error outcome shape")
            ensure(expected["error_code"] in errors, f"{ident}: unregistered error code")
            ensure(expected["enforcement"] == "block", f"{ident}: error must block")
        else:
            ensure(set(expected) == {"kind", "status", "reason_codes", "enforcement"},
                   f"{ident}: invalid decision shape")
            status = expected["status"]
            ensure(status in {"Permit", "Deny", "Indeterminate"},
                   f"{ident}: invalid decision status")
            codes = expected["reason_codes"]
            ensure(isinstance(codes, list) and bool(codes) and
                   len(set(codes)) == len(codes) and all(code in reasons for code in codes),
                   f"{ident}: unregistered or repeated reason code")
            ensure(expected["enforcement"] == ("allow" if status == "Permit" else "block"),
                   f"{ident}: invalid enforcement action")
        if case["kind"] == "negative":
            negative_inv_coverage.add(case["invariant_id"])
            negative_threat_coverage.add(case["threat_id"])
            ensure(expected.get("status") != "Permit" and expected["enforcement"] == "block",
                   f"{ident}: negative fixture cannot authorize")
        else:
            ensure(ident == "CASE-033", f"{ident}: new positive controls require an explicit reviewed contract revision")
            ensure(expected.get("status") == "Permit" and expected["enforcement"] == "allow",
                   f"{ident}: positive control must demonstrate explicit authorization")
        expected_by_id[ident] = expected

    ensure(BASELINE_CASES <= case_ids, "Baseline golden security case was removed")
    ensure(BASELINE_INVARIANTS <= negative_inv_coverage,
           "An established invariant lacks negative regression coverage")
    ensure(BASELINE_THREATS <= negative_threat_coverage,
           "An established threat lacks negative regression coverage")
    named = {case["id"]: case for case in cases}
    ensure(named["CASE-027"]["input_semantics"].get("permutation_of") == "CASE-003",
           "Baseline rule-order metamorphic link removed")
    anchors = {
        "CASE-001": {"kind": "Error", "error_code": "InvalidPolicy", "enforcement": "block"},
        "CASE-002": {"kind": "Decision", "status": "Deny", "reason_codes": ["DefaultDenied"], "enforcement": "block"},
        "CASE-003": {"kind": "Decision", "status": "Deny", "reason_codes": ["ExplicitDeny"], "enforcement": "block"},
        "CASE-006": {"kind": "Decision", "status": "Indeterminate", "reason_codes": ["MissingRequiredAttribute"], "enforcement": "block"},
        "CASE-033": {"kind": "Decision", "status": "Permit", "reason_codes": ["RequirementSatisfied"], "enforcement": "allow"},
    }
    for ident, outcome in anchors.items():
        ensure(expected_by_id.get(ident) == outcome, f"{ident}: immutable baseline semantic anchor changed")
    for case in cases:
        original = case["input_semantics"].get("permutation_of")
        if original is not None:
            ensure(original in expected_by_id, f"{case['id']}: unknown permutation target")
            ensure(case["expected"] == expected_by_id[original],
                   f"{case['id']}: rule ordering changed expected decision")

    return {"invariants": len(inv_ids), "threats": len(threat_ids),
            "cases": len(case_ids),
            "negative_cases": sum(c["kind"] == "negative" for c in cases),
            "runtime_verified": False}


def compare_runtime_results(contract: dict, supplied: dict) -> None:
    """Compare independently generated *normalized* evaluator results to fixtures.

    This comparison proves data matches expected values, not that the producer
    actually exercised the evaluator. CI integration must guarantee that.
    """
    validate_contract(contract)
    ensure(isinstance(supplied, dict) and supplied.get("contract_schema") == SCHEMA,
           "Results schema mismatch")
    ensure(supplied.get("contract_version") == contract["contract_version"],
           "Results version mismatch")
    producer = supplied.get("producer")
    ensure(isinstance(producer, dict) and producer.get("mode") == "runtime" and
           isinstance(producer.get("implementation"), str) and producer["implementation"].strip(),
           "Runtime results require attributable producer metadata")
    results = supplied.get("results")
    ensure(isinstance(results, list), "Results must be list")
    result_by_id = {}
    for result in results:
        ensure(isinstance(result, dict), "Result must be object")
        ident = result.get("id")
        require_identifier(ident, "CASE")
        ensure(ident not in result_by_id, f"Duplicate runtime result for {ident}")
        result_by_id[ident] = {k: v for k, v in result.items() if k != "id"}
    expected_by_id = {c["id"]: c["expected"] for c in contract["cases"]}
    ensure(set(result_by_id) == set(expected_by_id),
           f"Missing results: {sorted(set(expected_by_id)-set(result_by_id))}; "
           f"unexpected results: {sorted(set(result_by_id)-set(expected_by_id))}")
    for ident in sorted(expected_by_id):
        ensure(result_by_id[ident] == expected_by_id[ident],
               f"{ident}: evaluator output differs from normative golden contract")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lint", action="store_true", help="Lint the contract without executing the evaluator")
    parser.add_argument("--results", type=Path,
                        help="Compare normalized outcomes produced by the actual evaluator")
    parser.add_argument("--require-results", action="store_true",
                        help="Fail until the evaluator supplies --results")
    args = parser.parse_args(argv)
    try:
        contract = load_json(CORPUS)
        counts = validate_contract(contract)
        print("Security specification OK: "
              f"{counts['invariants']} invariants, {counts['threats']} threats, "
              f"{counts['cases']} cases ({counts['negative_cases']} negative)")
        if args.require_results and args.results is None:
            raise ContractError("Runtime results required: no evaluator has been executed")
        if args.results:
            compare_runtime_results(contract, load_json(args.results))
            print("Normalized runtime outputs matched golden fixtures (producer must be independently verified)")
        else:
            print("RUNTIME SEMANTICS NOT TESTED: evaluator integration pending FOSS-429/FOSS-435")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"SECURITY CONTRACT FAILURE: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
