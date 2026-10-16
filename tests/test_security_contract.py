"""Adversarial tests for normative security contract integrity, not the evaluator."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import security_contract as sc


class ContractFixturesTests(unittest.TestCase):
    def setUp(self):
        self.good = sc.load_json(sc.CORPUS)

    def bad(self, mutate):
        doc = copy.deepcopy(self.good)
        mutate(doc)
        with self.assertRaises(sc.ContractError):
            sc.validate_contract(doc)

    def test_full_corpus_is_valid(self):
        stats = sc.validate_contract(self.good)
        self.assertEqual(stats["cases"], 33)
        self.assertEqual(stats["negative_cases"], 32)
        self.assertFalse(stats["runtime_verified"])

    def test_exact_expected_negative_behaviors_are_present(self):
        rows = {case["id"]: case for case in self.good["cases"]}
        self.assertEqual(rows["CASE-001"]["expected"]["error_code"], "InvalidPolicy")
        self.assertEqual(rows["CASE-003"]["expected"]["status"], "Deny")
        self.assertEqual(rows["CASE-006"]["expected"]["status"], "Indeterminate")
        self.assertEqual(rows["CASE-017"]["expected"]["status"], "Indeterminate")
        self.assertEqual(rows["CASE-024"]["expected"]["error_code"], "ResourceLimitExceeded")
        self.assertEqual(rows["CASE-033"]["expected"]["status"], "Permit")

    def test_removed_invariant_is_rejected(self):
        self.bad(lambda d: d["invariants"].pop(0))

    def test_removed_threat_is_rejected(self):
        self.bad(lambda d: d["threats"].pop(0))

    def test_removed_golden_case_is_rejected(self):
        self.bad(lambda d: d["cases"].pop(0))

    def test_duplicate_case_id_is_rejected(self):
        self.bad(lambda d: d["cases"].append(copy.deepcopy(d["cases"][0])))

    def test_negative_case_may_not_authorize(self):
        def change(d):
            d["cases"][1]["expected"] = {
                "kind": "Decision", "status": "Permit",
                "reason_codes": ["RequirementSatisfied"], "enforcement": "allow"
            }
        self.bad(change)

    def test_missing_required_coverage_rejected(self):
        self.bad(lambda d: d["cases"][0].update({"invariant_id": "SEC-999"}))

    def test_unregistered_reason_is_rejected(self):
        self.bad(lambda d: d["cases"][2]["expected"]["reason_codes"].append("PermittedByMagic"))

    def test_missing_issuer_accountability_is_rejected(self):
        self.bad(lambda d: d["invariants"][0].update({"implementation_issue": ""}))

    def test_runtime_status_claims_rejected(self):
        self.bad(lambda d: d.update({"runtime_conformance_verified": True}))

    def test_rules_ordering_must_preserve_golden_decision(self):
        def change(d):
            d["cases"][26]["expected"]["reason_codes"] = ["DefaultDenied"]
        self.bad(change)

    def test_error_must_block(self):
        self.bad(lambda d: d["cases"][0]["expected"].update({"enforcement": "allow"}))

    def test_indeterminate_must_block(self):
        self.bad(lambda d: d["cases"][5]["expected"].update({"enforcement": "allow"}))

    def test_duplicate_input_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "duplicate.json"
            p.write_text('{"contract_schema":"a","contract_schema":"b"}')
            with self.assertRaises(sc.ContractError):
                sc.load_json(p)

    def results(self):
        return {
            "contract_schema": sc.SCHEMA,
            "contract_version": "1.0.0",
            "producer": {"mode": "runtime", "implementation": "future-cryptopolicy-evaluator"},
            "results": [{"id": c["id"], **copy.deepcopy(c["expected"])}
                        for c in self.good["cases"]]
        }

    def test_comparator_smoke_for_expected_result_projections(self):
        # Test of comparison mechanism only: these expected values are NOT from an evaluator.
        sc.compare_runtime_results(self.good, self.results())

    def test_comparator_catches_changed_decision(self):
        result = self.results()
        result["results"][2]["status"] = "Permit"
        with self.assertRaises(sc.ContractError):
            sc.compare_runtime_results(self.good, result)

    def test_comparator_catches_missing_case(self):
        result = self.results()
        result["results"].pop()
        with self.assertRaises(sc.ContractError):
            sc.compare_runtime_results(self.good, result)

    def test_comparator_catches_duplicate_case(self):
        result = self.results()
        result["results"].append(copy.deepcopy(result["results"][0]))
        with self.assertRaises(sc.ContractError):
            sc.compare_runtime_results(self.good, result)

    def test_comparator_results_can_arrive_out_of_order(self):
        result = self.results()
        result["results"].reverse()
        sc.compare_runtime_results(self.good, result)

    def test_comparator_rejects_unattributed_source(self):
        result = self.results()
        result["producer"]["mode"] = "mock"
        with self.assertRaises(sc.ContractError):
            sc.compare_runtime_results(self.good, result)


if __name__ == "__main__":
    unittest.main()
