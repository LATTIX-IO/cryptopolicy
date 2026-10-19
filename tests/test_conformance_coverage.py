"""FOSS-459 crosswalk integrity: no false complete conformance claims."""
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import conformance_coverage as cv


class ConformanceCrosswalkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline_bytes = cv.CORPUS.read_bytes()
        cls.manifest = cv.parse_strict_json(cv.MANIFEST.read_bytes())
        cls.source = (ROOT / cls.manifest["runtime_tests"]).read_text()

    def verify_modified(self, mutate) -> None:
        doc = copy.deepcopy(self.manifest)
        mutate(doc)
        with self.assertRaises(cv.CoverageError):
            cv.validate(doc, self.baseline_bytes, self.source)

    def test_strict_crosswalk_is_partial_with_every_case_accounted(self) -> None:
        result = cv.validate(self.manifest, self.baseline_bytes, self.source)
        self.assertEqual(result["total"], 33)
        self.assertEqual(result["runtime_subset"], 22)
        self.assertEqual(result["pending"], 11)

    def test_cannot_claim_full_runtime_pass(self) -> None:
        self.verify_modified(lambda d: d.update(complete_normative_conformance=True))

    def test_cannot_omit_unfinished_cases(self) -> None:
        self.verify_modified(lambda d: d["cases"].pop(0))

    def test_cannot_duplicate_or_reorder_cases(self) -> None:
        self.verify_modified(lambda d: d["cases"][0].update(id="CASE-003"))

    def test_cannot_create_fake_test_pointer(self) -> None:
        self.verify_modified(lambda d: d["cases"][1].update(test="case_002_no_such_runtime_test"))

    def test_cannot_claim_untested_case_is_complete(self) -> None:
        def altered(doc) -> None:
            doc["cases"][7] = {
                "id": "CASE-008", "status": "runtime-subset",
                "test": "case_008_signed_exception_works",
            }
        self.verify_modified(altered)

    def test_cannot_relabel_fixture_identity(self) -> None:
        self.verify_modified(lambda d: d.update(normative_git_blob_sha1="0" * 40))

    def test_cannot_claim_exact_ordered_reasons_at_subset_maturity(self) -> None:
        self.verify_modified(lambda d: d.update(
            check_kind="fully_verified_ordered_golden_output"))

    def test_cannot_reuse_test_as_evidence_for_second_case(self) -> None:
        def altered(doc) -> None:
            doc["cases"][2]["test"] = doc["cases"][1]["test"]
        self.verify_modified(altered)

    def test_cannot_hide_known_signing_exception_gap(self) -> None:
        self.verify_modified(lambda d: d["cases"][7].update(reason="fixed"))

    def test_duplicate_json_fields_fail_closed(self) -> None:
        with self.assertRaises(cv.CoverageError):
            cv.parse_strict_json(b'{"status":"pending","status":"runtime-subset"}')

    def test_missing_test_file_has_no_runtime_evidence(self) -> None:
        with self.assertRaises(cv.CoverageError):
            cv.validate(self.manifest, self.baseline_bytes, "")


if __name__ == "__main__":
    unittest.main()
