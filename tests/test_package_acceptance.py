"""Adversarial preflight checks for local .crate acceptance without publication."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts.package_acceptance import (
    AcceptanceFailure, assert_source_is_unpublishable, index_path,
    index_record, validate_archive,
)


def sample_archive(path: Path, *, member: str | None = None, link: bool = False) -> None:
    prefix = "pqc-kit-0.1.0/"
    files = {
        "Cargo.toml": (b'[package]\nname="pqc-kit"\nversion="0.1.0"\nrust-version="1.85"\n'
                       b'[dependencies]\nserde="1.0.228"\n'),
        "src/lib.rs": b"//! Test fixture.\n",
        "data/catalog-v1.json": b'{"entries":[]}\n',
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files.items():
            item = tarfile.TarInfo(prefix + name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
        if member is not None:
            item = tarfile.TarInfo(member)
            if link:
                item.type = tarfile.SYMTYPE
                item.linkname = "/etc/passwd"
                item.size = 0
                archive.addfile(item)
            else:
                data = b"unexpected"
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))


class PackagedAcceptanceTests(unittest.TestCase):
    def test_bootstrap_never_unblocks_registry_publishing(self) -> None:
        assert_source_is_unpublishable()

    def test_index_paths_and_dependency_registry_scoping(self) -> None:
        self.assertEqual(index_path("pqc-kit"), Path("pq/c-/pqc-kit"))
        self.assertEqual(index_path("cryptopolicy"), Path("cr/yp/cryptopolicy"))
        manifest = {"dependencies": {
            "pqc-kit": {"version": "=0.1.0"},
            "serde": {"version": "1.0.228", "features": ["derive"]},
        }}
        record = index_record("cryptopolicy", manifest, "a" * 64)
        dependencies = {d["name"]: d for d in record["deps"]}
        self.assertIsNone(dependencies["pqc-kit"]["registry"])
        self.assertEqual(dependencies["serde"]["registry"],
                         "https://github.com/rust-lang/crates.io-index")
        self.assertEqual(dependencies["serde"]["features"], ["derive"])

    def test_valid_archive_has_stable_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            package = Path(temp) / "pqc-kit-0.1.0.crate"
            sample_archive(package)
            manifest, digest = validate_archive(package, "pqc-kit")
            self.assertEqual(manifest["package"]["name"], "pqc-kit")
            self.assertEqual(len(digest), 64)

    def test_reject_traversal_and_symlink_archive_members(self) -> None:
        for bad, link in [
            ("pqc-kit-0.1.0/../secret", False),
            ("pqc-kit-0.1.0/.git/config", False),
            ("pqc-kit-0.1.0/unsafe", True),
        ]:
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as temp:
                package = Path(temp) / "pqc-kit-0.1.0.crate"
                sample_archive(package, member=bad, link=link)
                with self.assertRaises(AcceptanceFailure):
                    validate_archive(package, "pqc-kit")

    def test_reject_unversioned_path_only_dependencies(self) -> None:
        with self.assertRaises(AcceptanceFailure):
            index_record("cryptopolicy", {
                "dependencies": {"pqc-kit": {"version": "=0.1.0", "path": "../pqc-kit"}}
            }, "f" * 64)


if __name__ == "__main__":
    unittest.main()
