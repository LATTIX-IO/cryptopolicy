"""Regression tests for FOSS-424 release controls."""
import sys, tempfile, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import release_guard as guard
class ReleaseGuardTests(unittest.TestCase):
    def test_repository_passes(self): self.assertEqual(len(guard.verify(ROOT)),5)
    def test_reject_publishable_crate(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'Cargo.toml').write_text('[workspace]\nmembers=["crates/example"]\n')
            (root/'crates/example').mkdir(parents=True)
            manifest=root/'crates/example/Cargo.toml'
            manifest.write_text('[package]\nname="example"\npublish=["crates-io"]\n')
            with self.assertRaises(guard.GuardFailure): guard.check_workspace(root)
            manifest.write_text('[package]\nname="example"\n')
            with self.assertRaises(guard.GuardFailure): guard.check_workspace(root)
            manifest.write_text('[package]\nname="example"\npublish=false\n')
            self.assertEqual(guard.check_workspace(root),['example'])
    def mutate(self, filename, previous, replacement):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); folder=root/'.github/workflows'; folder.mkdir(parents=True)
            for p in (ROOT/'.github/workflows').glob('*.yml'):
                original=p.read_text()
                (folder/p.name).write_text(original.replace(previous,replacement,1) if p.name==filename else original)
            with self.assertRaises(guard.GuardFailure): guard.check_workflows(root)
    def test_publish_trigger(self): self.mutate('release-publish.yml','on:\n  workflow_dispatch:','on:\n  push: {}\n  workflow_dispatch:')
    def test_confirmation(self): self.mutate('release-publish.yml',"inputs.confirm == 'PUBLISH'","inputs.confirm == 'NO'")
    def test_environment(self): self.mutate('release-publish.yml','environment: crates-io-publish','environment: other')
    def test_enablement(self): self.mutate('release-publish.yml',"vars.CRYPTOPOLICY_RELEASES_ENABLED == 'true'","vars.CRYPTOPOLICY_RELEASES_ENABLED == 'false'")
    def test_auto_publish(self): self.mutate('release-plz.yml','command: release-pr','command: release')
    def test_credential_leak(self): self.mutate('release-plz.yml','command: release-pr','command: release-pr\n          # CARGO_REGISTRY_TOKEN')
if __name__=='__main__': unittest.main()
