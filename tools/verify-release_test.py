"""Offline regressions for the published-asset verifier's boundaries."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile
import warnings

spec = importlib.util.spec_from_file_location("verify_release", Path(__file__).with_name("verify-release.py"))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class VerifyTests(unittest.TestCase):
    def test_complete_stable_asset_set_and_exact_notes(self):
        names = verify.expected_assets("v0.6.0")
        self.assertEqual(len(names), 10)
        data = {"tag_name": "v0.6.0", "draft": False, "prerelease": False,
                "body": "# Rio v0.6.0\n\nClient evidence.\n",
                "assets": [{"name": n, "size": 1} for n in names]}
        verify.validate_release(data, "v0.6.0", data["body"].encode())
        for field, value in [("draft", True), ("prerelease", True), ("tag_name", "v0.5.0"),
                             ("body", "different"), ("assets", data["assets"][:-1])]:
            altered = dict(data, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify.validate_release(altered, "v0.6.0", data["body"].encode())

    def test_client_demo_cannot_be_waived_for_new_release(self):
        self.assertFalse(verify.client_demo_required("v0.5.0", True))
        self.assertTrue(verify.client_demo_required("v0.6.0", False))
        with self.assertRaises(ValueError):
            verify.client_demo_required("v0.6.0", True)

    def test_extract_only_regular_binary_and_refuse_duplicates(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            archive = root / "fixture.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                info = tarfile.TarInfo("rio"); info.size = 4
                bundle.addfile(info, io.BytesIO(b"test"))
                traversal = tarfile.TarInfo("../outside"); traversal.size = 4
                bundle.addfile(traversal, io.BytesIO(b"evil"))
            out = verify.extract_binary(archive, root / "native", "rio")
            self.assertEqual(out.read_bytes(), b"test")
            self.assertFalse((root.parent / "outside").exists())
            with tarfile.open(archive, "w:gz") as bundle:
                link = tarfile.TarInfo("rio"); link.type = tarfile.SYMTYPE; link.linkname = "../../outside"
                bundle.addfile(link)
            with self.assertRaises(ValueError):
                verify.extract_binary(archive, root / "bad", "rio")
            zipped = root / "duplicate.zip"
            with zipfile.ZipFile(zipped, "w") as bundle:
                bundle.writestr("rio.exe", b"one")
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    bundle.writestr("rio.exe", b"two")
            with self.assertRaises(ValueError):
                verify.extract_binary(zipped, root / "duplicate", "rio.exe")


if __name__ == "__main__":
    unittest.main()
