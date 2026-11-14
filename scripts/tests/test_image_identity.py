import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("publisher", Path(__file__).resolve().parents[1] / "publish-documents.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class ImageIdentityTests(unittest.TestCase):
    def archive(self, directory, config, *, entries=1, link=False):
        path = Path(directory) / "image.tar"
        with tarfile.open(path, "w") as archive:
            raw = json.dumps([{"Config": "claimed-config.json"}] * entries).encode()
            member = tarfile.TarInfo("manifest.json"); member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
            member = tarfile.TarInfo("claimed-config.json")
            if link:
                member.type = tarfile.SYMTYPE; member.linkname = "/outside"
                archive.addfile(member)
            else:
                member.size = len(config); archive.addfile(member, io.BytesIO(config))
        return path

    def test_identity_authenticates_bytes_independently_of_archive_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            first = publisher.archive_config_digest(self.archive(directory, b'{"rootfs":"first"}'))
            self.assertEqual(first, "sha256:" + hashlib.sha256(b'{"rootfs":"first"}').hexdigest())
            second = publisher.archive_config_digest(self.archive(directory, b'{"rootfs":"changed"}'))
            self.assertNotEqual(first, second)

    def test_ambiguous_images_and_linked_configurations_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for kwargs in [{"entries": 2}, {"link": True}]:
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    publisher.archive_config_digest(self.archive(directory, b"{}", **kwargs))
