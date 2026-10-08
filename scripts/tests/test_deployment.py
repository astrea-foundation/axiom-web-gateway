import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load("prepare-tinfoil")
publisher = load("publish-documents")


class DeploymentTests(unittest.TestCase):
    def args(self, output):
        return argparse.Namespace(image="ghcr.io/astrea-foundation/axiom-web-gateway@sha256:" + "12" * 32,
                                  publisher_key="34" * 32, cvm_version="0.14.13",
                                  gateway_origin="https://gateway.example", backend_origin="https://api.example",
                                  browser_origin=["https://app.example"], concurrency=32, sessions=512, output=output)

    def test_confidential_topology_and_measured_configuration(self):
        with tempfile.TemporaryDirectory() as output:
            config = prepare.prepare(self.args(output))
            container = config["containers"][0]
            self.assertTrue(container["attestation"])
            self.assertTrue(container["read_only"])
            self.assertEqual(container["user"], "10001:10001")
            self.assertNotIn("ports", container)
            self.assertNotIn("cvm_admin", container)
            self.assertNotIn("secrets", container)
            self.assertEqual(set(container["keys"]), {"axiom-encryption", "axiom-authorization"})
            self.assertEqual(config["networks"]["verification"]["egress"], "allowlist")
            # The pinned Rust verifier obtains signed release evidence and
            # AMD certificates through these public proxies before inference.
            self.assertTrue({"github-proxy.tinfoil.sh", "kds-proxy.tinfoil.sh"}
                            <= set(config["networks"]["verification"]["allow"]))
            runtime = json.loads(container["env"][0]["AXIOM_GATEWAY_CONFIG_JSON"])
            self.assertEqual(runtime["publisher_key"], "34" * 32)
            self.assertEqual(runtime["public_origin"], "https://gateway.example")
            self.assertEqual(runtime["attestation_socket"], "/tinfoil/attestation.sock")
            self.assertTrue((Path(output) / "tinfoil-config.yml").is_file())

    def test_configuration_rejects_mutable_images_and_bad_origins(self):
        with tempfile.TemporaryDirectory() as output:
            for field, value in [("image", "ghcr.io/example/gateway:latest"),
                                 ("gateway_origin", "http://gateway.example"),
                                 ("backend_origin", "https://user:secret@api.example"),
                                 ("publisher_key", "00"), ("concurrency", 0)]:
                with self.subTest(field=field):
                    args = self.args(output)
                    setattr(args, field, value)
                    with self.assertRaises(ValueError):
                        prepare.prepare(args)

    def test_offline_publisher_signatures_are_domain_separated(self):
        with tempfile.TemporaryDirectory() as output:
            key = Path(output) / "publisher.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True, capture_output=True)
            signed = publisher.signed({"sequence": 1}, "axiom-gateway-policy-v2", str(key))
            raw = base64.urlsafe_b64decode(signed["payload"] + "=" * (-len(signed["payload"]) % 4))
            self.assertEqual(json.loads(raw), {"sequence": 1})
            signature = Path(output) / "signature"
            signature.write_bytes(bytes.fromhex(signed["signature"]))
            public = Path(output) / "public.pem"
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)], check=True, capture_output=True)
            for domain, expected in [("axiom-gateway-policy-v2", 0), ("axiom-gateway-workload-v2", 1)]:
                message = Path(output) / "message"
                message.write_bytes(domain.encode() + b"\0" + raw)
                result = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public), "-sigfile", str(signature), "-in", str(message)], capture_output=True)
                self.assertEqual(result.returncode, expected)


if __name__ == "__main__":
    unittest.main()
