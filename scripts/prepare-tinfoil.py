#!/usr/bin/env python3
"""Generate a public config-only Tinfoil project. Never publish or create instances."""
import argparse
import json
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or value != "https://" + parsed.netloc):
        raise ValueError("canonical HTTPS origin required")
    host = parsed.hostname
    if not host:
        raise ValueError("canonical HTTPS origin required")
    host = "[" + host.lower() + "]" if ":" in host else host.encode("idna").decode().lower()
    if parsed.port == 443 or value != "https://" + host + (":" + str(parsed.port) if parsed.port is not None else ""):
        raise ValueError("canonical HTTPS origin required")
    return value


def prepare(args):
    if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", args.image):
        raise ValueError("immutable lowercase OCI image reference required")
    if not re.fullmatch(r"[0-9a-f]{64}", args.publisher_key):
        raise ValueError("pinned Ed25519 publisher public key required")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.cvm_version):
        raise ValueError("released CVM version required")
    if tuple(map(int, args.cvm_version.split("."))) < (0, 14, 13):
        raise ValueError("CVM 0.14.13 or newer required for this deployment contract")
    if not 1 <= args.concurrency <= 128 or not 1 <= args.sessions <= 1024:
        raise ValueError("invalid capacity")
    browsers = list(dict.fromkeys(origin(value) for value in args.browser_origin))
    if not browsers or len(browsers) > 16:
        raise ValueError("one to sixteen explicit browser origins required")
    runtime = json.loads((ROOT / "deploy/config.example.json").read_text())
    runtime.update(public_origin=origin(args.gateway_origin), backend_origin=origin(args.backend_origin),
                   publisher_key=args.publisher_key, browser_origins=browsers,
                   max_concurrency=args.concurrency, max_sessions=args.sessions)
    # Inference goes through the account-scoped ciphertext relay. These extra
    # public hosts supply upstream attestation/provenance and vendor collateral.
    allow = sorted({urlsplit(args.backend_origin).hostname, "inference.tinfoil.sh", "api.github.com",
                    "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
                    "raw.githubusercontent.com", "api.trustedservices.intel.com", "kdsintf.amd.com",
                    "rekor.sigstore.dev", "fulcio.sigstore.dev", "tuf-repo-cdn.sigstore.dev"})
    config = {"cvm-version": args.cvm_version, "cpus": 2, "memory": 4096,
              "networks": {"verification": {"egress": "allowlist", "allow": allow}},
              "attested-keys": [{"id": "axiom-encryption", "key": "x25519", "uid": 10001, "gid": 10001},
                                {"id": "axiom-authorization", "key": "ed25519", "uid": 10001, "gid": 10001}],
              "containers": [{"name": "gateway", "image": args.image, "user": "10001:10001",
                              "attestation": True, "keys": ["axiom-encryption", "axiom-authorization"],
                              "read_only": True, "networks": ["verification"], "restart": "on-failure",
                              "memory": "3072m", "pids_limit": 128,
                              "env": [{"AXIOM_GATEWAY_CONFIG_JSON": json.dumps(runtime, separators=(",", ":"))}]}],
              "shim": {"upstream-port": 8080, "upstream-container": "gateway",
                       "origins": browsers, "paths": ["/healthz", "/v1/attestation", "/v1/session", "/v1/rpc"]}}
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    # JSON is a strict YAML subset, accepted by the canonical Tinfoil parser.
    (output / "tinfoil-config.yml").write_text(json.dumps(config, indent=2) + "\n")
    workflows = output / ".github/workflows"
    workflows.mkdir(parents=True, exist_ok=True)
    for path in (ROOT / "deploy/tinfoil/config-repo/.github/workflows").glob("*.yml"):
        shutil.copyfile(path, workflows / path.name)
    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--cvm-version", required=True)
    parser.add_argument("--gateway-origin", required=True)
    parser.add_argument("--backend-origin", required=True)
    parser.add_argument("--browser-origin", action="append", required=True)
    parser.add_argument("--publisher-key", required=True)
    parser.add_argument("--concurrency", type=int, default=32)
    parser.add_argument("--sessions", type=int, default=512)
    parser.add_argument("--output", required=True)
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
