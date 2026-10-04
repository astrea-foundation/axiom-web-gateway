#!/usr/bin/env python3
"""Offline release-authority signing, never part of gateway runtime.

Qualified firmware policy is an operator-supplied trust root. Workload PCR11 is
calculated from this build's embedded UKI sections; PCR4 binds its PE digest into
the vendor-qualified boot event sequence. No quote-reported workload values are
accepted as a release manifest input.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("invalid qualified SHA256 digest")
    return bytes.fromhex(value)


def signed(payload, domain, key):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with tempfile.TemporaryDirectory() as folder:
        source = Path(folder) / "message"
        source.write_bytes(domain.encode() + b"\0" + raw)
        signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", str(source)])
    if len(signature) != 64:
        raise ValueError("publisher key must be Ed25519")
    return {"payload": base64.urlsafe_b64encode(raw).decode().rstrip("="), "signature": signature.hex()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["policy", "workload"])
    parser.add_argument("--key", required=True, help="offline Ed25519 publisher PEM")
    parser.add_argument("--profile", required=True, help="previously qualified Azure boot profile JSON")
    parser.add_argument("--output", required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--sequence", type=int)
    parser.add_argument("--appliance")
    parser.add_argument("--image-digest")
    args = parser.parse_args()
    profile = json.loads(Path(args.profile).read_text())
    if profile.get("qualified") is not True or profile.get("schema_version") != 1:
        raise ValueError("a vendor-qualified boot profile is required")
    # Digest links the profile to its archived independent qualification evidence.
    sha256(profile["qualification_evidence_sha256"])
    if args.generation < 1:
        raise ValueError("invalid workload generation")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if args.operation == "policy":
        if not args.sequence or args.sequence < 1:
            raise ValueError("monotonic policy sequence required")
        for field in ["mr_td", "mr_config_id", "mr_owner", "mr_owner_config", *profile["firmware"]["rt_mrs"]]:
            value = profile["firmware"].get(field, field)
            if not re.fullmatch(r"[0-9a-f]{96}", value):
                raise ValueError("invalid qualified Intel TDX identity")
        now = int(time.time())
        payload = {"schema_version": 1, "sequence": args.sequence, "issued_at": now, "expires_at": now + 86400,
                   "minimum_generation": args.generation, "azure_firmware": [profile["firmware"]]}
        path = output / "trust-policy.json"
        document = signed(payload, "axiom-gateway-policy-v1", args.key)
    else:
        if not args.appliance or not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image_digest or ""):
            raise ValueError("appliance directory and immutable OCI digest required")
        if subprocess.check_output(["git", "status", "--porcelain"], text=True).strip():
            raise ValueError("release provenance requires a clean committed checkout")
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        appliance = Path(args.appliance)
        candidate = json.loads((appliance / "candidate.json").read_text())
        if candidate["appliance_sha256"] != digest(appliance / "gateway.vhd") or candidate["uki_sha256"] != digest(appliance / "gateway.efi"):
            raise ValueError("candidate artifact changed after build")
        if candidate["secure_boot_certificate_sha256"] != profile["secure_boot_certificate_sha256"]:
            raise ValueError("Secure Boot certificate differs from qualified profile")
        pcr4 = bytes(32)
        for event in [*profile["pcr4_before_uki"], candidate["uki_pe_sha256"], *profile["pcr4_after_uki"]]:
            pcr4 = hashlib.sha256(pcr4 + sha256(event)).digest()
        measurement = candidate["pcr11"]["sha256"]
        if len(measurement) != 1 or measurement[0]["pcr"] != 11 or measurement[0].get("phase", "") != "":
            raise ValueError("unexpected UKI measurement phase")
        pcr11 = measurement[0]["hash"]
        sha256(pcr11)
        sha256(profile["pcr7"])
        recipe = hashlib.sha256()
        tracked = subprocess.check_output(["git", "ls-files", "-z", "Dockerfile", ".dockerignore", "deploy/appliance", "scripts/build-container.sh"])
        for path in (Path(name.decode()) for name in tracked.split(b"\0") if name):
            if path.is_file(): recipe.update(str(path).encode() + b"\0" + path.read_bytes())
        payload = {"schema_version": 1, "generation": args.generation, "source_repository": "https://github.com/astrea-foundation/axiom-web-gateway",
                   "source_revision": revision, "build_recipe_sha256": recipe.hexdigest(), "cargo_lock_sha256": digest("Cargo.lock"),
                   "gateway_image_digest": args.image_digest, "appliance_sha256": candidate["appliance_sha256"],
                   "pcrs": {"4": pcr4.hex(), "7": profile["pcr7"], "11": pcr11, "12": "00" * 32}}
        path = output / "manifests" / (pcr11 + ".json")
        path.parent.mkdir(exist_ok=True)
        document = signed(payload, "axiom-gateway-workload-v1", args.key)
    path.write_text(json.dumps(document, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
