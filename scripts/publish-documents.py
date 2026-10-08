#!/usr/bin/env python3
"""Sign measured Tinfoil release provenance with an offline Ed25519 authority.

Workload values come from the published build artifact, never a running quote.
The backend/browser additionally verify Tinfoil's Sigstore identity and the exact
artifact measurement before accepting this signed Axiom source/image mapping.
"""
import argparse
import importlib.util
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def signed(payload, domain, key):
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    with tempfile.TemporaryDirectory() as folder:
        source = Path(folder) / "message"
        source.write_bytes(domain.encode() + b"\0" + raw)
        signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", str(source)])
    if len(signature) != 64:
        raise ValueError("publisher key must be Ed25519")
    return {"payload": base64.urlsafe_b64encode(raw).decode().rstrip("="), "signature": signature.hex()}


def workload(args):
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip():
        raise ValueError("build provenance requires a clean committed checkout")
    raw = Path(args.deployment).read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("deployment artifact exceeds limit")
    artifact = json.loads(raw)
    # The authenticated release artifact embeds the exact config bytes measured
    # into the workload. Our generator emits JSON, a strict YAML subset.
    config = json.loads(base64.b64decode(artifact["config"], validate=True))
    containers = config["containers"]
    if len(containers) != 1 or containers[0]["name"] != "gateway":
        raise ValueError("unexpected container topology")
    image = containers[0]["image"]
    if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("immutable gateway image required")
    runtime = next(v["AXIOM_GATEWAY_CONFIG_JSON"] for v in containers[0]["env"] if "AXIOM_GATEWAY_CONFIG_JSON" in v)
    runtime = json.loads(runtime)
    spec = importlib.util.spec_from_file_location("prepare_tinfoil", ROOT / "scripts/prepare-tinfoil.py")
    prepare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare)
    with tempfile.TemporaryDirectory() as output:
        expected = prepare.prepare(argparse.Namespace(image=image, cvm_version=config["cvm-version"],
            gateway_origin=runtime["public_origin"], backend_origin=runtime["backend_origin"],
            browser_origin=runtime["browser_origins"], publisher_key=runtime["publisher_key"],
            concurrency=runtime["max_concurrency"], sessions=runtime["max_sessions"], output=output))
    if expected != config:
        raise ValueError("release config differs from the restricted generated topology")
    public = subprocess.check_output(["openssl", "pkey", "-in", args.key, "-pubout", "-outform", "DER"])
    if len(public) != 44 or public[:12].hex() != "302a300506032b6570032100" or public[12:].hex() != runtime["publisher_key"]:
        raise ValueError("measured publisher key differs from the signing authority")
    registers = [artifact["snp_measurement"], artifact["tdx_measurement"]["rtmr1"], artifact["tdx_measurement"]["rtmr2"]]
    if not all(re.fullmatch(r"[0-9a-f]{96}", value) for value in registers):
        raise ValueError("invalid build measurements")
    build = json.loads(Path(args.build_record).read_text())
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    spec = importlib.util.spec_from_file_location("record_build", ROOT / "scripts/record-build.py")
    record = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(record)
    if (build.get("schema_version") != 1 or build.get("clean") is not True
            or build["source_revision"] != revision or build["build_recipe_sha256"] != record.recipe()
            or build["cargo_lock_sha256"] != digest(ROOT / "Cargo.lock")
            or build["verifier_lock_sha256"] != digest(ROOT / "verifier/go.sum")):
        raise ValueError("build record does not match this clean source revision")
    # A published image's immutable configuration ID commits to all of its
    # layers. It must be the image produced by the recorded trusted build.
    subprocess.run([args.engine, "pull", image], check=True)
    image_id = subprocess.check_output([args.engine, "image", "inspect", "--format", "{{.Id}}", image], text=True).strip()
    image_id = image_id if image_id.startswith("sha256:") else "sha256:" + image_id
    if image_id != build["images"]["axiom-web-gateway"]:
        raise ValueError("published image differs from the recorded build")
    return {"schema_version": 2, "generation": args.generation,
            "source_repository": "https://github.com/astrea-foundation/axiom-web-gateway",
            "source_revision": revision,
            "build_recipe_sha256": build["build_recipe_sha256"], "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
            "verifier_lock_sha256": digest(ROOT / "verifier/go.sum"),
            "gateway_image_digest": image.split("@", 1)[1], "config_repository": args.config_repository,
            "config_digest": hashlib.sha256(raw).hexdigest(),
            "code_measurement": {"type": "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1", "registers": registers},
            "public_origin": runtime["public_origin"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["policy", "workload"])
    parser.add_argument("--key", required=True, help="offline Ed25519 publisher PEM")
    parser.add_argument("--config-repository", required=True, help="authenticated config release publisher owner/repo")
    parser.add_argument("--output", required=True)
    parser.add_argument("--generation", type=int, required=True)
    parser.add_argument("--sequence", type=int)
    parser.add_argument("--build-record", help="record from the trusted clean container build")
    parser.add_argument("--engine", choices=["podman", "docker"], default="podman")
    parser.add_argument("--deployment", help="published tinfoil-deployment.json build artifact")
    args = parser.parse_args()
    if args.generation < 1 or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.config_repository):
        raise ValueError("invalid generation or config publisher")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if args.operation == "policy":
        if not args.sequence or args.sequence < 1:
            raise ValueError("monotonic policy sequence required")
        now = int(time.time())
        payload = {"schema_version": 2, "sequence": args.sequence, "issued_at": now, "expires_at": now + 86400,
                   "minimum_generation": args.generation, "config_repository": args.config_repository}
        path = output / "trust-policy.json"
        document = signed(payload, "axiom-gateway-policy-v2", args.key)
    else:
        if not args.deployment or not args.build_record:
            raise ValueError("published deployment artifact and trusted build record required")
        # Authenticate the release workflow rather than trusting its download.
        subprocess.run(["gh", "attestation", "verify", args.deployment, "--repo", args.config_repository,
                        "--signer-workflow", args.config_repository + "/.github/workflows/tinfoil-release-publish.yml",
                        "--predicate-type", "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"], check=True)
        payload = workload(args)
        path = output / "manifests" / (payload["config_digest"] + ".json")
        path.parent.mkdir(exist_ok=True)
        document = signed(payload, "axiom-gateway-workload-v2", args.key)
    path.write_text(json.dumps(document, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
