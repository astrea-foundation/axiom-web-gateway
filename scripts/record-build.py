#!/usr/bin/env python3
"""Record image content IDs and exact clean source inputs for offline signing."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def recipe():
    value = hashlib.sha256()
    files = subprocess.check_output(["git", "ls-files", "-z", "Dockerfile", ".dockerignore", "deploy/tinfoil", "scripts", ".github/workflows"], cwd=ROOT)
    for name in files.split(b"\0"):
        if name and (ROOT / name.decode()).is_file():
            value.update(name + b"\0" + (ROOT / name.decode()).read_bytes())
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=["docker", "podman"], default="podman")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if revision != args.revision:
        raise ValueError("source revision changed during the build")
    images = {}
    for name in ["axiom-web-gateway", "axiom-gateway-verifier"]:
        images[name] = subprocess.check_output([args.engine, "image", "inspect", "--format", "{{.Id}}", name + ":dev"], text=True).strip()
        if not images[name].startswith("sha256:"):
            images[name] = "sha256:" + images[name]
    value = {"schema_version": 1, "source_revision": revision,
             "clean": not bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip()),
             "build_recipe_sha256": recipe(), "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
             "verifier_lock_sha256": digest(ROOT / "verifier/go.sum"), "images": images}
    Path(args.output).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
