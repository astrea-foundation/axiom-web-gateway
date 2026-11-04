#!/usr/bin/env python3
"""Stage the owned verifier bundle from the locked remote shared dependency."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def prepare():
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    dependencies = manifest["workspace"]["dependencies"]
    names = ("axiom-inference", "axiom-openai-compat", "axiom-secure-client")
    pins = {(dependencies[name]["git"], dependencies[name]["rev"]) for name in names}
    if len(pins) != 1:
        raise ValueError("the entire shared stack must use one remote revision")
    repository, revision = pins.pop()
    if repository != "https://github.com/astrea-foundation/axiom-desktop.git" or len(revision) != 40:
        raise ValueError("a full remote source revision is required")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=ROOT))
    packages = [p for p in metadata["packages"] if p["name"] == "axiom-secure-client"]
    if len(packages) != 1 or packages[0]["source"] != f"git+{repository}?rev={revision}#{revision}":
        raise ValueError("resolved shared client differs from the reviewed remote pin")
    source = Path(packages[0]["manifest_path"]).resolve().parents[2] / "vendor/axiom-direct-verifier"
    provenance = json.loads((source / "AXIOM_SOURCE.json").read_text())
    if (provenance["schema"] != 1
            or provenance["canonical_repository"] != "https://github.com/astrea-foundation/axiom-inference"):
        raise ValueError("unexpected verifier provenance")
    destination = ROOT / "out/direct-verifier"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for name, expected in provenance["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid bundle path")
        path = source / relative
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("verifier source digest mismatch: " + name)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    (destination / "AXIOM_SOURCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (destination / "SHARED_SOURCE.json").write_text(json.dumps(
        {"repository": repository, "revision": revision}, indent=2) + "\n")


if __name__ == "__main__":
    prepare()
