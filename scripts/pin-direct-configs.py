#!/usr/bin/env python3
"""Bind each measured account configuration to the built verifier executable."""
import hashlib
import json
from pathlib import Path


binary = Path("/usr/local/bin/axiom-direct-verify")
digest = hashlib.sha256(binary.read_bytes()).hexdigest()
for environment in ("staging", "production"):
    path = Path("/etc/axiom") / f"astreaai-{environment}.json"
    config = json.loads(path.read_text())
    config["verifier"]["binary_sha256"] = digest
    path.write_text(json.dumps(config, sort_keys=True) + "\n")
