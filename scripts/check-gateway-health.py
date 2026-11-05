#!/usr/local/bin/python3
"""Check real readiness and expose only a finite, non-secret startup phase."""
from pathlib import Path
import sys
import urllib.request

PHASES = frozenset({
    "configuration", "keys", "http-client", "vendor-document", "code-reference",
    "source-manifest", "trust-policy", "policy-signature", "collector",
    "proof-document", "proof-verifier", "proof-binding", "backend-admission",
    "listener", "ready",
})


def phase(path=Path("/dev/shm/axiom-gateway-startup")):
    try:
        with path.open("rb") as stream:
            value = stream.read(65).decode("ascii")
        return value if value in PHASES else "initializing"
    except (OSError, UnicodeError):
        return "initializing"


def main():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=2) as response:
            if response.status == 200:
                return 0
    except Exception:
        pass
    # Do not print HTTP errors or arbitrary file contents. Docker may publish
    # this bounded line through the provider's boot-health diagnostics.
    print("gateway startup phase: " + phase())
    return 1


if __name__ == "__main__":
    sys.exit(main())
