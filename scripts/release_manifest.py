from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.directory.resolve(strict=True)
    artifacts = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.resolve(strict=True) == arguments.output.resolve(
            strict=False
        ):
            continue
        data = path.read_bytes()
        artifacts.append(
            {"name": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
    manifest = {
        "version": 1,
        "release": arguments.version,
        "artifacts": artifacts,
        "signature_policy": (
            "SHA-256 plus exact-tag GitHub build provenance attestation "
            "with Sigstore-backed identity required"
        ),
    }
    arguments.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
