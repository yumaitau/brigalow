#!/usr/bin/env python3
"""Verify manifest signature and every payload digest. Pin the public key independently."""
import argparse
import hashlib
import json
import pathlib
import subprocess
def require(condition, message):
    if not condition:
        raise SystemExit(message)


p = argparse.ArgumentParser()
p.add_argument("directory", type=pathlib.Path)
p.add_argument("--public-key", required=True, type=pathlib.Path)
a = p.parse_args()
result = subprocess.run(
    ["openssl", "dgst", "-sha256", "-verify", str(a.public_key), "-signature",
     str(a.directory / "manifest.sig"), str(a.directory / "manifest.json")],
    capture_output=True,
)
require(result.returncode == 0, "release manifest signature invalid")
manifest = json.loads((a.directory / "manifest.json").read_text())
require(type(manifest.get("version")) is int and manifest["version"] == 1 and manifest.get("trust") == "lab", "invalid manifest metadata")
files = manifest.get("files")
require(isinstance(files, dict) and 0 < len(files) <= 20, "invalid manifest file list")
for name, digest in files.items():
    require(isinstance(name, str) and isinstance(digest, str) and pathlib.Path(name).name == name and name not in [".", ".."], "invalid artifact path")
    require(hashlib.sha256((a.directory / name).read_bytes()).hexdigest() == digest, "artifact digest mismatch")
print("Lab release signature and payload digests verified; identity depends on independently trusting the public key")
