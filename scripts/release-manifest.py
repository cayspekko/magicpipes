#!/usr/bin/env python3
"""Writes a release's manifest, release.json, for `magicpipes --upgrade` and `magicpipesd --upgrade`.

    scripts/release-manifest.py <tag> <owner/repo> <dist dir> [--security] > release.json

Lists each bare binary in <dist dir>, named `<binary>-<tag>-<target>[.exe]`, with the address the
release serves it at, its SHA-256 and its size. The release workflow signs the output; a binary
believes none of it until the signature checks (crates/magicpipes-core/src/release.rs).
"""

import hashlib
import json
import os
import re
import sys

TARGETS = ["aarch64-apple-darwin", "x86_64-pc-windows-msvc", "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"]
BINARIES = ["magicpipes", "magicpipesd"]


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 3:
        sys.exit(__doc__)
    tag, repo, dist = args
    version = tag[1:] if tag.startswith("v") else tag
    if not re.fullmatch(r"\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?", version):
        sys.exit(f"{tag} isn't a version")
    files = []
    for binary in BINARIES:
        for target in TARGETS:
            ext = ".exe" if "windows" in target else ""
            name = f"{binary}-{tag}-{target}{ext}"
            path = os.path.join(dist, name)
            if not os.path.isfile(path):
                sys.exit(f"{name} is missing from {dist}")
            digest = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    digest.update(chunk)
            files.append({
                "target": target,
                "binary": binary,
                "url": f"https://github.com/{repo}/releases/download/{tag}/{name}",
                "sha256": digest.hexdigest(),
                "size": os.path.getsize(path),
            })
    manifest = {"version": version, "notes": f"https://github.com/{repo}/releases/tag/{tag}", "files": files}
    if "--security" in sys.argv[1:]:
        manifest["security"] = True
    json.dump(manifest, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
