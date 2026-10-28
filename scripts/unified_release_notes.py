#!/usr/bin/env python3
"""List independently verified unified assets with one archive per architecture."""
import argparse
from pathlib import Path
import tempfile

import unified_archive

import release_verify
from private_files import write_exclusive


def render(folder, version, commit):
    release_verify.validate_version(version)
    names = (
        "vetroffproxy_" + version[1:] + "_linux_amd64.tar.gz",
        "vetroffproxy_" + version[1:] + "_linux_arm64.tar.gz",
    )
    if {p.name for p in folder.glob("*.tar.gz")} != set(names):
        raise ValueError("expected exactly one Linux archive per architecture")
    for name in names:
        with tempfile.TemporaryDirectory(prefix="vetroffproxy-notes-") as tmp:
            unified_archive.unpack(folder / name, Path(tmp), version, commit)
    lines = [
        "# VetroffProxy " + version,
        "",
        "Unified Linux distribution with one download per architecture.",
        "AMD64: a single NSS-enabled CLI and the complete verified Necko runtime.",
        "ARM64: a single NSS-enabled CLI and the complete verified Necko runtime.",
        "",
        "Source commit: " + commit,
        "",
        "| Archive | SHA-256 | Bytes |",
        "|---|---|---:|",
    ]
    for name in names:
        file = folder / name
        lines.append("| " + name + " | " + release_verify.sha(file) + " | " + str(file.stat().st_size) + " |")
    lines.extend(("", "Verify GitHub artifact attestations for this repository, source commit and release workflow.",
                  "Keep the full extracted bundle, including runtime/ and lib/.",
                  "This is an experimental prerelease, not proof of DPI indistinguishability.", ""))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    a = parser.parse_args()
    write_exclusive(a.out, render(a.input, a.version, a.commit), 0o600)


if __name__ == "__main__":
    main()
