"""Safely unpack and verify the single Necko+NSS Linux AMD64/ARM64 archive.

This format retains the full Necko integrity manifest and embeds the reviewed
NSS build metadata. The archive's SHA-256 still has to come from a trusted
release or artifact attestation before any executable is launched.
"""
from pathlib import Path
import re

import merge_necko_nss
import release_verify as contract
import necko_bundle


def unpack(source, destination, version, commit, archive_name=None):
    contract.validate_version(version)
    if not contract.COMMIT.fullmatch(commit):
        raise ValueError("expected full source commit")
    name = archive_name or source.name
    matches = re.fullmatch(r"foxtunnel_" + re.escape(version[1:]) + r"_linux_(amd64|arm64)\.tar\.gz", name)
    if not matches:
        raise ValueError("not a version-matched native Linux unified archive")
    arch = matches.group(1)
    merge_necko_nss.extract_regular(source, destination, prefix="foxtunnel-necko")
    manifest = necko_bundle.verify(destination, "linux-" + arch)
    observed = manifest['files']
    needed = ("foxtunnel", "lib/libnss3.so", "mozilla-runtime.json", "nss-build.json")
    if any(name not in observed for name in needed):
        raise ValueError("missing native engine component")

    nss = contract.read_json(destination / "nss-build.json")
    if (nss.get("version") != version or nss.get("commit") != commit or
            nss.get("target") != "linux/" + arch + "/nss" or
            nss.get("goarch") != arch or nss.get("goos") != "linux" or
            nss.get("build_flavor") != "nss" or nss.get("dirty") is not False):
        raise ValueError("NSS source identity mismatch")
    runtime = nss.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("kind") != "bundled-nss":
        raise ValueError("invalid NSS runtime metadata")
    mozilla = runtime.get("mozilla")
    if not isinstance(mozilla, dict):
        raise ValueError("missing NSS Mozilla provenance")
    if not contract.same_json(contract.read_json(destination / "mozilla-runtime.json"), mozilla):
        raise ValueError("NSS runtime provenance mismatch")
    libraries = mozilla.get("libraries")
    if not isinstance(libraries, dict) or "libnss3.so" not in libraries:
        raise ValueError("missing NSS library manifest")
    for name, digest in libraries.items():
        if (not isinstance(name, str) or not re.fullmatch(r"lib[A-Za-z0-9_.+-]+\.so", name)
                or observed.get("lib/" + name) != digest):
            raise ValueError("NSS library digest mismatch: " + str(name))
    return nss
