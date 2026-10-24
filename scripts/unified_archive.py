"""Safely unpack and verify the single Necko+NSS Linux/amd64 archive.

This format retains the full Necko integrity manifest and embeds the reviewed
NSS build metadata. The archive's SHA-256 still has to come from a trusted
release or artifact attestation before any executable is launched.
"""
from pathlib import Path
import re

import merge_necko_nss
import release_verify as contract


def unpack(source, destination, version, commit, archive_name=None):
    contract.validate_version(version)
    if not contract.COMMIT.fullmatch(commit):
        raise ValueError("expected full source commit")
    expected = "foxtunnel_" + version[1:] + "_linux_amd64.tar.gz"
    if (archive_name or source.name) != expected:
        raise ValueError("not a version-matched Linux amd64 unified archive")
    merge_necko_nss.extract_regular(source, destination, prefix="foxtunnel-necko")
    manifest = contract.read_json(destination / "manifest.json")
    if (manifest.get("schema") != 1 or manifest.get("helper_protocol") != 1 or
            manifest.get("platform") != "linux-amd64" or
            not contract.HASH.fullmatch(manifest.get("source_lock_sha256", "")) or
            not contract.HASH.fullmatch(manifest.get("client_js_sha256", ""))):
        raise ValueError("unsupported Necko bundle manifest")
    hashes = manifest.get("files")
    if not isinstance(hashes, dict) or not 1 <= len(hashes) <= 20000:
        raise ValueError("invalid bundle file manifest")
    observed = {}
    for child in destination.rglob("*"):
        if child.is_symlink():
            raise ValueError("links forbidden in a unified bundle")
        if not child.is_file() or child == destination / "manifest.json":
            continue
        rel = child.relative_to(destination).as_posix()
        observed[rel] = merge_necko_nss.sha(child)
    if observed != hashes:
        raise ValueError("combined bundle manifest mismatch")
    needed = ("foxtunnel", "foxtunnel-necko", "runtime/xpcshell", "runtime/libxul.so",
              "runtime/libnss3.so", "source-lock.json", "provenance.json",
              "lib/libnss3.so", "mozilla-runtime.json", "nss-build.json")
    if any(name not in observed for name in needed):
        raise ValueError("missing native engine component")
    if manifest["source_lock_sha256"] != observed["source-lock.json"]:
        raise ValueError("Gecko source lock digest mismatch")
    provenance = contract.read_json(destination / "provenance.json")
    source_lock = contract.read_json(destination / "source-lock.json")
    if not contract.same_json(provenance.get("source"), source_lock):
        raise ValueError("Necko provenance/source mismatch")

    nss = contract.read_json(destination / "nss-build.json")
    if (nss.get("version") != version or nss.get("commit") != commit or
            nss.get("target") != "linux/amd64/nss" or
            nss.get("goarch") != "amd64" or nss.get("goos") != "linux" or
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
