#!/usr/bin/env python3
"""Strict offline verification of a versioned FoxTunnel Mozilla bundle.

Never extracts, executes, or follows links from an untrusted archive.
Requires a trusted expected version and full commit SHA; the checksum in
metadata is not an independent signature. No network access is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import tarfile

from release_verify import (
    MAX_JSON, MAX_MEMBER, MAX_TOTAL, safe_name, validate_version, json_object,
    same_json,
)

SHA = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MAX_FILES = 1024
REQUIRED = {
    "foxtunnel", "build.json", "LICENSE", "THIRD_PARTY_NOTICES.txt",
    "mozilla-runtime.json", "neqo-provenance.json",
    "rust-dependencies.json", "rust-license-index.json",
    "integration.json", "INTEGRATION.md",
}


def is_sha(value: object) -> bool:
    return isinstance(value, str) and bool(SHA.fullmatch(value))


def read_json_bytes(data: bytes) -> dict:
    return json_object(data)


def check_meta(data: dict, tag: str, commit: str, archive_name: str) -> None:
    target = "linux/amd64/mozilla"
    expected = {
        "schema": 1,
        "version": tag,
        "target": target,
        "commit": commit,
        "artifact": archive_name,
        "tests_run": False,
        "published": False,
    }
    for key, value in expected.items():
        if type(data.get(key)) is not type(value) or data[key] != value:
            raise ValueError("invalid release metadata: " + key)
    if not is_sha(data.get("sha256")):
        raise ValueError("invalid archive SHA256")
    if type(data.get("size")) is not int or not 0 < data["size"] <= MAX_TOTAL:
        raise ValueError("invalid archive size")


def validate_bundle(archive: Path, metadata: Path, tag: str, commit: str) -> dict:
    validate_version(tag)
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ValueError("commit must be a trusted full SHA-1")
    expected_archive = f"foxtunnel_{tag[1:]}_linux_amd64_mozilla.tar.gz"
    if archive.name != expected_archive or metadata.name != expected_archive + ".metadata.json":
        raise ValueError("unexpected archive or metadata filename")
    if archive.is_symlink() or metadata.is_symlink():
        raise ValueError("release inputs must not be symlinks")
    if not archive.is_file() or not metadata.is_file():
        raise ValueError("missing archive or metadata")
    if archive.stat().st_size > MAX_TOTAL:
        raise ValueError("oversized compressed archive")
    m = read_json_bytes(metadata.read_bytes())
    check_meta(m, tag, commit, archive.name)
    if archive.stat().st_size != m["size"]:
        raise ValueError("archive size mismatch")
    digest = hashlib.sha256()
    with archive.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != m["sha256"]:
        raise ValueError("archive checksum mismatch")

    hashes, documents, count, total, folded = {}, {}, 0, 0, set()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            count += 1
            if count > MAX_FILES:
                raise ValueError("too many archive members")
            name = safe_name(member.name)
            if name.casefold() in folded:
                raise ValueError("duplicate casefolded archive member")
            folded.add(name.casefold())
            if not member.isfile() or member.mode & 0o7000:
                raise ValueError("symbolic link, special file or privileged mode in archive")
            if name == "foxtunnel" and member.mode & 0o111 != 0o111:
                raise ValueError("missing binary executable permission")
            if name != "foxtunnel" and member.mode & 0o111:
                raise ValueError("unexpected executable asset")
            if not 0 < member.size <= MAX_MEMBER or total + member.size > MAX_TOTAL:
                raise ValueError("oversized asset or decompressed bundle")
            total += member.size
            if not (name in REQUIRED or name.startswith("lib/") and name.count("/") == 1
                    or name.startswith("licenses/") and name.count("/") == 1):
                raise ValueError("unexpected asset")
            file = tar.extractfile(member)
            if file is None:
                raise ValueError("missing archive member content")
            checksum, read = hashlib.sha256(), 0
            collect = name.endswith(".json")
            if collect and member.size > MAX_JSON:
                raise ValueError("JSON asset is oversized")
            data = io.BytesIO() if collect else None
            while read < member.size:
                part = file.read(min(1024 * 1024, member.size - read))
                if not part:
                    raise ValueError("short archive member")
                read += len(part)
                checksum.update(part)
                if data is not None:
                    data.write(part)
            hashes[name] = checksum.hexdigest()
            if data is not None:
                documents[name] = read_json_bytes(data.getvalue())
    if not REQUIRED <= hashes.keys():
        raise ValueError("missing essential Mozilla archive members")
    build = documents["build.json"]
    contract = read_json_bytes((Path(__file__).resolve().parents[1] / "integration/contract.json").read_bytes())
    if not same_json(documents.get("integration.json"), contract):
        raise ValueError("embedded integration contract mismatch")
    source_fields = {
        "product": "protocol-core", "integration_schema": 1,
        "schema": 1, "version": tag, "commit": commit,
        "target": "linux/amd64/mozilla", "engine": "mozilla",
        "build_flavor": "mozilla", "protocol_draft": "foxtunnel-draft-0",
        "nss_version": "3.130", "neqo_version": "0.33.0",
        "rust_toolchain": "1.99.1",
        "experimental": True, "native_compiled": True,
        "tests_run": False, "binary_executed": False,
    }
    for key, expected in source_fields.items():
        if type(build.get(key)) is not type(expected) or build[key] != expected:
            raise ValueError("build.json mismatch: " + key)
    if build.get("quic_backends") != ["quic-go", "neqo"]:
        raise ValueError("missing native Neqo support")
    if build.get("tls_backends") != ["go", "nss"]:
        raise ValueError("missing NSS support")
    if not isinstance(build.get("asset_sha256"), dict):
        raise ValueError("missing per-asset SHA256")
    expected_assets = {name: sha for name, sha in hashes.items() if name != "build.json"}
    if not same_json(build["asset_sha256"], expected_assets):
        raise ValueError("embedded per-asset SHA256 mismatch")
    runtime = build.get("runtime")
    if not isinstance(runtime, dict) or runtime.get("kind") != "bundled-mozilla":
        raise ValueError("missing Mozilla runtime")
    mozilla = runtime.get("mozilla")
    if not isinstance(mozilla, dict) or not same_json(mozilla, documents["mozilla-runtime.json"]):
        raise ValueError("Mozilla provenance mismatch")
    libraries = mozilla.get("libraries")
    if not isinstance(libraries, dict) or "libnss3.so" not in libraries:
        raise ValueError("missing bundled NSS libraries")
    if {f"lib/{name}" for name in libraries} != {name for name in hashes if name.startswith("lib/")}:
        raise ValueError("unexpected/missing dynamic libraries")
    if any(hashes[f"lib/{name}"] != hash_value for name, hash_value in libraries.items()):
        raise ValueError("bundled dynamic library checksum mismatch")
    if hashes["neqo-provenance.json"] != runtime.get("neqo_provenance_sha256"):
        raise ValueError("Neqo provenance checksum mismatch")
    if hashes["rust-dependencies.json"] != runtime.get("rust_dependencies_sha256"):
        raise ValueError("Rust dependencies checksum mismatch")
    if documents["neqo-provenance.json"].get("neqo_version") != "0.33.0":
        raise ValueError("Neqo dependency version mismatch")
    license_index = documents["rust-license-index.json"]
    entries = license_index.get("entries") if isinstance(license_index, dict) else None
    if (not isinstance(entries, dict) or not entries
            or any(not isinstance(path, str) or not path for path in entries.values())
            or set(entries) != {name for name in hashes if name.startswith("licenses/Rust-")}):
        raise ValueError("incomplete Rust dependency licenses")
    if "licenses/Mozilla-about-license.html" not in hashes:
        raise ValueError("missing Mozilla license notice")
    return {"schema": 1, "version": tag, "commit": commit,
            "archive": archive.name, "sha256": m["sha256"], "bytes": m["size"],
            "members": count, "native_flavor": "mozilla", "verified": True}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--version", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--input", default="dist", type=Path)
    p.add_argument("--report", type=Path, help="optional new owner-only verification result")
    args = p.parse_args()
    filename = f"foxtunnel_{args.version[1:]}_linux_amd64_mozilla.tar.gz"
    try:
        if args.report is not None and args.report.exists():
            raise ValueError("refuse overwrite of verification report")
        result = validate_bundle(args.input / filename,
                                 args.input / (filename + ".metadata.json"),
                                 args.version, args.commit)
        if args.report:
            fd = args.report.open("x", encoding="utf-8")
            with fd:
                json.dump(result, fd, indent=2, sort_keys=True)
                fd.write("\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, tarfile.TarError, EOFError) as err:
        print("verification refused: " + str(err))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
