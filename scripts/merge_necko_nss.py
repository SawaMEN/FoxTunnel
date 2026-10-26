#!/usr/bin/env python3
"""Combine verified Necko and NSS into one native Linux AMD64/ARM64 release archive.

The original NSS and Necko artifacts are independently tested before merging.
The resulting single CLI is the NSS-enabled binary. Full Necko runs in a
separate pinned runtime/ directory and is selected by the normal engine flag.
No existing archive is replaced, and every packaged file is manifest-hashed.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile

import release_verify
import necko_bundle
from necko_platform import verify_elf

ROOT = Path(__file__).resolve().parents[1]

MAX_FILES = 20000
MAX_UNPACKED = 3 * 1024 * 1024 * 1024
MAX_FILE = 1024 * 1024 * 1024


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def extract_regular(archive_path, dest, prefix=""):
    """Extract regular members only; refuse links, traversal and duplicates."""
    seen, count, total = set(), 0, 0
    root_seen = False
    with tarfile.open(archive_path, "r:gz") as archive:
        for m in archive:
            raw = m.name.rstrip("/")
            # Historical package_necko emitted this exact root-directory alias.
            # No dot component elsewhere is accepted.
            if prefix and raw == prefix + "/." and m.isdir():
                raw = prefix
            if m.mode & 0o7000:
                raise ValueError("privileged archive member")
            parts = PurePosixPath(raw).parts
            if not parts or raw.startswith("/") or any(p in (".", "..") for p in raw.split("/")):
                raise ValueError("unsafe archive member")
            if prefix:
                if parts[0] != prefix:
                    raise ValueError("unexpected archive root: " + parts[0])
                parts = parts[1:]
                if not parts:
                    if not m.isdir() or root_seen:
                        raise ValueError("archive root must be a unique directory")
                    root_seen = True
                    continue
            if not parts:
                raise ValueError("empty archive member")
            name = "/".join(parts)
            if name in seen:
                raise ValueError("duplicate archive member: " + name)
            seen.add(name)
            count += 1
            if count > MAX_FILES:
                raise ValueError("too many archive members")
            path = dest.joinpath(*parts)
            if m.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isfile() or m.mode & 0o7000 or m.size < 0 or m.size > MAX_FILE:
                raise ValueError("nonregular or oversized archive member: " + name)
            total += m.size
            if total > MAX_UNPACKED:
                raise ValueError("unpacked archive is too large")
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(m) as src, path.open("xb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            if path.stat().st_size != m.size:
                raise ValueError("truncated member: " + name)
            path.chmod(m.mode & 0o777)
    if not count:
        raise ValueError("empty archive")


def merge_files(necko, nss):
    if not (necko / "manifest.json").is_file():
        raise ValueError("Necko manifest missing")
    if not (nss / "foxtunnel").is_file() or not (nss / "build.json").is_file():
        raise ValueError("NSS CLI and metadata required")
    metadata = release_verify.read_json(nss / "build.json")
    arch = metadata.get("goarch")
    if metadata.get("build_flavor") != "nss" or arch not in ("amd64", "arm64"):
        raise ValueError("native NSS build required")
    platform = "linux-" + arch
    necko_bundle.verify(necko, platform)
    verify_elf(nss / "foxtunnel", platform)
    if metadata.get("runtime", {}).get("mozilla", {}).get("libraries") is None:
        raise ValueError("NSS runtime provenance missing")
    if not (necko / "foxtunnel-necko").is_file() or not (necko / "runtime/xpcshell").is_file():
        raise ValueError("Necko helper/runtime missing")
    required = {
        "lib": nss / "lib",
        "mozilla-runtime.json": nss / "mozilla-runtime.json",
        "licenses/NSS-about-license.html": nss / "licenses/Mozilla-about-license.html",
        "licenses/NSS-THIRD-PARTY-NOTICES.txt": nss / "THIRD_PARTY_NOTICES.txt",
        "nss-build.json": nss / "build.json",
    }
    for dest, src in required.items():
        if not src.exists() or src.is_symlink():
            raise ValueError("missing NSS component: " + str(src))
        target = necko / dest
        if target.exists():
            raise ValueError("merged file collides with Necko runtime: " + dest)
        if src.is_dir():
            shutil.copytree(src, target, symlinks=False)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
    shutil.copyfile(nss / "foxtunnel", necko / "foxtunnel")
    (necko / "foxtunnel").chmod(0o755)

    manifest = json.loads((necko / "manifest.json").read_text())
    if manifest.get("schema") != 1 or manifest.get("platform") != platform:
        raise ValueError("incompatible Necko manifest")
    files = {p.relative_to(necko).as_posix(): sha(p)
             for p in sorted(necko.rglob("*")) if p.is_file() and p.name != "manifest.json"}
    # A file named manifest.json inside a nested directory is not special.
    for p in sorted(necko.rglob("manifest.json")):
        if p != necko / "manifest.json":
            files[p.relative_to(necko).as_posix()] = sha(p)
    if not files or len(files) > MAX_FILES:
        raise ValueError("invalid combined file count")
    manifest["files"] = files
    (necko / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def make_archive(bundle, archive_path):
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with archive_path.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w|") as tar:
                    for p in (bundle, *sorted(bundle.rglob("*"))):
                        rel = p.relative_to(bundle)
                        name = "foxtunnel-necko" if p == bundle else "foxtunnel-necko/" + rel.as_posix()
                        info = tar.gettarinfo(str(p), arcname=name)
                        info.uid = info.gid = info.mtime = 0
                        info.uname = info.gname = ""
                        if p.is_file():
                            with p.open("rb") as src:
                                tar.addfile(info, src)
                        else:
                            tar.addfile(info)
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise
    return sha(archive_path)


def merge(necko_archive, nss_archive, output, version, commit, arch="amd64"):
    if arch not in ("amd64", "arm64"):
        raise ValueError("unsupported unified architecture")
    release_verify.validate_version(version)
    # This verifies source commit, pinned NSS libraries, licenses and embedded
    # build.json using the existing offline release contract before extraction.
    release_verify.verify(argparse.Namespace(
        version=version, commit=commit, input=str(nss_archive.parent),
        target="linux/" + arch + "/nss"))
    expected = "foxtunnel_" + version[1:] + "_linux_" + arch + "_nss.tar.gz"
    if nss_archive.name != expected:
        raise ValueError("NSS archive name/version mismatch")
    if output.name != "foxtunnel_" + version[1:] + "_linux_" + arch + ".tar.gz":
        raise ValueError("unified output name/version/architecture mismatch")
    if output.exists():
        raise ValueError("refusing to replace an existing unified archive")
    with tempfile.TemporaryDirectory(prefix="foxtunnel-unify-") as tmp:
        tmp = Path(tmp)
        necko, nss = tmp / "necko", tmp / "nss"
        necko.mkdir()
        nss.mkdir()
        extract_regular(necko_archive, necko, prefix="foxtunnel-necko")
        extract_regular(nss_archive, nss)
        necko_bundle.verify(necko, "linux-" + arch,
                            ROOT / "experiments/firefox-necko/gecko.lock.json",
                            ROOT / "experiments/firefox-necko/client.js")
        meta = release_verify.read_json(nss / "build.json")
        if meta["version"] != version or meta["commit"] != commit:
            raise ValueError("NSS source/version mismatch")
        merge_files(necko, nss)
        necko_bundle.verify(necko, "linux-" + arch)
        digest = make_archive(necko, output)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64"), default="amd64")
    parser.add_argument("--necko", type=Path, required=True)
    parser.add_argument("--nss", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    a = parser.parse_args()
    print("Unified SHA-256:", merge(a.necko, a.nss, a.out, a.version, a.commit, a.arch))


if __name__ == "__main__":
    main()
