#!/usr/bin/env python3
"""Prepare and build the pinned, experimental Necko runtime (Linux amd64).

The source checkout must already exist. No browser artifact build is accepted:
these patches change C++ in libxul. A successful build is not an interop result.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "experiments/firefox-necko/gecko.lock.json"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args, source, **kwargs):
    return subprocess.run(args, cwd=source, check=True, **kwargs)


def git(source, *args):
    return run(["git", *args], source, text=True, capture_output=True).stdout.strip()


def checked_path(root, relative):
    path = root / relative
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("unsafe manifest path")
    if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise ValueError("source or patch path escapes its root")
    return path


def load_lock(lock_path=LOCK, root=ROOT):
    lock = json.loads(lock_path.read_text())
    if lock.get("schema") != 1 or not re.fullmatch(r"[0-9a-f]{40}", lock.get("revision", "")):
        raise ValueError("invalid Gecko source lock")
    if lock.get("platform") != "linux-amd64" or not lock.get("patches"):
        raise ValueError("unsupported Gecko source lock")
    seen = set()
    for patch in lock["patches"]:
        for field in ("sha256", "before_sha256", "after_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", patch.get(field, "")):
                raise ValueError("invalid patch digest")
        if patch["source_path"] in seen:
            raise ValueError("each source file must have one combined patch")
        seen.add(patch["source_path"])
        checked_path(root, patch["source_path"])
        path = checked_path(root, patch["path"])
        if sha256(path) != patch["sha256"]:
            raise ValueError("Gecko patch digest mismatch")
    return lock


def prepare(source, lock, root=ROOT):
    if git(source, "rev-parse", "HEAD") != lock["revision"]:
        raise ValueError("Gecko checkout revision differs from source lock")
    allowed = {p["source_path"] for p in lock["patches"]}
    dirty = set(git(source, "diff", "HEAD", "--name-only").splitlines())
    if not dirty <= allowed:
        raise ValueError("Gecko checkout has unrelated tracked modifications")
    pending = []
    # Validate every input before modifying any file. Exact hashes also reject
    # partial applications, altered whitespace and a locally replaced source.
    for patch in lock["patches"]:
        path = checked_path(source, patch["source_path"])
        digest = sha256(path)
        if digest == patch["after_sha256"]:
            continue
        if digest != patch["before_sha256"]:
            raise ValueError("Gecko source digest mismatch: " + patch["source_path"])
        pending.append(str(checked_path(root, patch["path"])))
    if pending:
        run(["git", "apply", "--check", *pending], source)
        run(["git", "apply", *pending], source)
    for patch in lock["patches"]:
        if sha256(checked_path(source, patch["source_path"])) != patch["after_sha256"]:
            raise ValueError("patched Gecko source digest mismatch")


def mozconfig(objdir, jobs):
    # These paths are parsed by mozconfig's shell, not by subprocess. Restrict
    # them instead of accepting shell substitutions from an output path.
    if not re.fullmatch(r"[/A-Za-z0-9_.-]+", str(objdir)):
        raise ValueError("Gecko object path must not contain shell metacharacters")
    if not 1 <= jobs <= 16:
        raise ValueError("Gecko jobs must be between 1 and 16")
    return f"""mk_add_options MOZ_OBJDIR={objdir}
mk_add_options MOZ_MAKE_FLAGS=-j{jobs}
ac_add_options --enable-application=browser
ac_add_options --enable-tests
ac_add_options --disable-debug
ac_add_options --disable-debug-symbols
ac_add_options --disable-crashreporter
ac_add_options --disable-updater
ac_add_options --disable-warnings-as-errors
ac_add_options --disable-lto
ac_add_options --enable-optimize=-O1
ac_add_options --enable-linker=lld
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    source, out = args.source.resolve(), args.out.resolve()
    if out == source or out.is_relative_to(source):
        raise ValueError("keep build configuration and objects outside the source checkout")
    lock = load_lock()
    prepare(source, lock)
    out.mkdir(parents=True, exist_ok=True)
    config = out / "mozconfig"
    config.write_text(mozconfig(out / "obj", args.jobs))
    provenance = {"schema": 1, "status": "source-prepared", "source": lock,
                  "mozconfig_sha256": sha256(config)}
    provenance_path = out / "provenance.json"
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    if args.prepare_only:
        return
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "amd64"):
        raise ValueError("this experimental build supports Linux amd64 only")
    env = os.environ.copy()
    env["MOZCONFIG"] = str(config)
    env["MOZ_OBJDIR"] = str(out / "obj")
    env["MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE"] = "pip"
    # Never allow an inherited artifact configuration to substitute stock C++.
    env.pop("MOZ_ARTIFACT_BUILDS", None)
    run([sys.executable, str(source / "mach"), "--no-interactive", "build"], source, env=env)
    runtime = out / "obj/dist/bin"
    files = ("xpcshell", "libxul.so", "libnss3.so", "platform.ini")
    provenance.update(status="built-not-interop-tested",
                      runtime={name: sha256(runtime / name) for name in files})
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    print(str(runtime / "xpcshell"))


if __name__ == "__main__":
    main()
