"""Validate a one-shot, update-branch-only Mozilla prerelease request."""
import os
from pathlib import Path
import re
import subprocess
from release_verify import read_json, validate_version

REQUEST = Path(".github/mozilla-release-candidate.json")
VERSION = re.compile(r"v0\.1\.0-alpha\.[1-9][0-9]*\Z")


def resolve(root: Path, event: str, ref: str) -> str:
    if event != "push" or ref != "refs/heads/update":
        raise ValueError("Mozilla prerelease request is update-push only")
    content = read_json(root / REQUEST)
    if set(content) != {"schema", "version"} or type(content["schema"]) is not int or content["schema"] != 1:
        raise ValueError("unexpected Mozilla prerelease request fields")
    version = content["version"]
    validate_version(version)
    if not VERSION.fullmatch(version):
        raise ValueError("this gate publishes experimental v0.1.0-alpha.N only")
    diff = subprocess.run(
        ["git", "diff", "--quiet", "HEAD^", "HEAD", "--", str(REQUEST)],
        cwd=root, capture_output=True,
    )
    if diff.returncode != 1:
        raise ValueError("release request must change in the triggering commit")
    notes = root / "docs" / "releases" / f"{version}.md"
    if not notes.is_file() or notes.stat().st_size == 0:
        raise ValueError("prerelease notes are missing")
    return version


def main():
    root = Path(__file__).resolve().parents[1]
    version = resolve(root, os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_REF"])
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("version=" + version + "\n")
    print("validated Mozilla prerelease request:", version)


if __name__ == "__main__":
    main()
