#!/usr/bin/env python3
"""Keep host VPN stacks and research tools outside the protocol runtime.

Run from any directory. Go resolves the actual transitive production graph,
including the selected build tags; no source-import regular expressions.
"""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/SawaMEN/FoxTunnel"
REMOVED_PATHS = (
    "internal/nativetun",
    "scripts/linux_native_vpn.py",
    "scripts/linux_tun_companion.py",
    "scripts/test_linux_tun_e2e.py",
    "scripts/test_linux_tun_netns.py",
    ".github/workflows/tun-netns.yml",
    ".github/workflows/native-tun-e2e.yml",
)
HOST_MODULES = (
    "gvisor.dev/gvisor",
    "github.com/xjasonlyu/tun2socks",
    "github.com/eycorsican/go-tun2socks",
    "github.com/sagernet/sing-box",
    "github.com/xtls/xray-core",
)
# The reviewed Necko process API is now a supported runtime dependency.
# Only this exact Go package is promoted; fingerprint tools, command-line lab
# programs and any new experiment subpackages remain forbidden. Its native
# fixtures are _test.go files and are not part of the production graph.
PROMOTED_RUNTIME_PACKAGES = {MODULE + "/experiments/firefox-necko"}
RESEARCH_PACKAGES = (
    MODULE + "/experiments",
    MODULE + "/cmd/ft-fingerprint",
    MODULE + "/cmd/ft-webprofile",
    MODULE + "/internal/fingerprint",
    MODULE + "/internal/webprofile",
)


def under(path, prefix):
    return path == prefix or path.startswith(prefix + "/")


def check(tags=""):
    errors = [
        "host VPN component restored: " + path
        for path in REMOVED_PATHS if (ROOT / path).exists()
    ]
    command = ["go", "list", "-mod=readonly", "-deps", "-f", "{{.ImportPath}}"]
    if tags:
        command += ["-tags", tags]
    # Both the SDK and process runtime must remain independent of lab tools.
    packages = subprocess.check_output(
        command + [".", "./cmd/foxtunnel", "./processhost"], cwd=ROOT, text=True
    ).splitlines()
    for package in packages:
        if any(under(package.lower(), p.lower()) for p in HOST_MODULES):
            errors.append("host VPN dependency in runtime: " + package)
        if package not in PROMOTED_RUNTIME_PACKAGES and any(under(package, p) for p in RESEARCH_PACKAGES):
            errors.append("research package in runtime: " + package)
    # Check selected modules too, including unused direct/transitive requirements.
    modules = subprocess.check_output(
        ["go", "list", "-mod=readonly", "-m", "-f", "{{.Path}}", "all"],
        cwd=ROOT, text=True,
    ).splitlines()
    for module in modules:
        if any(under(module.lower(), p.lower()) for p in HOST_MODULES):
            errors.append("host VPN module in dependency graph: " + module)
    if errors:
        raise SystemExit("\n".join(errors))
    print("Protocol-core boundaries valid (tags: " + (tags or "default") + ")")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tags", default="", help="Go build tags, e.g. nss,neqo")
    check(parser.parse_args().tags)
