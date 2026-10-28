#!/usr/bin/env python3
"""Add checksums of offline-verified archives to release notes; publish nothing."""
import argparse
from pathlib import Path

import release_verify as contract
from private_files import write_exclusive

ROOT = Path(__file__).resolve().parents[1]


def render(folder, version, commit, notes):
    contract.verify(argparse.Namespace(input=str(folder), version=version, commit=commit, target=None))
    rows = [contract.embedded_metadata(path) for path in sorted(folder.glob('*.tar.gz'))]
    text = notes.rstrip() + '\n\n## Verified archive identities\n\n'
    text += f'Source commit: `{commit}`. Protocol: `{contract.DRAFT}`. SDK/process schemas: 1/1.\n\n'
    text += '| Archive | SHA-256 | Bytes |\n|---|---|---:|\n'
    for row in rows:
        text += f"| {row['filename']} | `{row['sha256']}` | {row['size']} |\n"
    text += ('\nVerify these hashes before extraction. SHA-256 checks integrity; verify the GitHub '
             'artifact attestation against the exact repository, release workflow, source commit and ref '
             'to check signed provenance. Keep the complete bundle, including lib/. '
             'This is an experimental protocol core, not a production or censorship-resistance claim.\n')
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    notes = ROOT / 'docs/releases' / (args.version + '.md')
    # Validate version before constructing/reading a source filename.
    contract.validate_version(args.version)
    text = notes.read_text() if notes.is_file() else 'Experimental VetroffProxy protocol core for host integration.\n'
    write_exclusive(args.out, render(args.input, args.version, args.commit, text), 0o600)


if __name__ == '__main__':
    main()
