#!/usr/bin/env python3
"""Collect pinned Go launcher dependency notices for redistributable bundles."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def collect(go):
    deps = subprocess.check_output([go, 'list', '-deps', '-f',
        '{{if .Module}}{{.Module.Path}}|{{.Module.Dir}}{{end}}',
        './experiments/firefox-necko/cmd/vetroff-necko', './cmd/vetroff'], cwd=ROOT, text=True)
    goroot = Path(subprocess.check_output([go, 'env', 'GOROOT'], text=True).strip())
    modules = dict(line.split('|', 1) for line in deps.splitlines() if '|' in line)
    notices = ['Go standard library\n' + (goroot / 'LICENSE').read_text()]
    for module, directory in sorted(modules.items()):
        if module == 'github.com/SawaMEN/VetroffProxy':
            continue
        root = Path(directory)
        files = [p for p in root.iterdir() if p.is_file() and
                 (p.name.upper().startswith('LICENSE') or p.name.upper() in ('COPYING', 'NOTICE'))]
        if not files:
            raise ValueError('dependency license missing: ' + module)
        for path in sorted(files):
            notices.append(module + ' / ' + path.name + '\n' + path.read_text())
    return '\n\n' + ('\n\n' + '=' * 72 + '\n\n').join(notices) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.write_text(collect(args.go))


if __name__ == '__main__':
    main()
