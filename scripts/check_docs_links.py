#!/usr/bin/env python3
"""Check local Markdown links so reorganizing documentation cannot break navigation."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'!?\[[^\]\n]*\]\(([^)\n]+)\)')
FENCE = re.compile(r'^\s*([\x60]{3,}|~{3,})')
INLINE_CODE = re.compile(r'\x60[^\x60\n]*\x60')


def broken_links(root=ROOT):
    for document in sorted(root.rglob('*.md')):
        if any(part in {'.git', 'dist', 'node_modules'} for part in document.parts):
            continue
        fence = None
        for line_number, line in enumerate(document.read_text(encoding='utf-8').splitlines(), 1):
            marker = FENCE.match(line)
            if marker:
                token = marker.group(1)
                if fence is None:
                    fence = token[0]
                elif token[0] == fence:
                    fence = None
                continue
            if fence:
                continue
            line = INLINE_CODE.sub('', line)
            for match in LINK.finditer(line):
                raw = match.group(1).strip()
                if raw.startswith('<'):
                    target = raw.split('>', 1)[0][1:]
                else:
                    target = raw.split(maxsplit=1)[0]
                parsed = urlsplit(target)
                if (parsed.scheme or parsed.netloc or not parsed.path or
                        parsed.path.startswith('/') or target.startswith('//')):
                    continue
                local = document.parent / unquote(parsed.path)
                if not local.exists():
                    yield f'{document.relative_to(root)}:{line_number}: missing {target}'


if __name__ == '__main__':
    missing = list(broken_links())
    if missing:
        raise SystemExit('Broken Markdown links:\n' + '\n'.join(missing))
    print('Markdown relative links are valid')
