"""Resolve a reviewed release request; ordinary pushes and PRs never publish."""
import os
from pathlib import Path
import re
import subprocess
from release_verify import read_json, validate_version

REQUEST = '.github/release-request.json'


def resolve(root, event, ref, before, commit):
    request = root / REQUEST
    requested = None
    if request.exists():
        data = read_json(request)
        if set(data) != {'schema', 'version'} or type(data['schema']) is not int or data['schema'] != 1:
            raise ValueError('invalid release request schema')
        requested = data['version']
        validate_version(requested)
        if requested == 'v0.0.0-ci':
            raise ValueError('CI version cannot be a release request')
    if event == 'push' and ref.startswith('refs/tags/'):
        version = ref.removeprefix('refs/tags/')
        validate_version(version)
        if version == 'v0.0.0-ci':
            raise ValueError('CI version cannot be published from a tag')
        return dict(version=version, publish='true', source='tag')
    if event == 'push' and ref == 'refs/heads/main' and requested is not None:
        if not all(re.fullmatch(r'[0-9a-f]{40}', value) for value in (before, commit)) or before == '0' * 40:
            raise ValueError('release requests require a known before/source commit')
        result = subprocess.run(['git', 'diff', '--quiet', before, commit, '--', REQUEST], cwd=root, capture_output=True)
        if result.returncode == 1:
            return dict(version=requested, publish='true', source='request')
        if result.returncode != 0:
            raise ValueError('cannot establish release-request change')
    return dict(version='v0.0.0-ci', publish='false', source='ci')


if __name__ == '__main__':
    result = resolve(Path(__file__).resolve().parents[1], os.environ['GITHUB_EVENT_NAME'],
                     os.environ['GITHUB_REF'], os.environ.get('BEFORE_SHA', ''), os.environ['GITHUB_SHA'])
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        for key, value in result.items():
            output.write(f'{key}={value}\n')
    print(f"Build {result['version']}; publish={result['publish']}; source={result['source']}")
