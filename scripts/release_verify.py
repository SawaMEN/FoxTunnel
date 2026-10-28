"""Offline release contract checks. Never extract files or execute downloaded code."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import stat
import tarfile

TARGETS = set('linux/amd64/nss linux/arm64/nss'.split())
VERSION = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
DRAFT = 'foxtunnel-draft-0'
MAX_JSON = 4 * 1024 * 1024
MAX_MEMBER = 150 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_MEMBERS = 256
ARCHIVE_FIELDS = {'filename', 'sha256', 'size'}


def validate_version(version):
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError('version must be a v-prefixed semantic version')
    if '-' in version:
        for identifier in version.split('-', 1)[1].split('.'):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith('0'):
                raise ValueError('numeric prerelease identifiers cannot have leading zeros')


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('non-finite JSON value: ' + value)


def json_object(raw):
    if len(raw) > MAX_JSON:
        raise ValueError('JSON exceeds release limit')
    value = json.loads(raw, object_pairs_hook=_object, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError('release JSON must be an object')
    return value


def same_json(left, right):
    # Python equality aliases True/1 and False/0. Contract JSON must preserve types.
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def read_json(path):
    with path.open('rb') as f:
        return json_object(f.read(MAX_JSON + 1))


def safe_name(name):
    # The release layout contains regular files only. Reject names unsafe on
    # Linux and for portable extraction, including alternate streams and device aliases.
    if not isinstance(name, str) or not name or len(name) > 240 or '\\' in name:
        raise ValueError('unsafe archive member name')
    for part in name.split('/'):
        if (not re.fullmatch(r'[A-Za-z0-9_.+-]+', part) or part in ('.', '..')
                or part.endswith('.') or part.split('.')[0].upper() in
                {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}):
            raise ValueError('unsafe archive member name: ' + name)
    return name


def validate_metadata(p, version, commit):
    if not isinstance(p, dict):
        raise ValueError('artifact metadata must be an object')
    target = p.get('target')
    if not isinstance(target, str) or target not in TARGETS:
        raise ValueError('unsupported release target')
    goos, arch, flavor = target.split('/')
    expected = dict(version=version, commit=commit, goos=goos,
                    goarch=arch,
                    variant='', build_flavor=flavor,
                    protocol_draft=DRAFT, default_tls_backend='nss',
                    tls_backends=['go', 'nss'] if flavor == 'nss' else ['go'])
    if 'product' in p and (p['product'] != 'protocol-core' or type(p.get('integration_schema')) is not int or p['integration_schema'] != 1):
        raise ValueError('invalid protocol core integration contract')
    if p.get('product') == 'protocol-core' and any(type(p.get(k)) is not int or p[k] != 1 for k in ('sdk_schema', 'process_schema')):
        raise ValueError('invalid SDK/process schema')
    if type(p.get('schema')) is not int or p['schema'] != 1:
        raise ValueError('unsupported artifact schema')
    if p.get('dirty') is not False or p.get('experimental') is not True:
        raise ValueError('release must be clean and experimental')
    for key, value in expected.items():
        if p.get(key) != value:
            raise ValueError('artifact metadata mismatch: ' + key)
    if p.get('native_smoke_tested') is not True:
        raise ValueError('missing native smoke status')
    # Earlier schema-1 archives did not record the compiler in build.json.
    if 'go_version' in p and (not isinstance(p['go_version'], str) or not re.fullmatch(r'go\d+\.\d+\.\d+', p['go_version'])):
        raise ValueError('invalid Go compiler version')
    stamp = p.get('build_date')
    if not isinstance(stamp, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', stamp):
        raise ValueError('invalid build date')
    dt.datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ')
    suffix = '.tar.gz'
    if p.get('filename') != f'vetroff_{version[1:]}_{goos}_{arch}_{flavor}{suffix}':
        raise ValueError('archive filename does not match target/version')
    if not isinstance(p.get('sha256'), str) or not HASH.fullmatch(p['sha256']):
        raise ValueError('invalid archive hash')
    if type(p.get('size')) is not int or not 0 < p['size'] <= MAX_TOTAL:
        raise ValueError('invalid archive size')
    runtime = p.get('runtime')
    if not isinstance(runtime, dict):
        raise ValueError('missing runtime requirements')
    if flavor == 'go':
        if runtime != {'kind': 'cgo-disabled'}:
            raise ValueError('invalid portable runtime')
        return
    if (runtime.get('kind') != 'bundled-nss' or not p['native_smoke_tested']
            or not isinstance(runtime.get('baseline'), str) or not runtime['baseline']
            or runtime.get('packages') != ['glibc', 'libgcc-s1']):
        raise ValueError('invalid NSS runtime requirements')
    mozilla = runtime.get('mozilla')
    if not isinstance(mozilla, dict) or type(mozilla.get('schema')) is not int or mozilla['schema'] != 1:
        raise ValueError('invalid Mozilla provenance')
    if not isinstance(mozilla.get('nss_version'), str) or not mozilla['nss_version'] or runtime.get('nss_version') != mozilla['nss_version']:
        raise ValueError('invalid NSS version')
    if not isinstance(mozilla.get('firefox_version'), str) or not mozilla['firefox_version']:
        raise ValueError('missing Firefox version')
    for key in ('archive_sha256', 'source_sha256'):
        if not isinstance(mozilla.get(key), str) or not HASH.fullmatch(mozilla[key]):
            raise ValueError('invalid Mozilla hash')
    for key in ('archive_url', 'source_url'):
        if not isinstance(mozilla.get(key), str) or not mozilla[key].startswith('https://archive.mozilla.org/pub/firefox/releases/'):
            raise ValueError('invalid Mozilla source URL')
    libraries = mozilla.get('libraries')
    if not isinstance(libraries, dict) or not 1 <= len(libraries) <= 32 or 'libnss3.so' not in libraries:
        raise ValueError('invalid Mozilla library set')
    for name, digest in libraries.items():
        safe_name(name)
        if '/' in name or not name.endswith('.so') or not isinstance(digest, str) or not HASH.fullmatch(digest):
            raise ValueError('invalid Mozilla library entry')


def validate_manifest(m, version, commit, targets=None):
    validate_version(version)
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ValueError('expected source commit must be a full lowercase Git SHA')
    if (type(m.get('schema')) is not int or m['schema'] != 1 or m.get('version') != version
            or m.get('commit') != commit or m.get('protocol_draft') != DRAFT):
        raise ValueError('manifest schema/version/commit/draft mismatch')
    entries = m.get('artifacts')
    if not isinstance(entries, list) or not 1 <= len(entries) <= len(TARGETS):
        raise ValueError('invalid artifact list')
    seen = set()
    for p in entries:
        validate_metadata(p, version, commit)
        if p['target'] in seen:
            raise ValueError('duplicate release target')
        seen.add(p['target'])
    if seen != (TARGETS if targets is None else targets):
        raise ValueError('incomplete/unexpected release target set')
    return entries


def inspect_archive(path, metadata):
    """Hash every regular member with bounded reads; inspect JSON, never unpack."""
    if path.is_symlink() or not path.is_file():
        raise ValueError('archive must be a regular local file')
    if path.stat().st_size != metadata['size'] or sha(path) != metadata['sha256']:
        raise ValueError('archive hash/size mismatch')
    hashes, documents, seen, total = {}, {}, set(), 0
    executable = 'vetroff'
    libraries = metadata['runtime'].get('mozilla', {}).get('libraries', {})
    allowed = {executable, 'build.json', 'LICENSE', 'THIRD_PARTY_NOTICES.txt'}
    if metadata.get('product') == 'protocol-core':
        allowed |= {'integration.json', 'INTEGRATION.md'}
    if metadata['build_flavor'] == 'nss':
        allowed |= {'mozilla-runtime.json', *('lib/' + name for name in libraries)}

    def consume(name, size, mode, regular, source):
        nonlocal total
        safe_name(name)
        folded = name.casefold()
        if folded in seen or len(seen) >= MAX_MEMBERS:
            raise ValueError('duplicate/excess archive members')
        seen.add(folded)
        if not regular or mode & 0o7000:
            raise ValueError('archive contains a link/special file or privileged mode')
        if name not in allowed and not (name.startswith('licenses/') and name.count('/') == 1):
            raise ValueError('unexpected archive member: ' + name)
        if not 0 < size <= MAX_MEMBER or total + size > MAX_TOTAL:
            raise ValueError('archive member/total exceeds release limit')
        if name.endswith('.json') and size > MAX_JSON:
            raise ValueError('JSON exceeds release limit')
        if name == executable and mode & 0o111 != 0o111:
            raise ValueError('Unix executable lacks execute permissions')
        total += size
        digest, data, read = hashlib.sha256(), bytearray(), 0
        with source() as src:
            while block := src.read(min(1024 * 1024, size - read + 1)):
                read += len(block)
                if read > size:
                    raise ValueError('archive member exceeds declared size')
                digest.update(block)
                if name in ('build.json', 'mozilla-runtime.json', 'integration.json'):
                    data.extend(block)
        if read != size:
            raise ValueError('truncated archive member')
        hashes[name] = digest.hexdigest()
        if data:
            documents[name] = json_object(data)

    with tarfile.open(path, 'r|gz') as archive:
        for item in archive:
            consume(item.name, item.size, item.mode, item.isfile(),
                    lambda item=item: archive.extractfile(item))
    if not allowed <= hashes.keys() or not any(name.startswith('licenses/') for name in hashes):
        raise ValueError('missing required archive member')
    expected_build = {k: v for k, v in metadata.items() if k not in ARCHIVE_FIELDS}
    if not same_json(documents.get('build.json'), expected_build):
        raise ValueError('embedded build.json differs from release metadata')
    if metadata.get('product') == 'protocol-core':
        contract = read_json(Path(__file__).resolve().parents[1] / 'integration/contract.json')
        if not same_json(documents.get('integration.json'), contract):
            raise ValueError('embedded integration contract mismatch')
    if libraries:
        if 'licenses/Mozilla-about-license.html' not in hashes:
            raise ValueError('missing Mozilla license notices')
        if not same_json(documents.get('mozilla-runtime.json'), metadata['runtime']['mozilla']):
            raise ValueError('embedded Mozilla provenance differs from release metadata')
        for name, digest in libraries.items():
            if hashes.get('lib/' + name) != digest:
                raise ValueError('bundled Mozilla library hash mismatch: ' + name)


def embedded_metadata(path):
    """Read bounded build.json without extracting or executing an archive."""
    if path.is_symlink() or not path.is_file():
        raise ValueError('archive must be a regular local file')
    if not 0 < path.stat().st_size <= MAX_TOTAL:
        raise ValueError('invalid archive size')
    with tarfile.open(path, 'r|gz') as archive:
        for member in archive:
            if member.name == 'build.json':
                if not member.isfile() or not 0 < member.size <= MAX_JSON:
                    raise ValueError('invalid embedded build.json')
                with archive.extractfile(member) as source:
                    data = source.read(MAX_JSON + 1)
                if len(data) != member.size:
                    raise ValueError('truncated embedded build.json')
                metadata = json_object(data)
                metadata.update(filename=path.name, sha256=sha(path), size=path.stat().st_size)
                return metadata
    raise ValueError('missing embedded build.json')


def verify(a):
    """Verify both Linux NSS archives, or one explicitly selected target, offline."""
    validate_version(a.version)
    if not isinstance(a.commit, str) or not COMMIT.fullmatch(a.commit):
        raise ValueError('expected source commit must be a full lowercase Git SHA')
    if a.target is not None and a.target not in TARGETS:
        raise ValueError('unsupported requested target')
    base = Path(a.input)
    if a.target:
        target_filename = f"vetroff_{a.version[1:]}_{a.target.replace('/', '_')}.tar.gz"
        archives = [base / target_filename]
    else:
        archives = sorted(base.glob(f'vetroff_{a.version[1:]}_*.tar.gz'))
    if not archives:
        raise ValueError('no release archives found')
    seen = set()
    for path in archives:
        p = embedded_metadata(path)
        validate_metadata(p, a.version, a.commit)
        if p['target'] in seen or (a.target and p['target'] != a.target):
            raise ValueError('duplicate/unexpected release target')
        seen.add(p['target'])
        inspect_archive(path, p)
    if seen != ({a.target} if a.target else TARGETS):
        raise ValueError('incomplete/unexpected release target set')
    print(f'Verified {len(archives)} Linux archives for {a.version} from {a.commit}; no code executed')
