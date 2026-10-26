"""Native Necko platform detection and ELF architecture validation."""
import platform
import struct
import sys

MACHINES = {'linux-amd64': 62, 'linux-arm64': 183}


def host_platform():
    machine = platform.machine().lower()
    arch = {'x86_64': 'amd64', 'amd64': 'amd64',
            'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine)
    if sys.platform != 'linux' or arch is None:
        raise ValueError('native Necko requires Linux amd64 or ARM64')
    return 'linux-' + arch


def verify_elf(path, target):
    if target not in MACHINES:
        raise ValueError('unsupported Necko platform')
    with path.open('rb') as stream:
        header = stream.read(64)
    if (len(header) != 64 or header[:7] != b'\x7fELF\x02\x01\x01' or
            struct.unpack_from('<H', header, 16)[0] not in (2, 3) or
            struct.unpack_from('<H', header, 18)[0] != MACHINES[target] or
            struct.unpack_from('<I', header, 20)[0] != 1):
        raise ValueError('ELF architecture differs from target platform: ' + str(path))
