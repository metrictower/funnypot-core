#!/usr/bin/env python3
"""
Verify a decoy chain end to end: peel every layer in memory (the way a smart agent would), confirm each
layer is a valid archive of the format its name claims, and that the walk reaches the bottom set.

Usage: python3 -I scripts/dev/decoy-chain/peel-decoy-chain.py resources/decoy/chain.7z
Prints depth, per-format counts and the bottom member list; exits non-zero on any broken layer.
"""
import bz2
import gzip
import io
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

SEVENZ = shutil.which('7zz') or shutil.which('7z')
ARCHIVE_EXTS = ('.zip', '.7z', '.tar', '.tar.gz', '.tar.xz', '.tar.bz2', '.tar.zst', '.tar.lz4', '.cpio', '.iso')


def kind_of(data):
    if data[:4] == b'PK\x03\x04':
        return 'zip'
    if data[:6] == b'7z\xbc\xaf\x27\x1c':
        return '7z'
    if data[:2] == b'\x1f\x8b':
        return 'gz'
    if data[:3] == b'BZh':
        return 'bz2'
    if data[:6] == b'\xfd7zXZ\x00':
        return 'xz'
    if data[:4] == b'\x28\xb5\x2f\xfd':
        return 'zst'
    if data[:4] == b'\x04\x22\x4d\x18':
        return 'lz4'
    if data[:6] == b'070701':
        return 'cpio'
    if len(data) > 32774 and data[32769:32774] == b'CD001':
        return 'iso'
    if len(data) > 262 and data[257:262] == b'ustar':
        return 'tar'
    return None


def members(data, kind, work):
    """Return [(name, bytes)] for one layer (symlinks reported with bytes=None)."""
    if kind == 'zip':
        z = zipfile.ZipFile(io.BytesIO(data))
        return [(i.filename, z.read(i)) for i in z.infolist()]
    if kind == 'tar':
        t = tarfile.open(fileobj=io.BytesIO(data))
        return [(m.name, t.extractfile(m).read() if m.isfile() else None) for m in t.getmembers()]
    if kind in ('gz', 'bz2', 'xz', 'zst', 'lz4'):
        if kind == 'gz':
            raw = gzip.decompress(data)
        elif kind == 'bz2':
            raw = bz2.decompress(data)
        elif kind == 'xz':
            raw = lzma.decompress(data)
        else:
            tool = ['zstd', '-d', '-q', '-c'] if kind == 'zst' else ['lz4', '-d', '-q', '-c']
            raw = subprocess.run(tool, input=data, stdout=subprocess.PIPE, check=True).stdout
        return members(raw, 'tar', work)
    if kind == 'cpio':
        out, off = [], 0
        while True:
            hdr = data[off:off + 110]
            namesize, filesize = int(hdr[94:102], 16), int(hdr[54:62], 16)
            off += 110
            name = data[off:off + namesize - 1].decode('utf-8')
            off += namesize + ((4 - (110 + namesize) % 4) % 4)
            if name == 'TRAILER!!!':
                return out
            out.append((name, data[off:off + filesize]))
            off += filesize + ((4 - filesize % 4) % 4)
    if kind in ('7z', 'iso'):
        p = os.path.join(work, 'layer.bin')
        with open(p, 'wb') as f:
            f.write(data)
        listing = subprocess.run([SEVENZ, 'l', '-slt', '-ba', p], stdout=subprocess.PIPE, check=True,
                                 text=True, errors='surrogateescape').stdout
        names = [l[7:] for l in listing.splitlines() if l.startswith('Path = ')]
        attrs = [l[13:] for l in listing.splitlines() if l.startswith('Attributes = ')]
        out = []
        for n, a in zip(names, attrs + [''] * len(names)):
            if a.startswith('D'):
                continue
            b = subprocess.run([SEVENZ, 'e', '-so', '-bso0', '-bse0', p, n], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL).stdout
            out.append((n, b))
        return out
    raise ValueError(kind)


def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    work = tempfile.mkdtemp(prefix='peel-')
    depth, counts, longest = 0, {}, 0
    try:
        while True:
            kind = kind_of(data)
            if kind is None:
                raise SystemExit(f'layer {depth}: unrecognised bytes')
            ms = members(data, kind, work)
            counts[kind] = counts.get(kind, 0) + 1
            names = [n for n, _ in ms]
            if any(os.path.basename(n) == 'final-set.tar.gz' for n in names) or any(n.endswith('db-final.zip') for n in names):
                if any(n.endswith('db-final.zip') for n in names):
                    print('bottom:', sorted(names))
                    break
            arch = [(n, b) for n, b in ms if b is not None and n.lower().endswith(ARCHIVE_EXTS)]
            if not arch:
                raise SystemExit(f'layer {depth} ({kind}): no continuing archive in {names[:6]}')
            # The continuation is the largest archive member; stubs are small.
            n, data = max(arch, key=lambda x: len(x[1]))
            longest = max(longest, len(n.encode('utf-8')))
            depth += 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print(f'depth={depth} longest_member_path={longest} formats={dict(sorted(counts.items()))}')


if __name__ == '__main__':
    main()
