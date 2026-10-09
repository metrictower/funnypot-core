#!/usr/bin/env python3
"""
Build resources/decoy/chain.7z: the deep, mixed-format nested "backup" served for backup-ish archive
probes (DecoyArchiveBuilder wraps it at runtime in zip/tar/gz/bz2).

Dev-time only. Runs on an operator machine with local archivers; never in CI or at runtime. The
committed chain.7z + chain.json are the canonical artifact — a rebuild with other tool versions may
differ byte-wise, which is fine because the runtime pins the committed sha256.

Shape (built bottom-up, outermost = part 1):
  - a bottom cluster of dead ends (password zip, AES 7z with a discarded password, corrupt ISO,
    truncated tar.xz, orphan split volume, one /dev/urandom symlink) under a .env with a wrong password;
  - hundreds of layers of weighted mixed formats, each holding the continuing archive under a
    ~300-byte relative folder path, optional README / branching stubs / fake secrets;
  - a 4-8 KB "path wall" every ~50 layers, in a compressing layer;
  - an LZMA-compressed outer 7z, so nothing is greppable from the served bytes.

Safety invariants (asserted): one continuing archive per layer, stubs never branch, no absolute or
'..' names, exactly one symlink (target /dev/urandom), hostile names pass the validator, no marker
text visible in any layer's raw bytes, recursive extracted total bounded.

Usage: python3 -I scripts/dev/decoy-chain/build-decoy-chain.py [--seed N] [--target BYTES] [--out DIR]
"""
import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import names  # noqa: E402  (sibling module: name pools + hostile-name validator)
import content  # noqa: E402  (sibling module: README / secret / stub text)

# Plain tar pads to 10 KiB records by default; real tars written with -b1 use 512-byte records.
tarfile.RECORDSIZE = 512

SEVENZ = shutil.which('7zz') or shutil.which('7z')
EPOCH = 1672531200  # 2023-01-01, base of the seeded timestamp window

# Weighted formats. "cost" class drives placement: expensive formats lean deeper and are always
# wrapped by a compressing layer (tar/cpio/iso padding is erased by the next compressor).
FORMATS = {
    'zip': 35, '7z': 30, 'tgz': 10, 'tar': 5, 'txz': 5, 'tbz2': 4, 'tzst': 4, 'tlz4': 3, 'cpio': 2, 'iso': 2,
}
EXT = {'zip': 'zip', '7z': '7z', 'tgz': 'tar.gz', 'tar': 'tar', 'txz': 'tar.xz', 'tbz2': 'tar.bz2',
       'tzst': 'tar.zst', 'tlz4': 'tar.lz4', 'cpio': 'cpio', 'iso': 'iso'}
COMPRESSING = {'tgz', 'txz', 'tbz2', 'tzst', 'tlz4'}
PADDED = {'tar', 'cpio', 'iso'}          # must be wrapped by a COMPRESSING layer
NO_TEXT = {'tar', 'cpio', 'iso', 'tzst', 'tlz4'}  # raw containers, and zstd/lz4 (they keep short literals raw), carry archives only
SAFE_NAMES_ONLY = {'7z', 'iso', 'cpio'}  # tools on these paths choke on exotic names at build time

# Long enough that random compressed bytes never collide with them by chance.
MARKERS = [b'PASSWORD', b'DB_PASS', b'BEGIN OPENSSH', b'Part ', b'rotated', b'restore order',
           b'DO NOT DELETE', b'aws_secret', b'wp_users']
AKIA_RE = re.compile(rb'AKIA[A-Z0-9]{16}')


class Member:
    __slots__ = ('name', 'data', 'text', 'link')

    def __init__(self, name, data=b'', text=False, link=None):
        self.name, self.data, self.text, self.link = name, data, text, link


# ---------------------------------------------------------------- writers

def w_zip(members, mtime, nul_names=()):
    """Python zipfile: text deflated, archives stored. NUL bytes are patched into stored names
    afterwards (zipfile truncates at NUL), length-preserving so offsets stay valid."""
    buf = io.BytesIO()
    dt = _dostime(mtime)
    with zipfile.ZipFile(buf, 'w') as z:
        for m in members:
            if not (m.link is None):
                raise SystemExit('build invariant failed: m.link is None')
            zi = zipfile.ZipInfo(m.name, dt)
            zi.compress_type = zipfile.ZIP_DEFLATED if m.text else zipfile.ZIP_STORED
            zi.external_attr = (0o100644 << 16)
            zi.create_system = 3
            z.writestr(zi, m.data, compresslevel=9 if m.text else None)
    out = buf.getvalue()
    for placeholder, real in nul_names:
        pe, re_ = placeholder.encode('utf-8'), real.encode('utf-8', 'surrogatepass')
        if not (len(pe) == len(re_) and out.count(pe) == 2):
            raise SystemExit('build invariant failed: len(pe) == len(re_) and out.count(pe) == 2')
        out = out.replace(pe, re_)
    return out


def w_tar(members, mtime):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as t:
        for m in members:
            ti = tarfile.TarInfo(m.name)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = mtime, 1000, 1000, 'deploy', 'deploy'
            if m.link is not None:
                ti.type, ti.linkname, ti.mode = tarfile.SYMTYPE, m.link, 0o777
                t.addfile(ti)
            else:
                ti.size, ti.mode = len(m.data), 0o644
                t.addfile(ti, io.BytesIO(m.data))
    return buf.getvalue()


def w_cpio(members, mtime):
    """SVR4 newc cpio, written directly (bsdtar/cpio both read it)."""
    out = io.BytesIO()
    ino = 1000

    def rec(name, data, mode):
        nonlocal ino
        nb = name.encode('utf-8') + b'\0'
        hdr = '070701' + ''.join('%08X' % v for v in (
            ino, mode, 1000, 1000, 1, mtime, len(data), 0, 0, 0, 0, len(nb), 0))
        out.write(hdr.encode('ascii') + nb)
        out.write(b'\0' * ((4 - (110 + len(nb)) % 4) % 4))
        out.write(data)
        out.write(b'\0' * ((4 - len(data) % 4) % 4))
        ino += 1

    for m in members:
        if not (m.link is None):
            raise SystemExit('build invariant failed: m.link is None')
        rec(m.name, m.data, 0o100644)
    rec('TRAILER!!!', b'', 0)
    return out.getvalue()


def w_7z(members, work, compress_text=True):
    path = os.path.join(work, 'layer.7z')
    if os.path.exists(path):
        os.remove(path)
    # Archives first (stored), text last (LZMA): 7-Zip keeps earlier folders as-is on append, while a
    # later -mx0 append would leave earlier text members stored.
    for m in sorted(members, key=lambda m: m.text):
        if not (m.link is None):
            raise SystemExit('build invariant failed: m.link is None')
        # LZMA1 for text: LZMA2 stores tiny inputs as raw chunks, which would leave text greppable.
        level = '-m0=LZMA' if (m.text and compress_text) else '-mx0'
        src = os.path.join(work, 'si.bin')
        with open(src, 'wb') as f:
            f.write(m.data)
        with open(src, 'rb') as f:
            subprocess.run([SEVENZ, 'a', level, '-mtm-', '-mtc-', '-mta-', '-bso0', '-bsp0',
                            '-si' + m.name, path], stdin=f, check=True)
    with open(path, 'rb') as f:
        return f.read()


def w_iso(members, work, mtime):
    src = os.path.join(work, 'isosrc')
    shutil.rmtree(src, ignore_errors=True)
    os.makedirs(src)
    for m in members:
        p = os.path.join(src, m.name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as f:
            f.write(m.data)
        os.utime(p, (mtime, mtime))
    out = os.path.join(work, 'layer.iso')
    if os.path.exists(out):
        os.remove(out)
    if shutil.which('hdiutil'):
        subprocess.run(['hdiutil', 'makehybrid', '-quiet', '-iso', '-joliet', '-default-volume-name',
                        'BACKUP', '-o', out, src], check=True)
    else:
        subprocess.run(['xorriso', '-as', 'mkisofs', '-quiet', '-J', '-V', 'BACKUP', '-o', out, src],
                       check=True)
    with open(out, 'rb') as f:
        return f.read()


def compress(kind, data):
    if kind == 'tgz':
        return gzip.compress(data, 9, mtime=0)
    if kind == 'tbz2':
        return bz2.compress(data, 9)
    if kind == 'txz':
        return lzma.compress(data, preset=9)
    tool = {'tzst': ['zstd', '-19', '-q', '-c'], 'tlz4': ['lz4', '-9', '-q', '-c']}[kind]
    return subprocess.run(tool, input=data, stdout=subprocess.PIPE, check=True).stdout


def pack(kind, members, work, mtime, nul_names=()):
    if kind == 'zip':
        return w_zip(members, mtime, nul_names)
    if kind == '7z':
        return w_7z(members, work)
    if kind == 'tar':
        return w_tar(members, mtime)
    if kind == 'cpio':
        return w_cpio(members, mtime)
    if kind == 'iso':
        return w_iso(members, work, mtime)
    return compress(kind, w_tar(members, mtime))


def _dostime(ts):
    import time
    t = time.gmtime(ts)
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec - t.tm_sec % 2)


# ---------------------------------------------------------------- chain

class Builder:
    def __init__(self, seed, work, total_parts):
        self.rng = random.Random(seed)
        self.seed = seed
        self.work = work
        self.total_parts = total_parts
        self.stats = {'formats': {}, 'symlinks': 0, 'walls': 0, 'stubs': 0, 'secrets': 0,
                      'hostile_names': 0, 'extracted_total': 0}
        self.prev_kind = None
        self.run_len = 0

    # --- format schedule
    def pick_kind(self, k, inner_kind):
        """k counts layers from the bottom. Expensive formats lean deeper (small k)."""
        rng = self.rng
        if inner_kind in PADDED:
            pool = {f: w for f, w in FORMATS.items() if f in COMPRESSING}
        else:
            pool = dict(FORMATS)
            depth_bias = 1.6 if k < 250 else 0.6
            for f in pool:
                if f not in ('zip', '7z'):
                    pool[f] = pool[f] * depth_bias
        if self.prev_kind and self.run_len >= 3:
            pool.pop(self.prev_kind, None)
        if inner_kind == 'iso':
            pool.pop('iso', None)
        kinds, weights = zip(*pool.items())
        kind = rng.choices(kinds, weights)[0]
        self.run_len = self.run_len + 1 if kind == self.prev_kind else 1
        self.prev_kind = kind
        return kind

    def mtime(self, k):
        # Older the deeper; jitter keeps it non-linear.
        return EPOCH + (self.total_parts - k) * 51840 + self.rng.randint(0, 40000)

    # --- bottom cluster
    def bottom(self):
        rng, work = self.rng, self.work
        mt = self.mtime(0)
        members = []

        # password zip (ZipCrypto) and AES-256 7z with header encryption; passwords discarded.
        inner = os.path.join(work, 'bot')
        shutil.rmtree(inner, ignore_errors=True)
        os.makedirs(inner)
        with open(os.path.join(inner, 'wp_users.sql'), 'wb') as f:
            f.write(content.sql_dump_head(rng))
        pw = os.urandom(32).hex()
        zp = os.path.join(work, 'db-final.zip')
        if os.path.exists(zp):
            os.remove(zp)
        subprocess.run(['zip', '-q', '-X', '-P', pw, '-j', zp, os.path.join(inner, 'wp_users.sql')], check=True)
        members.append(Member('db-final.zip', open(zp, 'rb').read()))
        sp = os.path.join(work, 'secrets.7z')
        if os.path.exists(sp):
            os.remove(sp)
        subprocess.run([SEVENZ, 'a', '-bso0', '-bsp0', '-mx9', '-mhe=on', '-p' + os.urandom(32).hex(), sp,
                        os.path.join(inner, 'wp_users.sql')], check=True)
        members.append(Member('secrets.7z', open(sp, 'rb').read()))

        # corrupt ISO: valid image, primary volume descriptor (sector 16) scrambled.
        iso = bytearray(w_iso([Member('uploads.tar', w_tar([Member('index.php', b'<?php\n')], mt))], work, mt))
        iso[16 * 2048:16 * 2048 + 64] = rng.randbytes(64)
        members.append(Member('media-2023.iso', bytes(iso)))

        # truncated tar.xz
        txz = lzma.compress(w_tar([Member('www/' + n, rng.randbytes(900)) for n in ('a.jpg', 'b.jpg', 'c.jpg')], mt))
        members.append(Member('www-full.tar.xz', txz[:len(txz) * 3 // 5]))

        # orphan split volume: spanning signature + a plausible local header, no later volumes.
        z01 = b'PK\x07\x08' + w_zip([Member('site/wp-content/uploads.tar', rng.randbytes(1500))], mt)[:1200]
        members.append(Member('backup.z01', z01))

        # the one-off /dev/urandom symlink (operator-approved exception, FP-0713 spec §5.5).
        members.append(Member('db_dump.sql', link='/dev/urandom'))
        self.stats['symlinks'] += 1

        members.append(Member('README.txt', content.bottom_readme(rng), text=True))
        data = pack('tgz', members, work, mt)
        self.stats['extracted_total'] += sum(len(m.data) for m in members)
        self.count('tgz')
        return data, 'tgz', 'final-set.tar.gz'

    def count(self, kind):
        self.stats['formats'][kind] = self.stats['formats'].get(kind, 0) + 1

    # --- one wrapping layer
    def layer(self, k, inner, inner_kind, inner_name):
        rng = self.rng
        kind = self.pick_kind(k, inner_kind)
        part = self.total_parts - k
        mt = self.mtime(k)
        wall = (k % 50 == 25) and kind in COMPRESSING
        path = names.folder_path(rng, 4000 + rng.randint(0, 4000) if wall else rng.randint(240, 360),
                                 hostile=(kind not in SAFE_NAMES_ONLY))
        if kind == 'iso':
            path = names.iso_path(rng)
        if wall:
            self.stats['walls'] += 1
        members = [Member(path + '/' + inner_name, inner)]
        nul_names = []

        if kind not in NO_TEXT:
            if rng.random() < 0.4:
                members.append(Member(names.readme_name(rng), content.readme(rng, part, self.total_parts,
                                                                             self.secret_hint_part()), text=True))
            if k > 0 and k % rng.randint(18, 32) == 0:
                nm, data = content.fake_secret(rng)
                members.append(Member(names.near_path(rng, nm), data, text=True))
                self.stats['secrets'] += 1
            if rng.random() < 0.08:
                members.append(Member(names.near_path(rng, '.env'), content.wrong_env(rng), text=True))
                self.stats['secrets'] += 1

        nstubs = rng.choices([0, 1, 2, 3], [45, 35, 15, 5])[0]
        for i in range(nstubs):
            sname = names.stub_name(rng, part, i, safe=(kind in SAFE_NAMES_ONLY))
            members.append(Member(sname, self.stub(mt)))
            self.stats['stubs'] += 1

        if kind == 'zip' and rng.random() < 0.05:
            nm, real = names.nul_name(rng)
            members.append(Member(nm, rng.randbytes(rng.randint(40, 200))))
            nul_names.append((nm, real))
        if kind not in SAFE_NAMES_ONLY and rng.random() < 0.15:
            members.append(Member(names.hostile_file_name(rng), rng.randbytes(rng.randint(16, 160))))
            self.stats['hostile_names'] += 1

        rng.shuffle(members)
        for m in members:
            names.validate(m.name.replace('\x7f', '\0'))
        data = pack(kind, members, self.work, mt, nul_names)
        if greppable(data):
            # A compressor fell back to stored/raw blocks around this layer's text: drop the text.
            members = [m for m in members if not m.text]
            data = pack(kind, members, self.work, mt, nul_names)
            self.stats['text_dropped'] = self.stats.get('text_dropped', 0) + 1
        self.stats['extracted_total'] += sum(len(m.data) for m in members)
        self.count(kind)
        assert_ungreppable(data, kind, k)
        return data, kind, names.continuation_name(rng, part, EXT[kind])

    def stub(self, mt):
        """A short dead-end mini-chain (2-5 layers) ending in an empty or broken archive. Never branches."""
        rng = self.rng
        data = rng.choice([b'', b'PK\x05\x06' + b'\0' * 18, rng.randbytes(rng.randint(30, 120))])
        name = rng.choice(['part.zip', 'data.tar.gz', 'files.7z'])
        for _ in range(rng.randint(1, 4)):
            kind = rng.choice(['zip', 'tgz', 'zip', 'txz'])
            data = pack(kind, [Member(name, data)], self.work, mt)
            name = 'part.' + EXT[kind]
        return data

    def secret_hint_part(self):
        return self.rng.randint(self.total_parts - 30, self.total_parts + 400)


def greppable(data):
    return any(mk in data for mk in MARKERS) or AKIA_RE.search(data) is not None


def assert_ungreppable(data, kind, k):
    for mk in MARKERS:
        if mk in data:
            raise SystemExit(f'ungreppable invariant: marker {mk!r} visible in layer k={k} ({kind})')
    if AKIA_RE.search(data):
        raise SystemExit(f'ungreppable invariant: access-key shape visible in layer k={k} ({kind})')


def build(seed, target, total_parts, work):
    b = Builder(seed, work, total_parts)
    data, kind, name = b.bottom()
    k = 1
    outer = None
    while True:
        data, kind, name = b.layer(k, data, kind, name)
        k += 1
        if k % 25 == 0 or len(data) > target * 0.9:
            if kind in PADDED:
                continue
            outer = finalize(data, name, work)
            if len(outer) >= target:
                break
        if k > 6000:
            raise SystemExit('runaway: depth backstop hit')
    return outer, k, b.stats, name


def finalize(data, name, work):
    """Outer 7z, LZMA-compressed so nothing below is greppable from the served bytes."""
    return w_7z([Member(name, data, text=True)], work)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seed', type=int, default=713)
    ap.add_argument('--target', type=int, default=1_000_000)
    ap.add_argument('--ceiling', type=int, default=1_150_000)
    ap.add_argument('--out', default=os.path.join(HERE, '..', '..', '..', 'resources', 'decoy'))
    args = ap.parse_args()
    if not SEVENZ:
        raise SystemExit('7zz/7z not found')

    work = tempfile.mkdtemp(prefix='decoy-chain-')
    try:
        # Pass 1 measures depth so README "part N of M" counts line up; pass 2 is the real build.
        _, depth1, _, _ = build(args.seed, args.target, 1200, work)
        total = depth1 + random.Random(args.seed).randint(150, 400)  # claims more parts than exist
        outer, depth, stats, top = build(args.seed, args.target, total, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if len(outer) > args.ceiling:
        raise SystemExit(f'chain {len(outer)} B exceeds ceiling {args.ceiling}')
    if stats['symlinks'] != 1:
        raise SystemExit('exactly one symlink required')
    if stats['extracted_total'] > 1024 * 1024 * 1024:
        raise SystemExit('keep-every-layer extracted total over 1 GiB')

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, 'chain.7z'), 'wb') as f:
        f.write(outer)
    manifest = {
        'file': 'chain.7z',
        'bytes': len(outer),
        'sha256': hashlib.sha256(outer).hexdigest(),
        'depth': depth,
        'claimed_parts': total,
        'top_member': top,
        'seed': args.seed,
        'stats': stats,
        'tools': tool_versions(),
    }
    with open(os.path.join(args.out, 'chain.json'), 'w') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write('\n')
    print(json.dumps({k: manifest[k] for k in ('bytes', 'depth', 'sha256')}), file=sys.stderr)
    print(json.dumps(stats, sort_keys=True), file=sys.stderr)


def tool_versions():
    def first(cmd):
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            return next((l.strip() for l in r.stdout.splitlines() if l.strip()), '')[:80]
        except OSError:
            return ''
    return {
        'python': sys.version.split()[0],
        '7z': first([SEVENZ]),
        'zip': first(['zip', '-v']),
        'zstd': first(['zstd', '--version']),
        'lz4': first(['lz4', '--version']),
        'iso': 'hdiutil' if shutil.which('hdiutil') else first(['xorriso', '--version']),
    }


if __name__ == '__main__':
    main()
