"""
Name pools and the hostile-name validator for the decoy chain.

Hostile names are friction, never payloads. The validator enforces the line: a name may break
naive parsing (quotes, newlines, globs, escape-coloured text, shell-looking tokens), but expanding
or eval'ing it can only produce an error or a "command not found" — it can never run a real
command, inject an option into the attacker's own command, or point a write outside the
extraction directory.
"""
import re
import shutil
import unicodedata

SEGMENTS = [
    'var', 'www', 'html', 'wp-content', 'uploads', 'backups', 'backup', 'home', 'deploy', 'srv', 'nas',
    'share', 'site', 'old', 'releases', 'current', 'shared', 'storage', 'app', 'data', 'mysql', 'public',
    'htdocs', 'files', 'archive', 'incremental', 'daily', 'weekly', 'snapshots', 'restore', 'tmp', 'db',
    '2022', '2023', '2024', '01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12',
]

# Folder segments that break naive parsing but are harmless (validated below).
HOSTILE_SEGMENTS = [
    'old backups', "client's files", '"final"', 'copy of site', 'site [old]', 'uploads*', 'what?',
    '$BKP_SEGMENT_ROOT', '${PART_IDX:?missing part index}', '`_pt214`', '$(_restore_part)',
    '\x1b[8mhidden\x1b[0m', 'snap\x1b[2K\x1b[1A', 'line\n214_continued', 'tab\tseparated',
    'zero​width', 'café', 'café', 'rtl‮txt.gpj', '-- part restore',
]

HOSTILE_FILES = [
    'CON', 'NUL.txt', 'aux.sql', 'trailing. ', 'trailing.', '"quoted".sql', "it's-here.sql",
    'wp-config‮php.txt', 'zero​width.sql', 'café.sql', 'café.sql',
    '$BKP_SEGMENT_ROOT.sql', '${PART_IDX:?missing part index}.zip', '`_pt214`.sql', '$(_restore_3).tar',
    '\x1b[8mhidden.sql', '\x1b[2K\x1b[1Apart.sql', 'line1\n214_continued.sql', '*.sql', '[1-9].zip',
    'what?.zip', '-- part restore.zip', 'db dump (copy).sql'.replace('(', '[').replace(')', ']'),
]

HOSTILE_STUB_STEMS = ['"part"', "part's", 'part [b]', 'part*', '$PART_ALT', '`_pt_b`', 'part\x1b[8m', 'pa\u200brt']

README_NAMES = ['README.txt', 'readme.txt', 'NOTES.txt', 'restore-notes.txt', 'READ ME.txt',
                'README [1].txt', 'INFO', 'manifest.txt', 'part-info.txt']

NEAR_DIRS = ['', 'old/', 'config/', 'home/deploy/', 'var/www/html/', 'tmp/', 'site/', 'shared/']

# Variable names expanded by an eval must never exist on a real machine: a fixed, fictional prefix.
VAR_RE = re.compile(r'^(?:BKP|PART|RESTORE|NAS)_[A-Z0-9_]+$')
# Command-substitution tokens: one word, leading underscore/digit, no binary of that name.
TOKEN_RE = re.compile(r'^[_0-9][a-z0-9_]*$')
LINE_WORD_RE = re.compile(r'^[_0-9][a-z0-9_.]*$')
CSI_RE = re.compile(r'\x1b\[[0-9;]*[mKAB]')
DESTRUCTIVE = re.compile(r'(?:^|[\s/])-(?!- part )')  # option-like text only as the literal '-- part …'
FORBIDDEN_CHARS = set(';|&<>()\\') | {chr(c) for c in range(1, 32) if c not in (9, 10, 27)} | {'\x7f'}


def validate(name):
    """Raise ValueError if a name crosses from friction into payload."""
    if not name or name.startswith('/') or name.startswith('~'):
        raise ValueError(f'absolute/home name: {name!r}')
    segs = name.split('/')
    if any(s in ('..', '.') for s in segs):
        raise ValueError(f'traversal segment: {name!r}')
    if any(s.startswith('~') for s in segs):
        raise ValueError(f'tilde segment: {name!r}')
    body = name.replace('\0', '')
    # Strip validated substitutions/expansions, then check what is left.
    def sub_ok(m):
        tok = m.group(1)
        if not TOKEN_RE.match(tok) or shutil.which(tok):
            raise ValueError(f'substitution token not inert: {tok!r} in {name!r}')
        return '_'
    body = re.sub(r'`([^`]*)`', sub_ok, body)
    body = re.sub(r'\$\(([^)]*)\)', sub_ok, body)

    def var_ok(m):
        var = m.group(1) or m.group(2)
        if not VAR_RE.match(var):
            raise ValueError(f'variable may exist on a real host: {var!r} in {name!r}')
        return '_'
    body = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::\?[^}$`]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)', var_ok, body)
    if '$' in body or '`' in body:
        raise ValueError(f'unvalidated expansion: {name!r}')
    body = CSI_RE.sub('', body)
    if '\x1b' in body:
        raise ValueError(f'escape sequence outside CSI SGR/erase/cursor: {name!r}')
    bad = FORBIDDEN_CHARS & set(body)
    if bad:
        raise ValueError(f'forbidden chars {sorted(bad)!r}: {name!r}')
    if DESTRUCTIVE.search(body):
        raise ValueError(f'option-like text: {name!r}')
    # After a newline an eval runs the next line as a command: its first word must be inert.
    for line in body.split('\n')[1:]:
        word = line.split(' ')[0].split('\t')[0].split('/')[0]
        if word and (not LINE_WORD_RE.match(word) or shutil.which(word)):
            raise ValueError(f'line after newline is not inert: {word!r} in {name!r}')
    return name


def folder_path(rng, target_len, hostile=True):
    parts, n = [], 0
    while n < target_len:
        if hostile and rng.random() < 0.04:
            seg = rng.choice(HOSTILE_SEGMENTS)
        else:
            seg = rng.choice(SEGMENTS)
        parts.append(seg)
        n += len(seg.encode('utf-8')) + 1
    path = '/'.join(parts)
    return validate(path)


def iso_path(rng):
    return '/'.join(rng.choice(['BACKUP', 'SITE', 'DATA', 'OLD']) for _ in range(rng.randint(1, 3)))


def readme_name(rng):
    return rng.choice(README_NAMES)


def near_path(rng, leaf):
    return validate(rng.choice(NEAR_DIRS) + leaf)


def stub_name(rng, part, i, safe):
    ext = rng.choice(['zip', 'tar.gz', '7z', 'zip'])
    if not safe and rng.random() < 0.1:
        return validate(rng.choice(HOSTILE_STUB_STEMS) + f'_{part:04d}.{ext}')
    return rng.choice([f'part_{part:04d}{"abc"[i]}.{ext}', f'part_{part:04d}.{i + 1}.{ext}',
                       f'incremental-{part}{"abc"[i]}.{ext}', f'backup.part{part}-{i + 2}.{ext}'])


def continuation_name(rng, part, ext):
    return rng.choice([
        f'part_{part:04d}.{ext}', f'incremental-{part}.{ext}', f'backup.part{part}.{ext}',
        f'site-backup.p{part:04d}.{ext}', f'Backup [{part}].{ext}', f'set{part // 100}-part{part % 100:02d}.{ext}',
    ])


def hostile_file_name(rng):
    return validate(rng.choice(HOSTILE_FILES))


def nul_name(rng):
    """(placeholder, real) of equal UTF-8 length: \x7f stands in for the NUL patched in afterwards."""
    stem = rng.choice(['wp-config.php', 'backup.sql', 'users.csv'])
    real = stem + '\0' + '.txt'
    placeholder = stem + '\x7f' + '.txt'
    return placeholder, real


def nfc(s):
    return unicodedata.normalize('NFC', s)
