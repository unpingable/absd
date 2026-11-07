"""Coverage of shipped commands, using canonical mdoc and installed bytes.

This checks membership, never interprets roff. render-man.sh owns mdoc lint
and rendering; source review owns semantic accuracy.
"""
from pathlib import Path


class Refused(ValueError):
    pass


def check(root, names, files=None):
    root = Path(root)
    names = list(names)
    if len(names) != len(set(names)):
        raise Refused('duplicate command in composition')
    installed = None
    if files is not None:
        installed = {}
        for path, data in files:
            if path in installed:
                raise Refused(f'duplicate installed path: {path}')
            installed[path] = data
        # Actual composition is authoritative, even when it grows outside
        # the cheap pre-build declaration.
        names = sorted(set(names) | {p[5:] for p in installed if p.startswith('/bin/')})
    pages = {}
    errors = []
    for name in names:
        candidates = [root / 'man' / f'{name}.{s}' for s in (1, 8)]
        found = [p for p in candidates if p.is_file() and p.read_bytes().strip()]
        if len(found) != 1:
            errors.append(f'{name}: ' + ('ambiguous duplicate sources' if len(found) > 1 else 'missing nonempty source'))
        else:
            pages[name] = found[0].suffix[1:]
    if installed is not None:
        whatis = installed.get('/share/man/whatis', b'')
        if not whatis.strip():
            errors.append('missing nonempty /share/man/whatis')
        try:
            rows = [line.partition(' - ') for line in whatis.decode('ascii').splitlines() if line.strip()]
            entries = [name for name, separator, description in rows if separator and description.strip()]
        except UnicodeDecodeError as error:
            raise Refused('whatis is not ASCII') from error
        keys = [name for name, _, _ in rows]
        if len(keys) != len(set(keys)):
            errors.append('duplicate whatis entry')
        for name, section in pages.items():
            path = f'/share/man/cat{section}/{name}.0'
            if not installed.get(path, b'').strip():
                errors.append(f'{name}: missing nonempty rendered page {path}')
            if f'{name}({section})' not in entries:
                errors.append(f'{name}: missing whatis entry')
    if errors:
        raise Refused('; '.join(errors))
    return len(names)
