"""The release record and the release layout on the host (docs/RELEASE.md
sections 2, 3 and 5): the Python twin of the `absd-release` crate.

The record `/releases/<id>/release` is exactly seven lines, each ended by
one `\\n`:

    absd-release 1
    release=<id>
    kernel_abi=<n>
    fsd_protocol=<n>
    fs_format=<n>
    app_abi=<n>
    check=<sha256 of the six lines above, newlines included, lowercase hex>

`parse_record` accepts exactly what the crate's `parse` accepts and names
the file server's reason when it does not (`malformed_record`,
`check_mismatch`).

The layout: the file server serves `/bin` and `/share` from
`/releases/<id>/bin` and `/releases/<id>/share` of the release that
`/absd/selected` names, and refuses to serve at all without a selection
and a record. `release_layout` turns an importer file list written against
the logical paths into the physical one.
"""

import hashlib
import os
import re

# The identity fields written into release records. They must equal the
# `absd-release` crate's constants compiled into the services; the file
# server compares its own to the record at every boot (RELEASE.md §3), so a
# drift here is caught there.
IDENTITY = {"kernel_abi": 1, "fsd_protocol": 2, "fs_format": 2, "app_abi": 1}
RECORD_HEADER = "absd-release 1"
ID_RE = re.compile(r"\A[a-z0-9.-]{1,64}\Z")
# The id the services are compiled with when ABSD_RELEASE_ID is unset.
DEFAULT_ID = "dev"
SELECTED = "/absd/selected"
RELEASES = "/releases"
# Logical roots served from the selected release's tree.
BOUND = ("/bin", "/share")

_NUMBER = re.compile(rb"0|[1-9][0-9]{0,9}")
_CHECK = re.compile(rb"[0-9a-f]{64}")


class Malformed(ValueError):
    """A record, selection, or id the file server would refuse; `reason` is
    its reason name."""

    def __init__(self, reason, detail=None):
        super().__init__(detail or reason)
        self.reason = reason


def valid_id(release_id):
    return isinstance(release_id, str) and ID_RE.fullmatch(release_id) is not None


def check_id(release_id):
    if not valid_id(release_id):
        raise Malformed("malformed_id", f"release id {release_id!r} is not [a-z0-9.-]{{1,64}}")
    return release_id


def release_id_from_env(environ=None):
    """`ABSD_RELEASE_ID` from the environment, else the compiled default
    `dev`: the id the services of this build were compiled with."""
    environ = os.environ if environ is None else environ
    return check_id(environ.get("ABSD_RELEASE_ID") or DEFAULT_ID)


def record_text(release_id):
    check_id(release_id)
    lines = [RECORD_HEADER, f"release={release_id}"] + [f"{k}={v}" for k, v in IDENTITY.items()]
    body = "".join(line + "\n" for line in lines)
    return body + f"check={hashlib.sha256(body.encode()).hexdigest()}\n"


def parse_record(data):
    """The record's fields, or Malformed with the file server's reason."""
    if not isinstance(data, bytes) or b"\r" in data or not data.endswith(b"\n"):
        raise Malformed("malformed_record")
    lines = data[:-1].split(b"\n")
    if len(lines) != 7 or lines[0] != RECORD_HEADER.encode():
        raise Malformed("malformed_record")
    keys = ["release"] + list(IDENTITY)
    values = {}
    for key, line in zip(keys, lines[1:6]):
        prefix = key.encode() + b"="
        if not line.startswith(prefix) or len(line) == len(prefix):
            raise Malformed("malformed_record")
        values[key] = line[len(prefix):]
    if not lines[6].startswith(b"check="):
        raise Malformed("malformed_record")
    check = lines[6][len(b"check="):]
    if not _CHECK.fullmatch(check):
        raise Malformed("malformed_record")
    sealed = data[:len(data) - len(lines[6]) - 1]
    if hashlib.sha256(sealed).hexdigest().encode() != check:
        raise Malformed("check_mismatch")
    release = values["release"].decode("ascii", errors="replace")
    if not valid_id(release):
        raise Malformed("malformed_record")
    fields = {"release": release}
    for key in IDENTITY:
        if not _NUMBER.fullmatch(values[key]) or int(values[key]) > 0xFFFF_FFFF:
            raise Malformed("malformed_record")
        fields[key] = int(values[key])
    return fields


def selected_bytes(release_id):
    """The selection file's bytes: the id and one newline."""
    return f"{check_id(release_id)}\n".encode()


def parse_selected(data):
    """The id a selection names (one trailing newline allowed, as the file
    server allows), or Malformed("malformed_selected")."""
    if not isinstance(data, bytes):
        raise Malformed("malformed_selected")
    text = data[:-1] if data.endswith(b"\n") else data
    release_id = text.decode("ascii", errors="replace")
    if not valid_id(release_id):
        raise Malformed("malformed_selected")
    return release_id


def tree_root(release_id):
    return f"{RELEASES}/{check_id(release_id)}"


def physical(path, release_id):
    """Where a logical path is stored on a disk selecting `release_id`."""
    if any(path == root or path.startswith(root + "/") for root in BOUND):
        return tree_root(release_id) + path
    return path


def release_layout(files, release_id, select=True):
    """An importer file list `(path, bytes)` in the release layout: every
    `/bin/...` and `/share/...` path moved under `/releases/<id>/`, then the
    record `/releases/<id>/release` and (with `select`) `/absd/selected`
    appended. Idempotent: a list already in the layout comes back equal. A
    record or selection already present must be this release's; two
    entries that land on one path are refused."""
    root = tree_root(release_id)
    record_path = root + "/release"
    record = record_text(release_id).encode()
    selection = selected_bytes(release_id)
    out, seen = [], set()
    for path, data in files:
        if path == record_path:
            if data != record:
                raise Malformed("malformed_record", f"{path} is not the record of release {release_id}")
            continue
        if path == SELECTED and select:
            if data != selection:
                raise Malformed("malformed_selected", f"{path} selects {data!r}, not {release_id}")
            continue
        moved = physical(path, release_id)
        if moved in seen:
            raise ValueError(f"two entries land on {moved}")
        seen.add(moved)
        out.append((moved, data))
    out.append((record_path, record))
    if select:
        out.append((SELECTED, selection))
    return out
