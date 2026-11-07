"""Offline product-image mutation under the fixed writable guard.

The caller owns a halted image and waits for its one importer to terminate.
Only an exclusive new-image constructor may pass fresh=True. No helper here
repairs a dirty/missing marker or retires an earlier command.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import absd_fs
import storage_fence_state as guard


def marker(image):
    image = Path(image)
    region = absd_fs.fs_region(image, image.stat().st_size // absd_fs.SECTOR)
    if region is None:
        raise ValueError("writable guard: no filesystem region")
    selected = absd_fs.select(region)
    record = absd_fs.tree(region, selected).get(guard.PATH)
    if (not record or record["dir"] or record["readonly"] or record["size"] != guard.SECTOR
            or len(record["blocks"]) != 1):
        raise ValueError("writable guard: missing or invalid fixed marker")
    offset = (region.first + selected["geometry"]["data_first"]
              + record["blocks"][0] * absd_fs.SECTORS_PER_BLOCK) * absd_fs.SECTOR
    identity = (record["serial"], tuple(record["blocks"]), offset)
    return identity, absd_fs.content(region, selected, record)


@contextmanager
def mutation(image, *, fresh=False):
    if fresh:
        # No boot recipe may be published until the constructor has
        # successfully imported and verified its fresh seed and all files.
        yield
        return
    image = Path(image)
    fd = os.open(image, os.O_RDWR | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        identity, previous = marker(image)
        if guard.parse(previous) not in ("fresh", "clean"):
            raise ValueError("writable guard: unclean image; offline reconstruction required")

        def transition(expected, next_bytes):
            named = image.stat()
            if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError("writable guard: image pathname changed")
            current_identity, current = marker(image)
            if current_identity != identity or current != expected:
                raise ValueError("writable guard: marker identity or state changed")
            if os.pread(fd, guard.SECTOR, identity[2]) != expected:
                raise ValueError("writable guard: sector changed")
            if os.pwrite(fd, next_bytes, identity[2]) != guard.SECTOR:
                raise OSError("writable guard: incomplete sector write")
            os.fsync(fd)

        dirty = guard.encode("dirty")
        transition(previous, dirty)
        yield
        # Reached only after the importer completed successfully. Flush
        # all ordinary image work before restoring the original state last.
        os.fsync(fd)
        transition(dirty, previous)
    finally:
        os.close(fd)
