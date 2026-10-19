"""Sparse copies of immutable regular files owned by the media test fixture.

Scan with bounded memory and seek over zero blocks, including on filesystems
without reflinks or SEEK_HOLE. Concurrent source mutation is outside this
fixture helper's contract. Image bytes and logical length are unchanged.
"""
import os
import shutil


BLOCK_BYTES = 64 * 1024
ZERO_BLOCK = bytes(BLOCK_BYTES)


def copyfile(source, destination):
    """Copy file contents, leaving all-zero blocks as holes."""
    if os.path.exists(destination) and os.path.samefile(source, destination):
        raise shutil.SameFileError(source, destination, "same fixture file")
    with open(source, "rb") as reader, open(destination, "wb") as writer:
        while block := reader.read(BLOCK_BYTES):
            if block == ZERO_BLOCK[:len(block)]:
                writer.seek(len(block), os.SEEK_CUR)
            else:
                writer.write(block)
        # Seeking alone does not extend an all-zero file or its final hole.
        writer.truncate()
    return destination


def copy2(source, destination):
    """The copytree callback also preserves copy2's fixture metadata."""
    copyfile(source, destination)
    shutil.copystat(source, destination)
    return destination
