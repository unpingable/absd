"""Explicit fresh operator-image profiles; existing disks keep their geometry."""

DEFAULT_PROFILE = "128m"
DEFAULT_IMAGE_BYTES = 128 * 1024 * 1024
LARGE_IMAGE_BYTES = 2 * 1024 * 1024 * 1024
PROFILES = {DEFAULT_PROFILE: DEFAULT_IMAGE_BYTES, "2g": LARGE_IMAGE_BYTES}


def image_bytes(profile):
    try:
        return PROFILES[profile]
    except (KeyError, TypeError):
        raise ValueError(f"unknown operator disk profile {profile!r}; choose 128m or 2g") from None


def is_writable_size(size):
    """Policy only: callers must still validate the actual layout and state."""
    return size in (DEFAULT_IMAGE_BYTES, LARGE_IMAGE_BYTES)
