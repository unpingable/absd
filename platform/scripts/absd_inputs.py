"""Where the external inputs are, for the Python scripts: exactly what
scripts/inputs.sh resolves (it is asked, not reimplemented), so a script run
through a shell wrapper and one run by hand agree."""
import functools
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
NAMES = ("KERNEL", "PULSE", "AG", "NIGHTSHIFT", "NQ")


@functools.cache
def _resolved():
    script = 'root=$1; . "$root/scripts/inputs.sh"; ' + "; ".join(
        f'printf "%s\\n" "$ABSD_{name}_SOURCE"' for name in NAMES) + '; printf "%s\\n" "$ABSD_KERNEL_PROTECTED"'
    lines = subprocess.run(["sh", "-c", script, "sh", str(ROOT)], check=True, capture_output=True,
                           text=True).stdout.split("\n")
    return dict(zip(NAMES + ("PROTECTED",), lines))


def source(name):
    """The resolved directory of input NAME (KERNEL, PULSE, ...), or None."""
    found = _resolved()[name]
    return pathlib.Path(found).resolve() if found else None


def is_kernel_source(path):
    """Whether PATH is the kernel source itself, which is never built in:
    the scripts build in a disposable clone or copy of it."""
    path = pathlib.Path(path).resolve()
    protected = [pathlib.Path(p).resolve() for p in _resolved()["PROTECTED"].split(":") if p]
    return (path / ".git").is_file() or path == source("KERNEL") or path in protected
