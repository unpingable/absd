#!/usr/bin/env python3
"""Apply checkout paths without passing kernel codegen flags to embedded users."""

import os
from pathlib import Path
import subprocess
import sys


SEPARATOR = "\x1f"
ROOT_POLICY = "ABSD_KERNEL_ROOT_REMAP_TO"
DEFAULT_ROOT = "/absd/kernel"


def caller_flags(environment):
    # Cargo gives the encoded variable priority even when it is empty.
    if "CARGO_ENCODED_RUSTFLAGS" in environment:
        value = environment["CARGO_ENCODED_RUSTFLAGS"]
        return value.split(SEPARATOR) if value else []
    return environment.get("RUSTFLAGS", "").split()


def root_flags(root, environment, flags=None):
    roots = list(dict.fromkeys([str(Path(root).absolute()), str(Path(root).resolve())]))
    destination = DEFAULT_ROOT if flags is not None else environment.get(ROOT_POLICY, DEFAULT_ROOT)
    if flags is not None:
        pending = False
        for flag in flags:
            if pending:
                mapping, pending = flag, False
            elif flag == "--remap-path-prefix":
                pending = True
                continue
            elif flag.startswith("--remap-path-prefix="):
                mapping = flag[len("--remap-path-prefix="):]
            else:
                continue
            # Forward only an explicit checkout-root policy. Other caller
            # flags keep their kernel scope and are cleared by build-user.sh.
            # rustc permits '=' in FROM, but not TO: split at the last '='.
            source, separator, mapped_to = mapping.rpartition("=")
            if separator and source in roots:
                destination = mapped_to
    return [f"--remap-path-prefix={source}={destination}" for source in roots], destination


def compiler_source_flag(root, environment):
    mapping = subprocess.check_output(
        ["sh", str(Path(root) / "scripts/rust-source-map.sh")],
        env=environment, text=True,
    ).rstrip("\n")
    return "--remap-path-prefix=" + mapping


def main():
    mode, root, *arguments = sys.argv[1:]
    environment = dict(os.environ)
    if mode == "kernel":
        caller = caller_flags(environment)
        mapped, destination = root_flags(root, environment, caller)
        # Defaults precede the unchanged caller sequence, so explicit media
        # mappings win. Compiler-source normalization retains its old priority.
        flags = mapped + caller + [compiler_source_flag(root, environment)]
        environment[ROOT_POLICY] = destination
        environment["CARGO_ENCODED_RUSTFLAGS"] = SEPARATOR.join(flags)
        os.execvpe("cargo", ["cargo", *arguments], environment)
    elif mode == "user":
        mapped, _ = root_flags(root, environment)
        flags = mapped + [compiler_source_flag(root, environment)] + [
            "-C", "relocation-model=static",
            "-C", "code-model=large",
            "-C", "link-arg=-nostdlib",
            "-C", "link-arg=-static",
            "-C", "link-arg=-no-pie",
            "-C", "link-arg=-Wl,--build-id=sha1",
            "-C", f"link-arg=-Wl,-T,{root}/user/linker.ld",
        ]
        print(SEPARATOR.join(flags))
    else:
        raise SystemExit(f"unknown Rust build mode: {mode}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode if error.returncode >= 0 else 128 - error.returncode)
