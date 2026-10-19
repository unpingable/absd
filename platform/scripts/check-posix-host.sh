#!/bin/sh
# Host unit tests of the POSIX adapter (c/posix) against the kit's runtime
# mock (c/tests/host/mock_runtime.c) extended by c/posix/tests/host/mock_posix.c.
# Each test_*.c is one executable; its last line must be "<name> OK". The
# path stat hook is wrapped (--wrap) so mock_posix.c can force an unknown kind.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=$(mktemp -d "${TMPDIR:-/tmp}/posix-host.XXXXXX")
trap 'rm -rf "$out"' EXIT
count=0
for test in "$root"/c/posix/tests/host/test_*.c; do
    name=$(basename "$test" .c)
    # The sources as positional parameters, each quoted: the kit's three and every adapter file.
    set -- "$test" "$root/c/tests/host/mock_runtime.c" "$root/c/posix/tests/host/mock_posix.c" \
        "$root/c/libabs/malloc.c" "$root/c/libabs/fd.c" "$root/c/libabs/errno_map.c"
    for src in "$root"/c/posix/*.c; do set -- "$@" "$src"; done
    gcc -std=gnu11 -O1 -g -Wall -Wextra -Werror -DABSD_HOST_TEST -Wl,--wrap=__absd_std_fs_stat \
        -I"$root/c/include" -I"$root/c/tests/host" -I"$root/c/posix" -I"$root/c/posix/tests/host" \
        -o "$out/$name" "$@"
    "$out/$name" | tail -1 | grep -qx "$name OK" || { echo "check-posix-host: $name failed" >&2; exit 1; }
    count=$((count + 1))
done
printf '%s\n' "ABSD POSIX HOST TESTS OK tests=$count"
