#!/bin/sh
# Host unit tests of the C kit's C sources against a mock of the runtime
# hooks. Each test_*.c is one executable; its last line must be "<name> OK".
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
# SPEC A13: O_NOFOLLOW is a no-op only while the filesystem has exactly File
# and Dir; absd_stat_from_attr refuses any other kind (test_fd).
python3 -I "$root/scripts/check-fs-kinds.py" "$root"
python3 -I "$root/scripts/check-fs-kinds.py" "$root" --self-test >/dev/null
python3 -I "$root/scripts/check-fs-kinds.py" "$root" --exercise >/dev/null
out=$(mktemp -d "${TMPDIR:-/tmp}/ckit-host.XXXXXX")
trap 'rm -rf "$out"' EXIT
for test in "$root"/c/tests/host/test_*.c; do
    name=$(basename "$test" .c)
    sources="$root/c/libabs/malloc.c"
    case $name in
        test_fd|test_errno) sources="$sources $root/c/libabs/fd.c $root/c/libabs/errno_map.c" ;;
        test_setlocale) sources="$sources $root/c/libabs/locale.c" ;;
        test_strerror) sources="$sources $root/c/libabs/strerror_hook.c" ;;
    esac
    gcc -std=gnu11 -O1 -g -Wall -Wextra -Werror -DABSD_HOST_TEST \
        -I"$root/c/include" -I"$root/c/tests/host" \
        -o "$out/$name" "$test" "$root/c/tests/host/mock_runtime.c" $sources
    "$out/$name" | tail -1 | grep -qx "$name OK" || { echo "check-c-kit-host: $name failed" >&2; exit 1; }
done
printf '%s\n' "ABSD C KIT HOST TESTS OK tests=$(ls "$root"/c/tests/host/test_*.c | wc -l)"
