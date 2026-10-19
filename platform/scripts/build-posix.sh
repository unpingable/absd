#!/bin/sh
# Builds the POSIX adapter archive (c/posix/*.c) with the kit's driver into
# $camp/cports-build/lib/libabsd-posix.a (ABSD_CPORTS_BUILD overrides the
# directory, ABSD_CKIT_BUILD the kit's) and checks its symbol sets: it
# defines exactly the functions ADAPTER-DESIGN.md 1 names (plus A8's
# identity family) and references nothing but the runtime hooks, the kit's
# exports and Picolibc.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
kit=${ABSD_CKIT_BUILD:-$camp/ckit-build}/kit
out=${ABSD_CPORTS_BUILD:-$camp/cports-build}
mkdir -p "$out/lib" "$out/posix-obj"
test -x "$kit/bin/absd-cc" || { echo "build-posix: $kit/bin/absd-cc missing: run scripts/build-c-kit.sh" >&2; exit 1; }
rm -f "$out/posix-obj/"*.o "$out/lib/libabsd-posix.a"
# The tree, as spelled and physically, is mapped to /absd so that __FILE__
# (assert()) names no checkout path and the archive hashes the same anywhere.
prefix_map="-ffile-prefix-map=$root=/absd"
root_physical=$(CDPATH= cd -- "$root" && pwd -P)
[ "$root_physical" = "$root" ] || prefix_map="$prefix_map -ffile-prefix-map=$root_physical=/absd"
for src in "$root"/c/posix/*.c; do
    "$kit/bin/absd-cc" -c $prefix_map -Wall -Wextra -Werror -I"$root/c/posix" -o "$out/posix-obj/$(basename "$src" .c).o" "$src"
done
llvm-ar-18 rcs "$out/lib/libabsd-posix.a" "$out/posix-obj/"*.o
defined=$(llvm-nm-18 --defined-only --extern-only "$out/lib/libabsd-posix.a" | awk 'NF==3 {print $3}' | sort -u)
# Picolibc's strerror hook _user_strerror is the kit's (c/libabs/strerror_hook.c,
# R13), not the adapter's.
want="access chdir chmod chown closedir fchmod fchown fcntl getcwd getegid geteuid getgid gethostname getrusage getuid ioctl lchown lstat mkdir opendir pclose popen readdir readlink realpath rename rmdir setegid seteuid setgid setuid signal stat symlink system utimes"
if [ "$(printf '%s\n' $want | sort -u | tr '\n' ' ')" != "$(printf '%s\n' $defined | tr '\n' ' ')" ]; then
    echo "build-posix: defined symbols differ from the declared set" >&2
    printf '%s\n' $want | sort -u > "$out/posix-obj/want.txt"
    printf '%s\n' $defined > "$out/posix-obj/defined.txt"
    diff "$out/posix-obj/want.txt" "$out/posix-obj/defined.txt" >&2 || true; exit 1
fi
undefined=$(llvm-nm-18 -u "$out/lib/libabsd-posix.a" | awk 'NF==2 {print $2}' | sort -u)
allowed='^(__absd_std_(fs_(stat|fstat|mkdir|rmdir|rename|readdir|canonical|set_readonly|set_readonly_path)|chdir|getcwd)|absd_(fd_is_open|fd_handle|fd_access_mode|fd_lock|stat_from_attr|errno_from_native|open|close)|open|close|malloc|free|strlen|memcpy|memset|errno)$'
bad=$(printf '%s\n' $undefined | grep -Ev "$allowed" || true)
[ -z "$bad" ] || { echo "build-posix: unexpected undefined symbols: $bad" >&2; exit 1; }
printf '%s\n' "ABSD POSIX libabsd-posix.a $(sha256sum "$out/lib/libabsd-posix.a" | cut -d' ' -f1) objects=$(ls "$out/posix-obj/"*.o | wc -l)"
