#!/usr/bin/env bash
# Demand collection for the stage-2 programs (docs/c-ecosystem-20261010/posix/DEMAND.md).
# Compiles each program's objects for x86_64-unknown-none-elf against Picolibc's headers
# plus the compiler's freestanding headers (stddef.h, stdarg.h, float.h; Picolibc does not
# ship them), -ffreestanding -nostdinc -nostdlib -c, then records:
#   <variant>.undef.txt     nm -u over the objects minus symbols the objects define
#                           (the program's own demand on libc and POSIX)
#   <variant>.residual.txt  symbols still undefined after a trial link against Picolibc's
#                           libc.a/libm.a and the compiler builtins (what the kit and the
#                           adapter must provide once Picolibc's own objects are pulled in),
#                           each with the first object that references it
# Upstream sources are read in place and never modified; objects go to $OBJ.
# Usage: collect.sh PICOLIBC_INSTALL UPSTREAM_ROOT OBJ_ROOT OUT_DIR
set -euo pipefail
pico=$1; up=$2; objroot=$3; out=$4
res=$(clang -print-resource-dir)
builtins=$res/lib/linux/libclang_rt.builtins-x86_64.a
kit="--target=x86_64-unknown-none-elf -ffreestanding -nostdinc -nostdlib -mcmodel=large -fno-pic -fno-pie -fno-stack-protector -mno-avx -march=x86-64 -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -O2 -w -isystem $pico/include -isystem $res/include -ffile-prefix-map=$up=/upstream -ffile-prefix-map=$pico=/picolibc"
# Clang's diagnostics name sources as given on the command line, which no
# prefix map changes: each compile log is rewritten to the same /upstream and
# /picolibc names once its compiles are done, so the committed logs name no
# checkout or campaign path.
unpath() { sed -i -e "s|$up|/upstream|g" -e "s|$pico|/picolibc|g" "$1"; }
mkdir -p "$out"

collect() { # variant flags sources...
  local v=$1 flags=$2; shift 2
  local od=$objroot/$v; rm -rf "$od"; mkdir -p "$od"
  local log=$out/$v.compile.log; : > "$log"
  local objs=()
  for s in "$@"; do
    local o=$od/$(basename "${s%.c}").o
    if ! nice -n 10 clang $kit $flags -c "$s" -o "$o" >>"$log" 2>&1; then
      echo "COMPILE FAILED $s" | tee -a "$log"; continue
    fi
    objs+=("$o")
  done
  unpath "$log"
  if [ ${#objs[@]} -eq 0 ]; then echo "$v objects=0 (all compiles failed)"; : > "$out/$v.undef.txt"; : > "$out/$v.residual.txt"; return 0; fi
  llvm-nm-18 -u "${objs[@]}" 2>/dev/null | awk 'NF==2&&$1=="U"{print $2}' | sort -u > "$od/.u"
  llvm-nm-18 --defined-only "${objs[@]}" 2>/dev/null | awk 'NF==3{print $3}' | sort -u > "$od/.d"
  comm -23 "$od/.u" "$od/.d" > "$out/$v.undef.txt"
  # Trial link: every undefined symbol reported, with its first referencing object.
  ld.lld-17 -static -no-pie --gc-sections -e main --error-limit=0 -o "$od/a.out" \
    "${objs[@]}" "$pico/lib/libc.a" "$pico/lib/libm.a" "$builtins" > "$od/.link" 2>&1 || true
  python3 -I - "$od/.link" > "$out/$v.residual.txt" <<'PY'
import re, sys
sym = None; out = {}
for line in open(sys.argv[1]):
    m = re.search(r"undefined symbol: (\S+)", line)
    if m: sym = m.group(1); continue
    m = re.search(r">>> referenced by .*\(([^()]*)\)$", line) or re.search(r">>> referenced by (\S+)", line)
    if m and sym and sym not in out:
        ref = m.group(1).split("/")[-1]
        out[sym] = re.sub(r"^.*:", "", ref) if "libc.a" in ref or "libm.a" in ref else ref
for s in sorted(out): print(f"{s}\t{out[s]}")
PY
  printf '%s objects=%d undef=%d residual=%d\n' "$v" "${#objs[@]}" "$(wc -l < "$out/$v.undef.txt")" "$(wc -l < "$out/$v.residual.txt")"
}

L=$up/lua/src/src
lua_srcs=$(ls $L/*.c | grep -v '/luac\.c$')
collect lua-generic "-DLUA_COMPAT_5_3" $lua_srcs
collect lua-posix "-DLUA_COMPAT_5_3 -DLUA_USE_POSIX" $lua_srcs

Z=$up/zlib/src
zlib_lib="$Z/adler32.c $Z/compress.c $Z/crc32.c $Z/deflate.c $Z/gzclose.c $Z/gzlib.c $Z/gzread.c $Z/gzwrite.c $Z/infback.c $Z/inffast.c $Z/inflate.c $Z/inftrees.c $Z/trees.c $Z/uncompr.c $Z/zutil.c"
zflags="-I$Z -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_HIDDEN"
collect zlib-example "$zflags" $zlib_lib $Z/test/example.c
collect zlib-minigzip "$zflags" $zlib_lib $Z/test/minigzip.c

S=$up/sqlite-amalgamation/src/sqlite-amalgamation-3540000
T=$up/sqlite-src/src/sqlite-src-3540000/test
# Upstream defaults (what an unconfigured unix build pulls in). Expected to fail:
# sqlite3.c needs pthread.h (SQLITE_THREADSAFE=1) and shell.c needs getrusage and
# struct winsize declarations (see DEMAND.md, build-system adaptations).
collect sqlite-defaults "-I$S" $S/sqlite3.c $S/shell.c
# Build-system adaptations (DEMAND.md): _GNU_SOURCE makes Picolibc declare XSI names
# (getrusage) that glibc declares by default; sys/termios.h supplies struct winsize,
# which glibc's sys/ioctl.h pulls in and Picolibc's does not.
adapt="-D_GNU_SOURCE -include sys/termios.h"
base="$adapt -I$S -DSQLITE_OS_UNIX=1 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_ENABLE_LOCKING_STYLE=0 -DSQLITE_MAX_MMAP_SIZE=0"
# The configuration SQLITE-VFS.md recommends: no WAL (no shared memory).
rec="$base -DSQLITE_OMIT_WAL"
# The same with WAL kept, to measure what shared memory (xShmMap) adds.
collect sqlite-shell-wal "$base" $S/sqlite3.c $S/shell.c
collect sqlite-shell "$rec" $S/sqlite3.c $S/shell.c
collect sqlite-speedtest1 "$rec" $S/sqlite3.c $T/speedtest1.c

# Symbols the configured Picolibc defines (the PICOLIBC bucket's reference list).
llvm-nm-18 --defined-only "$pico/lib/libc.a" "$pico/lib/libm.a" 2>/dev/null \
  | awk 'NF==3 && $2 ~ /[TWDBRVC]/{print $3}' | sort -u > "$out/picolibc-1.8.12-defined.txt"
