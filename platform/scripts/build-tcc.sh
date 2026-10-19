#!/bin/sh
# Public snapshot: the omitted TinyCC stage is never a passing test.
printf '%s\n' 'TCC STAGE NOT_RUN: not included in the public source' >&2
exit 78
# Builds TinyCC for Stage 3 (STAGE3-DESIGN.md D3-D4). Host half:
#  - copies the staged tree (tcc-build/upstream, read-only) to
#    tcc-build/src-unpatched and tcc-build/src-patched, and applies
#    tcc/patches/*.patch in order to src-patched (git apply --check, then
#    git apply; any reject fails the build);
#  - host/: stock configure, the Linux reference compiler (with its own
#    libtcc1.a, so `host/tcc -B tcc-build/host` links against glibc);
#  - hostcfg-unpatched/ and hostcfg/: configured for ABSD (the configure line
#    below), unpatched and patched. Host programs that emit ABSD images.
#    Their path prefix is tcc-build/share/absd-c, not /share/absd-c (the
#    host has no /share): every other option is the target's;
#  - targetcfg/: the target's configure line verbatim (configure only), the
#    origin of tcc/build/config.h, which must agree with it;
#  - the target libtcc1.a built by hostcfg/tcc; tcc-build/share/absd-c/
#    {include,lib,tcc}; share.sha256; hostbuild.txt;
#  - verification: hello links with only -B and the kernel-exact gate accepts
#    it with two PT_LOADs; the unpatched build's image (hello-relro.elf) is
#    refused for PT_GNU_RELRO; P2's acceptance on exit.c; no PT_NOTE; all ten
#    kit tests compile, link and are accepted.
# Prints TCC HOSTBUILD OK patched=<n> share_files=<n> share_bytes=<n>.
# Cross half: tcc-build/absd/tcc built by absd-cc (ONE_SOURCE, tcc/build/
# config.h) in two clean rounds that must hash-equal (objects and ELF); the
# kit ELF/map check and the kernel-exact gate; the demand, every name
# resolved by Picolibc, the kit or the adapter; no host path but libabs.a's.
# Prints TCC BUILD OK tcc_bytes=<n> loads=<n> rounds=2 repro_scope=tcc.o,glue.o,link;
# appends the tccdefs_.h and cross-build digests to hostbuild.txt and a
# repro_scope row to sizes.txt.
set -eu
# Symbol ordering is part of the retained .demand reports (sort/comm):
# byte order on every host, as scripts/build-cports.sh does.
export LC_ALL=C
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
out=$camp/tcc-build
kit=${ABSD_CKIT_BUILD:-$camp/ckit-build}/kit
# The host compiler whose builtins the kit links: pinned like bin/absd-cc.
clang=${ABSD_CLANG:-clang-18}
posix_a=$camp/cports-build/lib/libabsd-posix.a
gate="python3 -I $root/scripts/check-abi-elf.py"
# Always staged: on an existing clone stage-tcc.sh only re-verifies it (HEAD,
# mode bits, archive hash), so a standalone build never reads an unverified
# tree (final review M9).
sh "$root/scripts/stage-tcc.sh"
commit=$(cut -f2 "$out/stage.txt")
for f in "$kit/bin/absd-cc" "$kit/lib/crt0.o" "$kit/lib/libc.a" "$kit/lib/libm.a" "$kit/lib/libabs.a" "$kit/lib/libabs_builtins.a" "$posix_a"; do
    test -f "$f" || { echo "build-tcc: $f missing (build the C kit and scripts/build-posix.sh first)" >&2; exit 1; }
done
jobs=$(nproc 2>/dev/null || echo 2)
# GITHASH=no: tcc's Makefile stamps `tcc -v` with `git log` of whatever
# repository encloses the build directory (here the development checkout), not tinycc's.
# The target's configure options (scout-tinycc.md 5). $1 = the share prefix.
switches='-static -Wl,-Ttext=0x8000400000 -std=c11 -D__SCHAR_MAX__=0x7f -D__SHRT_MAX__=0x7fff -D__has_extension(x)=0 -U__linux__ -U__linux -U__unix__ -U__unix'
xcflags='-DCONFIG_TCC_STATIC=1 -DCONFIG_TCC_SEMLOCK=0 -DCONFIG_TCC_ABSD=1'
absd_configure() {
    ./configure --cpu=x86_64 --elfinterp=- --config-bcheck=no --config-backtrace=no \
        --tccdir="$1/tcc" --sysincludepaths="$1/include:{B}/include" \
        --libpaths="$1/lib:{B}" --crtprefix="$1/lib" \
        --tcc-switches="$switches" --extra-cflags="$xcflags"
}
target_line="./configure --cpu=x86_64 --elfinterp=- --config-bcheck=no --config-backtrace=no --tccdir=/share/absd-c/tcc --sysincludepaths='/share/absd-c/include:{B}/include' --libpaths='/share/absd-c/lib:{B}' --crtprefix=/share/absd-c/lib --tcc-switches='$switches' --extra-cflags='$xcflags'"
share=$out/share/absd-c

rm -rf "$out/src-unpatched" "$out/src-patched" "$out/host" "$out/hostcfg-unpatched" "$out/hostcfg" "$out/targetcfg" "$out/share" "$out/obj"
mkdir -p "$out/obj"
# A pristine copy of the pinned commit; a plain directory under the development checkout, so
# git must not discover the enclosing repository when applying patches.
copy_src() { mkdir -p "$1"; git -C "$out/upstream" archive --format=tar "$commit" | tar -x -C "$1"; }
copy_src "$out/src-unpatched"
copy_src "$out/src-patched"
patches=$(ls "$root"/tcc/patches/*.patch | sort)
npatch=0
for p in $patches; do
    (cd "$out/src-patched" && GIT_CEILING_DIRECTORIES=$out git apply --check "$p" && GIT_CEILING_DIRECTORIES=$out git apply "$p") \
        || { echo "build-tcc: $(basename "$p") does not apply" >&2; exit 1; }
    npatch=$((npatch + 1))
    echo "TCC PATCH $(basename "$p") applied"
done
build_copy() { # $1 = source copy, $2 = build dir: an in-tree build in a fresh copy
    mkdir -p "$2"; (cd "$1" && tar -cf - .) | tar -x -C "$2"
}

# host/: stock configure, Linux reference.
build_copy "$out/src-unpatched" "$out/host"
(cd "$out/host" && ./configure > configure.log && make -j"$jobs" GITHASH=no tcc libtcc1.a > make.log 2>&1) \
    || { echo "build-tcc: host build failed (tcc-build/host/make.log)" >&2; exit 1; }
# hostcfg-unpatched/, hostcfg/: the target configure with the host's share prefix.
build_copy "$out/src-unpatched" "$out/hostcfg-unpatched"
(cd "$out/hostcfg-unpatched" && absd_configure "$share" > configure.log && make -j"$jobs" GITHASH=no tcc > make.log 2>&1) \
    || { echo "build-tcc: hostcfg-unpatched build failed" >&2; exit 1; }
build_copy "$out/src-patched" "$out/hostcfg"
(cd "$out/hostcfg" && absd_configure "$share" > configure.log && make -j"$jobs" GITHASH=no tcc > make.log 2>&1) \
    || { echo "build-tcc: hostcfg build failed (tcc-build/hostcfg/make.log)" >&2; exit 1; }
# targetcfg/: the verbatim target configure; tcc/build/config.h must carry
# the same target defines (it drops only the host-compiler lines).
build_copy "$out/src-patched" "$out/targetcfg"
(cd "$out/targetcfg" && absd_configure /share/absd-c > configure.log)
cfgdefs() { grep -E '^#define (TCC_VERSION|TCC_TARGET_|CONFIG_TCC)' "$1" | sort; }
cfgdefs "$out/targetcfg/config.h" > "$out/obj/config-target.txt"
cfgdefs "$root/tcc/build/config.h" | grep -Ev 'CONFIG_TCC_(STATIC|SEMLOCK|ABSD)' > "$out/obj/config-kept.txt"
cmp -s "$out/obj/config-target.txt" "$out/obj/config-kept.txt" \
    || { diff "$out/obj/config-target.txt" "$out/obj/config-kept.txt" >&2 || true; echo "build-tcc: tcc/build/config.h disagrees with the target configure" >&2; exit 1; }

# The share tree. Picolibc's libc.a is libc-picolibc.a here; libc.a is the
# GROUP script (WORKAROUNDS TCC-LIBC). Archives lose their debug sections.
mkdir -p "$share/include" "$share/lib" "$share/tcc"
(cd "$kit/include" && tar -cf - .) | tar -x -C "$share/include"
(cd "$out/src-patched/include" && tar -cf - .) | tar -x -C "$share/tcc" --one-top-level=include
for a in libabs.a libm.a libabs_builtins.a; do llvm-objcopy-18 --strip-debug "$kit/lib/$a" "$share/lib/$a"; done
llvm-objcopy-18 --strip-debug "$kit/lib/libc.a" "$share/lib/libc-picolibc.a"
llvm-objcopy-18 --strip-debug "$posix_a" "$share/lib/libabsd-posix.a"
cp "$root/tcc/build/libc.a.group" "$share/lib/libc.a"
# crt1.o is the kit's crt0 alone: its strong reference to _user_strerror
# pulls the kit's hook (strerror_hook.o, R13) from libabs.a in the GROUP.
ld.lld-17 -r -o "$share/lib/crt1.o" "$kit/lib/crt0.o"
tcc=$out/hostcfg/tcc
# Compiled by basename from their directory: tcc writes the source path as
# the STT_FILE symbol, and no checkout path may reach the share tree.
(cd "$root/tcc/build" && "$tcc" -c -o "$share/lib/crti.o" crti.c && "$tcc" -c -o "$share/lib/crtn.o" crtn.c)
# The target libtcc1.a, built by the patched hostcfg tcc against the share
# tree (the guest's include order), without tcov.o and dsohandle.o.
l1="libtcc1.o stdatomic.o atomic.o builtin.o alloca.o alloca-bt.o va_list.o"
(cd "$out/hostcfg" && make -C lib GITHASH=no ../libtcc1.a OBJ-libtcc1="$l1" XFLAGS="-B$share/tcc -I$out/hostcfg" > lib.log 2>&1) \
    || { echo "build-tcc: target libtcc1.a failed (tcc-build/hostcfg/lib.log)" >&2; exit 1; }
cp "$out/hostcfg/libtcc1.a" "$share/tcc/libtcc1.a"
members=$("$tcc" -ar t "$share/tcc/libtcc1.a" | tr '\n' ' ')
[ "$members" = "$l1 " ] || { echo "build-tcc: libtcc1.a members: $members" >&2; exit 1; }
# Modes normalized (llvm-objcopy and cp inherit the source modes).
chmod -R u=rwX,go=rX "$share"
find "$share" -type f -exec chmod 0644 {} +
find "$share" -type d -exec chmod 0755 {} +
# No host path in any share file. Exempt: lib/libabs.a, whose Rust panic
# locations name the kit's checkout (kit-owned, N3; absd-cc output has them).
# lib/libabs.a is path-free since the kit's N10 remap (two-path identical), so it is checked too.
leaks=
for f in $(cd "$share" && find . -type f | LC_ALL=C sort); do
    if strings -a "$share/$f" | grep -q -F -e /data/git -e "$camp"; then leaks="$leaks $f"; fi
done
[ -z "$leaks" ] || { echo "build-tcc: host paths in the share tree:$leaks" >&2; exit 1; }
echo "TCC SHARE PATHFREE OK files=$(find "$share" -type f | wc -l) exempt=none"
(cd "$out/share" && find absd-c -type f | LC_ALL=C sort | xargs sha256sum) > "$out/share.sha256"
share_files=$(wc -l < "$out/share.sha256")
share_bytes=$(cd "$out/share" && find absd-c -type f -printf '%s\n' | awk '{s+=$1} END {print s}')

# Verification (the kernel-exact gate is advice; the guest spawn is the truth).
v=$out/hostcfg/verify
mkdir -p "$v"
cd "$root"
"$tcc" -B "$share/tcc" c/tests/kit/hello.c -o "$v/hello.elf"
line=$($gate "$v/hello.elf") || { echo "$line" >&2; echo "build-tcc: hello refused" >&2; exit 1; }
echo "$line"
case $line in *" loads=2 "*) ;; *) echo "build-tcc: hello does not have two PT_LOADs" >&2; exit 1 ;; esac
"$out/hostcfg-unpatched/tcc" -B "$share/tcc" c/tests/kit/hello.c -o "$out/hostcfg-unpatched/hello-relro.elf"
if line=$($gate "$out/hostcfg-unpatched/hello-relro.elf"); then
    echo "$line" >&2; echo "build-tcc: the unpatched image was accepted" >&2; exit 1
fi
echo "$line"
case $line in *"type 0x6474e552)"*) ;; *) echo "build-tcc: unpatched refusal is not RELRO" >&2; exit 1 ;; esac
# P2: one .init_array and one .fini_array; the bothinit symbols defined; the
# arrays hold the program's and Picolibc's entries in the kit's order.
"$tcc" -B "$share/tcc" c/tests/kit/exit.c -o "$v/exit.elf"
readelf -S -W "$v/exit.elf" | grep -E ' \.(preinit|init|fini)_array' | sed 's/^ *//'
readelf -S -W "$v/exit.elf" | awk '{for(i=1;i<=NF;i++) if ($i ~ /^\.(preinit|init|fini)_array/) print $i}' | sort | tr '\n' ' ' > "$out/obj/arrays.txt"
[ "$(cat "$out/obj/arrays.txt")" = ".fini_array .init_array " ] || { echo "build-tcc: P2 sections: $(cat "$out/obj/arrays.txt")" >&2; exit 1; }
# tcc writes no .symtab without -g, so the symbols are read from a -g twin
# whose arrays must have the same sizes.
"$tcc" -B "$share/tcc" -g c/tests/kit/exit.c -o "$v/exit-g.elf"
sizes() { readelf -S -W "$1" | awk '$2 ~ /^\.(init|fini)_array$/ {print $2, $6}'; }
[ "$(sizes "$v/exit.elf")" = "$(sizes "$v/exit-g.elf")" ] || { echo "build-tcc: exit-g.elf arrays differ from exit.elf" >&2; exit 1; }
nm "$v/exit-g.elf" | grep -E '__(bothinit|preinit|init|fini)_array_(start|end)$'
nm "$v/exit-g.elf" | awk '$3 ~ /^__bothinit_array_(start|end)$/ && $2 ~ /^[A-Za-z]$/ && $2 != "U" && $2 != "w" {n++} END {exit n != 2}' \
    || { echo "build-tcc: __bothinit_array_* not defined" >&2; exit 1; }
readelf -x .init_array -x .fini_array "$v/exit-g.elf" | grep -E '^ +0x'
python3 -I - "$v/exit-g.elf" <<'EOF'
import struct, subprocess, sys
elf = sys.argv[1]
syms = {}
for ln in subprocess.run(["nm", elf], capture_output=True, text=True, check=True).stdout.splitlines():
    f = ln.split()
    if len(f) == 3 and f[1] in "tT":
        syms.setdefault(int(f[0], 16), f[2])
data = open(elf, "rb").read()
shoff, = struct.unpack_from("<Q", data, 0x28)
shnum, shstrndx = struct.unpack_from("<HH", data, 0x3c)
sh = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + 64 * i) for i in range(shnum)]
strs = sh[shstrndx][4]
def name(h): return data[strs + h[0]:data.index(b"\0", strs + h[0])].decode()
arr = {}
for h in sh:
    if name(h) in (".init_array", ".fini_array"):
        arr[name(h)] = [syms.get(a, hex(a)) for a in struct.unpack_from(f"<{h[5] // 8}Q", data, h[4])]
init, fini = arr[".init_array"], arr[".fini_array"]
print("TCC P2 init_array=" + ",".join(init) + " fini_array=" + ",".join(fini))
# exit.c's ctor; fini in the kit's order: Picolibc's stdout flush posix_exit
# (.fini_array.101), exit.c's dtor, Picolibc's atexit runner __call_exitprocs
# (.fini_array_onexit). __libc_fini_array walks it backwards.
ok = init == ["ctor"] and fini == ["posix_exit", "dtor", "__call_exitprocs"]
sys.exit(0 if ok else 1)
EOF
notes=0
for t in c/tests/kit/*.c; do
    name=$(basename "$t" .c)
    "$tcc" -B "$share/tcc" "$t" -o "$v/$name.elf" || { echo "build-tcc: $name does not compile or link" >&2; exit 1; }
    line=$($gate "$v/$name.elf") || { echo "$line" >&2; echo "build-tcc: $name refused" >&2; exit 1; }
    echo "$line"
    if readelf -l -W "$v/$name.elf" | grep -q NOTE; then notes=$((notes + 1)); echo "build-tcc: $name has PT_NOTE" >&2; fi
done
[ "$notes" = 0 ] || exit 1
echo "TCC KIT TESTS $(ls c/tests/kit/*.c | wc -l) accepted, PT_NOTE none"
# R2 receipt (host only): the unpatched and patched exit.c -g arrays and symbols.
sh "$root/scripts/tcc-unpatched-arrays.sh"

{
    echo "# tcc-build/hostbuild.txt: written by scripts/build-tcc.sh"
    printf 'stage\t%s\n' "$(cat "$out/stage.txt")"
    printf 'host_cc\t%s\n' "$(gcc --version | head -1)"
    printf 'host_tcc\t%s\n' "$("$out/host/tcc" -v)"
    printf 'hostcfg_tcc\t%s\n' "$("$tcc" -v)"
    printf 'configure_target\t%s\n' "$target_line"
    printf 'configure_hostcfg\t%s\n' "the target line with /share/absd-c replaced by $share"
    printf 'configure_host\t./configure\n'
    for p in $patches; do printf 'patch\t%s\tlines=%s\tsha256=%s\n' "$(basename "$p")" "$(wc -l < "$p")" "$(sha256sum "$p" | cut -d' ' -f1)"; done
    printf 'libtcc1\t%s\tsha256=%s\n' "$members" "$(sha256sum "$share/tcc/libtcc1.a" | cut -d' ' -f1)"
    printf 'share\tfiles=%s\tbytes=%s\tsha256_of_list=%s\n' "$share_files" "$share_bytes" "$(sha256sum "$out/share.sha256" | cut -d' ' -f1)"
} > "$out/hostbuild.txt"
echo "TCC HOSTBUILD OK patched=$npatch share_files=$share_files share_bytes=$share_bytes"

# Cross half (STAGE3-DESIGN.md D3): /bin/tcc for the guest, built by absd-cc
# as Stage 2 built its ports. tcc/build/config.h (checked above against
# targetcfg/) selects the target; tcc-main.c is the ONE_SOURCE unit.
# CONFIG_TCC_PREDEFS needs tccdefs_.h, which c2str (conftest.c -DC2STR)
# generates from include/tccdefs.h. c2str only strips comments and rewrites
# the host's platform macros (__x86_64__, __linux__, ...) to tcc's own
# compile-time names (TCC_TARGET_X86_64, TARGETOS_Linux, ...), so its output
# is target-independent: the target is chosen when tcc.o is compiled. It is
# generated here by targetcfg's own make and must equal hostcfg's. It goes in
# obj/gen, not -I targetcfg, whose config.h must not shadow tcc/build's.
cc=$kit/bin/absd-cc
(cd "$out/targetcfg" && make GITHASH=no tccdefs_.h > gen.log 2>&1) \
    || { echo "build-tcc: tccdefs_.h generation failed (tcc-build/targetcfg/gen.log)" >&2; exit 1; }
cmp -s "$out/targetcfg/tccdefs_.h" "$out/hostcfg/tccdefs_.h" \
    || { echo "build-tcc: targetcfg and hostcfg tccdefs_.h differ" >&2; exit 1; }
mkdir -p "$out/obj/gen" "$out/repro"
cp "$out/targetcfg/tccdefs_.h" "$out/obj/gen/tccdefs_.h"
# tccdefs_.h is a tcc.o input: its digest goes into hostbuild.txt (final
# review M13, Task 4 #3), with the cross build's below.
printf 'tccdefs_h\t%s\tsha256=%s\n' "targetcfg/tccdefs_.h (== hostcfg/tccdefs_.h)" "$(sha256sum "$out/obj/gen/tccdefs_.h" | cut -d' ' -f1)" >> "$out/hostbuild.txt"
# The prefix maps keep the checkout paths out of __FILE__ (tcc's asserts and
# Picolibc's assert); the image must carry no the development checkout path of its own.
pmap="-ffile-prefix-map=$out/src-patched=tcc -ffile-prefix-map=$root/tcc/build=tcc/build -ffile-prefix-map=$out/obj/gen=tcc"
for round in 1 2; do
    rm -rf "$out/absd" "$out/obj/tcc.o" "$out/obj/glue.o"; mkdir -p "$out/absd"
    "$cc" -c -O2 -DONE_SOURCE=1 $pmap -I"$out/src-patched" -I"$root/tcc/build" -I"$out/obj/gen" \
        -o "$out/obj/tcc.o" "$root/tcc/build/tcc-main.c" \
        || { echo "build-tcc: tcc.o does not compile" >&2; exit 1; }
    "$cc" -c -O2 -Wall -Wextra -Werror $pmap -o "$out/obj/glue.o" "$root/tcc/build/glue.c" \
        || { echo "build-tcc: glue.o does not compile" >&2; exit 1; }
    # The Stage 2 link order: objects, then the adapter archive (the kit's
    # crt0 brings Picolibc's strerror hook, R13). absd-cc writes the map to
    # absd/tcc.map.
    "$cc" -o "$out/absd/tcc" "$out/obj/tcc.o" "$out/obj/glue.o" "$posix_a"
    (cd "$out" && sha256sum obj/tcc.o obj/glue.o absd/tcc) > "$out/repro/round$round.sha256"
done
cmp -s "$out/repro/round1.sha256" "$out/repro/round2.sha256" \
    || { diff "$out/repro/round1.sha256" "$out/repro/round2.sha256" >&2 || true; echo "build-tcc: the two cross builds differ" >&2; exit 1; }
elf=$out/absd/tcc
printf 'cross_tcc\tabsd/tcc\tbytes=%s\tsha256=%s\trounds=2 (repro/round1.sha256 == repro/round2.sha256)\n' \
    "$(stat -c %s "$elf")" "$(sha256sum "$elf" | cut -d' ' -f1)" >> "$out/hostbuild.txt"
kline=$(python3 -I "$root/scripts/check-c-elf.py" "$elf" --map "$elf.map") \
    || { echo "$kline" >&2; echo "build-tcc: tcc refused by the kit ELF/map check" >&2; exit 1; }
echo "$kline"
aline=$($gate "$elf") || { echo "$aline" >&2; echo "build-tcc: tcc refused by the kernel-exact gate" >&2; exit 1; }
echo "$aline"
loads=$(printf '%s\n' "$aline" | sed -n 's/.* loads=\([0-9]*\) .*/\1/p')
# Demand, by build-cports.sh's method: the names the linked objects
# reference and do not define, every one defined by Picolibc, the kit or the
# adapter. glue.o is among the linked objects.
resolvers="$kit/lib/libc.a $kit/lib/libm.a $kit/lib/libabs.a $kit/lib/libabs_builtins.a $("$clang" -print-resource-dir)/lib/linux/libclang_rt.builtins-x86_64.a $posix_a"
llvm-nm-18 --defined-only --extern-only $resolvers 2>/dev/null | awk 'NF==3 {print $3}' | sort -u > "$out/obj/resolvers.txt"
objs="$out/obj/tcc.o $out/obj/glue.o"
llvm-nm-18 -u $objs | awk 'NF==2 && $1=="U" {print $2}' | sort -u > "$out/obj/tcc.u"
llvm-nm-18 --defined-only $objs | awk 'NF==3 {print $3}' | sort -u > "$out/obj/tcc.d"
comm -23 "$out/obj/tcc.u" "$out/obj/tcc.d" > "$elf.demand"
unresolved=$(comm -23 "$elf.demand" "$out/obj/resolvers.txt")
[ -z "$unresolved" ] || { echo "build-tcc: tcc demands names nothing defines:" >&2; printf '  %s\n' $unresolved >&2; exit 1; }
echo "DEMAND tcc names=$(wc -l < "$elf.demand") unresolved=0"
# No host path of the build's own. libabs.a's Rust panic locations (kit N3)
# are the only permitted hits, and each must be a .rs location equal to a
# whole string of libabs.a (grep -x). One known exception: `strings` reads
# the hex digit table 0123456789abcdef and the path that follows it in
# libabs.a's rodata as one string, so that exact concatenation is accepted
# too (whole line, never a substring).
strings -a "$elf" | grep -F -e /data/git -e "$camp" > "$out/obj/tcc.paths" || true
strings -a "$kit/lib/libabs.a" > "$out/obj/libabs.strings"
foreign=
while IFS= read -r hit; do
    case $hit in *.rs) grep -qxF -e "$hit" -e "0123456789abcdef$hit" "$out/obj/libabs.strings" && continue ;; esac
    foreign="$foreign
$hit"
done < "$out/obj/tcc.paths"
[ -z "$foreign" ] || { printf '%s\n' "$foreign" >&2; echo "build-tcc: host paths in tcc beyond libabs.a's" >&2; exit 1; }
echo "TCC PATHFREE OK libabs_rs_hits=$(wc -l < "$out/obj/tcc.paths")"
tcc_bytes=$(stat -c %s "$elf")
{
    printf 'tcc\t%s\t%s\n' "$tcc_bytes" "$(wc -l < "$elf.demand")"
    printf 'share\t%s\t%s\n' "$share_bytes" "$share_files"
    printf 'repro_scope\t%s\n' "tcc.o,glue.o,link (adapter archive: input)"
} > "$out/sizes.txt"
cat "$out/sizes.txt"
echo "TCC BUILD OK tcc_bytes=$tcc_bytes loads=$loads rounds=2 repro_scope=tcc.o,glue.o,link"
