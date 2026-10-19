#!/bin/sh
# Build LLVM, Clang and LLD 18.1.8 (cxx/PIN) as static ABSD programs for
# x86_64-unknown-none-elf against the C kit, single-task profile (cxx/README.md,
# "LLVM on the kit"), and the same configuration for x86_64-linux as a twin
# whose heap and time are measured on the host. Host only: nothing boots.
#
# Usage: build-llvm-kit.sh [STEP...]   (default: every step, in order)
#   source     copy the staged source (scripts/stage-llvm.sh) to $out/src and
#              apply cxx/patches/llvm/*.patch in order (replaced every run)
#   cxx        the C++ runtime, LLVM profile (build-cxx-runtime.sh,
#              ABSD_CXX_PROFILE=llvm) into $out/cxx
#   posix      the POSIX adapter archive (build-posix.sh) into $out/posix
#   tblgen     llvm-tblgen and clang-tblgen for the host, from the pinned
#              source, into $out/tblgen
#   configure  CMake for the ABSD build in $out/kit
#   support    LLVMSupport only, then the dependency audit ($out/kit/support-audit.txt)
#   clang      the clang driver+cc1 image ($out/kit/bin/clang)
#   lld        the lld image ($out/kit/bin/lld)
#   gate       scripts/check-c-elf.py, stripped sizes, PT_LOADs, undefined
#              symbols and static data (IMAGE.gate beside each image)
#   alternatives  the image-size alternatives: cc1 (no driver), cc1-fe (no
#              code generator), llc, clang-o0 and cc1-fe-o0 (-O0 pipeline
#              only); linked and gated the same way
#   twin       the same configuration for x86_64-linux (host clang 18 and
#              its libstdc++, glibc), clang and lld, in $out/twin
#
# The kit is $ABSD_CKIT (default $camp/ckit-build/kit). Output is
# $ABSD_LLVM_BUILD (default $camp/llvm-build, outside the repository).
# Every compile runs under nice -n 19 with at most $ABSD_LLVM_JOBS (default 4)
# jobs and waits while the 1-minute load average exceeds $ABSD_LLVM_MAX_LOAD
# (default 8). The job limit is host-wide: a build step also waits while any
# other ninja is building under $ABSD_LLVM_BUILD (the kit and the twin never
# build at once).
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
kit=${ABSD_CKIT:-$camp/ckit-build/kit}
out=${ABSD_LLVM_BUILD:-$camp/llvm-build}
up=${ABSD_LLVM_UPSTREAM:-$camp/upstream}
jobs=${ABSD_LLVM_JOBS:-4}
max_load=${ABSD_LLVM_MAX_LOAD:-8}
die() { echo "build-llvm-kit: $*" >&2; exit 1; }
[ "$jobs" -le 4 ] 2>/dev/null || die "ABSD_LLVM_JOBS=$jobs: at most 4"
[ -n "$out" ] && [ "$out" != / ] || die "ABSD_LLVM_BUILD is empty or /"
version=$(grep -v '^#' "$root/cxx/PIN" | awk -F'\t' 'NF == 6 { print $2 }')
staged=$up/llvm-project/src/llvm-project-$version.src
src=$out/src
tblgen=$out/tblgen
kitb=$out/kit
twin=$out/twin
[ -x "$kit/bin/absd-cc" ] && [ -f "$kit/BUILT-FROM" ] || die "$kit is not a built C kit (ABSD_CKIT)"
clang_version=$(clang-18 -dumpversion) || die "clang-18 not found"
[ "${clang_version%%.*}" = 18 ] || die "clang-18 is clang $clang_version"
resource=$(clang-18 -print-resource-dir)

wait_load() {
    while :; do
        load=$(cut -d' ' -f1 /proc/loadavg)
        awk -v l="$load" -v m="$max_load" 'BEGIN { exit !(l > m) }' || return 0
        echo "build-llvm-kit: 1-minute load $load exceeds $max_load; waiting" >&2
        sleep 60
    done
}
# Another ninja building in this campaign's build directory (kit or twin).
other_ninja() {
    pgrep -f "ninja -C $out/" > /dev/null 2>&1
}
# ninja under nice, one target set, log appended; load and the host-wide
# one-build rule checked first.
build() {   # dir log targets...
    d=$1 log=$2; shift 2
    while other_ninja; do
        echo "build-llvm-kit: another LLVM build is running under $out; waiting" >&2
        sleep 60
    done
    wait_load
    t0=$(date +%s)
    nice -n 19 ninja -C "$d" -j "$jobs" -k 0 "$@" >> "$log" 2>&1 ||
        { tail -40 "$log"; die "ninja $* failed (log $log)"; }
    echo "ninja $* seconds=$(( $(date +%s) - t0 ))" >> "$d/TIMES"
}

# The kit's compile flags, exactly as its driver states them; C++ units take
# -fno-builtin in place of -ffreestanding (as absd-c++ and the runtime do).
kit_cflags=$(sed -n 's/^cflags="\(.*\)"$/\1/p' "$kit/bin/absd-cc")
case $kit_cflags in
    *'-isystem $kit/include -isystem $clang_include') ;;
    *) die "the kit's cflags no longer end in its two -isystem directories: $kit_cflags" ;;
esac
code_flags=${kit_cflags%' -isystem $kit/include -isystem $clang_include'}
case " $code_flags " in *" -ffreestanding "*) ;; *) die "the kit's cflags no longer carry -ffreestanding" ;; esac
cxx_code_flags=$(printf '%s' "$code_flags" | sed 's/ -ffreestanding / -fno-builtin /')
# LLVM is C++17 in strict ISO mode, under which Picolibc hides its POSIX,
# BSD and GNU declarations (realpath, usleep, getentropy; the *_l functions
# libc++'s <locale> calls); clang++ predefines _GNU_SOURCE for a glibc
# target, which is what LLVM is written against.
# LLVM_ABSD_KIT selects the single-task port (cxx/patches/llvm).
port_defs="-D_GNU_SOURCE -DLLVM_ABSD_KIT=1"

step_source() {
    [ -f "$staged/llvm/CMakeLists.txt" ] || die "$staged is not staged: run scripts/stage-llvm.sh"
    cmp -s "$staged/LICENSE.TXT" "$root/cxx/llvm-project.LICENSE" || die "$staged/LICENSE.TXT is not the pinned licence"
    rm -rf "${src:?}"
    mkdir -p "$src"
    for d in llvm clang lld cmake libcxx libcxxabi libunwind runtimes third-party LICENSE.TXT; do
        cp -a "$staged/$d" "$src/$d"
    done
    chmod -R u+w "$src"
    # The ABSD OS layer of LLVMSupport (included in place of Unix/*.inc
    # by cxx/patches/llvm/0004).
    mkdir -p "$src/llvm/lib/Support/ABSD"
    cp "$root"/cxx/glue/llvm-support/*.inc "$src/llvm/lib/Support/ABSD/"
    for p in "$root"/cxx/patches/llvm/*.patch; do
        [ -f "$p" ] || continue
        patch -s -p1 -d "$src" --no-backup-if-mismatch < "$p" || die "patch $p does not apply"
    done
    # The pass registry of the -O0-only image (alternatives step).
    python3 "$root/scripts/llvm-o0-registry.py" "$src/llvm/lib/Passes/PassRegistry.def" \
        "$src/llvm/lib/Passes/PassRegistryO0.def"
    ls "$root"/cxx/patches/llvm/*.patch 2>/dev/null | xargs -r -n1 basename > "$src/ABSD-PATCHES"
    echo "LLVM SOURCE OK $src patches=$(wc -l < "$src/ABSD-PATCHES")"
}

step_cxx() {
    ABSD_CKIT=$kit ABSD_CXX_PROFILE=llvm ABSD_LLVM_SRC=$src ABSD_CXX_BUILD=$out/cxx \
        ABSD_CXX_JOBS=$jobs ABSD_CXX_MAX_LOAD=$max_load sh "$root/scripts/build-cxx-runtime.sh"
}

step_posix() {
    ABSD_CKIT_BUILD=$(dirname "$kit") ABSD_CPORTS_BUILD=$out/posix sh "$root/scripts/build-posix.sh"
}

step_tblgen() {
    mkdir -p "$tblgen"
    wait_load
    nice -n 19 cmake -G Ninja -S "$staged/llvm" -B "$tblgen" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
        -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_ENABLE_PROJECTS=clang \
        -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
        -DLLVM_ENABLE_ZSTD=OFF -DLLVM_ENABLE_ZLIB=OFF -DLLVM_ENABLE_LIBXML2=OFF \
        > "$tblgen/configure.log" 2>&1 || { tail -30 "$tblgen/configure.log"; die "tblgen configure failed"; }
    build "$tblgen" "$tblgen/build.log" llvm-tblgen clang-tblgen
}

# The options both builds share (the scout's list, section 6, checked
# against the pinned tree's CMake).
common_options() {
    cat <<OPTS
-DCMAKE_BUILD_TYPE=MinSizeRel
-DCMAKE_C_FLAGS_MINSIZEREL=-Oz -DNDEBUG
-DCMAKE_CXX_FLAGS_MINSIZEREL=-Oz -DNDEBUG
-DLLVM_ENABLE_PROJECTS=clang;lld
-DLLVM_TARGETS_TO_BUILD=X86
-DLLVM_DEFAULT_TARGET_TRIPLE=x86_64-unknown-none-elf
-DLLVM_ENABLE_THREADS=OFF
-DLLVM_ENABLE_ZLIB=OFF
-DLLVM_ENABLE_ZSTD=OFF
-DLLVM_ENABLE_LIBXML2=OFF
-DLLVM_ENABLE_TERMINFO=OFF
-DLLVM_ENABLE_LIBEDIT=OFF
-DLLVM_ENABLE_LIBPFM=OFF
-DLLVM_ENABLE_FFI=OFF
-DLLVM_ENABLE_CURL=OFF
-DLLVM_ENABLE_HTTPLIB=OFF
-DLLVM_ENABLE_BACKTRACES=OFF
-DLLVM_ENABLE_CRASH_OVERRIDES=OFF
-DLLVM_ENABLE_PLUGINS=OFF
-DLLVM_ENABLE_PIC=OFF
-DLLVM_ENABLE_UNWIND_TABLES=OFF
-DLLVM_DISABLE_ASSEMBLY_FILES=ON
-DBUILD_SHARED_LIBS=OFF
-DLLVM_BUILD_LLVM_DYLIB=OFF
-DLLVM_LINK_LLVM_DYLIB=OFF
-DLLVM_ENABLE_ASSERTIONS=OFF
-DLLVM_APPEND_VC_REV=OFF
-DLLVM_ENABLE_EH=OFF
-DLLVM_ENABLE_RTTI=OFF
-DLLVM_BUILD_STATIC=ON
-DLLVM_INCLUDE_TESTS=OFF
-DLLVM_INCLUDE_BENCHMARKS=OFF
-DLLVM_INCLUDE_EXAMPLES=OFF
-DLLVM_INCLUDE_DOCS=OFF
-DLLVM_INCLUDE_UTILS=OFF
-DLLVM_BUILD_TOOLS=OFF
-DLLVM_BUILD_UTILS=OFF
-DLLVM_ENABLE_BINDINGS=OFF
-DLLVM_ENABLE_OCAMLDOC=OFF
-DLLVM_TABLEGEN=$tblgen/bin/llvm-tblgen
-DCLANG_TABLEGEN=$tblgen/bin/clang-tblgen
-DLLVM_NATIVE_TOOL_DIR=$tblgen/bin
-DCLANG_ENABLE_STATIC_ANALYZER=OFF
-DCLANG_ENABLE_ARCMT=OFF
-DCLANG_PLUGIN_SUPPORT=OFF
-DCLANG_INCLUDE_TESTS=OFF
-DCLANG_INCLUDE_DOCS=OFF
-DCLANG_BUILD_TOOLS=ON
-DCLANG_DEFAULT_LINKER=lld
-DCLANG_SPAWN_CC1=OFF
-DLLD_BUILD_TOOLS=ON
OPTS
}

# CLANG_HAVE_RLIMITS is answered by a header probe (sys/resource.h, which
# Picolibc has); the kit defines no getrlimit/setrlimit and an ABSD stack is
# a fixed 4 MiB reservation (C-INTERFACE.md section 2), so cc1 does not try
# to raise it. Consequence: with threads off clang's
# runWithSufficientStackSpace never checks either, so input deep enough to
# need more than 4 MiB of stack is a page fault (the parent sees
# -1000 - 14), with no "stack nearly exhausted" diagnostic. HAVE_DECL_ARC4RANDOM: Picolibc declares and defines
# arc4random, but its member leaves weak references (arc4random_abort,
# arc4random_fork_detect) that scripts/check-c-elf.py refuses, so the kit
# does not offer it; LLVM's random numbers then come from rand() seeded by
# the kit's getentropy (cxx/patches/llvm/0004).
# LLVM_APPEND_VC_REV=OFF: the build copy lives inside whatever checkout
# holds the campaign directory, and LLVM would otherwise put that
# repository's remote URL and commit into clang's version string.
step_configure() {
    [ -x "$tblgen/bin/llvm-tblgen" ] && [ -x "$tblgen/bin/clang-tblgen" ] || die "run the tblgen step first"
    [ -f "$out/cxx/lib/libc++.a" ] || die "run the cxx step first"
    [ -f "$out/posix/lib/libabsd-posix.a" ] || die "run the posix step first"
    mkdir -p "$kitb"
    rm -f "$kitb/CMakeCache.txt"
    cflags="$code_flags $port_defs -isystem $kit/include -isystem $resource/include"
    cxxflags="$cxx_code_flags $port_defs -nostdinc++ -isystem $out/cxx/include/c++/v1 -isystem $kit/include -isystem $resource/include"
    prefix_map="-ffile-prefix-map=$src=/llvm-project-$version -ffile-prefix-map=$kitb=/llvm-build"
    link="$root/cxx/bin/absd-llvm-link --kit=$kit --cxx=$out/cxx --posix=$out/posix/lib/libabsd-posix.a"
    opts=$(common_options)
    wait_load
    old_ifs=$IFS; IFS='
'
    set -- $opts
    IFS=$old_ifs
    nice -n 19 cmake -G Ninja -S "$src/llvm" -B "$kitb" \
        -DCMAKE_TOOLCHAIN_FILE="$root/cxx/absd-llvm-toolchain.cmake" \
        -DABSD_LINK="$link" \
        -DCMAKE_C_FLAGS="$cflags $prefix_map" -DCMAKE_CXX_FLAGS="$cxxflags $prefix_map" \
        -DCMAKE_ASM_FLAGS="$cflags" \
        -DLLVM_HOST_TRIPLE=x86_64-unknown-none-elf \
        -DCLANG_HAVE_RLIMITS=OFF -DHAVE_DECL_ARC4RANDOM=0 \
        "$@" > "$kitb/configure.log" 2>&1 || { tail -40 "$kitb/configure.log"; die "configure failed (log $kitb/configure.log)"; }
    echo "LLVM CONFIGURE OK $kitb"
}

step_support() {
    build "$kitb" "$kitb/build.log" LLVMSupport
    # Every C-level symbol LLVMSupport's objects reference that neither the
    # kit, the POSIX adapter, the C++ runtime nor LLVM defines; empty once
    # the port is complete (cxx/README.md lists what each one became).
    defs=$(mktemp); trap 'rm -f "$defs"' EXIT
    llvm-nm-18 --defined-only "$kit"/lib/*.a "$out"/cxx/lib/*.a "$out/posix/lib/libabsd-posix.a" \
        "$kitb/lib/libLLVMSupport.a" "$kitb/lib/libLLVMDemangle.a" 2>/dev/null |
        awk 'NF == 3 { print $3 }' | sort -u > "$defs"
    llvm-nm-18 -A -u "$kitb/lib/libLLVMSupport.a" 2>/dev/null | awk '{ print $NF }' | sort -u |
        comm -23 - "$defs" > "$kitb/support-audit.txt"
    [ ! -s "$kitb/support-audit.txt" ] || { cat "$kitb/support-audit.txt"; die "LLVMSupport needs symbols the kit does not provide"; }
    echo "LLVM SUPPORT OK undefined-beyond-kit=0"
}

step_clang() {
    build "$kitb" "$kitb/build.log" clang
}

step_lld() {
    build "$kitb" "$kitb/build.log" lld
}

# The image gate for one linked image: scripts/check-c-elf.py with its map,
# the stripped image (what a spawner would hold), its PT_LOADs, undefined
# symbols and the static data the heap window does not hold (.data, .bss
# live in the image's own segment, not the heap).
gate_one() {   # image
    img=$1 g=$1.gate
    [ -f "$img" ] || { echo "GATE $img absent" | tee "$g"; return 0; }
    llvm-strip-18 -o "$img.stripped" "$img"
    {
        python3 "$root/scripts/check-c-elf.py" "$img" --map "$img.map" || true
        python3 "$root/scripts/check-c-elf.py" "$img.stripped" || true
        printf 'bytes %s stripped %s spawn-cap %s\n' "$(stat -c %s "$img")" "$(stat -c %s "$img.stripped")" $((32 << 20))
        printf 'sha256 %s stripped-sha256 %s\n' "$(sha256sum "$img" | cut -d' ' -f1)" "$(sha256sum "$img.stripped" | cut -d' ' -f1)"
        llvm-readelf-18 -lW "$img.stripped" | grep -E '^ +(LOAD|TLS|DYNAMIC|INTERP|GNU)'
        echo "undefined:"; llvm-nm-18 -u "$img" | sed 's/^/  /'
        llvm-size-18 -A "$img" | awk '$1 ~ /^\.(text|rodata|data|bss|ldata|lbss|lrodata|init_array|fini_array|got)/ || $1 == "__lcxx_override" { printf "section %s %s\n", $1, $2 }'
    } > "$g" 2>&1
    cat "$g"
}

step_gate() {
    gate_one "$kitb/bin/clang-18"
    gate_one "$kitb/bin/lld"
    built_from
}

# What the images in kit/bin were built from: the platform commit and
# whether the files that shape them were dirty, every patch and glue file
# by digest, and the kit, runtime and adapter archives.
built_from() {
    dirty=no
    [ -z "$(git -C "$root" status --porcelain -- cxx scripts/build-llvm-kit.sh scripts/build-cxx-runtime.sh scripts/llvm-o0-registry.py)" ] || dirty=yes
    {
        printf 'commit %s\n' "$(git -C "$root" rev-parse HEAD)"
        printf 'dirty %s\n' "$dirty"
        printf 'llvm-project %s\n' "$version"
        printf 'clang %s\n' "$(clang-18 --version | head -n 1)"
        printf 'ld.lld %s\n' "$(ld.lld-17 --version)"
        printf 'kit %s commit %s\n' "$kit" "$(sed -n 's/^commit //p' "$kit/BUILT-FROM")"
        for f in lib/libc.a lib/libabs.a lib/libabs_builtins.a lib/crt0.o absd-c.ld; do
            printf 'kit-%s %s\n' "$f" "$(sha256sum "$kit/$f" | cut -d' ' -f1)"
        done
        for f in "$out"/cxx/lib/libc++.a "$out"/cxx/lib/libc++abi.a "$out"/posix/lib/libabsd-posix.a; do
            printf '%s %s\n' "${f#$out/}" "$(sha256sum "$f" | cut -d' ' -f1)"
        done
        for f in "$root"/cxx/patches/llvm/*.patch "$root"/cxx/glue/*/*; do
            printf '%s %s\n' "${f#$root/}" "$(sha256sum "$f" | cut -d' ' -f1)"
        done
        for i in "$kitb"/bin/*.stripped; do
            printf 'image %s %s bytes=%s\n' "$(basename "$i" .stripped)" "$(sha256sum "$i" | cut -d' ' -f1)" "$(stat -c %s "$i")"
        done
    } > "$kitb/BUILT-FROM"
}

# The Linux twin: the same options, built for x86_64-linux by host clang 18
# against glibc and libstdc++, with LLVM_ABSD_KIT defined so that its file
# handling is the port's (files read into the heap, output built in memory,
# no signal handlers, no program execution), then measured compiling the
# kit's hello.c and 500-line C file at -O0 (the kit's flags, its Picolibc
# headers, this clang's own resource headers) and linking hello with the
# kit's link line: /usr/bin/time -v three times each, one strace for the
# heap (scripts/llvm-heap-peak.py). Results in $twin/MEASURE.
step_twin() {
    [ -x "$tblgen/bin/llvm-tblgen" ] || die "run the tblgen step first"
    mkdir -p "$twin"
    rm -f "$twin/CMakeCache.txt"
    opts=$(common_options)
    old_ifs=$IFS; IFS='
'
    set -- $opts
    IFS=$old_ifs
    wait_load
    nice -n 19 cmake -G Ninja -S "$src/llvm" -B "$twin" \
        -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
        -DCMAKE_C_FLAGS="-DLLVM_ABSD_KIT=1" -DCMAKE_CXX_FLAGS="-DLLVM_ABSD_KIT=1" \
        "$@" > "$twin/configure.log" 2>&1 || { tail -40 "$twin/configure.log"; die "twin configure failed"; }
    build "$twin" "$twin/build.log" clang lld llc
    twin_alternatives
    measure_twin
}

# The twin's cc1-fe and clang-o0, made as the alternatives step makes the
# kit's (same glue, same substitutions on the twin's own commands), so
# that the split pipeline and the -O0-only image can be run on the host.
twin_alternatives() {
    ta=$twin/alt
    mkdir -p "$ta"
    cflags_cmd=$(ninja -C "$twin" -t commands bin/clang-18 | grep -F 'driver.cpp.o -c ' | tail -n 1)
    link_cmd=$(ninja -C "$twin" -t commands bin/clang-18 | tail -n 1)
    for g in cc1-main frontend-no-targets; do
        compile=$(printf '%s' "$cflags_cmd" | sed "s| -MD -MT [^ ]* -MF [^ ]*||; s| -o [^ ]*driver.cpp.o| -o $ta/$g.o|; s| -c [^ ]*driver.cpp\$| -c $root/cxx/glue/llvm-images/$g.cpp|")
        ( cd "$twin" && nice -n 19 sh -c "$compile" ) || die "twin compile $g failed"
    done
    o0objs=
    for f in PassBuilder PassBuilderPipelines; do
        cmd=$(ninja -C "$twin" -t commands lib/libLLVMPasses.a | grep -F "/$f.cpp.o -c " | tail -n 1)
        cmd=$(printf '%s' "$cmd" | sed "s| -MD -MT [^ ]* -MF [^ ]*||; s| -o [^ ]*/$f.cpp.o| -DLLVM_ABSD_O0_ONLY=1 -o $ta/$f.o0.o|")
        ( cd "$twin" && nice -n 19 sh -c "$cmd" ) || die "twin compile $f (O0 only) failed"
        o0objs="$o0objs $ta/$f.o0.o"
    done
    drv=tools/clang/tools/driver/CMakeFiles/clang.dir
    base=$(printf '%s' "$link_cmd" | sed "s|^: && ||; s| && :\$||")
    fe=$(printf '%s' "$base" | sed "s| $drv/driver.cpp.o| $ta/cc1-main.o $ta/frontend-no-targets.o|; s| $drv/clang-driver.cpp.o||; s| -o bin/clang-18 | -o bin/cc1-fe |; s| lib/libLLVMX86[A-Za-z]*\.a||g")
    o0=$(printf '%s' "$base" | sed "s| -o bin/clang-18 | -o bin/clang-o0 |; s| $drv/driver.cpp.o| $drv/driver.cpp.o$o0objs|")
    ( cd "$twin" && nice -n 19 sh -c "$fe" ) > "$ta/link.log" 2>&1 || { tail -20 "$ta/link.log"; die "twin cc1-fe link failed"; }
    ( cd "$twin" && nice -n 19 sh -c "$o0" ) >> "$ta/link.log" 2>&1 || { tail -20 "$ta/link.log"; die "twin clang-o0 link failed"; }
}

measure_twin() {
    m=$twin/measure
    rm -rf "${m:?}"; mkdir -p "$m"
    tc=$twin/bin/clang-18
    tres=$("$tc" -print-resource-dir)
    flags="$code_flags -isystem $kit/include -isystem $tres/include"
    cp "$root/cxx/tests/llvm/hello.c" "$root/cxx/tests/llvm/c500.c" "$m/"
    {
        printf 'twin clang %s\n' "$("$tc" --version | head -n 1)"
        printf 'twin lld %s\n' "$("$twin/bin/ld.lld" --version)"
        printf 'flags %s -O0 -c\n' "$flags"
        for f in hello c500; do
            for i in 1 2 3; do
                ( cd "$m" && /usr/bin/time -v "$tc" $flags -O0 -c "$f.c" -o "$f.o" ) 2> "$m/time.$f.$i.txt"
                printf 'cc1 %s run %s max_rss_kb=%s wall=%s\n' "$f" "$i" \
                    "$(sed -n 's/^.*Maximum resident set size (kbytes): //p' "$m/time.$f.$i.txt")" \
                    "$(sed -n 's/^.*Elapsed (wall clock) time (h:mm:ss or m:ss): //p' "$m/time.$f.$i.txt")"
            done
            ( cd "$m" && strace -f -o "$m/strace.$f.txt" -e trace=brk,mmap,munmap,mremap,openat,close "$tc" $flags -O0 -c "$f.c" -o "$f.o" )
            printf 'cc1 %s %s object_bytes=%s sha256=%s\n' "$f" "$(python3 "$root/scripts/llvm-heap-peak.py" "$m/strace.$f.txt")" \
                "$(stat -c %s "$m/$f.o")" "$(sha256sum "$m/$f.o" | cut -d' ' -f1)"
        done
        builtins=$(clang-18 -print-resource-dir)/lib/linux/libclang_rt.builtins-x86_64.a
        link="-static -no-pie --gc-sections -T $kit/absd-c.ld $kit/lib/crt0.o hello.o --start-group $kit/lib/libabs.a $kit/lib/libc.a $kit/lib/libm.a $kit/lib/libabs_builtins.a $builtins --end-group"
        for i in 1 2 3; do
            ( cd "$m" && /usr/bin/time -v "$twin/bin/ld.lld" $link -Map=hello.elf.map -o hello.elf ) 2> "$m/time.link.$i.txt"
            printf 'lld hello run %s max_rss_kb=%s wall=%s\n' "$i" \
                "$(sed -n 's/^.*Maximum resident set size (kbytes): //p' "$m/time.link.$i.txt")" \
                "$(sed -n 's/^.*Elapsed (wall clock) time (h:mm:ss or m:ss): //p' "$m/time.link.$i.txt")"
        done
        ( cd "$m" && strace -f -o "$m/strace.link.txt" -e trace=brk,mmap,munmap,mremap,openat,close "$twin/bin/ld.lld" $link -Map=hello.elf.map -o hello.elf )
        printf 'lld hello %s\n' "$(python3 "$root/scripts/llvm-heap-peak.py" "$m/strace.link.txt")"
        python3 "$root/scripts/check-c-elf.py" "$m/hello.elf" --map "$m/hello.elf.map" || true
        # The -O0-only image compiles to the same object, and refuses -O2.
        for f in hello c500; do
            ( cd "$m" && "$twin/bin/clang-o0" $flags -O0 -c "$f.c" -o "$f.o0.o" )
            if cmp -s "$m/$f.o" "$m/$f.o0.o"; then same=identical; else same=DIFFERENT; fi
            ( cd "$m" && strace -f -o "$m/strace.$f.o0.txt" -e trace=brk,mmap,munmap,mremap,openat,close "$twin/bin/clang-o0" $flags -O0 -c "$f.c" -o "$f.o0.o" )
            printf 'clang-o0 %s object %s %s\n' "$f" "$same" "$(python3 "$root/scripts/llvm-heap-peak.py" "$m/strace.$f.o0.txt")"
        done
        if ( cd "$m" && "$twin/bin/clang-o0" $flags -O2 -c hello.c -o hello.o2.o ) 2> "$m/o0-refuses-O2.txt"; then
            echo "clang-o0 -O2 ACCEPTED (unexpected)"
        else
            echo "clang-o0 -O2 refused: $(grep -m1 -o 'buildPerModuleDefaultPipeline[^"]*' "$m/o0-refuses-O2.txt")"
        fi
        # The split pipeline: cc1-fe writes bitcode with the cc1 arguments
        # the driver would use, llc writes the object, lld links it.
        for f in hello c500; do
            "$tc" $flags -O0 -c "$m/$f.c" -o "$m/$f.split.o" -emit-llvm -### 2>&1 |
                python3 -c 'import shlex,sys
for l in sys.stdin:
    a = shlex.split(l)
    if len(a) > 2 and a[1] == "-cc1":
        print("\n".join(shlex.quote(x) for x in a[2:]))' > "$m/$f.cc1.rsp"
            sed -i "s|^$m/$f.split.o\$|$m/$f.bc|" "$m/$f.cc1.rsp"
            ( cd "$m" && strace -f -o "$m/strace.$f.fe.txt" -e trace=brk,mmap,munmap,mremap,openat,close "$twin/bin/cc1-fe" "@$m/$f.cc1.rsp" )
            ( cd "$m" && strace -f -o "$m/strace.$f.llc.txt" -e trace=brk,mmap,munmap,mremap,openat,close \
                "$twin/bin/llc" -O0 -filetype=obj -mtriple=x86_64-unknown-none-elf -code-model=large \
                -relocation-model=static -mcpu=x86-64 -mattr=-avx -function-sections -data-sections \
                "$f.bc" -o "$f.split.o" )
            printf 'split %s cc1-fe %s bitcode_bytes=%s\n' "$f" "$(python3 "$root/scripts/llvm-heap-peak.py" "$m/strace.$f.fe.txt")" "$(stat -c %s "$m/$f.bc")"
            printf 'split %s llc %s object_bytes=%s\n' "$f" "$(python3 "$root/scripts/llvm-heap-peak.py" "$m/strace.$f.llc.txt")" "$(stat -c %s "$m/$f.split.o")"
        done
        ( cd "$m" && "$twin/bin/ld.lld" $(printf '%s' "$link" | sed 's| hello.o | hello.split.o |') -Map=hello.split.elf.map -o hello.split.elf )
        python3 "$root/scripts/check-c-elf.py" "$m/hello.split.elf" --map "$m/hello.split.elf.map" || true
    } > "$twin/MEASURE" 2>&1
    cat "$twin/MEASURE"
}

# Image-size alternatives (the scout's section 4), each linked and gated
# like clang and lld, so the size gate (T3) has measured numbers:
#   bin/cc1      clang's compiler proper without the driver
#                (cxx/glue/llvm-images/cc1-main.cpp in place of driver.cpp)
#   bin/cc1-fe   the same with no LLVM target registered
#                (frontend-no-targets.cpp in place of the X86 target
#                libraries): -emit-llvm-bc only
#   bin/llc      LLVM's llc, the back half of the split
# Each is the clang link command ninja records, with those substitutions.
step_alternatives() {
    [ -f "$kitb/bin/clang-18" ] || die "run the clang step first"
    build "$kitb" "$kitb/build.log" llc
    cflags_cmd=$(ninja -C "$kitb" -t commands bin/clang-18 | grep -F 'driver.cpp.o -c ' | tail -n 1)
    link_cmd=$(ninja -C "$kitb" -t commands bin/clang-18 | tail -n 1)
    [ -n "$cflags_cmd" ] && [ -n "$link_cmd" ] || die "cannot read clang's commands from ninja"
    alt=$kitb/alt
    mkdir -p "$alt"
    for g in cc1-main frontend-no-targets; do
        compile=$(printf '%s' "$cflags_cmd" | sed "s| -MD -MT [^ ]* -MF [^ ]*||; s| -o [^ ]*driver.cpp.o| -o $alt/$g.o|; s| -c [^ ]*driver.cpp\$| -c $root/cxx/glue/llvm-images/$g.cpp|")
        ( cd "$kitb" && nice -n 19 sh -c "$compile" ) || die "compile $g failed"
    done
    drv=tools/clang/tools/driver/CMakeFiles/clang.dir
    cc1_link=$(printf '%s' "$link_cmd" | sed "s|^: && ||; s| && :\$||; s| $drv/driver.cpp.o| $alt/cc1-main.o|; s| $drv/clang-driver.cpp.o||; s| -o bin/clang-18 | -o bin/cc1 |")
    fe_link=$(printf '%s' "$cc1_link" | sed "s| -o bin/cc1 | -o bin/cc1-fe |; s| lib/libLLVMX86[A-Za-z]*\.a||g; s| $alt/cc1-main.o| $alt/cc1-main.o $alt/frontend-no-targets.o|")
    wait_load
    ( cd "$kitb" && nice -n 19 sh -c "$cc1_link" ) || die "link cc1 failed"
    ( cd "$kitb" && nice -n 19 sh -c "$fe_link" ) || die "link cc1-fe failed"
    # The -O0-only pipeline: PassBuilder.cpp and PassBuilderPipelines.cpp
    # compiled again with LLVM_ABSD_O0_ONLY (cxx/patches/llvm/0009), linked
    # ahead of libLLVMPasses.a into a whole clang (clang-o0) and into the
    # front end (cc1-fe-o0).
    o0objs=
    for f in PassBuilder PassBuilderPipelines; do
        cmd=$(ninja -C "$kitb" -t commands lib/libLLVMPasses.a | grep -F "/$f.cpp.o -c " | tail -n 1)
        [ -n "$cmd" ] || die "cannot read the compile command of $f.cpp"
        cmd=$(printf '%s' "$cmd" | sed "s| -MD -MT [^ ]* -MF [^ ]*||; s| -o [^ ]*/$f.cpp.o| -DLLVM_ABSD_O0_ONLY=1 -o $alt/$f.o0.o|")
        wait_load
        ( cd "$kitb" && nice -n 19 sh -c "$cmd" ) || die "compile $f (O0 only) failed"
        o0objs="$o0objs $alt/$f.o0.o"
    done
    clang_o0_link=$(printf '%s' "$link_cmd" | sed "s|^: && ||; s| && :\$||; s| -o bin/clang-18 | -o bin/clang-o0 |; s| $drv/driver.cpp.o| $drv/driver.cpp.o$o0objs|")
    fe_o0_link=$(printf '%s' "$fe_link" | sed "s| -o bin/cc1-fe | -o bin/cc1-fe-o0 |; s| $alt/cc1-main.o| $alt/cc1-main.o$o0objs|")
    ( cd "$kitb" && nice -n 19 sh -c "$clang_o0_link" ) || die "link clang-o0 failed"
    ( cd "$kitb" && nice -n 19 sh -c "$fe_o0_link" ) || die "link cc1-fe-o0 failed"
    for i in cc1 cc1-fe llc clang-o0 cc1-fe-o0; do gate_one "$kitb/bin/$i"; done
    built_from
}

steps=${*:-source cxx posix tblgen configure support clang lld gate alternatives twin}
for s in $steps; do
    case $s in
        source|cxx|posix|tblgen|configure|support|clang|lld|gate|alternatives|twin) "step_$s" ;;
        *) die "unknown step $s" ;;
    esac
done
