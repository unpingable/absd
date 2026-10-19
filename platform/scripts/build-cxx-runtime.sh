#!/bin/sh
# Build the C++0 runtime: libc++abi and libc++ from the pinned LLVM source
# (cxx/PIN, staged by scripts/stage-llvm.sh) for x86_64-unknown-none-elf
# against the C kit's Picolibc headers, static only, -Oz, under the kit's own
# compile flags (the cflags line of the kit's bin/absd-cc, read, not
# restated; C++ units take -fno-builtin in place of -ffreestanding, below); libc++ is compiled -fno-exceptions -fno-rtti, libc++abi
# -fno-exceptions with RTTI (it implements type_info and dynamic_cast, and
# refuses to compile without it; a program built -fno-rtti pulls none of
# it). The options add those flags themselves. Single-task profile: threads,
# exceptions, RTTI, localization (iostream), filesystem, random_device, the
# monotonic clock, wide characters and the time-zone database are off;
# libc++abi uses its no-threads static guard and its own operator new/delete
# over the kit's malloc/aligned_alloc, so nothing is stubbed (cxx/README.md).
# Output, outside the repository in $ABSD_CXX_BUILD (default
# $camp/cxx-build, replaced on every run except work/ which is reused):
#   lib/libc++.a lib/libc++abi.a   the archives absd-c++ links
#   include/c++/v1/                the headers (with the generated __config_site)
#   bin/absd-c++                   a copy of cxx/bin/absd-c++
#   BUILT-FROM                     source commit, pin, toolchain, kit, hashes
#   cmake-cache.txt                the CMake cache of the build
# The kit is $ABSD_CKIT (default $camp/ckit-build/kit; scripts/build-c-kit.sh).
# ABSD_CXX_PROFILE selects the configuration: c++0 (the default, above) or
# llvm, the runtime the LLVM build links (scripts/build-llvm-kit.sh): the
# same, except that libc++ is built
#   - with its external thread API answered by
#     cxx/glue/libcxx/__external_threading (single-task bookkeeping: no
#     thread is ever created, a self-deadlock is refused), because LLVM
#     holds std::mutex and std::call_once whatever LLVM_ENABLE_THREADS says;
#   - with the monotonic clock libc++ then requires, for which the kit has
#     no clock_gettime: steady_clock over the kit's times() ticks
#     (cxx/patches/llvm/0001);
#   - with wide characters and localization (std::wstring in LLVM Support,
#     std::stringstream in some 25 LLVM and Clang files), over Picolibc's
#     C-locale *_l functions, and regex's class masks fixed for Picolibc's
#     signed char ctype mask (cxx/patches/llvm/0002);
# from the patched source in $ABSD_LLVM_SRC. libc++abi keeps its no-threads
# guard. Filesystem, random_device and exceptions stay off. Default output
# $camp/llvm-build/cxx.
# Every compile runs under nice -n 19 with at most $ABSD_CXX_JOBS (default 4)
# jobs; the build waits while the 1-minute load average exceeds
# $ABSD_CXX_MAX_LOAD (default 8).
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
camp=$(dirname "$root")
kit=${ABSD_CKIT:-$camp/ckit-build/kit}
profile=${ABSD_CXX_PROFILE:-c++0}
case $profile in
    c++0) out=${ABSD_CXX_BUILD:-$camp/cxx-build} ;;
    llvm) out=${ABSD_CXX_BUILD:-$camp/llvm-build/cxx} ;;
    *) echo "build-cxx-runtime: ABSD_CXX_PROFILE=$profile: c++0 or llvm" >&2; exit 1 ;;
esac
up=${ABSD_LLVM_UPSTREAM:-$camp/upstream}
jobs=${ABSD_CXX_JOBS:-4}
max_load=${ABSD_CXX_MAX_LOAD:-8}
die() { echo "build-cxx-runtime: $*" >&2; exit 1; }
[ "$jobs" -le 4 ] 2>/dev/null || die "ABSD_CXX_JOBS=$jobs: at most 4"

version=$(grep -v '^#' "$root/cxx/PIN" | awk -F'\t' 'NF == 6 { print $2 }')
commit=$(grep -v '^#' "$root/cxx/PIN" | awk -F'\t' 'NF == 6 { print $3 }')
sha=$(grep -v '^#' "$root/cxx/PIN" | awk -F'\t' 'NF == 6 { print $5 }')
src=$up/llvm-project/src/llvm-project-$version.src
if [ "$profile" = llvm ]; then
    src=${ABSD_LLVM_SRC:-$camp/llvm-build/src}
    grep -q '_LIBCPP_ABSD_KIT' "$src/libcxx/src/chrono.cpp" ||
        die "$src is not the patched LLVM source (cxx/patches/llvm; scripts/build-llvm-kit.sh prepares it)"
fi
[ -f "$src/runtimes/CMakeLists.txt" ] || die "$src is not staged: run scripts/stage-llvm.sh"
cmp -s "$src/LICENSE.TXT" "$root/cxx/llvm-project.LICENSE" || die "$src/LICENSE.TXT is not the pinned licence"
[ -x "$kit/bin/absd-cc" ] && [ -f "$kit/BUILT-FROM" ] && [ -f "$kit/include/picolibc.h" ] ||
    die "$kit is not a built C kit (ABSD_CKIT; scripts/build-c-kit.sh)"

clang_version=$(clang-18 -dumpversion) || die "clang-18 not found"
[ "${clang_version%%.*}" = 18 ] || die "clang-18 is clang $clang_version"
resource=$(clang-18 -print-resource-dir)
# The kit's compile flags, exactly as its driver states them.
kit_cflags=$(sed -n 's/^cflags="\(.*\)"$/\1/p' "$kit/bin/absd-cc")
[ -n "$kit_cflags" ] || die "no cflags line in $kit/bin/absd-cc"
case $kit_cflags in
    *'-isystem $kit/include -isystem $clang_include') ;;
    *) die "the kit's cflags no longer end in its two -isystem directories: $kit_cflags" ;;
esac
cflags=$(printf '%s' "$kit_cflags" | sed "s|\\\$kit|$kit|; s|\\\$clang_include|$resource/include|")
# C++ translation units are hosted: under -ffreestanding clang gives C++
# no special main (it would be mangled _Z4mainv) and libc++ is the hosted
# library. -fno-builtin keeps what -ffreestanding meant for code generation
# (no assumption about the C library's functions); every other flag is the
# kit's. absd-c++ makes the same substitution.
case " $cflags " in *" -ffreestanding "*) ;; *) die "the kit's cflags no longer carry -ffreestanding" ;; esac
cxx_base=$(printf '%s' "$cflags" | sed 's/ -ffreestanding / -fno-builtin /')
threads="-DLIBCXX_ENABLE_THREADS=OFF -DLIBCXX_ENABLE_MONOTONIC_CLOCK=OFF"
wide=OFF
localization=OFF
if [ "$profile" = llvm ]; then
    # -std=c++23 is strict ISO, under which Picolibc hides its POSIX and
    # GNU declarations (strerror_r, which libc++ calls once threads are on;
    # strtod_l and the other *_l functions of its locale support, which
    # Picolibc declares under _GNU_SOURCE, as clang++ predefines it for a
    # glibc target).
    cxx_base="$cxx_base -D_LIBCPP_ABSD_KIT -D_GNU_SOURCE -isystem $root/cxx/glue/libcxx"
    threads="-DLIBCXX_ENABLE_THREADS=ON -DLIBCXX_HAS_EXTERNAL_THREAD_API=ON -DLIBCXX_ENABLE_MONOTONIC_CLOCK=ON"
    # LLVM's Support headers name std::wstring (ConvertUTF.h), and some
    # 25 LLVM and Clang files use std::stringstream; Picolibc has the
    # wide-character and *_l locale functions libc++ needs for both (its
    # locales are the C locale's; setlocale is the kit's, R14).
    wide=ON
    localization=ON
fi

wait_load() {
    while :; do
        load=$(cut -d' ' -f1 /proc/loadavg)
        awk -v l="$load" -v m="$max_load" 'BEGIN { exit !(l > m) }' || return 0
        echo "build-cxx-runtime: 1-minute load $load exceeds $max_load; waiting" >&2
        sleep 60
    done
}

[ -n "$out" ] && [ "$out" != / ] || die "ABSD_CXX_BUILD is empty or /"
work=$out/work
mkdir -p "$out"
rm -rf "${out:?}/lib" "${out:?}/include" "${out:?}/bin" "${out:?}/BUILT-FROM" "${out:?}/cmake-cache.txt" "${out:?}/work"
mkdir -p "$work"
# Paths of the source and build directories are remapped so the archives do
# not depend on where either lives (__FILE__ in assertion texts).
prefix_map="-ffile-prefix-map=$src=/llvm-project-$version -ffile-prefix-map=$work=/cxx-build"
c_flags="$cflags $prefix_map"
cxx_flags="$cxx_base $prefix_map"

wait_load
start=$(date +%s)
nice -n 19 cmake -G Ninja -S "$src/runtimes" -B "$work" \
    -DCMAKE_TOOLCHAIN_FILE="$root/cxx/absd-toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_C_FLAGS="$c_flags" -DCMAKE_CXX_FLAGS="$cxx_flags" -DCMAKE_ASM_FLAGS="$c_flags" \
    -DCMAKE_C_FLAGS_MINSIZEREL="-Oz -DNDEBUG" -DCMAKE_CXX_FLAGS_MINSIZEREL="-Oz -DNDEBUG" \
    -DCMAKE_INSTALL_PREFIX="$out" \
    -DLLVM_ENABLE_RUNTIMES="libcxxabi;libcxx" \
    -DLLVM_ENABLE_PER_TARGET_RUNTIME_DIR=OFF \
    -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_DOCS=OFF \
    -DLIBCXX_ENABLE_SHARED=OFF -DLIBCXX_ENABLE_STATIC=ON \
    -DLIBCXX_ENABLE_EXCEPTIONS=OFF -DLIBCXX_ENABLE_RTTI=OFF \
    $threads \
    -DLIBCXX_ENABLE_LOCALIZATION=$localization -DLIBCXX_ENABLE_FILESYSTEM=OFF \
    -DLIBCXX_ENABLE_RANDOM_DEVICE=OFF -DLIBCXX_ENABLE_WIDE_CHARACTERS=$wide \
    -DLIBCXX_ENABLE_TIME_ZONE_DATABASE=OFF \
    -DLIBCXX_ENABLE_VENDOR_AVAILABILITY_ANNOTATIONS=OFF \
    -DLIBCXX_INCLUDE_TESTS=OFF -DLIBCXX_INCLUDE_BENCHMARKS=OFF -DLIBCXX_INCLUDE_DOCS=OFF \
    -DLIBCXX_USE_COMPILER_RT=ON -DLIBCXX_CXX_ABI=libcxxabi \
    -DLIBCXX_ENABLE_STATIC_ABI_LIBRARY=OFF -DLIBCXX_ENABLE_ABI_LINKER_SCRIPT=OFF \
    -DLIBCXX_HARDENING_MODE=none \
    -DLIBCXXABI_ENABLE_SHARED=OFF -DLIBCXXABI_ENABLE_STATIC=ON \
    -DLIBCXXABI_ENABLE_EXCEPTIONS=OFF -DLIBCXXABI_ENABLE_THREADS=OFF \
    -DLIBCXXABI_BAREMETAL=ON -DLIBCXXABI_USE_LLVM_UNWINDER=OFF -DLIBCXXABI_USE_COMPILER_RT=ON \
    -DLIBCXXABI_ENABLE_ASSERTIONS=OFF -DLIBCXXABI_INCLUDE_TESTS=OFF \
    -DLIBCXXABI_ENABLE_NEW_DELETE_DEFINITIONS=ON \
    -DLIBCXX_HAS_PTHREAD_LIB=NO -DLIBCXX_HAS_RT_LIB=NO -DLIBCXX_HAS_ATOMIC_LIB=NO \
    -DLIBCXXABI_HAS_PTHREAD_LIB=NO -DLIBCXXABI_HAS_DL_LIB=NO -DLIBCXXABI_HAS_CXA_THREAD_ATEXIT_IMPL=NO \
    > "$out/configure.log" 2>&1 || { tail -40 "$out/configure.log"; die "cmake configure failed (log $out/configure.log)"; }
wait_load
nice -n 19 ninja -C "$work" -j "$jobs" cxx cxxabi > "$out/build.log" 2>&1 ||
    { tail -40 "$out/build.log"; die "ninja failed (log $out/build.log)"; }
wait_load
nice -n 19 ninja -C "$work" -j "$jobs" install-cxx install-cxxabi \
    > "$out/install.log" 2>&1 || { tail -40 "$out/install.log"; die "install failed (log $out/install.log)"; }
end=$(date +%s)
for f in lib/libc++.a lib/libc++abi.a include/c++/v1/__config_site include/c++/v1/vector include/c++/v1/cxxabi.h; do
    [ -f "$out/$f" ] || die "$out/$f was not installed"
done
# The single-task profile, as configured (the generated __config_site).
want_site="_LIBCPP_HAS_NO_THREADS _LIBCPP_HAS_NO_LOCALIZATION _LIBCPP_HAS_NO_FILESYSTEM _LIBCPP_HAS_NO_RANDOM_DEVICE _LIBCPP_HAS_NO_MONOTONIC_CLOCK _LIBCPP_HAS_NO_WIDE_CHARACTERS"
if [ "$profile" = llvm ]; then
    want_site="_LIBCPP_HAS_THREAD_API_EXTERNAL _LIBCPP_HAS_NO_FILESYSTEM _LIBCPP_HAS_NO_RANDOM_DEVICE"
    ! grep -q '^#define _LIBCPP_HAS_NO_THREADS$' "$out/include/c++/v1/__config_site" || die "__config_site defines _LIBCPP_HAS_NO_THREADS"
    cp "$root/cxx/glue/libcxx/__external_threading" "$out/include/c++/v1/__external_threading"
fi
for m in $want_site; do
    grep -q "^#define $m\$" "$out/include/c++/v1/__config_site" || die "__config_site does not define $m"
done
# No member may name a library for the linker to add (.deplibs, from
# `#pragma comment(lib, ...)`): there is no librt, libpthread or libatomic.
# The library probes above are answered NO because CMake's probe only
# compiles (CMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY) and says yes to all.
for a in libc++.a libc++abi.a; do
    ! llvm-readelf-18 -SW "$out/lib/$a" | grep -q '\.deplibs' || die "$a carries a .deplibs section"
done
cp "$work/CMakeCache.txt" "$out/cmake-cache.txt"
mkdir -p "$out/bin"; cp "$root/cxx/bin/absd-c++" "$out/bin/absd-c++"; chmod 755 "$out/bin/absd-c++"

dirty=no; [ -z "$(git -C "$root" status --porcelain -- cxx scripts/build-cxx-runtime.sh scripts/stage-llvm.sh)" ] || dirty=yes
{ printf 'commit %s\n' "$(git -C "$root" rev-parse HEAD)"
  printf 'dirty %s\n' "$dirty"
  [ "$profile" = c++0 ] || printf 'profile %s source=%s\n' "$profile" "$src"
  printf 'llvm-project %s commit=%s sha256=%s\n' "$version" "$commit" "$sha"
  printf 'clang %s\n' "$(clang-18 --version | head -n 1)"
  printf 'cmake %s\n' "$(cmake --version | head -n 1)"
  printf 'ninja %s\n' "$(ninja --version)"
  printf 'kit %s\n' "$kit"
  printf 'kit-commit %s\n' "$(sed -n 's/^commit //p' "$kit/BUILT-FROM")"
  for f in lib/libc.a lib/libabs.a lib/crt0.o; do
      printf 'kit-%s %s\n' "$f" "$(sha256sum "$kit/$f" | cut -d' ' -f1)"
  done
  printf 'cflags %s -Oz\n' "$cflags"
  printf 'cxxflags %s -Oz (libc++ -fno-exceptions -fno-rtti, libc++abi -fno-exceptions)\n' "$cxx_base"
  printf 'build-seconds %s jobs %s\n' "$((end - start))" "$jobs"
  for f in lib/libc++.a lib/libc++abi.a; do
      printf '%s %s bytes=%s\n' "$f" "$(sha256sum "$out/$f" | cut -d' ' -f1)" "$(stat -c %s "$out/$f")"
  done
  printf 'headers %s\n' "$(cd "$out/include/c++/v1" && find . -type f | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -d' ' -f1)"
} > "$out/BUILT-FROM"
echo "CXX RUNTIME OK libc++.a=$(stat -c %s "$out/lib/libc++.a") libc++abi.a=$(stat -c %s "$out/lib/libc++abi.a") seconds=$((end - start)) out=$out"
