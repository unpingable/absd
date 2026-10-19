#!/bin/sh
# Builds the LLVM runtime profile's probes (cxx/README.md, "The C++ runtime,
# LLVM profile") with absd-c++ against $ABSD_CXX_BUILD (default
# llvm-build/cxx beside the repository), gates each with
# scripts/check-c-elf.py and prints what the guest must show. The probes are
# ABSD programs: the host cannot run them (the Linux twin links libstdc++,
# not this libc++), so the run is the steward's.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
camp=$(dirname "$root")
cxx=${ABSD_CXX_BUILD:-$camp/llvm-build/cxx}
out=${ABSD_LLVM_PROFILE_TESTS:-$camp/llvm-build/profile-tests}
[ -f "$cxx/include/c++/v1/__external_threading" ] || { echo "check-llvm-profile: $cxx is not the LLVM runtime profile" >&2; exit 1; }
mkdir -p "$out"
for t in ok relock call_once_reentry condvar_wait sp_mut_nested rs_nested; do
    # -D_GNU_SOURCE: the profile's <locale> calls Picolibc's *_l functions,
    # declared only under it (LLVM is built with it too). random_shuffle
    # left C++17; the probes name it to reach random_shuffle.cpp's lock.
    ABSD_CXX_BUILD=$cxx sh "$cxx/bin/absd-c++" -O2 -D_GNU_SOURCE -D_LIBCPP_ENABLE_CXX17_REMOVED_RANDOM_SHUFFLE \
        -o "$out/$t" "$root/cxx/tests/llvm-profile/$t.cpp"
    python3 "$root/scripts/check-c-elf.py" "$out/$t" --map "$out/$t.map"
    # The would-wait probes must carry the abort message (the glue's text).
    case $t in
        ok) ;;
        *) grep -q 'would wait for another task' "$out/$t" || { echo "check-llvm-profile: $t lacks the abort message" >&2; exit 1; } ;;
    esac
    printf 'LLVM PROFILE PROBE %s sha256=%s expect=%s\n' "$t" "$(sha256sum "$out/$t" | cut -d' ' -f1)" \
        "$([ "$t" = ok ] && echo 'status 0, stdout = ok.expected' || echo 'status 134, first stdout line, stderr: libc++ (ABSD, one task per process): ... would wait for another task')"
done
