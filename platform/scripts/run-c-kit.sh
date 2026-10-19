#!/bin/sh
# The C kit's qualification: host checks, every kit program built and
# ELF/map-checked, every embedded-route case booted through the kernel's
# external-test with the Linux reference build's output as the expected
# bytes, then (Task 12) the shell-route matrix.
# A program listed in c/tests/kit/divergences.txt must differ from Linux:
# its ABSD output is pinned in c/tests/kit/absd-expected/<program>.out and
# the boot must match that exactly (status 0 and reclamation still enforced).
# ABSD_SKIP_BUILD=1 reuses build-c-kit.sh output; a kit without a
# kit/BUILT-FROM stamp, or whose stamp names another commit or other archive
# hashes, is refused (rebuild it). ABSD_C_GCC=1 adds a second
# pass that builds every program with gcc under the kit's link line and
# boots the embedded cases again. ABSD_CKIT_BUILD (default
# <campaign>/ckit-build) is the kit build directory, as for build-c-kit.sh.
set -eu
# Symbol ordering is part of the retained .demand reports (sort/comm):
# byte order on every host, as scripts/build-cports.sh does.
export LC_ALL=C
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
python3 -B "$root/scripts/test-c-kit-confirmation.py"
camp=$(dirname "$root")
kernel=${ABSD_KERNEL_RUN:?set ABSD_KERNEL_RUN to a disposable kernel clone}
[ -d "$kernel" ] || { echo "run-c-kit: ABSD_KERNEL_RUN $kernel is not a directory" >&2; exit 1; }
forbidden=/data/git/absd-kernel
[ -d "$forbidden" ] && forbidden=$(CDPATH= cd -- "$forbidden" && pwd -P)
[ "$(CDPATH= cd -- "$kernel" && pwd -P)" != "$forbidden" ] ||
    { echo "run-c-kit: ABSD_KERNEL_RUN must not be /data/git/absd-kernel" >&2; exit 1; }
ckit=${ABSD_CKIT_BUILD:-$camp/ckit-build}
export ABSD_CKIT_BUILD=$ckit    # build-c-kit.sh builds into the same directory
kit=$ckit/kit
work=$ckit/tests
# external-test's own QEMU line has no -cpu; the runtime and getentropy need RDRAND.
qemu="qemu-system-x86_64 -cpu max,vendor=GenuineIntel,+rdrand"
# Reproducibility: two clean kit builds (the runtime's cargo target, the C
# objects and kit/ removed between them; Picolibc is pinned and not rebuilt),
# each followed by a clang build of every kit program; the archives, crt0.o
# and every program ELF must hash identically.
tests=$root/c/tests/kit
if [ "${ABSD_SKIP_BUILD:-0}" != 1 ]; then
    repro=$ckit/repro
    rm -rf "$repro"; mkdir -p "$repro"
    repro_programs=$(grep -v '^#' "$tests/cases.tsv" | grep -v '^[[:space:]]*$' | grep -v '^native' | cut -f2 | sort -u)
    for round in 1 2; do
        rm -rf "$ckit/absd-c" "$ckit/kit" "$ckit/cb"
        rm -f "$ckit/"*.o
        "$root/scripts/build-c-kit.sh"
        bin=$ckit/tests/absd; rm -rf "$ckit/tests"; mkdir -p "$bin"
        for program in $repro_programs; do
            "$kit/bin/absd-cc" -c -o "$bin/$program.o" "$tests/$program.c"
            "$kit/bin/absd-cc" -o "$bin/$program" "$bin/$program.o"
        done
        (cd "$ckit" && sha256sum kit/lib/libabs.a kit/lib/libabs_builtins.a kit/lib/crt0.o \
            $(for program in $repro_programs; do printf 'tests/absd/%s ' "$program"; done)) > "$repro/round$round.sha256"
    done
    if ! cmp -s "$repro/round1.sha256" "$repro/round2.sha256"; then
        diff "$repro/round1.sha256" "$repro/round2.sha256" || true
        echo "run-c-kit: the two clean kit builds differ" >&2; exit 1
    fi
    libabs=$(awk '$2 == "kit/lib/libabs.a" { print $1 }' "$repro/round2.sha256")
    printf '%s\n' "ABSD C KIT REPRODUCIBLE OK builds=2 libabs=$libabs programs=$(echo $repro_programs | wc -w)"
fi
# The kit must be this tree's: its BUILT-FROM stamp names this commit and
# the hashes of the archives it holds.
stamp=$kit/BUILT-FROM
[ -f "$stamp" ] || { echo "run-c-kit: $stamp missing: rebuild the kit with scripts/build-c-kit.sh" >&2; exit 1; }
built=$(awk '$1 == "commit" { print $2 }' "$stamp")
head=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo none)
[ "$built" = "$head" ] ||
    { echo "run-c-kit: the kit in $kit was built from $built, this tree is $head: rebuild it" >&2; exit 1; }
awk '$1 ~ /^lib\// { print $2 "  " $1 }' "$stamp" | (cd "$kit" && sha256sum -c --quiet) ||
    { echo "run-c-kit: the kit's archives differ from $stamp" >&2; exit 1; }
printf '%s\n' "C KIT BUILT-FROM OK commit=$built dirty=$(awk '$1 == "dirty" { print $2 }' "$stamp")"
sh "$root/scripts/check-c-kit-host.sh"
python3 -I "$root/scripts/check-c-headers.py" "$root"
rm -rf "$work"; mkdir -p "$work/linux"
# Self-checks of the toolchain guards: the ELF checker must refuse an
# unresolved weak reference, and absd-cc must emit stack-clash probes.
self=$work/selfcheck; mkdir -p "$self"
printf '%s\n' 'extern void missing(void) __attribute__((weak)); int main(void){missing(); return 0;}' > "$self/weak.c"
"$kit/bin/absd-cc" -o "$self/weak" "$self/weak.c"
if python3 -I "$root/scripts/check-c-elf.py" "$self/weak" --map "$self/weak.map" > "$self/weak.check"; then
    cat "$self/weak.check"; echo "run-c-kit: check-c-elf.py accepted an unresolved weak reference" >&2; exit 1
fi
grep -q 'undefined symbol missing (weak)' "$self/weak.check"
# ... and a Picolibc libos fallback, naming the member.
printf '%s\n' '#include <signal.h>' 'int main(void){ return signal(SIGINT, SIG_IGN) == SIG_ERR; }' > "$self/libos.c"
"$kit/bin/absd-cc" -o "$self/libos" "$self/libos.c"
if python3 -I "$root/scripts/check-c-elf.py" "$self/libos" --map "$self/libos.map" > "$self/libos.check"; then
    cat "$self/libos.check"; echo "run-c-kit: check-c-elf.py accepted a Picolibc libos fallback" >&2; exit 1
fi
grep -q 'libos fallback libos_fallback_signal.c.o pulled' "$self/libos.check"
# ... while strerror and perror link and pass (R13): Picolibc's weak
# _user_strerror hook resolves to the kit's definition, not to nothing.
printf '%s\n' '#include <stdio.h>' '#include <string.h>' 'int main(void){ perror("p"); return printf("%s\n", strerror(2)) < 0; }' > "$self/errmsg.c"
"$kit/bin/absd-cc" -o "$self/errmsg" "$self/errmsg.c"
python3 -I "$root/scripts/check-c-elf.py" "$self/errmsg" --map "$self/errmsg.map" > "$self/errmsg.check" ||
    { cat "$self/errmsg.check"; echo "run-c-kit: check-c-elf.py refused a strerror/perror program" >&2; exit 1; }
grep -q 'libabs.a(strerror_hook.o):(.ltext._user_strerror)' "$self/errmsg.map" ||
    { echo "run-c-kit: _user_strerror did not come from libabs.a(strerror_hook.o)" >&2; exit 1; }
# A program whose stdio never names stdout (perror only; files only) keeps
# bufio.c's guarded weak `stdout` undefined, which the check admits beside
# `stdin` (R13 F1); the weak `missing` above shows any other name refused.
printf '%s\n' '#include <stdio.h>' '#include <errno.h>' 'int main(void){ errno = ENOENT; perror("p"); return 0; }' > "$self/perroronly.c"
printf '%s\n' '#include <stdio.h>' 'int main(void){ FILE *f = fopen("x", "w"); if (!f) return 1; fputs("a\n", f); return fclose(f) != 0; }' > "$self/fileonly.c"
for p in perroronly fileonly; do
    "$kit/bin/absd-cc" -o "$self/$p" "$self/$p.c"
    llvm-nm-18 -u "$self/$p" | grep -q ' w stdout$' ||
        { echo "run-c-kit: $p does not carry the weak stdout it is meant to test" >&2; exit 1; }
    python3 -I "$root/scripts/check-c-elf.py" "$self/$p" --map "$self/$p.map" > "$self/$p.check" ||
        { cat "$self/$p.check"; echo "run-c-kit: check-c-elf.py refused $p (weak stdout)" >&2; exit 1; }
done
printf '%s\n' 'void g(char *); void f(void) { char b[70000]; g(b); }' > "$self/frame.c"
"$kit/bin/absd-cc" -c -o "$self/frame.o" "$self/frame.c"
llvm-objdump-18 -d "$self/frame.o" | grep -Eq 'sub[q]?[[:space:]]+\$0x1000,[[:space:]]*%rsp' ||
    { echo "run-c-kit: absd-cc emitted no stack-clash probe loop" >&2; exit 1; }
echo "C KIT SELF-CHECKS OK"
tab=$(printf '\t')
tests=$root/c/tests/kit
# Kit-program cases only: a `native` row names a platform command (the matrix's).
cases() { grep -v '^#' "$tests/cases.tsv" | grep -v '^[[:space:]]*$' | grep -v "^native${tab}"; }
embedded=$(cases | grep -vc "^shell${tab}" || true)
[ "$embedded" -ge 1 ] || { echo "run-c-kit: cases.tsv has no embedded case" >&2; exit 1; }
programs=$(cases | cut -f2 | sort -u)
builtins=$("${ABSD_CLANG:-clang-18}" -print-resource-dir)/lib/linux/libclang_rt.builtins-x86_64.a   # absd-cc's

# gcc under the kit's flags and absd-cc's link line (the clang builtins
# archive, not libgcc: the Stage 0 verdict). Ubuntu's gcc defines
# _FORTIFY_SOURCE by default, which would pull Picolibc's __*_chk members;
# -U_FORTIFY_SOURCE keeps the gcc build's demand equal to clang's, and the
# map check refuses any *_chk symbol.
gcc_compile() {
    gcc -std=gnu11 -O2 -U_FORTIFY_SOURCE -ffreestanding -nostdinc -nostdlib -mcmodel=large -fno-pic -fno-pie -fno-stack-protector \
        -mno-avx -march=x86-64 -fcf-protection=none -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections \
        -fstack-clash-protection -isystem "$kit/include" -isystem "$(gcc -print-file-name=include)" -c -o "$2" "$1"
}
gcc_link() {
    ld.lld-17 -static -no-pie --gc-sections -T "$kit/absd-c.ld" -Map="$2.map" -o "$2" \
        "$kit/lib/crt0.o" "$1" --start-group "$kit/lib/libabs.a" "$kit/lib/libc.a" "$kit/lib/libm.a" \
        "$kit/lib/libabs_builtins.a" "$builtins" --end-group
}

# Build every program (embedded or not) with one compiler, ELF- and
# map-check it, and record its undefined-symbol demand before the link.
build_all() {
    compiler=$1 dir=$work/$1
    mkdir -p "$dir"
    for program in $programs; do
        src=$tests/$program.c
        if [ "$compiler" = clang ]; then
            "$kit/bin/absd-cc" -c -o "$dir/$program.o" "$src"
            "$kit/bin/absd-cc" -o "$dir/$program" "$dir/$program.o"
        else
            gcc_compile "$src" "$dir/$program.o"
            gcc_link "$dir/$program.o" "$dir/$program"
        fi
        llvm-nm-18 -u "$dir/$program.o" | awk '{print $NF}' | sort > "$dir/$program.demand"
        python3 -I "$root/scripts/check-c-elf.py" "$dir/$program" --map "$dir/$program.map" ||
            { echo "run-c-kit: $compiler $program refused by the ELF/map check" >&2; exit 1; }
    done
}

# Boot every embedded case of one pass. Linux references live in $work/linux.
run_embedded() {
    compiler=$1 dir=$work/$1 marker=embedded
    [ "$compiler" = gcc ] && marker=embedded-gcc
    cases | grep -v "^shell${tab}" | while IFS="$tab" read -r route program stdin args; do
        id=$program; [ "$stdin" = - ] || id=$program.${stdin%.*}
        input=$work/$id.input expected=$work/$id.expected
        reason=$(awk -F "$tab" -v p="$program" '$1 == p { print $2 }' "$tests/divergences.txt")
        boot_expected=$expected
        if [ -n "$reason" ]; then
            boot_expected=$tests/absd-expected/$program.out
            if ! [ -f "$boot_expected" ]; then
                boot_expected=$dir/$id.unpinned; : > "$boot_expected"
            elif cmp -s "$boot_expected" "$expected"; then
                echo "run-c-kit: $program is listed as diverging but its pinned ABSD output equals Linux" >&2; exit 1
            fi
        fi
        started=$(date +%s)
        nice -n 10 make --no-print-directory -C "$kernel" external-test QEMU="$qemu" EXTERNAL_USER_ELF="$dir/$program" \
            EXTERNAL_INPUT="$input" EXTERNAL_EXPECTED="$boot_expected" >"$dir/$id.boot.log" 2>&1 ||
            { cat "$dir/$id.boot.log"; cp "$kernel/build/external.serial.log" "$dir/$id.serial.log" 2>/dev/null || true
              python3 -I "$kernel/scripts/check-external-output.py" --print "$dir/$id.serial.log" > "$dir/$id.absd.out" 2>/dev/null || true
              [ -n "$reason" ] && ! [ -f "$tests/absd-expected/$program.out" ] &&
                  echo "run-c-kit: no pinned ABSD output for diverging $program; review $dir/$id.absd.out and pin it as $tests/absd-expected/$program.out" >&2
              echo "run-c-kit: $compiler $id failed on the embedded route" >&2; exit 1; }
        cp "$kernel/build/external.serial.log" "$dir/$id.serial.log"
        grep -qx 'EXTERNAL status=0 frames=0 processes=0 cells=0 pipes=0' "$dir/$id.serial.log"
        echo "$id $(( $(date +%s) - started ))" >> "$dir/boot-seconds"
        if [ -n "$reason" ]; then
            echo "C KIT DIVERGES $program :: $reason"
        else
            echo "C KIT CASE OK $marker $id"
        fi
    done
}

# Linux references: the same sources, built natively, run as the embedded
# route runs them.
for program in $programs; do
    gcc -std=gnu11 -O2 -Wall -o "$work/linux/$program" "$tests/$program.c"
done
cases | grep -v "^shell${tab}" | while IFS="$tab" read -r route program stdin args; do
    id=$program; [ "$stdin" = - ] || id=$program.${stdin%.*}
    input=$work/$id.input
    if [ "$stdin" = - ]; then : > "$input"; else cp "$tests/inputs/$stdin" "$input"; fi
    # The embedded route has no startup record: argv is [absd-std-probe],
    # stderr shares the console, so the reference merges 2>&1 and runs with
    # argv[0] = absd-std-probe and an empty environment.
    # A zero exit is the embedded harness's precondition (it checks status=0).
    (cd "$work" && env -i bash -c "exec -a absd-std-probe '$work/linux/$program' < '$input' > '$work/$id.expected' 2>&1") ||
        { echo "run-c-kit: the Linux reference of $program exited non-zero" >&2; exit 1; }
done

build_all clang
echo "C KIT BUILD OK clang programs=$(echo $programs | wc -w)"
run_embedded clang
printf '%s\n' "ABSD C KIT EMBEDDED OK cases=$embedded"
if [ "${ABSD_C_GCC:-0}" = 1 ]; then
    build_all gcc
    echo "C KIT BUILD OK gcc programs=$(echo $programs | wc -w)"
    run_embedded gcc
    printf '%s\n' "ABSD C KIT EMBEDDED GCC OK cases=$embedded"
fi

# The shell route (scripts/c-kit-matrix.py): one `net fsd` boot, each
# shell/both case as absd-sh's child in its own SSH exec session, compared
# with the Linux build; resources and startup-record vectors checked.
for file in sshd.elf absd-fsd.elf fixture-import.elf sshtest.elf fsd-probe.elf commands/absd-sh manpages/whatis \
        commands/head commands/df commands/sysinfo; do
    test -f "$root/$file" || { echo "run-c-kit: $file missing: run prepare-and-build.sh and build-ssh.sh" >&2; exit 1; }
done
work_shell=$ckit/shell-work
rm -rf "$work_shell" "$work_shell.log"; mkdir -p "$work_shell"
nice -n 10 python3 "$root/scripts/c-kit-matrix.py" --work "$work_shell" --kernel "$kernel" --shell "$root/commands/absd-sh" \
    --qemu "$qemu" --kit "$tests" --absd "$work/clang" --linux "$work/linux" --vectors "$root/c/vectors/startup" \
    > "$work_shell.log" 2>&1 || { grep -v '^  ok ' "$work_shell.log"; echo "run-c-kit: the shell-route matrix failed" >&2; exit 1; }
grep '^C KIT ' "$work_shell.log"
grep -q '^C KIT MATRIX OK' "$work_shell.log" || { echo "run-c-kit: no C KIT MATRIX OK" >&2; exit 1; }
shell=$(sed -n 's/^C KIT SHELL OK cases=\([0-9]*\).*/\1/p' "$work_shell.log")
defects=$(sed -n 's/^C KIT SHELL OK .*defects=\([0-9]*\).*/\1/p' "$work_shell.log")
printf '%s\n' "ABSD C KIT OK embedded=$embedded shell=$shell shell_defects=$defects"
