#!/bin/sh
# Stage-0 link-form probe: hello built with clang and with gcc, linked by
# ld.lld-17 at the image window with Picolibc's libc.a (which carries libm;
# the installed libm.a is an empty stub) and the builtins.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
camp=$(dirname "$root")
pico=$camp/picolibc/install
out=$camp/stage0; mkdir -p "$out"
flags="-ffreestanding -nostdinc -nostdlib -mcmodel=large -fno-pic -fno-pie -fno-stack-protector -mno-avx -march=x86-64 -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -O2 -isystem $pico/include"
builtins=$(clang -print-resource-dir)/lib/linux/libclang_rt.builtins-x86_64.a

clang --target=x86_64-unknown-none-elf $flags -isystem "$(clang -print-resource-dir)/include" -c "$root/c/tests/stage0/hello.c" -o "$out/hello-clang.o"
ld.lld-17 -static -no-pie --gc-sections -T "$root/c/absd-c.ld" -o "$out/hello-clang" "$out/hello-clang.o" "$pico/lib/libc.a" "$builtins"

gcc $flags -fcf-protection=none -c "$root/c/tests/stage0/hello.c" -o "$out/hello-gcc.o"
ld.lld-17 -static -no-pie --gc-sections -T "$root/c/absd-c.ld" -o "$out/hello-gcc" "$out/hello-gcc.o" "$pico/lib/libc.a" /usr/lib/gcc/x86_64-linux-gnu/13/libgcc.a

for elf in hello-clang hello-gcc; do python3 -I "$root/scripts/check-c-elf.py" "$out/$elf"; done
printf 'hello from C on ABSD\n' > "$out/expected.txt"
: > "$out/input.txt"
