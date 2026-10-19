#!/bin/sh
# Public snapshot: the omitted TinyCC stage is never a passing test.
printf '%s\n' 'TCC STAGE NOT_RUN: not included in the public source' >&2
exit 78
# Host-only receipt for the unpatched init/fini finding (scout R2, STAGE3.md
# section 3): c/tests/kit/exit.c built with -g (tcc writes no .symtab
# without it) by tcc-build/hostcfg-unpatched/tcc and by tcc-build/hostcfg/tcc
# against the share tree; for each, the .preinit_array/.init_array/
# .fini_array sections (readelf -S) and the array bound symbols (nm). Run by
# scripts/build-tcc.sh after the host half; runnable alone on existing
# builds. Writes tcc-build/unpatched-init-fini.txt (no host path in it) and
# fails unless the unpatched image has more than one array section and an
# undefined __bothinit_array_* and the patched one has exactly .init_array
# and .fini_array with both __bothinit_array_* defined.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
out=$(dirname "$root")/tcc-build
share=$out/share/absd-c
obj=$out/obj
mkdir -p "$obj"
cd "$root"
receipt=$out/unpatched-init-fini.txt
sections() { readelf -S -W "$1" | sed -n 's/^ *\[ *[0-9]*\] *//p' | awk '$1 ~ /^\.(preinit|init|fini)_array/'; }
symbols() { nm "$1" | awk '$NF ~ /^__(bothinit|preinit|init|fini)_array_(start|end)$/' | sort -k3; }
{
    echo "# tcc-build/unpatched-init-fini.txt: written by scripts/tcc-unpatched-arrays.sh"
    echo "# source c/tests/kit/exit.c, built with -g -B share/absd-c/tcc; readelf -S -W (array sections), nm (bound symbols)"
    for build in hostcfg-unpatched hostcfg; do
        elf=$obj/arrays-$build-g.elf
        "$out/$build/tcc" -B "$share/tcc" -g c/tests/kit/exit.c -o "$elf"
        echo "== $build/tcc exit.c -g: sections"
        sections "$elf"
        echo "== $build/tcc exit.c -g: symbols"
        symbols "$elf"
    done
} > "$receipt"
u=$obj/arrays-hostcfg-unpatched-g.elf p=$obj/arrays-hostcfg-g.elf
un=$(sections "$u" | wc -l)
uw=$(symbols "$u" | awk '$NF ~ /^__bothinit/ && NF == 2' | wc -l)
pn=$(sections "$p" | awk '{print $1}' | sort | tr '\n' ' ')
pd=$(symbols "$p" | awk '$NF ~ /^__bothinit/ && NF == 3 && $2 != "U" && $2 != "w"' | wc -l)
[ "$un" -gt 1 ] && [ "$uw" = 2 ] || { cat "$receipt" >&2; echo "tcc-unpatched-arrays: the unpatched image does not show R2" >&2; exit 1; }
[ "$pn" = ".fini_array .init_array " ] && [ "$pd" = 2 ] || { cat "$receipt" >&2; echo "tcc-unpatched-arrays: the patched image does not show P2" >&2; exit 1; }
echo "TCC R2 RECEIPT OK unpatched_sections=$un unpatched_bothinit_undefined=$uw patched_sections=2 patched_bothinit_defined=$pd"
