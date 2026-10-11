#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
toolchain=${ABSD_RUST_TOOLCHAIN:-$HOME/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu}
source_root=$toolchain/lib/rustlib/src/rust
. "$root/scripts/inputs.sh"
# The four workload sources are inputs of the full profile only
# (scripts/inputs.sh); the core profile neither needs nor checks them.
if [ "$ABSD_PROFILE" = full ]; then
    pulse=$(absd_source PULSE)
    ag=$(absd_source AG)
    nightshift=$(absd_source NIGHTSHIFT)
    nq=$(absd_source NQ)
fi

fail() {
    printf '%s\n' "verify-inputs: $*" >&2
    exit 1
}

expect_file_hash() {
    expected=$1
    path=$2
    actual=$(sha256sum "$path" | awk '{print $1}')
    test "$actual" = "$expected" || fail "unexpected SHA-256 for $path: $actual"
}

# A file only the extended integration programs read: checked in the full
# profile, where they are built.
expect_extended_file_hash() {
    if [ "$ABSD_PROFILE" = full ]; then
        expect_file_hash "$@"
    fi
}

expect_file_hash \
    bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6 \
    "$toolchain/bin/rustc"
expect_file_hash \
    841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66 \
    "$toolchain/bin/cargo"

compiler_identity=$("$toolchain/bin/rustc" --version --verbose | sha256sum | awk '{print $1}')
test "$compiler_identity" = \
    4fdff2578428e9c5c08ddd7a0d3079c1a106b1cdaa46e73e46f7cd32b0fb9cad || \
    fail "compiler identity changed: $compiler_identity"
# Without the `os:` line, which describes the host, not Cargo (the binary
# itself is pinned by digest above).
cargo_identity=$("$toolchain/bin/cargo" --version --verbose | grep -v '^os: ' | sha256sum | awk '{print $1}')
test "$cargo_identity" = \
    59577842430d2b2a0a16ab80f6e10933ca064c09112b91b8ce0ddbdb747772ea || \
    fail "Cargo identity changed: $cargo_identity"

library_hash=$(
    cd "$source_root"
    find library -type f -print0 |
        LC_ALL=C sort -z |
        xargs -0 sha256sum |
        sha256sum |
        awk '{print $1}'
)
library_files=$(find "$source_root/library" -type f | wc -l)
library_bytes=$(find "$source_root/library" -type f -printf '%s\n' |
    awk '{total += $1} END {print total}')
library_symlinks=$(find "$source_root/library" -type l | wc -l)
test "$library_hash" = \
    fcb80715180e5a9cc3179b032d2df540bfadb7a3ea35b04f02d4d97e5aafda3b || \
    fail "rust-src library snapshot changed: $library_hash"
test "$library_files" -eq 2236 || fail "rust-src file count changed: $library_files"
test "$library_bytes" -eq 45837761 || fail "rust-src byte count changed: $library_bytes"
test "$library_symlinks" -eq 0 || fail "rust-src gained symlinks: $library_symlinks"

# The snapshot's upstream identity: the published rust-src 1.95.0 component
# (the rustup channel manifest of 2026-04-16 names it), whose
# library/ tree is byte-identical to the installed one (README.md). With
# ABSD_RUST_SRC_TARBALL naming a downloaded copy, check its digest and that
# its library/ has the same fingerprint.
rust_src_url=https://static.rust-lang.org/dist/2026-04-16/rust-src-1.95.0.tar.xz
rust_src_sha256=67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363
rust_src_commit=59807616e1fa2540724bfbac14d7976d7e4a3860
rust_src_tarball=not-checked
if [ -n "${ABSD_RUST_SRC_TARBALL:-}" ]; then
    test -f "$ABSD_RUST_SRC_TARBALL" || fail "ABSD_RUST_SRC_TARBALL is not a file: $ABSD_RUST_SRC_TARBALL"
    expect_file_hash "$rust_src_sha256" "$ABSD_RUST_SRC_TARBALL"
    tarball_tree=$(mktemp -d)
    tar -C "$tarball_tree" -xJf "$ABSD_RUST_SRC_TARBALL" \
        rust-src-1.95.0/rust-src/lib/rustlib/src/rust/library
    tarball_hash=$(
        cd "$tarball_tree/rust-src-1.95.0/rust-src/lib/rustlib/src/rust"
        find library -type f -print0 |
            LC_ALL=C sort -z |
            xargs -0 sha256sum |
            sha256sum |
            awk '{print $1}'
    )
    rm -rf "$tarball_tree"
    test "$tarball_hash" = "$library_hash" || \
        fail "the rust-src tarball's library differs from the installed snapshot: $tarball_hash"
    rust_src_tarball=verified
fi

expect_file_hash \
    a71cabccca743f7c0e0e48e8bbce9732a95362ec27ea6ecf7cbbf4cdc4b7eccd \
    "$root/patches/rust-1.95.0-absd-std.patch"
expect_extended_file_hash \
    c43c6822901c0ef4a00dfd63c9849f1f35e0bce69587c824a881f53843a53536 \
    "$root/patches/ag-store-absd.patch"
expect_file_hash \
    1ef64200d3d3b6f52b660924993c87eeb0ed9b79c3614e7721dac6e8fc06d21a \
    "$root/targets/x86_64-unknown-absd.json"
expect_file_hash \
    f5c59f42e35f4b906f5cc6857479421a493641bad6e12a5e14f5d12a952e72a1 \
    "$root/.cargo/config.toml"
expect_file_hash \
    0558296e4ed45bb5abf111de1dad31dd9874926ce12c21d2b5f6e09b5a8a0faa \
    "$root/user-linker.ld"
expect_file_hash \
    9f5faa2ed635d3f8efabc6674673dd2ede386ad5284cc006b2e712bf0d5207be \
    "$root/scripts/rustc-staged.sh"
expect_file_hash \
    ec8167b113f25659f879487cd5d7bef7edfdbba81386fc2a72d01808d320cf9e \
    "$root/pins/library.Cargo.lock"
expect_extended_file_hash \
    78f99a2acacee3799c82d3406af9ae60997ec0b6620191f6e57a77ba53197973 \
    "$root/patches/nightshiftd-absd.patch"
expect_extended_file_hash \
    c2b1bdcf0d3c1a860e3ec666f166742e16c474d61c2587e8ac7aaafa607e4e26 \
    "$root/pins/nightshift-absd.Cargo.lock"
expect_extended_file_hash \
    494a3d3534b0fe147985bc8898cfd0c4b2dc40367451d894133e7423f503ddfb \
    "$root/patches/pulse-nq-load-support-absd.patch"
expect_extended_file_hash \
    cb7c88e532900254d51f982fcad0240fa716516c099af6ff42d4f40768fd4e46 \
    "$root/pins/pulse-absd.Cargo.lock"
expect_extended_file_hash \
    f86c342f850847160e006e9c06e63fbcca0b39b134301a6cf1838dc5b8c68e02 \
    "$root/patches/pulse-absd-frame-pressure.patch"
expect_extended_file_hash \
    27715dfb467b39d2caf267901fefa869204bfdf5773d0bbb1568605f49626082 \
    "$root/pins/pulse-observe-absd.Cargo.lock"
expect_extended_file_hash \
    9e458f47fc169d524e882331f6d99da3a2547716b03bb2cc768518fc37adde96 \
    "$root/observe/question.v1.json"
expect_extended_file_hash \
    f3c4e78e58ee3cacfbe0a7b1d7cd0ddae59f130c90f4d4898c40ba41a2bf9080 \
    "$root/observe/profile.v1.json"
expect_extended_file_hash \
    731ab8476e9c6dad3a25f11a395a6445c5619721d59143b3ea697ae5d388d095 \
    "$root/observe/threshold-policy.v1.json"
expect_extended_file_hash \
    cd4c99bc319f730e1b460265911b38c75755a1e7750a471fe3408567a3a65d5e \
    "$root/tools/pulse-frame-pressure-reference/Cargo.lock"
expect_extended_file_hash \
    b53d2a3725f1da1a9f81afe86bffb38f1d83ec06df8335d9e7ac4726303cab7f \
    "$root/tools/pulse-support-reference/Cargo.lock"
expect_extended_file_hash \
    3b9c4e41f8111cfbecd632d6a77ada4b70f7545823623d8006a8a153470778a4 \
    "$root/patches/nq-absd.patch"
expect_extended_file_hash \
    946812dd976d2c4e36400e1cc46d930359a23a4e3d0e3e665923aa8748490b7c \
    "$root/nq/Cargo.toml"
expect_extended_file_hash \
    01e95121eb3e0bb2c065bb89f652eb0ce3b5d590c5ad80abcb0dfb5af27e3041 \
    "$root/pins/nq-absd.Cargo.lock"
expect_extended_file_hash \
    d069450bf9203c4dd47acf083e1049ff7e53b0fd29b727b804fd6656e15a84e6 \
    "$root/patches/ag-loopctl-absd.patch"
expect_extended_file_hash \
    284a0b6aa50f2a43c52d01dad9778420f50adda90eeb0e174d67863342c39f29 \
    "$root/patches/ring-absd.patch"
expect_extended_file_hash \
    8fa2c9d25a2afb16403b8d0cfd19b26fdb083953f355d2544e435509330ab726 \
    "$root/ag/Cargo.toml"
expect_extended_file_hash \
    4588737203d6aae311aa8f4fb006009576c313a96e0bb80fe44c419e120b605a \
    "$root/pins/ag-absd.Cargo.lock"
expect_file_hash \
    5173dbad29eca9a673d5f17f57bb76d50d7139b2cc034cfe91762e7a0c90e2f6 \
    "$root/Cargo.toml"
expect_extended_file_hash \
    046ad6a0afe080669291f969e863491d07f0dbc9d97305fe3180921acfa74ffc \
    "$root/integration/Cargo.toml"
expect_extended_file_hash \
    b666aeacbbb90b00f08c25242168fba668dcdab33ac99fd187debf59d7299acb \
    "$root/integration/Cargo.lock"
expect_file_hash \
    34fc1a0d6ffe2edeb5dad3f41450dfdeb75ff36d6627f26e24487d1a4245541f \
    "$root/Cargo.lock"

vendor_hash=$(
    cd "$root"
    find vendor/rustc-literal-escaper vendor/ctrlc-stub vendor/tempfile vendor/nix-absd -type f -print0 |
        LC_ALL=C sort -z |
        xargs -0 sha256sum |
        sha256sum |
        awk '{print $1}'
)
test "$vendor_hash" = \
    17efa65ad2d1c098a385fb80c6232bac07640b0137f5e9c5a32e9fc889b20dfa || \
    fail "vendored crates changed: $vendor_hash"

target_spec=$(
    RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH="$root/targets" \
        "$toolchain/bin/rustc" -Zunstable-options \
        --target x86_64-unknown-absd --print target-spec-json |
        sha256sum | awk '{print $1}'
)
test "$target_spec" = \
    ea944f585aa5b5222c6a3918c43b2538f50293df3622c23b611a9a7a870f13a2 || \
    fail "normalized target specification changed: $target_spec"
target_cfg=$(
    RUSTC_BOOTSTRAP=1 RUST_TARGET_PATH="$root/targets" \
        "$toolchain/bin/rustc" -Zunstable-options \
        --target x86_64-unknown-absd --print cfg |
        LC_ALL=C sort |
        sha256sum | awk '{print $1}'
)
test "$target_cfg" = \
    df627bdcf32fd0d272e744b68a17686ef062003ab6bd3a3eb910441dfdb7842c || \
    fail "target cfg changed: $target_cfg"

if [ "$ABSD_PROFILE" = full ]; then
# A workload input is a Git checkout, checked by commit, or a snapshot (a
# plain directory, as in a source distribution), checked by the Git tree
# identity of its files against the pinned commit's tree (scripts/inputs.sh).
pulse_tree=b3f746c4e16b5303d0fd7bf98b327bfa14382951
ag_tree=3c44f564e2be9add17224954f6e5bb45ccdec84c
if absd_is_checkout "$pulse"; then
    test "$(git -C "$pulse" rev-parse --is-inside-work-tree 2>/dev/null)" = true || \
        fail "Pulse source is absent: $pulse"
    test "$(git -C "$pulse" rev-parse HEAD)" = \
        81c2354674990679f43be4f207349ff1b2429bc7 || fail "Pulse commit changed"
    test "$(git -C "$pulse" rev-parse HEAD^{tree})" = "$pulse_tree" || fail "Pulse commit tree changed"
    test -z "$(git -C "$pulse" status --porcelain --untracked-files=all)" || \
        fail "Pulse source is not clean"
    pulse_input=checkout
else
    absd_check_snapshot Pulse "$pulse" "$pulse_tree" || fail "Pulse snapshot changed"
    pulse_input=snapshot
fi

if absd_is_checkout "$ag"; then
    test "$(git -C "$ag" rev-parse --is-inside-work-tree 2>/dev/null)" = true || \
        fail "AG source is absent: $ag"
    test "$(git -C "$ag" rev-parse HEAD)" = \
        21c8da079f2465a2466c54431cc315699fc57cbe || fail "AG commit changed"
    test "$(git -C "$ag" rev-parse HEAD^{tree})" = "$ag_tree" || fail "AG commit tree changed"
    test -z "$(git -C "$ag" status --porcelain --untracked-files=all)" || \
        fail "AG source is not clean"
    ag_input=checkout
else
    absd_check_snapshot AG "$ag" "$ag_tree" || fail "AG snapshot changed"
    ag_input=snapshot
fi
expect_file_hash \
    5807228823ca7b2b89610a24ca0a7a2db29253b5f34a0b73600b2873d8b64c88 \
    "$pulse/traces/demo.jsonl"
expect_file_hash \
    17fa6e9d9cc975a700b34013672eba457efe1365d52451a2cd55e43ad88f6ba4 \
    "$pulse/artifacts/demo-report.json"
expect_file_hash \
    d34b73bd78e73afe1402228258fec6ee7cb850a91bcd899ec072b32647ea2356 \
    "$pulse/Cargo.lock"

# Nightshift is read only through `git archive` of its pinned commit, so the
# primary checkout may be dirty; the commit's tree is what is pinned.
nightshift_tree=bd7afe042251fc4f007413871589a01d26e0583f
if absd_is_checkout "$nightshift"; then
    test "$(git -C "$nightshift" rev-parse e2675dd854dbfe633bf14456595d722e88bf92bc^{tree})" = \
        bd7afe042251fc4f007413871589a01d26e0583f || fail "Nightshift commit tree changed"
    nightshift_input=checkout
else
    absd_check_snapshot Nightshift "$nightshift" "$nightshift_tree" || fail "Nightshift snapshot changed"
    nightshift_input=snapshot
fi
test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fixture_id"])' \
    "$root/fixtures/nightshift/manifest.json")" = \
    sha256:94ffea09d750078455638ab8dde2ac086b3ce6d735d4fcb8d37ee93bb7e76661 || \
    fail "Nightshift fixture identity changed"
# The writer's posture-only request (the fixture's cycle request without
# its proposal, resealed) is not bound by the manifest; pin it here.
expect_file_hash \
    ec2e6708a91e32bda568a41686a31d41d47a79bdcf2135e96584950fee489390 \
    "$root/fixtures/nightshift/posture-request.json"

test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fixture_id"])' \
    "$root/fixtures/pulse/manifest.json")" = \
    sha256:a2b6c183c0ea2b7ac76c6fe9aa90583975a1562bf6ec9675fe44d5b075ae4ab1 || \
    fail "Pulse support fixture identity changed"

# NQ-NG likewise: `git archive` of the pinned commit, whose tree is pinned.
nq_tree=13c0b6b36ec26b941adc586088275df248360492
if absd_is_checkout "$nq"; then
    test "$(git -C "$nq" rev-parse 80574417f0188afd37992db7ac764a6f0f72ff62^{tree})" = \
        13c0b6b36ec26b941adc586088275df248360492 || fail "NQ-NG commit tree changed"
    nq_input=checkout
else
    absd_check_snapshot NQ-NG "$nq" "$nq_tree" || fail "NQ-NG snapshot changed"
    nq_input=snapshot
fi
expect_file_hash \
    c128c045cd70140591392d743b7ef86bff00d11eace2a898dc59ff8cad2cf00c \
    "$root/fixtures/nq/manifest.json"

# The AG native path's Linux reference (make-reference-fixture.sh's run
# i-fresh-ag; the manifest binds every file and the Linux binaries).
expect_file_hash \
    321f3f9b61159f8a9618df0ef59bf36b7ec68f3d00d0b7d1f09fa600fe4220d9 \
    "$root/fixtures/ag-native/manifest.json"
else
    pulse_input=not-checked ag_input=not-checked nightshift_input=not-checked nq_input=not-checked
fi

# The SSH server: its own workspace and lock, and the sunset patch (the
# sunset archive itself is checked against its crates.io checksum by
# scripts/stage-ssh.sh).
expect_file_hash \
    370a2f637fbecf5963f39c7d6db455708319276afd3b8b4671a278399818f0f5 \
    "$root/patches/sunset-server-channel.patch"
expect_file_hash \
    922027e5d11127c4c6f0c8555bdfcbced8b487db7eb7e69c87c32374e7c8f510 \
    "$root/ssh/Cargo.toml"
expect_file_hash \
    6d22e11ddaa76f1fbacce61cb9bcbde0d58a954fcf383b66871b73cabe565e96 \
    "$root/ssh/Cargo.lock"

# The source-portability probe: its program list (registry archives are
# checked against these crates.io checksums by scripts/stage-compat.sh) and
# the pinned ABSD locks.
compat_hash=$(
    cd "$root"
    find compat/programs.tsv pins/compat -type f -print0 |
        LC_ALL=C sort -z |
        xargs -0 sha256sum |
        sha256sum |
        awk '{print $1}'
)
test "$compat_hash" = \
    facbcc010b05fad55caa8373f136c780a74eddf68b99f8b28678e72d03e1f2b0 || \
    fail "compat programs or locks changed: $compat_hash"

# The manual's renderer (scripts/render-man.sh): GNU groff 1.23.0 from
# Debian's groff-base 1.23.0-3build2. The binaries, the whole macro and
# font tree, and the site-local macro files mdoc reads are pinned, so a
# rendered page is a function of its mdoc source.
groff_version=$(env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/groff --version | sed -n 1p)
test "$groff_version" = "GNU groff version 1.23.0" || fail "groff version changed: $groff_version"
expect_file_hash \
    186e3a7f85c766fe2ecb7e9504f89d4d3b21fe6a84217a31e814c0c2e67cd72f \
    /usr/bin/groff
expect_file_hash \
    5da9f7722e3a40cf56a2bcfd0d83f83925063c01bc42d4f7d6ea54201d6b0a4c \
    /usr/bin/troff
expect_file_hash \
    a7751409bd40e43bfe9dddef4758436c56a4357fbe315b856ea0bd1c70d54ac6 \
    /usr/bin/grotty
expect_file_hash \
    b6d2cd92375db94039424ba024c135660ec5512aa5b6b8418a2d63744a03c78d \
    /etc/groff/man.local
expect_file_hash \
    925e3cc819f9a4e9fdcf44fac993184bef3be2e6d33a9a6104640e51dd75239a \
    /etc/groff/mdoc.local
groff_tree=$(
    cd /usr/share/groff/1.23.0
    find . -type f -print0 |
        LC_ALL=C sort -z |
        xargs -0 sha256sum |
        sha256sum |
        awk '{print $1}'
)
test "$groff_tree" = \
    78d3c916205f76a4bd1169d7a65a0ac8be8f9518178e67b9e0474a6634857cc0 || \
    fail "groff macro and font tree changed: $groff_tree"

printf '%s\n' "ABSD RUST INPUTS OK profile=$ABSD_PROFILE rust_src=$rust_src_url sha256=$rust_src_sha256 commit=$rust_src_commit library=$library_hash tarball=$rust_src_tarball pulse=$pulse_input ag=$ag_input nightshift=$nightshift_input nq=$nq_input"
