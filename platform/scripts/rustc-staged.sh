#!/bin/sh
set -eu

real=${ABSD_REAL_RUSTC:?set ABSD_REAL_RUSTC}
stage=${ABSD_STAGED_SYSROOT:?set ABSD_STAGED_SYSROOT}

for argument in "$@"; do
    if [ "$argument" = "--print=sysroot" ]; then
        real_sysroot=$($real --print sysroot)
        "$real" -Zunstable-options "$@" | while IFS= read -r line; do
            if [ "$line" = "$real_sysroot" ]; then
                printf '%s\n' "$stage"
            else
                printf '%s\n' "$line"
            fi
        done
        exit 0
    fi
done
if [ "$#" -eq 2 ] && [ "$1" = "--print" ] && [ "$2" = "sysroot" ]; then
    printf '%s\n' "$stage"
    exit 0
fi

# The experimental custom target requires `restricted_std` in every target
# crate that links `std`, including unmodified third-party dependencies. Cargo
# cannot express that feature transitively. Inject it only for ABSD target
# crates, and never into the staged standard-library build itself.
absd_target=false
library_crate=false
crate_name=
previous=
for argument in "$@"; do
    if [ "$argument" = "--target=x86_64-unknown-absd" ] || \
        { [ "$previous" = "--target" ] && [ "$argument" = "x86_64-unknown-absd" ]; }
    then
        absd_target=true
    fi
    case "$argument" in
        "$stage"/lib/rustlib/src/rust/library/*) library_crate=true ;;
    esac
    if [ "$previous" = "--crate-name" ]; then
        crate_name=$argument
        case "$argument" in
            core|alloc|std|proc_macro|panic_abort|panic_unwind|unwind|compiler_builtins|rustc_demangle|std_detect|rustc_std_workspace_core|rustc_std_workspace_alloc|rustc_std_workspace_std)
                library_crate=true
                ;;
        esac
    fi
    previous=$argument
done
if [ "$absd_target" = true ] && [ "$library_crate" = false ]; then
    case "$crate_name" in
        ppv_lite86|absd_broker|absd_runtime|absd_durable|absd_fs|absd_sqlite|absd_std_probe|panic_std|exit_std|text_stats|pulse_std|ag_authority|pulse_journal_std|ag_sqlite|fixture_import|broker_echo|broker_requester|absd_net|netd_probe|ctrlc|libc)
            exec "$real" -Zunstable-options "$@"
            ;;
        ag_primitives|ag_kernel|serde_jcs|pulse_runtime|pulse_nq_load_support|pulse_absd_frame_pressure|pulse_agent|pulse_l3_bridge|libsqlite3_sys|rusqlite|nightshiftd|nightshift_observation_resolver|nightshift|ag_store|anstream|ag_campaign|strsim|clap_lex|is_terminal_polyfill|anstyle_query|tempfile|nq_app|nq|nq_core|nq_store|nq_protocol|nq_profiles|nq_helper_sandbox|nq_build_info|serde_spanned|toml_datetime|toml_edit|toml|tokio|ag_protocol|ag_session|ag_app|ag_loopctl)
            attribute='feature(restricted_std)'
            ;;
        *)
            attribute='cfg_attr(feature="std", feature(restricted_std))'
            # Source-portability probe (scripts/build-compat.sh): unmodified
            # upstream crates may link `std` without a `std` feature. Gate
            # every crate; a `no_std` crate refuses the gate as an unknown
            # feature and is compiled again without it.
            if [ "${ABSD_RESTRICTED_STD_ALL:-0}" = 1 ]; then
                # An unmodified program never names absd-runtime, which
                # holds the CRT entry, allocator, and std's hooks; the
                # staged manifest adds it as a dependency and it is linked
                # although no source refers to it.
                for argument in "$@"; do
                    shift
                    case "$argument" in
                        absd_runtime=*) argument="force:$argument" ;;
                    esac
                    set -- "$@" "$argument"
                done
                log=$(mktemp)
                if "$real" -Zunstable-options "-Zcrate-attr=feature(restricted_std)" "$@" 2>"$log"; then
                    cat "$log" >&2
                    rm -f "$log"
                    exit 0
                fi
                if grep -q 'unknown feature `restricted_std`' "$log"; then
                    rm -f "$log"
                    exec "$real" -Zunstable-options "$@"
                fi
                cat "$log" >&2
                rm -f "$log"
                exit 1
            fi
            ;;
    esac
    exec "$real" -Zunstable-options "-Zcrate-attr=$attribute" "$@"
fi
exec "$real" -Zunstable-options "$@"
