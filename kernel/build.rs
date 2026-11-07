// The embedded S1 consumer is x86; ARM returns before reading these images.
mod arch {
    pub const ELF_MACHINE: u16 = 62;
}
#[allow(dead_code)]
#[path = "src/elf.rs"]
mod elf;
#[allow(dead_code)]
#[path = "src/frame_geometry.rs"]
mod frame_geometry;
#[allow(dead_code)]
#[path = "abi/src/layout.rs"]
mod layout;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=ABSD_LOCAL_CONSOLE");
    if let Ok(value) = env::var("ABSD_LOCAL_CONSOLE") {
        assert!(
            value == "0" || value == "1",
            "ABSD_LOCAL_CONSOLE must be 0 or 1"
        );
    }
    for cfg in [
        "absd_mutant_wait_skip_recheck",
        "absd_mutant_wait_no_eof",
        "absd_mutant_wait_ignore_revocation",
        "absd_mutant_wait_ignore_timeout",
        "absd_mutant_frame_authority",
        "absd_mutant_cell_duplicate_widen",
        "absd_mutant_handle_ignore_tag",
        "absd_mutant_cell_skip_release",
        "absd_mutant_denied_cell_effect",
        "absd_mutant_ivrs_skip_checksum",
        "absd_mutant_ivrs_accept_ivmd",
        "absd_mutant_ivrs_unpaired",
        "absd_mutant_ivrs_alias_overlap",
        "absd_mutant_ivrs_strict_overlap",
        "absd_mutant_ivrs_alias_target",
        "absd_mutant_ivrs_second_unit",
        "absd_mutant_dma_enforced_arms",
        "absd_mutant_dma_witness_ignored",
        "absd_mutant_amdvi_irq_forward",
        "absd_mutant_amdvi_irq_pass_bits",
        "absd_mutant_amdvi_irq_no_invalidate",
        "absd_mutant_amdvi_irq_revoke_no_invalidate",
        "absd_mutant_amdvi_tail_unchecked",
        "absd_mutant_amdvi_tail_record_kept",
        "absd_mutant_amdvi_tail_health_kept",
        "absd_mutant_dma_inherited_overflow_ignored",
        "absd_mutant_pci_raw_bme",
        "absd_mutant_amdvi_overlap_unchecked",
        "absd_mutant_dma_registry_ignored",
        "absd_mutant_amdvi_domain_constant",
        "absd_mutant_amdvi_shared_irtable",
        "absd_mutant_amdvi_shared_root",
        "absd_mutant_amdvi_msix_unmasked",
        "absd_mutant_dma_release_ignored",
        "absd_mutant_contain_conflict_ignored",
        "absd_mutant_rtl8125_exhaustion_ignored",
        "absd_mutant_rtl8125_stall_unbounded",
        "absd_mutant_contain_overflow_unnoted",
        "absd_mutant_operator_last_fault_only",
        "absd_mutant_rtl8125_no_rx_grant",
        "absd_mutant_contain_extra_page",
        "absd_mutant_contain_skip_bme_clear",
        "absd_mutant_operator_overflow_ignored",
        "absd_mutant_operator_target_fault_ignored",
        "absd_mutant_check_retired_passes",
        "absd_mutant_check_ignores_submission",
        "absd_mutant_contain_grant_before_clear",
        "absd_mutant_refusal_clears_display_path",
        "absd_mutant_contain_gate_open",
        "absd_mutant_contain_latch_ignored",
        "absd_mutant_contain_owner_ignored",
        "absd_mutant_contain_reregister",
        "absd_mutant_mcfg_unreadable_absent",
        "absd_mutant_scope_sibling_any",
        "absd_mutant_ahci_write_uncontained",
        "absd_mutant_scope_path_ignored",
        "absd_mutant_scope_peers_ignored",
        "absd_mutant_scope_ats_ignored",
        "absd_mutant_scope_fixture_any",
        "absd_mutant_ivrs_any_capability",
        "absd_mutant_ivrs_ignore_reserved",
        "absd_mutant_ivrs_skip_constraints",
        "absd_mutant_ivrs_broad_alias",
        "absd_mutant_ivrs_plain_overlap",
        "absd_mutant_amdvi_claim_disabled",
        "absd_mutant_ivrs_hats_used_only",
        "absd_mutant_ivrs_silent_alias",
        "absd_mutant_amdvi_quirk_any",
        "absd_mutant_amdvi_ignore_tolerated",
        "absd_mutant_amdvi_ignore_closure",
        "absd_mutant_amdvi_quirk_ppr",
        "absd_mutant_amdvi_quirk_ncounter",
        "absd_mutant_amdvi_quirk_banks",
        "absd_mutant_amdvi_quirk_reserved_count",
        "absd_mutant_amdvi_quirk_ppr_bits",
        "absd_mutant_amdvi_tolerated_selected_target",
        "absd_mutant_amdvi_counter_read",
        "absd_mutant_amdvi_efr_unsupported",
        "absd_mutant_amdvi_skip_wait",
        "absd_mutant_amdvi_invalidate_target_only",
        "absd_mutant_amdvi_blocked_passthrough_form",
        "absd_mutant_amdvi_grant_first",
        "absd_mutant_amdvi_priority_late",
        "absd_inject_setup_unit_error",
        "absd_mutant_amdvi_regrant_retained",
        "absd_mutant_amdvi_settles",
        "absd_mutant_amdvi_contained_unchecked",
        "absd_mutant_amdvi_overflow_forgotten",
        "absd_mutant_amdvi_failed_admits",
        "absd_mutant_amdvi_ignore_unit_errors",
        "absd_mutant_amdvi_ignore_table_errors",
    ] {
        println!("cargo:rustc-check-cfg=cfg({cfg})");
    }
    println!("cargo:rustc-check-cfg=cfg(absd_mutant_no_rights_check)");
    println!("cargo:rustc-check-cfg=cfg(absd_mutant_free_any_owner)");
    println!("cargo:rustc-check-cfg=cfg(absd_mutant_ignore_writable)");
    println!("cargo:rustc-check-cfg=cfg(absd_mutant_skip_fpu_restore)");
    println!("cargo:rustc-check-cfg=cfg(absd_mutant_fresh_fpu_dirty)");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64") {
        return;
    }
    println!("cargo:rerun-if-env-changed=ABSD_PORTABILITY_ELF");
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_USER_ELF");
    println!("cargo:rerun-if-env-changed=ABSD_PCM_PLAYBACK");
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_INPUT");
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_READER_ELF");
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_READER_INPUT");
    println!("cargo:rerun-if-env-changed=ABSD_BROKER_POLICY");
    println!("cargo:rerun-if-env-changed=ABSD_FILE_SERVER_ELF");
    println!("cargo:rerun-if-env-changed=ABSD_LOGD_ELF");
    println!("cargo:rerun-if-env-changed=ABSD_LOGD_FAULT");
    println!("cargo:rerun-if-env-changed=ABSD_NET_WAIT_TICKS");
    println!("cargo:rerun-if-env-changed=ABSD_ENROLL_STREAM");
    println!("cargo:rerun-if-env-changed=ABSD_KERNEL_ROOT_REMAP_TO");
    for owner in 1..=4 {
        println!("cargo:rerun-if-env-changed=ABSD_OWNER_{owner}_ELF");
    }
    println!("cargo:rerun-if-changed=user");
    // The user programs link the ABI crate: layout or number changes there
    // must rebuild them too.
    println!("cargo:rerun-if-changed=abi");
    println!("cargo:rerun-if-changed=src/elf.rs");
    println!("cargo:rerun-if-changed=src/frame_geometry.rs");
    println!("cargo:rerun-if-changed=scripts/build-user.sh");
    println!("cargo:rerun-if-changed=scripts/rust-source-map.sh");
    println!("cargo:rerun-if-changed=scripts/rust-build-flags.py");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let supplied = |name: &str| {
        env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map(|path| {
                println!("cargo:rerun-if-changed={}", path.display());
                path.canonicalize()
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            })
    };
    println!("cargo:rerun-if-env-changed=ABSD_INSTALLER_PAYLOAD");
    let installer = supplied("ABSD_INSTALLER_PAYLOAD")
        .map(|path| fs::read(path).expect("read installer payload"))
        .unwrap_or_default();
    assert!(
        installer.len() <= 64 * 1024 * 1024,
        "installer payload exceeds 64 MiB"
    );
    fs::write(out.join("installer.bin"), installer).expect("stage installer payload");
    let portable = supplied("ABSD_PORTABILITY_ELF");
    let external_user = supplied("ABSD_EXTERNAL_USER_ELF");
    if let Some(path) = &external_user {
        let bytes = fs::read(path).expect("read external userspace ELF");
        assert!(
            bytes.starts_with(b"\x7fELF\x02"),
            "external user image is not ELF64"
        );
    }
    let external_reader = supplied("ABSD_EXTERNAL_READER_ELF");
    if let Some(path) = &external_reader {
        let bytes = fs::read(path).expect("read external reader ELF");
        assert!(
            bytes.starts_with(b"\x7fELF\x02"),
            "external reader image is not ELF64"
        );
    }
    let logd_fault = env::var("ABSD_LOGD_FAULT").unwrap_or_else(|_| "0".into());
    assert!(
        ["0", "1"].contains(&logd_fault.as_str()),
        "ABSD_LOGD_FAULT must be 0 or 1"
    );
    let logd = supplied("ABSD_LOGD_ELF");
    if let Some(path) = &logd {
        let bytes = fs::read(path).expect("read logd ELF");
        assert!(bytes.starts_with(b"\x7fELF\x02"), "logd image is not ELF64");
    }
    let file_server = supplied("ABSD_FILE_SERVER_ELF");
    if let Some(path) = &file_server {
        let bytes = fs::read(path).expect("read file server ELF");
        assert!(
            bytes.starts_with(b"\x7fELF\x02"),
            "file server image is not ELF64"
        );
    }
    let reader_input = out.join("external-reader-input.bin");
    if let Some(path) = supplied("ABSD_EXTERNAL_READER_INPUT") {
        fs::copy(path, &reader_input).expect("copy external reader input");
    } else {
        fs::write(&reader_input, []).expect("create empty external reader input");
    }
    let owners: Vec<Option<PathBuf>> = (1..=4)
        .map(|owner| {
            let path = supplied(&format!("ABSD_OWNER_{owner}_ELF"));
            if let Some(path) = &path {
                let bytes = fs::read(path).expect("read owner ELF");
                assert!(
                    bytes.starts_with(b"\x7fELF\x02"),
                    "owner image is not ELF64"
                );
            }
            path
        })
        .collect();
    let policy = out.join("broker-policy.txt");
    if let Some(path) = supplied("ABSD_BROKER_POLICY") {
        fs::copy(path, &policy).expect("copy broker policy");
    } else {
        fs::write(&policy, []).expect("create empty broker policy");
    }
    let embedded_input = out.join("external-input.bin");
    if let Some(path) = supplied("ABSD_EXTERNAL_INPUT") {
        fs::copy(path, &embedded_input).expect("copy external input");
    } else {
        fs::write(&embedded_input, []).expect("create empty external input");
    }

    // The same guard as src/lib.rs, here because this script builds the
    // embedded programs before the kernel library compiles.
    assert!(
        env::var_os("CARGO_FEATURE_BUILDER_LARGE_ENVELOPE").is_none()
            || env::var_os("CARGO_FEATURE_FRAME_ADMISSION_V0").is_none(),
        "builder-large-envelope cannot be combined with served frame admission"
    );
    assert!(
        env::var_os("CARGO_FEATURE_BUILDER_CLASS_HEAP").is_none()
            || env::var_os("CARGO_FEATURE_FRAME_ADMISSION_V0").is_none(),
        "builder-class-heap cannot be combined with served frame admission"
    );
    let service_budget = |path: &Option<PathBuf>, fallback: usize| {
        if env::var_os("CARGO_FEATURE_FRAME_ADMISSION_V0").is_none() {
            return fallback;
        }
        path.as_ref().map_or(fallback, |path| {
            let bytes = fs::read(path).expect("read served image");
            let image = elf::parse(&bytes).expect("valid served ELF");
            frame_geometry::service_frames(&image).expect("served image fits frame geometry")
        })
    };
    let logd_frames = service_budget(&logd, 9333);
    let fsd_frames = service_budget(&file_server, 9333);
    let sshd_frames = service_budget(&external_user, 9434);
    // Init's commitment matters only to served admission; other builds keep
    // the accepted fallback, as the service budgets above do (the envelope's
    // layout bound would exceed the admission range it cannot use).
    let init_frames = if env::var_os("CARGO_FEATURE_FRAME_ADMISSION_V0").is_some() {
        frame_geometry::SERVED_INIT_FRAMES
    } else {
        16427
    };
    println!(
        "cargo:rustc-env=ABSD_SERVED_TOTAL_FRAMES={}",
        init_frames + fsd_frames + sshd_frames + if logd.is_some() { logd_frames } else { 0 }
    );
    // Init's private PCM modes and grant follow the kernel feature, never an
    // environment setting alone: a grant request without the driver fails.
    let native_pcm = env::var_os("CARGO_FEATURE_NATIVE_PCM_EXPERIMENT").is_some();
    assert!(
        native_pcm || env::var_os("ABSD_PCM_PLAYBACK").is_none_or(|value| value.is_empty()),
        "ABSD_PCM_PLAYBACK needs the native-pcm-experiment kernel feature"
    );
    println!("cargo:rerun-if-env-changed=ABSD_USER_SUCCESSOR");
    let mwm = env::var_os("CARGO_FEATURE_MWM_EXPERIMENT").is_some();
    let status = Command::new("sh")
        .arg("scripts/build-user.sh")
        .arg(&out)
        .env("ABSD_USER_NATIVE_PCM", if native_pcm { "1" } else { "0" })
        .env("ABSD_USER_MWM", if mwm { "1" } else { "0" })
        .env("ABSD_SERVED_INIT_FRAMES", init_frames.to_string())
        .env("ABSD_SERVED_FSD_FRAMES", fsd_frames.to_string())
        .env("ABSD_SERVED_LOGD_FRAMES", logd_frames.to_string())
        .env("ABSD_SERVED_SSHD_FRAMES", sshd_frames.to_string())
        .env("ABSD_EXTERNAL_INPUT_EMBED", &embedded_input)
        .env("ABSD_EXTERNAL_READER_INPUT_EMBED", &reader_input)
        .env("ABSD_BROKER_POLICY_EMBED", &policy)
        .env("ABSD_LOGD_PRESENT", if logd.is_some() { "1" } else { "" })
        .env("ABSD_LOGD_FAULT", logd_fault)
        .env(
            "ABSD_FILE_SERVER_PRESENT",
            if file_server.is_some() { "1" } else { "" },
        )
        .env(
            "ABSD_EXTERNAL_READER_PRESENT",
            if external_reader.is_some() { "1" } else { "" },
        )
        .status()
        .expect("launch userspace build");
    assert!(status.success(), "userspace build failed");

    for name in [
        "init",
        "hello_a",
        "hello_b",
        "exit7",
        "fault",
        "fpu",
        "trap",
        "privileged",
        "heap",
        "unmapped",
        "overflow",
        "cell",
        "shared",
        "readonly",
        "watcher",
        "piper",
        "sleeper",
        "shell",
        "fuzz",
        "multi_handle",
        "stack_grow",
        "stack_jump",
        "orphaner",
        "supervised_worker",
        "recovery_worker",
        "service_client",
        "client_service_worker",
        "alloc_probe",
        "isolation",
        "input_stream",
        "external_workload",
        "block_probe",
        "external_reader",
        "owner_1",
        "owner_2",
        "owner_3",
        "owner_4",
        "nic_probe",
        "file_server",
        "machine_probe",
        "hostile_probe",
        "rt_probe",
        "fpu_mxcsr",
        "smp_user",
        "logd",
    ] {
        let path = if matches!(name, "init" | "hello_a")
            && let Some(path) = &portable
        {
            path.clone()
        } else if name == "external_workload" {
            external_user
                .as_ref()
                .cloned()
                .unwrap_or_else(|| out.join(format!("{name}.elf")))
        } else if name == "external_reader" {
            // Without a supplied reader the slot holds the default workload
            // image; init never runs it unless a reader was supplied.
            external_reader
                .as_ref()
                .cloned()
                .unwrap_or_else(|| out.join("external_workload.elf"))
        } else if name == "logd" {
            logd.as_ref()
                .cloned()
                .unwrap_or_else(|| out.join("external_workload.elf"))
        } else if name == "file_server" {
            // Without a supplied server the slot holds the default workload
            // image; init refuses an `fsd` boot unless one was supplied.
            file_server
                .as_ref()
                .cloned()
                .unwrap_or_else(|| out.join("external_workload.elf"))
        } else if let Some(owner) = name.strip_prefix("owner_") {
            // Without supplied owners the slots hold the broker test child.
            let owner: usize = owner.parse().expect("owner number");
            owners[owner - 1]
                .clone()
                .unwrap_or_else(|| out.join("broker_child.elf"))
        } else {
            out.join(format!("{name}.elf"))
        };
        println!(
            "cargo:rustc-env=ABSD_USER_{}_ELF={}",
            name.to_ascii_uppercase(),
            path.display()
        );
    }
}
