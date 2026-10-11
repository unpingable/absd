use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    for cfg in [
        "absd_mutant_cell_duplicate_widen",
        "absd_mutant_handle_ignore_tag",
        "absd_mutant_cell_skip_release",
        "absd_mutant_denied_cell_effect",
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
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_INPUT");
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_READER_ELF");
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_READER_INPUT");
    println!("cargo:rerun-if-env-changed=ABSD_BROKER_POLICY");
    println!("cargo:rerun-if-env-changed=ABSD_FILE_SERVER_ELF");
    println!("cargo:rerun-if-env-changed=ABSD_NET_WAIT_TICKS");
    for owner in 1..=4 {
        println!("cargo:rerun-if-env-changed=ABSD_OWNER_{owner}_ELF");
    }
    println!("cargo:rerun-if-changed=user");
    // The user programs link the ABI crate: layout or number changes there
    // must rebuild them too.
    println!("cargo:rerun-if-changed=abi");
    println!("cargo:rerun-if-changed=scripts/build-user.sh");

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

    let status = Command::new("sh")
        .arg("scripts/build-user.sh")
        .arg(&out)
        .env("ABSD_EXTERNAL_INPUT_EMBED", &embedded_input)
        .env("ABSD_EXTERNAL_READER_INPUT_EMBED", &reader_input)
        .env("ABSD_BROKER_POLICY_EMBED", &policy)
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
