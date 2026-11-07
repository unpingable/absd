use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=ABSD_LOGD_FAULT");
    let logd_fault = env::var("ABSD_LOGD_FAULT").unwrap_or_else(|_| "0".into());
    assert!(
        ["0", "1"].contains(&logd_fault.as_str()),
        "ABSD_LOGD_FAULT must be 0 or 1"
    );
    println!("cargo:rustc-env=ABSD_LOGD_FAULT={logd_fault}");
    println!("cargo:rerun-if-env-changed=ABSD_LOGD_PRESENT");
    println!(
        "cargo:rustc-env=ABSD_LOGD_PRESENT={}",
        env::var("ABSD_LOGD_PRESENT").unwrap_or_default()
    );
    println!("cargo:rerun-if-env-changed=ABSD_LOCAL_CONSOLE");
    if let Ok(value) = env::var("ABSD_LOCAL_CONSOLE") {
        assert!(
            value == "0" || value == "1",
            "ABSD_LOCAL_CONSOLE must be 0 or 1"
        );
    }
    println!("cargo:rerun-if-env-changed=ABSD_USER_SUCCESSOR");
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_USER_ELF");
    let digest = if env::var("ABSD_USER_SUCCESSOR").as_deref() == Ok("1") {
        env::var_os("ABSD_EXTERNAL_USER_ELF")
            .map(|path| {
                println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
                let result = std::process::Command::new("sha256sum")
                    .arg(path)
                    .output()
                    .expect("ELF digest");
                assert!(result.status.success(), "ELF digest failed");
                String::from_utf8(result.stdout).expect("digest UTF-8")[..64].to_owned()
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    println!("cargo:rustc-env=ABSD_MWM_SUCCESSOR_SHA={digest}");
    embed("ABSD_RESERVATION_ACTOR_EMBED", "reservation-actor.elf");
    embed("ABSD_CAPABILITY_ACTOR_EMBED", "capability-actor.elf");
    embed(
        "ABSD_AUTHORITY_EFFECT_CHILD_EMBED",
        "authority-effect-child.elf",
    );
    embed("ABSD_EXTERNAL_INPUT_EMBED", "external-input.bin");
    embed(
        "ABSD_EXTERNAL_READER_INPUT_EMBED",
        "external-reader-input.bin",
    );
    embed("ABSD_BROKER_POLICY_EMBED", "broker-policy.txt");
    println!("cargo:rerun-if-env-changed=ABSD_EXTERNAL_READER_PRESENT");
    let present = env::var("ABSD_EXTERNAL_READER_PRESENT").unwrap_or_default();
    println!("cargo:rustc-env=ABSD_EXTERNAL_READER_PRESENT={present}");
    println!("cargo:rerun-if-env-changed=ABSD_FILE_SERVER_PRESENT");
    let server = env::var("ABSD_FILE_SERVER_PRESENT").unwrap_or_default();
    println!("cargo:rustc-env=ABSD_FILE_SERVER_PRESENT={server}");
    // A qualification boot's NIC-worker deadline in ticks; empty means the
    // default hour (init `NET_WAIT_TICKS_DEFAULT`).
    println!("cargo:rerun-if-env-changed=ABSD_NET_WAIT_TICKS");
    let ticks = env::var("ABSD_NET_WAIT_TICKS").unwrap_or_default();
    assert!(
        ticks.is_empty() || ticks.parse::<u64>().is_ok_and(|value| value > 0),
        "ABSD_NET_WAIT_TICKS must be a positive number of ticks"
    );
    println!("cargo:rustc-env=ABSD_NET_WAIT_TICKS={ticks}");
    // A dedicated enrollment image (init `ENROLL_STREAM`): empty or 1.
    println!("cargo:rerun-if-env-changed=ABSD_ENROLL_STREAM");
    let enroll = env::var("ABSD_ENROLL_STREAM").unwrap_or_default();
    assert!(
        enroll.is_empty() || enroll == "1",
        "ABSD_ENROLL_STREAM must be empty or 1"
    );
    println!("cargo:rustc-env=ABSD_ENROLL_STREAM={enroll}");
}

/// Exposes one embedded input file to init as `include_bytes!(env!(name))`,
/// an empty file when none was supplied.
fn embed(name: &str, default_name: &str) {
    println!("cargo:rerun-if-env-changed={name}");
    let path = match env::var_os(name).filter(|value| !value.is_empty()) {
        Some(value) => {
            let path = PathBuf::from(value);
            println!("cargo:rerun-if-changed={}", path.display());
            path.canonicalize()
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        }
        None => {
            let path = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join(default_name);
            fs::write(&path, []).expect("create empty external input");
            path
        }
    };
    println!("cargo:rustc-env={name}={}", path.display());
}
