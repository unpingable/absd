use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

const PIN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ID: &str = "0123456789abcdef0123456789abcdef";

fn valid_config() -> String {
    format!("peer=192.0.2.2:443\nname=document.example\npath=/one.txt\nissuer_spki={PIN}\n")
}

fn valid_args() -> Vec<String> {
    [
        "--boot",
        ID,
        "--pit-ms",
        "20",
        "--rtc",
        "100",
        "--utc-ms",
        "100000",
        "--uncertainty",
        "1000",
        "--grant-expiry",
        "15020",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "https-document-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn staging(&self) -> PathBuf {
        self.0.join(format!(".https-document-{ID}.stage"))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn actual_fixed_config_preserves_exact_peer_name_path_and_pin() {
    let cfg = config(&valid_config()).unwrap();
    assert_eq!(
        cfg.peer,
        Address {
            ip: [192, 0, 2, 2],
            port: 443
        }
    );
    assert_eq!(cfg.name, "document.example");
    assert_eq!(cfg.path, "/one.txt");
    assert_eq!(cfg.issuer_spki, [0x11; 32]);
}

#[test]
fn actual_config_refuses_extra_duplicate_wrong_order_and_injection() {
    for text in [
        valid_config() + "unknown=1\n",
        valid_config().replace("name=document.example", "peer=192.0.2.2:443"),
        valid_config().replace(
            "peer=192.0.2.2:443\nname=document.example",
            "name=document.example\npeer=192.0.2.2:443",
        ),
        valid_config().replace("/one.txt", "/one.txt HTTP/1.1"),
        valid_config().replace("/one.txt", "/one.txt\rInjected: x"),
        valid_config().replace("/one.txt", "/one.txt#fragment"),
        valid_config().replace("document.example", "DOCUMENT.example"),
        valid_config().replace("192.0.2.2:443", "192.0.2.2:0"),
        valid_config().replace("192.0.2.2:443", "192.0.2.2:0443"),
        valid_config().replace("192.0.2.2:443", "peer.example:443"),
    ] {
        assert!(config(&text).is_err(), "{text}");
    }
}

#[test]
fn actual_config_refuses_overlong_name_path_and_noncanonical_pin() {
    assert!(
        config(&valid_config().replace("/one.txt", &format!("/{}", "a".repeat(1024)))).is_err()
    );
    assert!(config(&valid_config().replace(PIN, &"1".repeat(63))).is_err());
    assert!(config(&valid_config().replace(PIN, &"A".repeat(64))).is_err());
    assert!(
        config(
            &valid_config().replace("document.example", &format!("{}.example", "a".repeat(254)))
        )
        .is_err()
    );
}

#[test]
fn actual_arguments_accept_only_complete_unique_attestation_and_grant() {
    let args = valid_args();
    let (anchor, expiry) = arguments(&args).unwrap();
    assert_eq!(anchor.boot, unhex::<16>(ID).unwrap());
    assert_eq!(
        (
            anchor.pit_ms,
            anchor.rtc_s,
            anchor.utc_ms,
            anchor.uncertainty_ms,
            expiry
        ),
        (20, 100, 100000, 1000, 15020)
    );
    let reverse: Vec<_> = args.chunks_exact(2).rev().flatten().cloned().collect();
    assert_eq!(arguments(&reverse).unwrap().1, 15020);
    assert!(arguments(&args[..10]).is_err());
    let mut duplicate = args.clone();
    duplicate[2] = "--boot".into();
    assert!(arguments(&duplicate).is_err());
    let mut unknown = args.clone();
    unknown[2] = "--time".into();
    assert!(arguments(&unknown).is_err());
}

#[test]
fn actual_numeric_and_hex_decoders_refuse_ambiguity_and_overflow() {
    for text in [
        "",
        "00",
        "01",
        "+1",
        "-1",
        " 1",
        "1 ",
        "18446744073709551616",
    ] {
        assert!(decimal(text).is_err());
    }
    assert_eq!(decimal("18446744073709551615").unwrap(), u64::MAX);
    for text in [
        "0123",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcdeg",
    ] {
        assert!(unhex::<16>(text).is_err());
    }
    assert_eq!(hex(&unhex::<16>(ID).unwrap()), ID);
}

#[test]
fn actual_file_reader_refuses_empty_and_oversized_inputs() {
    let temp = Temp::new();
    let path = temp.0.join("public.der");
    fs::write(&path, b"").unwrap();
    assert!(bounded_file(path.to_str().unwrap(), 4).is_err());
    fs::write(&path, b"12345").unwrap();
    assert!(bounded_file(path.to_str().unwrap(), 4).is_err());
    fs::write(&path, b"1234").unwrap();
    assert_eq!(bounded_file(path.to_str().unwrap(), 4).unwrap(), b"1234");
}

#[test]
fn actual_publication_refuses_bounds_before_creating_storage() {
    let temp = Temp::new();
    assert!(publish(&temp.0, "../outside", b"ok", b"receipt", || Ok(())).is_err());
    assert!(publish(&temp.0, ID, &[0; 16_385], b"receipt", || Ok(())).is_err());
    assert!(publish(&temp.0, ID, b"ok", &[0; 4097], || Ok(())).is_err());
    assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 0);
}

#[test]
fn actual_exclusive_stage_collision_preserves_existing_files() {
    let temp = Temp::new();
    fs::create_dir(temp.staging()).unwrap();
    fs::write(temp.staging().join("body"), b"existing").unwrap();
    assert!(publish(&temp.0, ID, b"new", b"receipt", || Ok(())).is_err());
    assert_eq!(fs::read(temp.staging().join("body")).unwrap(), b"existing");
}

#[test]
fn actual_policy_refusal_removes_only_known_created_files() {
    let temp = Temp::new();
    assert_eq!(
        publish(&temp.0, ID, b"body", b"receipt", || Err("clock refused")).unwrap_err(),
        "clock refused"
    );
    assert!(!temp.staging().exists());
    assert!(!temp.0.join(format!("https-document-{ID}")).exists());
}

#[test]
fn actual_policy_refusal_does_not_remove_unknown_storage() {
    let temp = Temp::new();
    assert!(
        publish(&temp.0, ID, b"body", b"receipt", || {
            fs::write(temp.staging().join("unowned"), b"retain").unwrap();
            Err("clock refused")
        })
        .is_err()
    );
    assert_eq!(fs::read(temp.staging().join("unowned")).unwrap(), b"retain");
    assert!(!temp.staging().join("body").exists());
    assert!(!temp.staging().join("receipt").exists());
}

#[test]
fn host_cannot_claim_native_commit_and_preserves_synced_staging() {
    let temp = Temp::new();
    assert_eq!(
        publish(&temp.0, ID, b"body", b"receipt", || Ok(())).unwrap_err(),
        "publication outcome refused or unknown; preserve paths, no retry"
    );
    assert_eq!(fs::read(temp.staging().join("body")).unwrap(), b"body");
    assert_eq!(
        fs::read(temp.staging().join("receipt")).unwrap(),
        b"receipt"
    );
    assert!(!temp.0.join(format!("https-document-{ID}")).exists());
}
