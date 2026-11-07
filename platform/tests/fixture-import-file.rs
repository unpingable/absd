#[path = "../src/fixture_import_file.rs"]
mod file;

use absd_fs::{Device, Error, Fs, OpenFlags, SECTOR};
use file::{Boundary, import_file};
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;

#[derive(Clone)]
struct Disk(Rc<RefCell<Vec<[u8; SECTOR]>>>);
impl Device for Disk {
    fn sectors(&self) -> u64 {
        self.0.borrow().len() as u64
    }
    fn read(&mut self, sector: u64, out: &mut [u8; SECTOR]) -> Result<(), Error> {
        *out = self.0.borrow()[sector as usize];
        Ok(())
    }
    fn write(&mut self, sector: u64, data: &[u8; SECTOR]) -> Result<(), Error> {
        self.0.borrow_mut()[sector as usize] = *data;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
fn mounted() -> (Disk, Fs<Disk>) {
    let mut disk = Disk(Rc::new(RefCell::new(vec![[0; SECTOR]; 8192])));
    absd_fs::format(&mut disk, 7).unwrap();
    let fs = Fs::mount(disk.clone(), true).unwrap();
    (disk, fs)
}
fn put(fs: &mut Fs<Disk>, path: &str, bytes: &[u8]) {
    let h = fs
        .open(
            path.as_bytes(),
            OpenFlags {
                read: true,
                write: true,
                create_new: true,
                ..OpenFlags::default()
            },
        )
        .unwrap();
    assert_eq!(fs.write_at(h, 0, bytes).unwrap(), bytes.len());
    fs.sync().unwrap();
    fs.close(h).unwrap();
}
fn read(fs: &mut Fs<Disk>, path: &str) -> Option<Vec<u8>> {
    let size = match fs.stat(path.as_bytes()) {
        Ok(a) => a.size,
        Err(Error::NotFound) => return None,
        Err(e) => panic!("{e:?}"),
    };
    let h = fs
        .open(
            path.as_bytes(),
            OpenFlags {
                read: true,
                ..OpenFlags::default()
            },
        )
        .unwrap();
    let mut out = vec![0; size as usize];
    assert_eq!(fs.read_at(h, 0, &mut out).unwrap(), out.len());
    fs.close(h).unwrap();
    Some(out)
}
fn add(fs: &mut Fs<Disk>, step: u64, path: &str, data: &[u8]) -> Result<u64, String> {
    import_file(
        fs,
        &mut Cursor::new(data),
        step,
        path,
        data.len() as u64,
        Sha256::digest(data).into(),
        &mut [0; 4096],
        |_, _, _| Ok(()),
    )
}
fn no_temps(fs: &Fs<Disk>) {
    assert!(
        !fs.read_dir(b"/")
            .unwrap()
            .iter()
            .any(|(name, _)| name.starts_with(b".absd-import-"))
    );
    fs.check().unwrap();
}

#[test]
fn creates_append_prefixes_and_replace_commit_verified_bytes() {
    let (_, mut fs) = mounted();
    assert_eq!(add(&mut fs, 1, "/file", b"first").unwrap(), 0);
    let old = fs.stat(b"/file").unwrap().serial;
    let old_handle = fs
        .open(
            b"/file",
            OpenFlags {
                read: true,
                ..OpenFlags::default()
            },
        )
        .unwrap();
    assert_eq!(add(&mut fs, 3, "/file", b" second").unwrap(), 5);
    assert_ne!(fs.stat(b"/file").unwrap().serial, old);
    let mut prior = [0; 5];
    fs.read_at(old_handle, 0, &mut prior).unwrap();
    assert_eq!(&prior, b"first");
    fs.close(old_handle).unwrap();
    assert_eq!(add(&mut fs, 3, "/file", b" third").unwrap(), 12);
    assert_eq!(read(&mut fs, "/file").unwrap(), b"first second third");
    assert_eq!(add(&mut fs, 2, "/another", b"new").unwrap(), 0);
    assert_eq!(add(&mut fs, 4, "/file", b"replacement").unwrap(), 0);
    assert_eq!(read(&mut fs, "/file").unwrap(), b"replacement");
    no_temps(&fs);
}

#[test]
fn every_process_loss_boundary_remounts_old_or_verified_successor() {
    for step in 1..=4 {
        for cut in [
            Boundary::DirectoryCreated,
            Boundary::Created,
            Boundary::PrefixCopied,
            Boundary::InputWritten,
            Boundary::Synced,
            Boundary::Verified,
            Boundary::Renamed,
        ] {
            let (disk, mut fs) = mounted();
            let previous = if step >= 3 {
                put(&mut fs, "/file", b"prefix");
                Some(b"prefix".to_vec())
            } else {
                None
            };
            let data = vec![0x5a; 9000];
            let new = if step == 3 {
                [b"prefix".as_slice(), &data].concat()
            } else {
                data.clone()
            };
            let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                import_file(
                    &mut fs,
                    &mut Cursor::new(&data),
                    step,
                    "/file",
                    data.len() as u64,
                    Sha256::digest(&data).into(),
                    &mut [0; 4096],
                    |point, _, _| {
                        if point == cut {
                            panic!("simulated process loss: {point:?}");
                        }
                        Ok(())
                    },
                )
                .unwrap();
            }));
            assert!(stopped.is_err(), "step={step} cut={cut:?}");
            drop(fs);
            let mut reopened = Fs::mount(disk, true).unwrap();
            assert_eq!(
                read(&mut reopened, "/file"),
                if cut == Boundary::Renamed {
                    Some(new.clone())
                } else {
                    previous
                },
                "step={step} cut={cut:?}"
            );
            let temp = reopened
                .read_dir(b"/")
                .unwrap()
                .into_iter()
                .find(|(name, _)| name.starts_with(b".absd-import-"));
            if matches!(cut, Boundary::Synced | Boundary::Verified) {
                let name = temp.expect("durable candidate before rename").0;
                let path = format!("/{}/file", String::from_utf8(name).unwrap());
                assert_eq!(read(&mut reopened, &path), Some(new));
            } else if cut == Boundary::Renamed {
                let name = temp
                    .expect("owned empty directory before post-commit cleanup")
                    .0;
                assert!(
                    reopened
                        .read_dir(format!("/{}", String::from_utf8(name).unwrap()).as_bytes())
                        .unwrap()
                        .is_empty()
                );
            }
            reopened.check().unwrap();
        }
    }
}

#[test]
fn wrong_digest_and_truncated_input_never_publish_or_modify_the_final_file() {
    for step in 1..=4 {
        for truncated in [false, true] {
            let (_, mut fs) = mounted();
            if step >= 3 {
                put(&mut fs, "/file", b"old");
            }
            let before = read(&mut fs, "/file");
            let data = b"candidate";
            let supplied = if truncated { &data[..3] } else { &data[..] };
            let digest = if truncated {
                Sha256::digest(data).into()
            } else {
                [0x33; 32]
            };
            let result = import_file(
                &mut fs,
                &mut Cursor::new(supplied),
                step,
                "/file",
                data.len() as u64,
                digest,
                &mut [0; 4],
                |_, _, _| Ok(()),
            );
            assert!(result.is_err());
            assert_eq!(read(&mut fs, "/file"), before);
            no_temps(&fs);
        }
    }
}

#[test]
fn prefix_and_suffix_readback_mutation_refuse_without_replacing_the_original() {
    for offset in [0, 6] {
        let (_, mut fs) = mounted();
        put(&mut fs, "/file", b"prefix");
        let result = import_file(
            &mut fs,
            &mut Cursor::new(b"suffix"),
            3,
            "/file",
            6,
            Sha256::digest(b"suffix").into(),
            &mut [0; 4],
            |point, fs, temp| {
                if point == Boundary::Synced {
                    let h = fs
                        .open(
                            temp.as_bytes(),
                            OpenFlags {
                                write: true,
                                ..OpenFlags::default()
                            },
                        )
                        .unwrap();
                    fs.write_at(h, offset, b"!").unwrap();
                    fs.sync().unwrap();
                    fs.close(h).unwrap();
                }
                Ok(())
            },
        );
        assert!(result.unwrap_err().contains("digest mismatch"));
        assert_eq!(read(&mut fs, "/file").unwrap(), b"prefix");
        no_temps(&fs);
    }
}

#[test]
fn creation_does_not_overwrite_existing_or_intervening_destination() {
    for step in [1, 2] {
        let (_, mut fs) = mounted();
        put(&mut fs, "/file", b"existing");
        assert!(
            add(&mut fs, step, "/file", b"new")
                .unwrap_err()
                .contains("Exists")
        );
        assert_eq!(read(&mut fs, "/file").unwrap(), b"existing");
        no_temps(&fs);
        let (_, mut fs) = mounted();
        let result = import_file(
            &mut fs,
            &mut Cursor::new(b"new"),
            step,
            "/file",
            3,
            Sha256::digest(b"new").into(),
            &mut [0; 4],
            |point, fs, _| {
                if point == Boundary::Verified {
                    put(fs, "/file", b"intervening");
                }
                Ok(())
            },
        );
        assert!(result.unwrap_err().contains("Exists"));
        assert_eq!(read(&mut fs, "/file").unwrap(), b"intervening");
        no_temps(&fs);
    }
}

#[test]
fn append_refuses_missing_readonly_or_directory_sources() {
    let (_, mut fs) = mounted();
    assert!(
        add(&mut fs, 3, "/absent", b"new")
            .unwrap_err()
            .contains("NotFound")
    );
    put(&mut fs, "/file", b"old");
    fs.set_readonly_path(b"/file", true).unwrap();
    assert!(
        add(&mut fs, 3, "/file", b"new")
            .unwrap_err()
            .contains("Denied")
    );
    fs.mkdir(b"/directory").unwrap();
    assert!(
        add(&mut fs, 3, "/directory", b"new")
            .unwrap_err()
            .contains("IsDir")
    );
    assert_eq!(read(&mut fs, "/file").unwrap(), b"old");
    no_temps(&fs);
}

#[test]
fn temporary_collisions_are_never_removed_and_the_limit_refuses() {
    let (_, mut fs) = mounted();
    for n in 0..64 {
        put(&mut fs, &format!("/.absd-import-{n:04x}"), b"unrelated");
    }
    assert!(
        add(&mut fs, 2, "/file", b"new")
            .unwrap_err()
            .contains("collision limit")
    );
    for n in 0..64 {
        assert_eq!(
            read(&mut fs, &format!("/.absd-import-{n:04x}")).unwrap(),
            b"unrelated"
        );
    }
    assert_eq!(read(&mut fs, "/file"), None);
    fs.check().unwrap();
}

#[test]
fn insufficient_temp_capacity_refuses_before_construction() {
    let (_, mut fs) = mounted();
    put(&mut fs, "/file", &vec![0x41; 16384]);
    let fill = (fs.free_blocks() as usize - 1) * absd_fs::BLOCK;
    put(&mut fs, "/filler", &vec![0x42; fill]);
    let before = fs.free_blocks();
    assert!(
        add(&mut fs, 3, "/file", &[1; 8192])
            .unwrap_err()
            .contains("NoSpace temporary_blocks=")
    );
    assert_eq!(fs.free_blocks(), before);
    assert_eq!(read(&mut fs, "/file").unwrap(), vec![0x41; 16384]);
    no_temps(&fs);
}

#[test]
fn metadata_reserve_is_not_consumed_for_temp_creation() {
    let (_, mut fs) = mounted();
    put(&mut fs, "/file", b"old");
    fs.set_reserve(absd_fs::OBJECT_BUDGET);
    assert!(
        add(&mut fs, 3, "/file", b"new")
            .unwrap_err()
            .contains("NoSpace")
    );
    assert_eq!(read(&mut fs, "/file").unwrap(), b"old");
    no_temps(&fs);
}

#[test]
fn an_interrupted_synced_append_is_reconciled_before_retry_or_skip() {
    for cut in [Boundary::Verified, Boundary::Renamed] {
        let (disk, mut fs) = mounted();
        put(&mut fs, "/file", b"first");
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = import_file(
                &mut fs,
                &mut Cursor::new(b" second"),
                3,
                "/file",
                7,
                Sha256::digest(b" second").into(),
                &mut [0; 4],
                |p, _, _| {
                    if p == cut {
                        panic!("interrupted");
                    }
                    Ok(())
                },
            );
        }));
        drop(fs);
        let mut fs = Fs::mount(disk, true).unwrap();
        match read(&mut fs, "/file").unwrap().as_slice() {
            b"first" => {
                assert_eq!(cut, Boundary::Verified);
                add(&mut fs, 3, "/file", b" second").unwrap();
            }
            b"first second" => assert_eq!(cut, Boundary::Renamed),
            other => panic!("unrecognized prefix: {other:?}"),
        }
        assert_eq!(read(&mut fs, "/file").unwrap(), b"first second");
        // The abandoned candidate remains separately owned; retry did not delete it.
        if cut == Boundary::Verified {
            assert_eq!(
                read(&mut fs, "/.absd-import-0000/file").unwrap(),
                b"first second"
            );
        }
        fs.check().unwrap();
    }
}

#[test]
fn fixture_inputs_cannot_claim_the_temporary_namespace() {
    let (_, mut fs) = mounted();
    for path in ["/.absd-import-0000", "/x/.absd-import-1abc/file"] {
        assert!(
            add(&mut fs, 2, path, b"x")
                .unwrap_err()
                .contains("reserved")
        );
    }
    no_temps(&fs);
}

#[test]
fn replacement_refuses_readonly_target_instead_of_bypassing_it() {
    let (_, mut fs) = mounted();
    put(&mut fs, "/file", b"old");
    fs.set_readonly_path(b"/file", true).unwrap();
    assert!(
        add(&mut fs, 4, "/file", b"new")
            .unwrap_err()
            .contains("Denied")
    );
    assert_eq!(read(&mut fs, "/file").unwrap(), b"old");
    no_temps(&fs);
}

#[test]
fn shared_path_vectors_and_native_boundary_names_match_the_contract() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixture-import-paths.json")).unwrap();
    for row in rows.as_array().unwrap() {
        assert_eq!(
            file::reserved_path(row["path"].as_str().unwrap()),
            row["reserved"].as_bool().unwrap()
        );
    }
    let names: std::collections::BTreeSet<_> = [
        Boundary::DirectoryCreated,
        Boundary::Created,
        Boundary::PrefixCopied,
        Boundary::InputWritten,
        Boundary::Synced,
        Boundary::Verified,
        Boundary::Renamed,
    ]
    .into_iter()
    .map(Boundary::name)
    .collect();
    assert_eq!(names.len(), 7);
    assert_eq!(file::CHUNK, 64 * 1024);
}
