#![feature(restricted_std)]
//! Installed-boot fixture using FSD's existing filesystem and storage owners.
use absd_fs::{Error, OpenFlags};
use absd_runtime::storage;
const PATH: &[u8] = b"/native-installer-143";
const BYTES: &[u8] = b"ABSD native installer 143 persistent file v1\n";
fn main() {
    absd_runtime::link_anchor();
    // The pilot uses the same bounded native format/mount as FSD's first
    // mount, without claiming a selected release or a served SSH system.
    storage::mount(true, true).expect("mount installed filesystem");
    let mut fs = storage::take_mounted().expect("take installed filesystem");
    match fs.stat(PATH) {
        Ok(attr) => {
            assert_eq!(attr.size, BYTES.len() as u64);
            let handle = fs.open(PATH, OpenFlags { read: true, ..OpenFlags::default() }).expect("open installed file");
            let mut data = [0u8; BYTES.len()];
            assert_eq!(fs.read_at(handle, 0, &mut data).expect("read installed file"), BYTES.len());
            fs.close(handle).expect("close installed file");
            assert_eq!(data, BYTES, "installed file differs after cold boot");
            println!("INSTALL PERSIST VERIFIED");
        }
        Err(Error::NotFound) => {
            let flags = OpenFlags { read: false, write: true, create: false, create_new: true, truncate: false };
            let handle = fs.open(PATH, flags).expect("create installed file");
            assert_eq!(fs.write_at(handle, 0, BYTES).expect("write installed file"), BYTES.len());
            fs.close(handle).expect("close installed file");
            fs.sync().expect("sync installed file");
            println!("INSTALL PERSIST CREATED SYNCED");
        }
        Err(error) => panic!("stat installed file: {error:?}"),
    }
}
