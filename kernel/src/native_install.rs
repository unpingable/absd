//! QEMU-only binding of the tested installer to the existing AHCI/block owner.
use crate::{ahci_block, block, serial};
use absd_kernel::native_installer::{self as engine, Device, Disk, IoError, Outcome};

static PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/installer.bin"));
struct Target;
impl Disk for Target {
    fn read(&mut self, lba: u64, bytes: &mut [u8]) -> Result<(), IoError> {
        block::read_sectors(lba, bytes).map_err(|_| IoError)
    }
    fn write(&mut self, lba: u64, bytes: &[u8]) -> Result<(), IoError> {
        block::write_sectors(lba, bytes).map_err(|_| IoError)
    }
    fn flush(&mut self) -> Result<(), IoError> {
        block::flush().map_err(|_| IoError)
    }
}
pub fn run(consent: Option<&[u8]>) -> ! {
    let consent = consent.and_then(|word| {
        if word.len() != 8 {
            return None;
        }
        let mut value = 0u32;
        for byte in word {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => return None,
            };
            value = (value << 4) | u32::from(digit);
        }
        Some(value)
    });
    let outcome = match ahci_block::installer_identity() {
        Some((identity, unique))
            if !block::partitioned() && block::backend() == Some(block::Backend::Ahci) =>
        {
            serial::write("INSTALL PLAN serial=");
            serial::write(core::str::from_utf8(identity.serial()).unwrap_or("?"));
            serial::write(" model=");
            serial::write(core::str::from_utf8(identity.model()).unwrap_or("?"));
            serial::write(" sectors=");
            serial::decimal(identity.sectors);
            serial::write(" esp=256MiB state=2GiB policy=blank-whole-disk-only payload-crc=");
            serial::hex_digits(u64::from(absd_kernel::gpt::crc32(PAYLOAD)), 8);
            serial::write(
                "\nINSTALL POLICY: consent and identity must pass before the whole-disk blank check; no writes until complete\n",
            );
            engine::install(
                &mut Target,
                PAYLOAD,
                Device {
                    serial: identity.serial(),
                    model: identity.model(),
                    sectors: identity.sectors,
                    unique,
                    writable: block::writable(),
                },
                consent,
            )
        }
        _ => Outcome::Refused("unsupported-target"),
    };
    let (label, reason, status) = match outcome {
        Outcome::Installed => (
            "INSTALLED",
            "flush-readback-complete remove-install-media cold-boot",
            0,
        ),
        Outcome::Refused(reason) => ("REFUSED", reason, 2),
        Outcome::Incomplete(reason) => ("INCOMPLETE", reason, 3),
    };
    serial::write("INSTALL ");
    serial::write(label);
    serial::write(" ");
    serial::write(reason);
    serial::write("\n");
    if status == 3 {
        serial::write(
            "INSTALL RECOVERY: keep media and disk; inspect offline; automatic retry refused\n",
        );
    }
    crate::exit_qemu(status)
}
