//! x86 interrupt-vector reservations shared by BSP and AP IDTs.
pub const PIT: u8 = 0x20;
pub const SERIAL: u8 = 0x24;
pub const PIC_SPURIOUS_MASTER: u8 = 0x27;
pub const BLOCK: u8 = 0x2e;
pub const PIC_SPURIOUS_SLAVE: u8 = 0x2f;
pub const SYSCALL: u8 = 0x80;
pub const USB: u8 = 0xd0;
pub const AP_TIMER: u8 = 0xe0;
pub const AP_IPI: u8 = 0xf1;
pub const BSP_ACK: u8 = 0xf2;
pub const BSP_STOP: u8 = 0xf3;
pub const APIC_SPURIOUS: u8 = 0xff;

const _: () = {
    let vectors = [
        PIT,
        SERIAL,
        PIC_SPURIOUS_MASTER,
        BLOCK,
        PIC_SPURIOUS_SLAVE,
        SYSCALL,
        USB,
        AP_TIMER,
        AP_IPI,
        BSP_ACK,
        BSP_STOP,
        APIC_SPURIOUS,
    ];
    let mut i = 0;
    while i < vectors.len() {
        assert!(vectors[i] >= 32);
        let mut j = 0;
        while j < i {
            assert!(vectors[i] != vectors[j]);
            j += 1;
        }
        i += 1;
    }
};
