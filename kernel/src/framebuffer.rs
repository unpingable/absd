//! The firmware framebuffer as a second console sink.
//!
//! GRUB sets a linear framebuffer because the Multiboot2 header asks for
//! one, and describes it in boot-information tag 8. Once `init` accepts it,
//! every byte written to COM1 is also drawn here (`serial::byte_out`), so
//! boot markers, process output, panics, and kernel fault reports reach the
//! screen on a machine without a serial port. Serial output is unchanged.

use absd_fbcon::{self as fbcon, Channel, Geometry, TextConsole};

use crate::mmio;

const TAG_FRAMEBUFFER: u32 = 8;
const TYPE_DIRECT_COLOR: u8 = 1;

/// Every printable ASCII character, drawn once at boot and read back.
pub const PROBE_TEXT: &[u8] = b"FRAMEBUFFER PROBE !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unavailable {
    /// The boot information carries no framebuffer tag.
    NoTag,
    /// The tag is shorter than its fields.
    Malformed,
    /// Indexed-colour or EGA text framebuffers are not drawn.
    NotDirectColor(u8),
    Geometry(fbcon::Refusal),
    Map(mmio::MapError),
}

struct State {
    console: TextConsole,
    /// Kernel virtual address of the mapping, and the firmware's physical one.
    address: u64,
    physical: u64,
    bytes: usize,
}

static mut STATE: Option<State> = None;
/// Set while a byte is being drawn. A fault raised by the drawing itself
/// re-enters through the fault report; the console then turns itself off so
/// the report still reaches serial.
static mut DRAWING: bool = false;

fn state() -> Option<&'static mut State> {
    unsafe { (*core::ptr::addr_of_mut!(STATE)).as_mut() }
}

fn frame(state: &State) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut(state.address as *mut u8, state.bytes) }
}

/// Finds, validates, maps, and clears the framebuffer. Draws nothing else.
pub fn init(info: *const u8, total_size: usize) -> Result<(), Unavailable> {
    let tag = find_tag(info, total_size).ok_or(Unavailable::NoTag)?;
    let (physical, geometry) = parse(tag)?;
    let address = mmio::map(
        physical,
        geometry.bytes() as u64,
        mmio::Cache::UncachedMinus,
    )
    .map_err(Unavailable::Map)?;
    let mut state = State {
        console: TextConsole::new(geometry),
        address,
        physical,
        bytes: geometry.bytes(),
    };
    let pixels = frame(&state);
    state.console.clear(pixels);
    unsafe {
        *core::ptr::addr_of_mut!(STATE) = Some(state);
    }
    Ok(())
}

fn find_tag(info: *const u8, total_size: usize) -> Option<&'static [u8]> {
    let mut offset = 8usize;
    while offset.checked_add(8).is_some_and(|end| end <= total_size) {
        let tag = unsafe { info.add(offset) };
        let kind = unsafe { core::ptr::read_unaligned(tag.cast::<u32>()) };
        let size = unsafe { core::ptr::read_unaligned(tag.add(4).cast::<u32>()) } as usize;
        if kind == 0 || size < 8 || offset.checked_add(size).is_none_or(|end| end > total_size) {
            return None;
        }
        if kind == TAG_FRAMEBUFFER {
            return Some(unsafe { core::slice::from_raw_parts(tag, size) });
        }
        offset += (size + 7) & !7;
    }
    None
}

/// Tag 8: address, pitch, width, height, bpp, type, then for direct colour
/// the red/green/blue field positions and mask sizes at offset 32.
fn parse(tag: &[u8]) -> Result<(u64, Geometry), Unavailable> {
    if tag.len() < 38 {
        return Err(Unavailable::Malformed);
    }
    let u32_at = |at: usize| u32::from_le_bytes([tag[at], tag[at + 1], tag[at + 2], tag[at + 3]]);
    let address = u64::from(u32_at(8)) | (u64::from(u32_at(12)) << 32);
    let pitch = u32_at(16);
    let width = u32_at(20);
    let height = u32_at(24);
    let bpp = tag[28];
    let kind = tag[29];
    if kind != TYPE_DIRECT_COLOR {
        return Err(Unavailable::NotDirectColor(kind));
    }
    let channel = |at: usize| Channel {
        shift: tag[at],
        bits: tag[at + 1],
    };
    let geometry = Geometry::direct(
        width,
        height,
        pitch,
        bpp,
        channel(32),
        channel(34),
        channel(36),
    )
    .map_err(Unavailable::Geometry)?;
    Ok((address, geometry))
}

/// Draws one console byte, if the framebuffer is active.
pub fn put(byte: u8) {
    let Some(state) = state() else {
        return;
    };
    unsafe {
        if core::ptr::read_volatile(core::ptr::addr_of!(DRAWING)) {
            *core::ptr::addr_of_mut!(STATE) = None;
            core::ptr::write_volatile(core::ptr::addr_of_mut!(DRAWING), false);
            return;
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DRAWING), true);
    }
    let frame = frame(state);
    state.console.write_byte(frame, byte);
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DRAWING), false);
    }
}

/// Later text is drawn in the failure colours.
pub fn fault_colors() {
    if let Some(state) = state() {
        state
            .console
            .set_colors(fbcon::FAULT_FOREGROUND, fbcon::FAULT_BACKGROUND);
    }
}

/// A line only the screen shows: serial logs stay byte-for-byte unchanged.
pub fn notice(text: &str, value: u64) {
    if state().is_none() {
        return;
    }
    for byte in text.bytes() {
        put(byte);
    }
    let mut digits = [0u8; 20];
    let mut count = 0;
    let mut rest = value;
    loop {
        digits[count] = b'0' + (rest % 10) as u8;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    for index in (0..count).rev() {
        put(digits[index]);
    }
    put(b'\n');
}

pub struct Summary {
    pub geometry: Geometry,
    pub columns: usize,
    pub rows: usize,
    pub scale: usize,
    pub address: u64,
}

pub fn summary() -> Option<Summary> {
    state().map(|state| Summary {
        geometry: state.console.geometry(),
        columns: state.console.columns(),
        rows: state.console.rows(),
        scale: state.console.scale(),
        address: state.physical,
    })
}

/// The next cell the console will draw.
pub fn position() -> Option<(usize, usize)> {
    state().map(|state| state.console.position())
}

/// Reads the framebuffer back and checks `text` was drawn from `start` in
/// the normal colours. Returns the number of cells checked.
pub fn verify(start: (usize, usize), text: &[u8]) -> Result<usize, (usize, usize)> {
    let state = state().ok_or((0, 0))?;
    let colors = state.console.colors();
    state.console.verify_text(frame(state), start, text, colors)
}
