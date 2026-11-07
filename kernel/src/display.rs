#[cfg(test)]
use std::vec::Vec;

#[cfg(test)]
use crate::handle::MAX_HANDLES;
use crate::handle::{HandleError, HandleTable, Object, RIGHT_READ, RIGHT_WRITE};
use crate::syscall::{
    ERROR_AGAIN, ERROR_BAD_HANDLE, ERROR_FAULT, ERROR_INVALID, ERROR_IO, ERROR_RIGHTS, ERROR_STALE,
    ERROR_TOO_MANY_HANDLES,
};
use crate::user_memory::UserMemoryError;
use absd_fbcon::{Channel, Geometry};

#[cfg(not(test))]
static mut MIRROR_SUPPRESSED: bool = false;
#[cfg(not(test))]
static mut EMERGENCY: bool = false;
#[cfg(test)]
std::thread_local! {
    static MIRROR_SUPPRESSED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EMERGENCY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub fn set_presentation_owned(owned: bool) {
    #[cfg(test)]
    MIRROR_SUPPRESSED.with(|flag| flag.set(owned));
    #[cfg(not(test))]
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(MIRROR_SUPPRESSED), owned);
    }
}

pub fn mirror_suppressed() -> bool {
    #[cfg(test)]
    return MIRROR_SUPPRESSED.with(std::cell::Cell::get);
    #[cfg(not(test))]
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(MIRROR_SUPPRESSED))
    }
}

pub fn emergency_active() -> bool {
    #[cfg(test)]
    return EMERGENCY.with(std::cell::Cell::get);
    #[cfg(not(test))]
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(EMERGENCY))
    }
}

pub fn set_emergency() {
    #[cfg(test)]
    EMERGENCY.with(|flag| flag.set(true));
    #[cfg(not(test))]
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(EMERGENCY), true);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayState {
    pub writers: u32,
    pub generation: u64,
    pub next_generation: u64,
    pub high_water: u64,
    pub masked: bool,
    pub active: bool,
    pub geometry: Option<Geometry>,
    #[cfg(test)]
    pub pixels: Vec<u8>,
}

#[cfg(test)]
static TEST_STAGING_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static mut STAGING: [u8; 65536] = [0; 65536];

impl Default for DisplayState {
    fn default() -> Self {
        Self::new()
    }
}

impl DisplayState {
    pub const fn new_const() -> Self {
        Self {
            writers: 0,
            generation: 0,
            next_generation: 1,
            high_water: 0,
            masked: false,
            active: false,
            geometry: None,
            #[cfg(test)]
            pixels: Vec::new(),
        }
    }

    pub fn new() -> Self {
        let state = Self::new_const();
        #[cfg(test)]
        let state = {
            let mut state = state;
            state.pixels = vec![0; default_geometry().bytes()];
            state
        };
        state
    }

    pub fn open(
        &mut self,
        table: &mut HandleTable,
        pid: u64,
        framebuffer_ready: bool,
    ) -> Result<u64, i64> {
        if pid != 1 {
            return Err(ERROR_RIGHTS);
        }
        if !framebuffer_ready {
            return Err(ERROR_IO);
        }
        if self.writers != 0 || self.next_generation == u64::MAX {
            return Err(ERROR_AGAIN);
        }
        let generation = self.next_generation;
        let handle = table
            .insert(Object::Display(generation), RIGHT_READ | RIGHT_WRITE)
            .map_err(handle_error)?;
        self.next_generation += 1;
        self.generation = generation;
        self.high_water = 0;
        self.masked = false;
        self.active = true;
        self.geometry = Some(default_geometry());
        self.clear_buffer();
        self.masked = false;
        self.retain(RIGHT_WRITE);
        set_presentation_owned(true);
        Ok(handle)
    }

    pub fn retain(&mut self, rights: u8) {
        if rights & RIGHT_WRITE != 0 {
            self.writers += 1;
        }
    }

    pub fn release(&mut self, rights: u8) {
        if rights & RIGHT_WRITE != 0 {
            assert!(self.writers > 0);
            self.writers -= 1;
            if self.writers == 0 {
                self.active = false;
                self.masked = true;
                self.clear_buffer();
            }
        }
    }

    pub fn check(
        &self,
        table: &HandleTable,
        handle: u64,
        generation: u64,
        rights: u8,
    ) -> Result<(), i64> {
        let found = table.lookup(handle).map_err(handle_error)?;
        let Object::Display(open_generation) = found.object else {
            return Err(ERROR_BAD_HANDLE);
        };
        if !self.active || open_generation != generation || generation != self.generation {
            return Err(ERROR_STALE);
        }
        found.require(rights).map_err(handle_error)
    }

    pub fn info(&self, table: &HandleTable, handle: u64) -> Result<[u8; 48], i64> {
        let found = table.lookup(handle).map_err(handle_error)?;
        let Object::Display(open_generation) = found.object else {
            return Err(ERROR_BAD_HANDLE);
        };
        if !self.active || open_generation != self.generation {
            return Err(ERROR_STALE);
        }
        found.require(RIGHT_READ).map_err(handle_error)?;
        let geometry = self.geometry.ok_or(ERROR_IO)?;
        let mut record = [0u8; 48];
        put_u32(&mut record, 0, geometry.width as u32);
        put_u32(&mut record, 4, geometry.height as u32);
        put_u32(&mut record, 8, geometry.pitch as u32);
        record[12] = 32;
        record[13] = 1;
        for (offset, channel) in [
            (16, geometry.red),
            (18, geometry.green),
            (20, geometry.blue),
        ] {
            record[offset] = channel.shift;
            record[offset + 1] = channel.bits;
        }
        put_u64(&mut record, 24, self.generation);
        put_u64(&mut record, 32, self.high_water);
        put_u64(&mut record, 40, 65536);
        Ok(record)
    }

    pub fn present(
        &mut self,
        table: &HandleTable,
        handle: u64,
        request: [u8; 48],
        write: impl FnOnce(Geometry, u32, u32, u32, u32, u32, &[u8]) -> Result<(), i64>,
        validate: impl FnOnce(usize) -> Result<(), UserMemoryError>,
        mut copy: impl FnMut(&mut [u8]) -> Result<(), UserMemoryError>,
    ) -> Result<(), i64> {
        let sequence = u64_at(&request, 0);
        let x = u32_at(&request, 8);
        let y = u32_at(&request, 12);
        let width = u32_at(&request, 16);
        let height = u32_at(&request, 20);
        let pitch = u32_at(&request, 24);
        let format = u32_at(&request, 28);
        let payload_length = u64_at(&request, 32);
        let generation = u64_at(&request, 40);
        self.check(table, handle, generation, RIGHT_WRITE)?;
        if sequence == 0 || sequence <= self.high_water || self.high_water == u64::MAX {
            return Err(ERROR_STALE);
        }
        let geometry = self.geometry.ok_or(ERROR_IO)?;
        if format != 1 | (32 << 8) {
            return Err(ERROR_INVALID);
        }
        let payload_length = usize::try_from(payload_length).map_err(|_| ERROR_INVALID)?;
        validate_rectangle(geometry, x, y, width, height, pitch, payload_length)?;
        validate(payload_length).map_err(|_| ERROR_FAULT)?;
        #[cfg(test)]
        let _guard = TEST_STAGING_LOCK.lock().unwrap();
        let staging = unsafe { &mut *core::ptr::addr_of_mut!(STAGING) };
        copy(&mut staging[..payload_length]).map_err(|_| ERROR_FAULT)?;
        write_rect_to_buffer(
            self,
            geometry,
            x,
            y,
            width,
            height,
            pitch,
            &staging[..payload_length],
            write,
        )?;
        self.high_water = sequence;
        self.masked = false;
        Ok(())
    }

    pub fn mask(
        &mut self,
        table: &HandleTable,
        handle: u64,
        sequence: u64,
        generation: u64,
    ) -> Result<(), i64> {
        self.check(table, handle, generation, RIGHT_WRITE)?;
        if sequence == 0 || sequence <= self.high_water || self.high_water == u64::MAX {
            return Err(ERROR_STALE);
        }
        self.clear_buffer();
        self.masked = true;
        self.high_water = sequence;
        Ok(())
    }

    pub fn console_restore(
        &mut self,
        table: &HandleTable,
        handle: u64,
        sequence: u64,
        generation: u64,
    ) -> Result<(), i64> {
        self.check(table, handle, generation, RIGHT_WRITE)?;
        if sequence == 0 || sequence <= self.high_water || self.high_water == u64::MAX {
            return Err(ERROR_STALE);
        }
        set_presentation_owned(false);
        self.high_water = sequence;
        Ok(())
    }

    pub fn fault_fixture(
        &self,
        table: &HandleTable,
        handle: u64,
        generation: u64,
        fault_boot: bool,
        quiescent: bool,
    ) -> Result<(), i64> {
        self.check(table, handle, generation, RIGHT_WRITE)?;
        if !fault_boot || !quiescent {
            return Err(ERROR_INVALID);
        }
        Ok(())
    }

    #[cfg(test)]
    fn clear_buffer(&mut self) {
        let geometry = self.geometry.expect("geometry");
        for y in 0..geometry.height {
            for x in 0..geometry.width {
                let index = y * geometry.pitch + x * geometry.bytes_per_pixel;
                let value = 0x102040u32.to_le_bytes();
                self.pixels[index..index + geometry.bytes_per_pixel]
                    .copy_from_slice(&value[..geometry.bytes_per_pixel]);
            }
        }
    }

    #[cfg(not(test))]
    fn clear_buffer(&mut self) {}
}

pub fn boot_init_word(
    feature_enabled: bool,
    demo: bool,
    fault: bool,
    incompatible_smp: bool,
) -> Result<Option<u64>, i64> {
    if fault && !demo || incompatible_smp && (demo || fault) {
        return Err(crate::syscall::ERROR_INVALID);
    }
    if !feature_enabled {
        return if demo || fault {
            Err(crate::syscall::ERROR_NOT_IMPLEMENTED)
        } else {
            Ok(None)
        };
    }
    Ok(demo.then_some(0x4d57))
}

pub fn default_geometry() -> Geometry {
    Geometry::direct(
        1024,
        768,
        4096,
        32,
        Channel { shift: 16, bits: 8 },
        Channel { shift: 8, bits: 8 },
        Channel { shift: 0, bits: 8 },
    )
    .unwrap()
}

fn put_u32(record: &mut [u8; 48], offset: usize, value: u32) {
    record[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(record: &mut [u8; 48], offset: usize, value: u64) {
    record[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn u32_at(request: &[u8; 48], offset: usize) -> u32 {
    u32::from_le_bytes(request[offset..offset + 4].try_into().unwrap())
}

fn u64_at(request: &[u8; 48], offset: usize) -> u64 {
    u64::from_le_bytes(request[offset..offset + 8].try_into().unwrap())
}

pub fn request_snapshot(bytes: &[u8]) -> Result<[u8; 48], i64> {
    bytes.try_into().map_err(|_| ERROR_FAULT)
}

pub fn validate_rectangle(
    geometry: Geometry,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    pitch: u32,
    payload_length: usize,
) -> Result<(), i64> {
    if width == 0 || height == 0 || pitch == 0 || payload_length == 0 {
        return Err(ERROR_INVALID);
    }
    let row_bytes = width
        .checked_mul(geometry.bytes_per_pixel as u32)
        .ok_or(ERROR_INVALID)?;
    if pitch < row_bytes {
        return Err(ERROR_INVALID);
    }
    if x.checked_add(width)
        .is_none_or(|end| end > geometry.width as u32)
        || y.checked_add(height)
            .is_none_or(|end| end > geometry.height as u32)
    {
        return Err(ERROR_INVALID);
    }
    let expected = (pitch as usize)
        .checked_mul(height as usize)
        .ok_or(ERROR_INVALID)?;
    if expected != payload_length || payload_length > 65536 {
        return Err(ERROR_INVALID);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_rect_to_buffer(
    state: &mut DisplayState,
    geometry: Geometry,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    pitch: u32,
    payload: &[u8],
    write: impl FnOnce(Geometry, u32, u32, u32, u32, u32, &[u8]) -> Result<(), i64>,
) -> Result<(), i64> {
    validate_rectangle(geometry, x, y, width, height, pitch, payload.len())?;
    write(geometry, x, y, width, height, pitch, payload)?;
    #[cfg(test)]
    {
        for row in 0..height as usize {
            let destination =
                (y as usize + row) * geometry.pitch + x as usize * geometry.bytes_per_pixel;
            let source = row * pitch as usize;
            let count = width as usize * geometry.bytes_per_pixel;
            state.pixels[destination..destination + count]
                .copy_from_slice(&payload[source..source + count]);
        }
    }
    #[cfg(not(test))]
    let _ = state;
    Ok(())
}

fn handle_error(error: HandleError) -> i64 {
    match error {
        HandleError::Invalid => ERROR_BAD_HANDLE,
        HandleError::Rights => ERROR_RIGHTS,
        HandleError::Full => ERROR_TOO_MANY_HANDLES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_write(_: Geometry, _: u32, _: u32, _: u32, _: u32, _: u32, _: &[u8]) -> Result<(), i64> {
        Ok(())
    }

    fn open_fixture() -> (DisplayState, HandleTable, u64) {
        let mut state = DisplayState::new();
        let mut table = HandleTable::new(1);
        let handle = state.open(&mut table, 1, true).unwrap();
        (state, table, handle)
    }

    #[test]
    fn open_requires_pid1_and_one_writer_generation() {
        let mut state = DisplayState::new();
        let mut table = HandleTable::new(1);
        let handle = state.open(&mut table, 1, true).unwrap();
        assert_eq!(state.generation, 1);
        assert_eq!(state.writers, 1);
        assert_eq!(state.open(&mut table, 1, true), Err(ERROR_AGAIN));
        assert_eq!(state.open(&mut table, 2, true), Err(ERROR_RIGHTS));
        assert_eq!(
            state.check(&table, handle, 1, RIGHT_READ | RIGHT_WRITE),
            Ok(())
        );
    }

    #[test]
    fn duplicate_and_release_balance_writers_and_mask_only_on_last_close() {
        let (mut state, mut table, _handle) = open_fixture();
        state.retain(RIGHT_WRITE);
        assert_eq!(state.writers, 2);
        state.release(RIGHT_WRITE);
        assert!(!state.masked);
        state.release(RIGHT_WRITE);
        assert!(state.masked);
        let _successor = state.open(&mut table, 1, true).unwrap();
        assert_eq!(state.generation, 2);
        assert_eq!(state.high_water, 0);
    }

    #[test]
    fn failed_open_preserves_pixels_mirroring_generation_and_high_water() {
        let (mut state, mut table, _handle) = open_fixture();
        state.release(RIGHT_WRITE);
        let before = state.clone();
        for _ in 1..MAX_HANDLES {
            table.insert(Object::Console, RIGHT_READ).unwrap();
        }
        assert_eq!(state.open(&mut table, 1, true), Err(ERROR_TOO_MANY_HANDLES));
        assert_eq!(state, before);
    }

    #[test]
    fn old_read_only_reference_is_stale_after_reopen() {
        let (mut state, mut table, handle) = open_fixture();
        let (observer, _object) = table.duplicate(handle, RIGHT_READ).unwrap();
        state.release(RIGHT_WRITE);
        state.open(&mut table, 1, true).unwrap();
        assert_eq!(
            state.check(&table, observer, 2, RIGHT_READ),
            Err(ERROR_STALE)
        );
    }

    #[test]
    fn generation_exhaustion_preserves_state() {
        let (mut state, mut table, _handle) = open_fixture();
        state.release(RIGHT_WRITE);
        state.next_generation = u64::MAX;
        let before = state.clone();
        assert_eq!(state.open(&mut table, 1, true), Err(ERROR_AGAIN));
        assert_eq!(state, before);
    }

    #[test]
    fn mirroring_yields_only_to_explicit_restore_and_emergency_is_independent() {
        set_presentation_owned(true);
        assert!(mirror_suppressed());
        assert!(!emergency_active());
        set_emergency();
        assert!(emergency_active());
        set_presentation_owned(false);
        assert!(!mirror_suppressed());
        assert!(emergency_active());
    }

    const RGB32: u32 = 1 | (32 << 8);

    #[derive(Clone, Copy)]
    struct Rectangle {
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        color: u32,
    }

    impl Rectangle {
        fn new(x: u32, y: u32, width: u32, height: u32, color: u32) -> Self {
            Self {
                x,
                y,
                width,
                height,
                color,
            }
        }
    }

    fn expected_screen(rectangles: &[Rectangle]) -> Vec<u8> {
        let mut pixels = [0x40, 0x20, 0x10, 0x00].repeat(1024 * 768);
        for rectangle in rectangles {
            let color = rectangle.color.to_le_bytes();
            for y in rectangle.y..rectangle.y + rectangle.height {
                for x in rectangle.x..rectangle.x + rectangle.width {
                    let index = (y * 1024 + x) as usize * 4;
                    pixels[index..index + 4].copy_from_slice(&color);
                }
            }
        }
        pixels
    }

    #[allow(clippy::too_many_arguments)]
    fn request(
        sequence: u64,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        pitch: u32,
        format: u32,
        payload_length: u64,
        generation: u64,
    ) -> [u8; 48] {
        let mut request = [0u8; 48];
        request[0..8].copy_from_slice(&sequence.to_le_bytes());
        request[8..12].copy_from_slice(&x.to_le_bytes());
        request[12..16].copy_from_slice(&y.to_le_bytes());
        request[16..20].copy_from_slice(&width.to_le_bytes());
        request[20..24].copy_from_slice(&height.to_le_bytes());
        request[24..28].copy_from_slice(&pitch.to_le_bytes());
        request[28..32].copy_from_slice(&format.to_le_bytes());
        request[32..40].copy_from_slice(&payload_length.to_le_bytes());
        request[40..48].copy_from_slice(&generation.to_le_bytes());
        request
    }

    fn valid_payload() -> Vec<u8> {
        0x20c080u32.to_le_bytes().repeat(64 * 64)
    }

    #[test]
    fn present_copies_a_complete_rectangle_before_advancing() {
        let (mut state, table, handle) = open_fixture();
        let payload = valid_payload();
        let request = request(1, 16, 16, 64, 64, 256, RGB32, payload.len() as u64, 1);
        state
            .present(
                &table,
                handle,
                request,
                no_write,
                |_| Ok(()),
                |destination| {
                    destination.copy_from_slice(&payload);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            state.pixels,
            expected_screen(&[Rectangle::new(16, 16, 64, 64, 0x20c080)])
        );
        assert_eq!(state.high_water, 1);
    }

    #[test]
    fn later_page_copy_failure_has_no_effect() {
        let (mut state, table, handle) = open_fixture();
        let before = state.clone();
        let payload = valid_payload();
        let request = request(1, 16, 16, 64, 64, 256, RGB32, payload.len() as u64, 1);
        let result = state.present(
            &table,
            handle,
            request,
            no_write,
            |_| Ok(()),
            |destination| {
                destination[..256].copy_from_slice(&payload[..256]);
                Err(UserMemoryError::Unmapped)
            },
        );
        assert_eq!(result, Err(ERROR_FAULT));
        assert_eq!(state, before);
    }

    #[test]
    fn present_rejects_wrong_format_without_effects() {
        let (mut state, table, handle) = open_fixture();
        let before = state.clone();
        let payload = valid_payload();
        let request = request(1, 16, 16, 64, 64, 256, 0, payload.len() as u64, 1);
        assert_eq!(
            state.present(&table, handle, request, no_write, |_| Ok(()), |_| Ok(())),
            Err(ERROR_INVALID)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn present_rejects_out_of_frame_rectangle_without_effects() {
        let (mut state, table, handle) = open_fixture();
        let before = state.clone();
        let payload = valid_payload();
        let request = request(1, 1000, 16, 64, 64, 256, RGB32, payload.len() as u64, 1);
        assert_eq!(
            state.present(&table, handle, request, no_write, |_| Ok(()), |_| Ok(())),
            Err(ERROR_INVALID)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn present_rejects_oversized_payload_without_effects() {
        let (mut state, table, handle) = open_fixture();
        let before = state.clone();
        let payload = vec![0u8; 65537];
        let request = request(1, 0, 0, 1, 1, 65536, RGB32, payload.len() as u64, 1);
        assert_eq!(
            state.present(&table, handle, request, no_write, |_| Ok(()), |_| Ok(())),
            Err(ERROR_INVALID)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn present_rejects_wrong_generation_without_effects() {
        let (mut state, table, handle) = open_fixture();
        let before = state.clone();
        let payload = valid_payload();
        let request = request(1, 16, 16, 64, 64, 256, RGB32, payload.len() as u64, 2);
        assert_eq!(
            state.present(&table, handle, request, no_write, |_| Ok(()), |_| Ok(())),
            Err(ERROR_STALE)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn present_rejects_nonincreasing_sequence_without_effects() {
        let (mut state, table, handle) = open_fixture();
        let before = state.clone();
        let payload = valid_payload();
        let request = request(0, 16, 16, 64, 64, 256, RGB32, payload.len() as u64, 1);
        assert_eq!(
            state.present(&table, handle, request, no_write, |_| Ok(()), |_| Ok(())),
            Err(ERROR_STALE)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn read_only_and_missing_handles_cannot_mutate_display() {
        let (mut state, mut table, handle) = open_fixture();
        let before = state.clone();
        let (observer, _object) = table.duplicate(handle, RIGHT_READ).unwrap();
        let payload = valid_payload();
        let request = request(1, 16, 16, 64, 64, 256, RGB32, payload.len() as u64, 1);
        assert_eq!(
            state.present(&table, observer, request, no_write, |_| Ok(()), |_| Ok(())),
            Err(ERROR_RIGHTS)
        );
        assert_eq!(state.mask(&table, observer, 1, 1), Err(ERROR_RIGHTS));
        assert_eq!(
            state.console_restore(&table, observer, 1, 1),
            Err(ERROR_RIGHTS)
        );
        assert_eq!(
            state.fault_fixture(&table, observer, 1, true, true),
            Err(ERROR_RIGHTS)
        );
        assert_eq!(state.mask(&table, handle + 1, 1, 1), Err(ERROR_BAD_HANDLE));
        assert_eq!(state, before);
    }

    #[test]
    fn present_rejects_wrong_object_without_effects() {
        let (mut state, mut table, _handle) = open_fixture();
        let wrong = table
            .insert(Object::Console, RIGHT_READ | RIGHT_WRITE)
            .unwrap();
        let before = state.clone();
        let request = request(1, 16, 16, 64, 64, 256, RGB32, 16384, 1);
        assert_eq!(
            state.present(&table, wrong, request, no_write, |_| Ok(()), |_| Ok(())),
            Err(ERROR_BAD_HANDLE)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn present_rejects_closed_handle_without_effects() {
        let (mut state, mut table, handle) = open_fixture();
        let before = state.clone();
        table.close(handle).unwrap();
        let request = request(1, 16, 16, 64, 64, 256, RGB32, 16384, 1);
        assert_eq!(
            state.present(&table, handle, request, no_write, |_| Ok(()), |_| Ok(())),
            Err(ERROR_BAD_HANDLE)
        );
        assert_eq!(state, before);
    }

    #[test]
    fn mask_and_console_restore_follow_sequence() {
        let (mut state, table, handle) = open_fixture();
        let payload = valid_payload();
        let request = request(1, 16, 16, 64, 64, 256, RGB32, payload.len() as u64, 1);
        state
            .present(
                &table,
                handle,
                request,
                no_write,
                |_| Ok(()),
                |destination| {
                    destination.copy_from_slice(&payload);
                    Ok(())
                },
            )
            .unwrap();
        state.mask(&table, handle, 2, 1).unwrap();
        assert_eq!(state.pixels, expected_screen(&[]));
        assert_eq!(state.high_water, 2);
        assert!(mirror_suppressed());
        let before = state.clone();
        assert_eq!(
            state.console_restore(&table, handle, 3, 2),
            Err(ERROR_STALE)
        );
        assert_eq!(
            state.console_restore(&table, handle, 2, 1),
            Err(ERROR_STALE)
        );
        assert!(mirror_suppressed());
        assert_eq!(state, before);
        state.console_restore(&table, handle, 3, 1).unwrap();
        assert_eq!(state.high_water, 3);
        assert!(!mirror_suppressed());
        assert_eq!(state.mask(&table, handle, 2, 1), Err(ERROR_STALE));
    }

    #[test]
    fn fault_requires_current_writer_boot_gate_and_quiescence() {
        let (state, table, handle) = open_fixture();
        assert_eq!(state.fault_fixture(&table, handle, 1, true, true), Ok(()));
        assert_eq!(
            state.fault_fixture(&table, handle, 1, false, true),
            Err(ERROR_INVALID)
        );
        assert_eq!(
            state.fault_fixture(&table, handle, 1, true, false),
            Err(ERROR_INVALID)
        );
        assert_eq!(
            state.fault_fixture(&table, handle, 2, true, true),
            Err(ERROR_STALE)
        );
        assert_eq!(
            state.fault_fixture(&table, handle + 1, 1, true, true),
            Err(ERROR_BAD_HANDLE)
        );
    }

    #[test]
    fn info_uses_handle_generation_and_exposes_no_physical_address() {
        let (mut state, mut table, handle) = open_fixture();
        let record = state.info(&table, handle).unwrap();
        assert_eq!(&record[0..4], &1024u32.to_le_bytes());
        assert_eq!(&record[4..8], &768u32.to_le_bytes());
        assert_eq!(&record[8..12], &4096u32.to_le_bytes());
        assert_eq!(record[12], 32);
        assert_eq!(record[13], 1);
        assert_eq!(&record[14..16], &[0, 0]);
        assert_eq!(&record[16..22], &[16, 8, 8, 8, 0, 8]);
        assert_eq!(&record[22..24], &[0, 0]);
        assert_eq!(&record[24..32], &1u64.to_le_bytes());
        assert_eq!(&record[32..40], &0u64.to_le_bytes());
        assert_eq!(&record[40..48], &65536u64.to_le_bytes());
        let (observer, _) = table.duplicate(handle, RIGHT_READ).unwrap();
        state.release(RIGHT_WRITE);
        let before = state.clone();
        assert_eq!(state.info(&table, observer), Err(ERROR_STALE));
        assert_eq!(state, before);
    }

    #[test]
    fn request_snapshot_rejects_wrong_length() {
        assert_eq!(request_snapshot(&[0u8; 47]), Err(ERROR_FAULT));
        assert_eq!(request_snapshot(&[0u8; 49]), Err(ERROR_FAULT));
    }

    #[test]
    fn malformed_present_requests_never_validate_or_copy_user_payload() {
        let (mut state, table, handle) = open_fixture();
        let cases = [
            (
                request(1, 16, 16, 0, 64, 256, RGB32, 16384, 1),
                ERROR_INVALID,
            ),
            (request(1, 16, 16, 64, 0, 256, RGB32, 0, 1), ERROR_INVALID),
            (
                request(1, 16, 16, 64, 64, 255, RGB32, 16384, 1),
                ERROR_INVALID,
            ),
            (
                request(1, u32::MAX, 16, 64, 64, 256, RGB32, 16384, 1),
                ERROR_INVALID,
            ),
            (
                request(1, 16, 16, 64, 64, 256, RGB32, u64::MAX, 1),
                ERROR_INVALID,
            ),
            (
                request(1, 16, 16, 64, 64, 256, RGB32, 16384, 0),
                ERROR_STALE,
            ),
        ];
        for (request, expected) in cases {
            let before = state.clone();
            let result = state.present(
                &table,
                handle,
                request,
                no_write,
                |_| panic!("range validated"),
                |_| panic!("payload copied"),
            );
            assert_eq!(result, Err(expected));
            assert_eq!(state, before);
        }
    }

    #[test]
    fn payload_range_failure_happens_before_staging_copy() {
        let (mut state, table, handle) = open_fixture();
        let before = state.clone();
        let request = request(1, 16, 16, 64, 64, 256, RGB32, 16384, 1);
        let result = state.present(
            &table,
            handle,
            request,
            no_write,
            |length| {
                assert_eq!(length, 16384);
                Err(UserMemoryError::Unmapped)
            },
            |_| panic!("payload copied"),
        );
        assert_eq!(result, Err(ERROR_FAULT));
        assert_eq!(state, before);
    }

    #[test]
    fn nonincreasing_and_exhausted_sequences_preserve_all_mutations() {
        let (mut state, table, handle) = open_fixture();
        let payload = valid_payload();
        let initial = request(1, 16, 16, 64, 64, 256, RGB32, 16384, 1);
        state
            .present(
                &table,
                handle,
                initial,
                no_write,
                |_| Ok(()),
                |destination| {
                    destination.copy_from_slice(&payload);
                    Ok(())
                },
            )
            .unwrap();
        for sequence in [0, 1, u64::MAX] {
            state.high_water = if sequence == u64::MAX { u64::MAX } else { 1 };
            let before = state.clone();
            assert_eq!(state.mask(&table, handle, sequence, 1), Err(ERROR_STALE));
            assert_eq!(state, before);
            assert_eq!(
                state.present(
                    &table,
                    handle,
                    request(sequence, 16, 16, 64, 64, 256, RGB32, 16384, 1),
                    no_write,
                    |_| Ok(()),
                    |_| Ok(())
                ),
                Err(ERROR_STALE)
            );
            assert_eq!(state, before);
        }
    }

    #[test]
    fn boot_routing_refuses_unsupported_or_incompatible_modes() {
        use crate::syscall::ERROR_NOT_IMPLEMENTED;
        assert_eq!(boot_init_word(true, false, false, false), Ok(None));
        assert_eq!(boot_init_word(true, true, false, false), Ok(Some(0x4d57)));
        assert_eq!(boot_init_word(true, true, true, false), Ok(Some(0x4d57)));
        assert_eq!(boot_init_word(true, false, true, false), Err(ERROR_INVALID));
        assert_eq!(boot_init_word(true, true, false, true), Err(ERROR_INVALID));
        assert_eq!(
            boot_init_word(false, true, false, false),
            Err(ERROR_NOT_IMPLEMENTED)
        );
        assert_eq!(boot_init_word(false, false, false, false), Ok(None));
    }
}
