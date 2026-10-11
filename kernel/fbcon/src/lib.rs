//! Text rasterizer for a linear direct-colour framebuffer.
//!
//! This crate only knows pixel geometry, the embedded 8x13 font, and a
//! cursor. It draws into a byte slice, so the same code runs against the
//! firmware framebuffer in the kernel and against ordinary memory in host
//! tests. The console is a bounded ring of text rows: a newline clears the
//! row it enters and the row after it, and the cursor wraps from the last
//! row to the first. Nothing is ever read back or moved, so the cost of a
//! line does not depend on how slow framebuffer reads are, and a row is
//! cleared only as far as text was drawn on it.
#![no_std]

pub mod font8x13;

use font8x13 as font;

/// Normal console colours, as `0xRRGGBB`.
pub const FOREGROUND: u32 = 0x00e0_e0e0;
pub const BACKGROUND: u32 = 0x0010_2040;
/// Colours for kernel failure reports (panic, kernel fault, halt notice).
pub const FAULT_FOREGROUND: u32 = 0x00ff_ffff;
pub const FAULT_BACKGROUND: u32 = 0x00a0_0000;

/// Fewer text cells than this is not a usable console.
pub const MIN_COLUMNS: usize = 40;
pub const MIN_ROWS: usize = 8;
/// Rows beyond this are left unused on very tall screens.
pub const MAX_ROWS: usize = 256;
/// Screens at least this wide draw every font pixel as a 2x2 block.
pub const DOUBLE_SCALE_WIDTH: usize = 1600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Channel {
    pub shift: u8,
    pub bits: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// Only 24 and 32 bits per pixel are drawn.
    UnsupportedDepth(u8),
    /// A colour channel is empty, wider than 8 bits, or outside the pixel.
    BadChannel,
    PitchTooSmall,
    TooSmall,
    SizeOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    pub width: usize,
    pub height: usize,
    /// Bytes from one pixel row to the next.
    pub pitch: usize,
    pub bytes_per_pixel: usize,
    pub red: Channel,
    pub green: Channel,
    pub blue: Channel,
}

impl Geometry {
    /// A direct-colour (RGB) framebuffer as firmware describes it.
    pub fn direct(
        width: u32,
        height: u32,
        pitch: u32,
        bits_per_pixel: u8,
        red: Channel,
        green: Channel,
        blue: Channel,
    ) -> Result<Self, Refusal> {
        let bytes_per_pixel = match bits_per_pixel {
            24 => 3,
            32 => 4,
            other => return Err(Refusal::UnsupportedDepth(other)),
        };
        for channel in [red, green, blue] {
            if channel.bits == 0
                || channel.bits > 8
                || usize::from(channel.shift) + usize::from(channel.bits) > bytes_per_pixel * 8
            {
                return Err(Refusal::BadChannel);
            }
        }
        let width = width as usize;
        let height = height as usize;
        let pitch = pitch as usize;
        let row = width
            .checked_mul(bytes_per_pixel)
            .ok_or(Refusal::SizeOverflow)?;
        if pitch < row {
            return Err(Refusal::PitchTooSmall);
        }
        pitch.checked_mul(height).ok_or(Refusal::SizeOverflow)?;
        let geometry = Self {
            width,
            height,
            pitch,
            bytes_per_pixel,
            red,
            green,
            blue,
        };
        let scale = geometry.scale();
        if width / (font::GLYPH_WIDTH * scale) < MIN_COLUMNS
            || height / (font::GLYPH_HEIGHT * scale) < MIN_ROWS
        {
            return Err(Refusal::TooSmall);
        }
        Ok(geometry)
    }

    /// Bytes the framebuffer occupies.
    pub fn bytes(&self) -> usize {
        self.pitch * self.height
    }

    pub fn scale(&self) -> usize {
        if self.width >= DOUBLE_SCALE_WIDTH {
            2
        } else {
            1
        }
    }

    /// The pixel value for an `0xRRGGBB` colour.
    pub fn encode(&self, rgb: u32) -> u32 {
        let part = |value: u32, channel: Channel| {
            let value = value & 0xff;
            (value >> (8 - channel.bits)) << channel.shift
        };
        part(rgb >> 16, self.red) | part(rgb >> 8, self.green) | part(rgb, self.blue)
    }
}

/// The glyph drawn for `byte`: printable ASCII as itself, anything else as
/// `?`.
pub fn glyph(byte: u8) -> &'static [u8; font::GLYPH_HEIGHT] {
    let byte = if (font::FIRST..=font::LAST).contains(&byte) {
        byte
    } else {
        b'?'
    };
    &font::GLYPHS[usize::from(byte - font::FIRST)]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextConsole {
    geometry: Geometry,
    scale: usize,
    columns: usize,
    rows: usize,
    column: usize,
    row: usize,
    foreground: u32,
    background: u32,
    /// Cells drawn on each row since it was last cleared.
    extent: [u16; MAX_ROWS],
}

impl TextConsole {
    pub fn new(geometry: Geometry) -> Self {
        let scale = geometry.scale();
        Self {
            geometry,
            scale,
            columns: geometry.width / (font::GLYPH_WIDTH * scale),
            rows: (geometry.height / (font::GLYPH_HEIGHT * scale)).min(MAX_ROWS),
            column: 0,
            row: 0,
            foreground: geometry.encode(FOREGROUND),
            background: geometry.encode(BACKGROUND),
            extent: [0; MAX_ROWS],
        }
    }

    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub fn columns(&self) -> usize {
        self.columns
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn scale(&self) -> usize {
        self.scale
    }

    /// `(column, row)` of the next cell to be drawn.
    pub fn position(&self) -> (usize, usize) {
        (self.column, self.row)
    }

    /// Encoded `(foreground, background)` pixel values in use.
    pub fn colors(&self) -> (u32, u32) {
        (self.foreground, self.background)
    }

    pub fn set_colors(&mut self, foreground: u32, background: u32) {
        self.foreground = self.geometry.encode(foreground);
        self.background = self.geometry.encode(background);
    }

    /// Fills the whole framebuffer with the background and homes the cursor.
    pub fn clear(&mut self, frame: &mut [u8]) {
        for y in 0..self.geometry.height {
            self.fill_span(frame, y, 0, self.geometry.width, self.background);
        }
        self.extent = [0; MAX_ROWS];
        self.column = 0;
        self.row = 0;
    }

    pub fn write_bytes(&mut self, frame: &mut [u8], bytes: &[u8]) {
        for &byte in bytes {
            self.write_byte(frame, byte);
        }
    }

    pub fn write_byte(&mut self, frame: &mut [u8], byte: u8) {
        match byte {
            b'\n' => self.newline(frame),
            b'\r' => self.column = 0,
            b'\t' => {
                let stop = (self.column / 8 + 1) * 8;
                while self.column < stop.min(self.columns) {
                    self.write_byte(frame, b' ');
                }
            }
            _ => {
                // The wrap is deferred until a character needs the cell, so a
                // line of exactly `columns` characters and its newline do
                // not leave an empty row behind.
                if self.column == self.columns {
                    self.newline(frame);
                }
                self.draw_cell(frame, self.column, self.row, byte);
                self.column += 1;
                let extent = &mut self.extent[self.row];
                *extent = (*extent).max(self.column as u16);
            }
        }
    }

    fn newline(&mut self, frame: &mut [u8]) {
        self.column = 0;
        self.row = (self.row + 1) % self.rows;
        self.clear_row(frame, self.row);
        // Keep one blank row ahead of the cursor so the newest line is
        // visible after the ring wraps.
        self.clear_row(frame, (self.row + 1) % self.rows);
    }

    fn clear_row(&mut self, frame: &mut [u8], row: usize) {
        let cells = usize::from(self.extent[row]);
        if cells == 0 {
            return;
        }
        let height = font::GLYPH_HEIGHT * self.scale;
        let width = cells * font::GLYPH_WIDTH * self.scale;
        for y in row * height..(row + 1) * height {
            self.fill_span(frame, y, 0, width, self.background);
        }
        self.extent[row] = 0;
    }

    fn fill_span(&self, frame: &mut [u8], y: usize, x: usize, count: usize, value: u32) {
        let bytes = value.to_le_bytes();
        let step = self.geometry.bytes_per_pixel;
        let start = y * self.geometry.pitch + x * step;
        for pixel in frame[start..start + count * step].chunks_exact_mut(step) {
            pixel.copy_from_slice(&bytes[..step]);
        }
    }

    fn draw_cell(&self, frame: &mut [u8], column: usize, row: usize, byte: u8) {
        let rows = glyph(byte);
        let step = self.geometry.bytes_per_pixel;
        let foreground = self.foreground.to_le_bytes();
        let background = self.background.to_le_bytes();
        let left = column * font::GLYPH_WIDTH * self.scale;
        let top = row * font::GLYPH_HEIGHT * self.scale;
        for (glyph_y, bits) in rows.iter().enumerate() {
            for repeat_y in 0..self.scale {
                let y = top + glyph_y * self.scale + repeat_y;
                let line = y * self.geometry.pitch + left * step;
                let span = font::GLYPH_WIDTH * self.scale * step;
                for (index, pixel) in frame[line..line + span].chunks_exact_mut(step).enumerate() {
                    let glyph_x = index / self.scale;
                    let lit = bits & (0x80 >> glyph_x) != 0;
                    pixel.copy_from_slice(if lit {
                        &foreground[..step]
                    } else {
                        &background[..step]
                    });
                }
            }
        }
    }

    /// Whether every pixel of one cell shows `byte` in the given encoded
    /// colours.
    pub fn cell_matches(
        &self,
        frame: &[u8],
        column: usize,
        row: usize,
        byte: u8,
        colors: (u32, u32),
    ) -> bool {
        if column >= self.columns || row >= self.rows {
            return false;
        }
        let rows = glyph(byte);
        let step = self.geometry.bytes_per_pixel;
        let foreground = colors.0.to_le_bytes();
        let background = colors.1.to_le_bytes();
        let left = column * font::GLYPH_WIDTH * self.scale;
        let top = row * font::GLYPH_HEIGHT * self.scale;
        for y in 0..font::GLYPH_HEIGHT * self.scale {
            let bits = rows[y / self.scale];
            let line = (top + y) * self.geometry.pitch + left * step;
            for x in 0..font::GLYPH_WIDTH * self.scale {
                let expected = if bits & (0x80 >> (x / self.scale)) != 0 {
                    &foreground[..step]
                } else {
                    &background[..step]
                };
                let at = line + x * step;
                if frame[at..at + step] != *expected {
                    return false;
                }
            }
        }
        true
    }

    /// Checks that `text` (no control characters) was drawn starting at
    /// `start` in `colors`, following the same deferred wrap as
    /// `write_byte`. Returns the number of cells checked, or the first cell
    /// that differs.
    pub fn verify_text(
        &self,
        frame: &[u8],
        start: (usize, usize),
        text: &[u8],
        colors: (u32, u32),
    ) -> Result<usize, (usize, usize)> {
        let (mut column, mut row) = start;
        for &byte in text {
            if column == self.columns {
                column = 0;
                row = (row + 1) % self.rows;
            }
            if byte < b' ' || !self.cell_matches(frame, column, row, byte, colors) {
                return Err((column, row));
            }
            column += 1;
        }
        Ok(text.len())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const XRGB: (Channel, Channel, Channel) = (
        Channel { shift: 16, bits: 8 },
        Channel { shift: 8, bits: 8 },
        Channel { shift: 0, bits: 8 },
    );

    fn geometry(width: u32, height: u32, bpp: u8) -> Geometry {
        let pitch = width * u32::from(bpp / 8) + 64;
        Geometry::direct(width, height, pitch, bpp, XRGB.0, XRGB.1, XRGB.2).unwrap()
    }

    fn frame(geometry: &Geometry) -> Vec<u8> {
        vec![0xa5; geometry.bytes()]
    }

    fn pixel(geometry: &Geometry, frame: &[u8], x: usize, y: usize) -> u32 {
        let at = y * geometry.pitch + x * geometry.bytes_per_pixel;
        let mut bytes = [0u8; 4];
        bytes[..geometry.bytes_per_pixel]
            .copy_from_slice(&frame[at..at + geometry.bytes_per_pixel]);
        u32::from_le_bytes(bytes)
    }

    #[test]
    fn encodes_channel_positions_and_widths() {
        let rgb = geometry(640, 480, 32);
        assert_eq!(rgb.encode(0x12_34_56), 0x0012_3456);
        let bgr = Geometry::direct(
            640,
            480,
            2560,
            32,
            Channel { shift: 0, bits: 8 },
            Channel { shift: 8, bits: 8 },
            Channel { shift: 16, bits: 8 },
        )
        .unwrap();
        assert_eq!(bgr.encode(0x12_34_56), 0x0056_3412);
        let narrow = Geometry::direct(
            640,
            480,
            2560,
            32,
            Channel { shift: 20, bits: 6 },
            Channel { shift: 10, bits: 6 },
            Channel { shift: 0, bits: 6 },
        )
        .unwrap();
        assert_eq!(
            narrow.encode(0xff_80_04),
            (0x3f << 20) | (0x20 << 10) | 0x01
        );
    }

    #[test]
    fn refuses_what_it_cannot_draw() {
        let (r, g, b) = XRGB;
        assert_eq!(
            Geometry::direct(640, 480, 1280, 16, r, g, b),
            Err(Refusal::UnsupportedDepth(16))
        );
        assert_eq!(
            Geometry::direct(640, 480, 2559, 32, r, g, b),
            Err(Refusal::PitchTooSmall)
        );
        assert_eq!(
            Geometry::direct(200, 480, 800, 32, r, g, b),
            Err(Refusal::TooSmall)
        );
        let outside = Channel { shift: 20, bits: 8 };
        assert_eq!(
            Geometry::direct(640, 480, 1920, 24, outside, g, b),
            Err(Refusal::BadChannel)
        );
        assert_eq!(
            Geometry::direct(640, 480, 2560, 32, Channel { shift: 0, bits: 0 }, g, b),
            Err(Refusal::BadChannel)
        );
    }

    #[test]
    fn draws_glyph_pixels_exactly_and_nothing_else() {
        for bpp in [24, 32] {
            let geometry = geometry(640, 480, bpp);
            let mut frame = frame(&geometry);
            let mut console = TextConsole::new(geometry);
            console.clear(&mut frame);
            console.write_byte(&mut frame, b'A');
            let (foreground, background) = console.colors();
            let bits = glyph(b'A');
            for (y, row) in bits.iter().enumerate() {
                for x in 0..font::GLYPH_WIDTH {
                    let lit = row & (0x80 >> x) != 0;
                    let expected = if lit { foreground } else { background };
                    assert_eq!(
                        pixel(&geometry, &frame, x, y),
                        expected,
                        "bpp={bpp} x={x} y={y}"
                    );
                }
            }
            // The next cell and the pitch padding are untouched by the glyph.
            assert!(console.cell_matches(&frame, 1, 0, b' ', console.colors()));
            let padding = geometry.width * geometry.bytes_per_pixel;
            assert!(
                frame[padding..geometry.pitch]
                    .iter()
                    .all(|&byte| byte == 0xa5)
            );
            assert_eq!(console.position(), (1, 0));
        }
    }

    #[test]
    fn verify_text_finds_a_single_wrong_pixel() {
        let geometry = geometry(640, 480, 32);
        let mut frame = frame(&geometry);
        let mut console = TextConsole::new(geometry);
        console.clear(&mut frame);
        let text = b"ABSD KERNEL BOOT";
        console.write_bytes(&mut frame, text);
        let colors = console.colors();
        assert_eq!(
            console.verify_text(&frame, (0, 0), text, colors),
            Ok(text.len())
        );
        assert_eq!(
            console.verify_text(&frame, (0, 0), b"ABSD KERNEL BOOX", colors),
            Err((15, 0))
        );
        // Flip one background pixel inside the fourth cell.
        let at = 5 * geometry.pitch + (3 * font::GLYPH_WIDTH) * 4;
        frame[at] ^= 1;
        assert_eq!(
            console.verify_text(&frame, (0, 0), text, colors),
            Err((3, 0))
        );
    }

    #[test]
    fn newline_wraps_the_ring_and_keeps_a_blank_row_ahead() {
        let geometry = geometry(640, 480, 32);
        let mut frame = frame(&geometry);
        let mut console = TextConsole::new(geometry);
        console.clear(&mut frame);
        let rows = console.rows();
        for line in 0..rows + 2 {
            console.write_byte(&mut frame, b'a' + (line % 26) as u8);
            console.write_byte(&mut frame, b'\n');
        }
        // rows + 2 lines: the cursor is two rows past the wrap.
        assert_eq!(console.position(), (0, 2));
        let colors = console.colors();
        let last = rows + 1;
        assert!(console.cell_matches(&frame, 0, 1, b'a' + (last % 26) as u8, colors));
        // The cursor row and the one after it were cleared.
        assert!(console.cell_matches(&frame, 0, 2, b' ', colors));
        assert!(console.cell_matches(&frame, 0, 3, b' ', colors));
        // An older line beyond the gap survives.
        assert!(console.cell_matches(&frame, 0, 4, b'a' + 4, colors));
    }

    #[test]
    fn a_full_line_and_its_newline_leave_no_empty_row() {
        let geometry = geometry(640, 480, 32);
        let mut frame = frame(&geometry);
        let mut console = TextConsole::new(geometry);
        console.clear(&mut frame);
        let columns = console.columns();
        for _ in 0..columns {
            console.write_byte(&mut frame, b'x');
        }
        assert_eq!(console.position(), (columns, 0));
        console.write_byte(&mut frame, b'\n');
        console.write_byte(&mut frame, b'y');
        assert_eq!(console.position(), (1, 1));
        // A longer line wraps onto the next row.
        let text = vec![b'z'; columns + 3];
        let start = (0, 2);
        console.write_byte(&mut frame, b'\n');
        console.write_bytes(&mut frame, &text);
        assert_eq!(console.position(), (3, 3));
        assert_eq!(
            console.verify_text(&frame, start, &text, console.colors()),
            Ok(text.len())
        );
    }

    #[test]
    fn unprintable_bytes_draw_a_question_mark_and_tabs_align() {
        let geometry = geometry(640, 480, 32);
        let mut frame = frame(&geometry);
        let mut console = TextConsole::new(geometry);
        console.clear(&mut frame);
        console.write_bytes(&mut frame, &[0x01, 0xff, b'\t', b'k']);
        let colors = console.colors();
        assert!(console.cell_matches(&frame, 0, 0, b'?', colors));
        assert!(console.cell_matches(&frame, 1, 0, b'?', colors));
        assert!(console.cell_matches(&frame, 8, 0, b'k', colors));
    }

    #[test]
    fn fault_colours_apply_to_later_cells_only() {
        let geometry = geometry(640, 480, 32);
        let mut frame = frame(&geometry);
        let mut console = TextConsole::new(geometry);
        console.clear(&mut frame);
        console.write_byte(&mut frame, b'N');
        let normal = console.colors();
        console.set_colors(FAULT_FOREGROUND, FAULT_BACKGROUND);
        console.write_byte(&mut frame, b'F');
        let fault = console.colors();
        assert_ne!(normal, fault);
        assert!(console.cell_matches(&frame, 0, 0, b'N', normal));
        assert!(console.cell_matches(&frame, 1, 0, b'F', fault));
        assert!(!console.cell_matches(&frame, 1, 0, b'F', normal));
    }

    #[test]
    fn wide_screens_double_every_font_pixel() {
        let geometry = geometry(1920, 1080, 32);
        assert_eq!(geometry.scale(), 2);
        let mut frame = frame(&geometry);
        let mut console = TextConsole::new(geometry);
        assert_eq!(console.columns(), 1920 / 16);
        assert_eq!(console.rows(), 1080 / 26);
        console.clear(&mut frame);
        console.write_byte(&mut frame, b'#');
        let (foreground, background) = console.colors();
        let bits = glyph(b'#');
        for y in 0..font::GLYPH_HEIGHT * 2 {
            for x in 0..font::GLYPH_WIDTH * 2 {
                let lit = bits[y / 2] & (0x80 >> (x / 2)) != 0;
                let expected = if lit { foreground } else { background };
                assert_eq!(pixel(&geometry, &frame, x, y), expected);
            }
        }
        assert!(console.cell_matches(&frame, 0, 0, b'#', console.colors()));
    }

    #[test]
    fn every_glyph_leaves_its_top_row_blank() {
        // The host screendump oracle takes each cell's background from its
        // top-left pixel; that is only sound while no glyph lights it.
        for glyph in font::GLYPHS.iter() {
            assert_eq!(glyph[0] & 0x80, 0);
        }
    }
}
