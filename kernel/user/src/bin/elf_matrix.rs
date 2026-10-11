//! Adversarial ELF matrix for `spawn_image` (syscall 31). Every image is
//! built here byte by byte from one known-good template, and each case
//! mutates the fields it names. Around every case the probe takes a
//! `resource_census` (processes, handles, pipes, cells, frames) and requires
//! it unchanged afterwards, then starts a known-good control image whose PID
//! must follow the last one issued: a refusal leaves no slot, frame, handle,
//! or PID behind, and the loader still accepts a valid image. Accepted
//! images run a short self-check of their own memory (file bytes present,
//! bytes past `filesz` zero, permissions enforced) and report through their
//! exit status or fault. A terminal sentinel child spawned first must still
//! report its original outcome at the end. Run by `scripts/elf-matrix-test.sh`.
#![no_std]
#![no_main]

use absd_abi::layout::{USER_IMAGE_MAX, USER_IMAGE_MIN};
use absd_abi::syscall::{
    MAX_MAP_PAGES, RESOURCE_CENSUS_BYTES, SYS_RESOURCE_CENSUS, SYS_SPAWN_IMAGE, SpawnImageRequest,
};
use absd_user::{
    Child, MAX_SPAWN_IMAGE_BYTES, MultiStart, Outcome, Pipe, info, map, syscall3, time, unmap,
    wait, yield_now,
};
use core::fmt::Write as _;

absd_user::multi_entry!(main);

const BASE: u64 = USER_IMAGE_MIN;
const CODE_OFFSET: usize = 0x1000;
const CODE_VA: u64 = BASE;
const DATA_OFFSET: usize = 0x2000;
const DATA_VA: u64 = BASE + 0x10000;
const DATA_WORD: u32 = 0x1122_3344;
/// Bytes in the file past a segment's `filesz`; the loader must not copy them.
const GARBAGE: u8 = 0xaa;
const TEMPLATE_BYTES: usize = 0x3000;
const BUFFER_PAGES: u64 = 16;
const BUFFER_BYTES: usize = BUFFER_PAGES as usize * 4096;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_GNU_STACK: u32 = 0x6474_e551;
const R: u32 = 4;
const W: u32 = 2;
const X: u32 = 1;
const PAGE_FAULT: u64 = 14;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    Refused(i64),
    Exited(i32),
    Faulted(u64),
    Killed,
}

#[derive(Clone, Copy)]
enum Op {
    /// Exit with the check's index unless the dword at the address matches.
    Check(u64, u32),
    /// Store one byte (a fault if the page is not writable).
    Store(u64, u8),
    /// Jump to the address (a fault if the page is not executable).
    Jump(u64),
}

/// Encodes `ops` and a final `exit(42)`. A failed check exits with its
/// one-based index.
fn assemble(ops: &[Op], out: &mut [u8]) -> usize {
    let mut n = 0;
    let mut fixups = [0usize; 16];
    let mut fixup_count = 0;
    let mut emit = |bytes: &[u8], n: &mut usize| {
        out[*n..*n + bytes.len()].copy_from_slice(bytes);
        *n += bytes.len();
    };
    for (index, op) in ops.iter().enumerate() {
        match *op {
            Op::Check(address, value) => {
                emit(&[0xbf], &mut n); // mov edi, imm32
                emit(&(index as u32 + 1).to_le_bytes(), &mut n);
                emit(&[0x48, 0xb8], &mut n); // mov rax, imm64
                emit(&address.to_le_bytes(), &mut n);
                emit(&[0x8b, 0x00], &mut n); // mov eax, [rax]
                emit(&[0x3d], &mut n); // cmp eax, imm32
                emit(&value.to_le_bytes(), &mut n);
                emit(&[0x0f, 0x85], &mut n); // jne exit
                fixups[fixup_count] = n;
                fixup_count += 1;
                emit(&[0; 4], &mut n);
            }
            Op::Store(address, value) => {
                emit(&[0x48, 0xb8], &mut n);
                emit(&address.to_le_bytes(), &mut n);
                emit(&[0xc6, 0x00, value], &mut n); // mov byte [rax], imm8
            }
            Op::Jump(address) => {
                emit(&[0x48, 0xb8], &mut n);
                emit(&address.to_le_bytes(), &mut n);
                emit(&[0xff, 0xe0], &mut n); // jmp rax
            }
        }
    }
    emit(&[0xbf, 42, 0, 0, 0], &mut n); // mov edi, 42
    let exit = n;
    emit(&[0xb8, 3, 0, 0, 0, 0xcd, 0x80, 0x0f, 0x0b], &mut n); // exit; ud2
    for &at in &fixups[..fixup_count] {
        let relative = (exit as i64 - (at as i64 + 4)) as i32;
        out[at..at + 4].copy_from_slice(&relative.to_le_bytes());
    }
    n
}

const DEFAULT_CHECKS: [Op; 5] = [
    Op::Check(DATA_VA, DATA_WORD),
    Op::Check(DATA_VA + 0x10, 0),
    Op::Check(DATA_VA + 0xffc, 0),
    Op::Check(DATA_VA + 0x1000, 0),
    Op::Check(DATA_VA + 0x1ffc, 0),
];

struct Img {
    base: *mut u8,
    capacity: usize,
    len: usize,
}

impl Img {
    fn bytes(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.base, self.capacity) }
    }
    fn put16(&mut self, at: usize, value: u16) {
        self.bytes()[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(&mut self, at: usize, value: u32) {
        self.bytes()[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(&mut self, at: usize, value: u64) {
        self.bytes()[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn entry(&mut self, entry: u64) {
        self.put64(24, entry);
    }
    fn phnum(&mut self, count: u16) {
        self.put16(56, count);
    }
    /// Program header `index` of the table at offset 64.
    #[allow(clippy::too_many_arguments)]
    fn ph(
        &mut self,
        index: usize,
        kind: u32,
        flags: u32,
        offset: u64,
        va: u64,
        filesz: u64,
        memsz: u64,
        align: u64,
    ) {
        let at = 64 + index * 56;
        self.put32(at, kind);
        self.put32(at + 4, flags);
        self.put64(at + 8, offset);
        self.put64(at + 16, va);
        self.put64(at + 24, va);
        self.put64(at + 32, filesz);
        self.put64(at + 40, memsz);
        self.put64(at + 48, align);
    }
    fn ph_field(&mut self, index: usize, field: usize, value: u64) {
        let at = 64 + index * 56 + field;
        if field < 8 {
            self.put32(at, value as u32);
        } else {
            self.put64(at, value);
        }
    }
    /// The template: header; code (R+X, one page) at `CODE_VA` from file
    /// offset 0x1000 running `ops`; data (R+W, 0x10 file bytes, two pages
    /// of memory) at `DATA_VA` from 0x2000, the rest of that file page
    /// garbage the loader must not copy.
    fn template(&mut self, ops: &[Op]) {
        self.bytes()[..TEMPLATE_BYTES].fill(0);
        self.len = TEMPLATE_BYTES;
        let header = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        self.bytes()[0..8].copy_from_slice(&header);
        self.put16(16, 2);
        self.put16(18, 62);
        self.put32(20, 1);
        self.entry(CODE_VA);
        self.put64(32, 64);
        self.put16(52, 64);
        self.put16(54, 56);
        self.phnum(2);
        let mut code = [0u8; 512];
        let code_len = assemble(ops, &mut code);
        self.bytes()[CODE_OFFSET..CODE_OFFSET + code_len].copy_from_slice(&code[..code_len]);
        self.ph(
            0,
            PT_LOAD,
            R | X,
            CODE_OFFSET as u64,
            CODE_VA,
            code_len as u64,
            0x1000,
            0x1000,
        );
        self.ph(
            1,
            PT_LOAD,
            R | W,
            DATA_OFFSET as u64,
            DATA_VA,
            0x10,
            0x2000,
            0x1000,
        );
        self.put32(DATA_OFFSET, DATA_WORD);
        self.bytes()[DATA_OFFSET + 4..DATA_OFFSET + 0x10].fill(0x55);
        self.bytes()[DATA_OFFSET + 0x10..TEMPLATE_BYTES].fill(GARBAGE);
    }
}

/// A one-segment image whose code exits 42: the control spawned after every
/// case. It lives on the stack so the 32 MiB case can use the whole heap.
fn control_image() -> [u8; 160] {
    let mut bytes = [0u8; 160];
    bytes[0..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    let mut put = |at: usize, value: &[u8]| bytes[at..at + value.len()].copy_from_slice(value);
    put(16, &2u16.to_le_bytes());
    put(18, &62u16.to_le_bytes());
    put(20, &1u32.to_le_bytes());
    put(24, &(BASE + 120).to_le_bytes());
    put(32, &64u64.to_le_bytes());
    put(52, &64u16.to_le_bytes());
    put(54, &56u16.to_le_bytes());
    put(56, &1u16.to_le_bytes());
    put(64, &PT_LOAD.to_le_bytes());
    put(68, &(R | X).to_le_bytes());
    put(80, &BASE.to_le_bytes());
    put(88, &BASE.to_le_bytes());
    put(96, &160u64.to_le_bytes());
    put(104, &160u64.to_le_bytes());
    put(112, &0x1000u64.to_le_bytes());
    put(
        120,
        &[0xbf, 42, 0, 0, 0, 0xb8, 3, 0, 0, 0, 0xcd, 0x80, 0x0f, 0x0b],
    );
    bytes
}

fn spawn_raw(image: u64, length: u64) -> i64 {
    let request = SpawnImageRequest {
        image,
        image_bytes: length,
        handles: 0,
        handle_count: 0,
    };
    unsafe { syscall3(SYS_SPAWN_IMAGE, &request as *const _ as u64, 0, 0) }
}

fn census() -> [u64; 5] {
    let mut record = [0u64; 5];
    const _: () = assert!(RESOURCE_CENSUS_BYTES == 40);
    let code = unsafe { syscall3(SYS_RESOURCE_CENSUS, record.as_mut_ptr() as u64, 0, 0) };
    if code != 0 {
        return [u64::MAX; 5];
    }
    record
}

struct Run<'a> {
    console: absd_user::Console,
    control: &'a [u8],
    last_pid: u64,
    cases: u32,
    mismatches: u32,
}

impl Run<'_> {
    /// Starts an image; a started child is reaped and reported by outcome.
    /// The child's PID must be the next one.
    fn spawn(&mut self, image: u64, length: u64) -> Result<Seen, &'static str> {
        let raw = spawn_raw(image, length);
        if raw < 0 {
            return Ok(Seen::Refused(raw));
        }
        let child = Child::from_raw(raw as u64);
        let pid = info(Some(child)).map_err(|_| "info")?.pid;
        if pid != self.last_pid + 1 {
            return Err("pid not contiguous");
        }
        self.last_pid = pid;
        Ok(match wait(Some(child)).map_err(|_| "wait")? {
            Outcome::Exited(status) => Seen::Exited(status),
            Outcome::Faulted { vector, .. } => Seen::Faulted(vector),
            Outcome::Killed => Seen::Killed,
        })
    }

    fn case(
        &mut self,
        name: &str,
        image: u64,
        length: u64,
        expected: Seen,
    ) -> Result<(), &'static str> {
        let before = census();
        let seen = self.spawn(image, length)?;
        let after = census();
        if before != after || before[0] == u64::MAX {
            let _ = writeln!(
                self.console,
                "ELF {name} CENSUS before={before:?} after={after:?}"
            );
            return Err("census changed");
        }
        // The loader takes a valid image immediately afterwards.
        let control = self.spawn(self.control.as_ptr() as u64, self.control.len() as u64)?;
        if control != Seen::Exited(42) || census() != before {
            return Err("control after case");
        }
        self.cases += 1;
        let verdict = if seen == expected { "" } else { " MISMATCH" };
        if seen != expected {
            self.mismatches += 1;
        }
        let _ = match seen {
            Seen::Refused(code) => writeln!(self.console, "ELF {name} refused={code}{verdict}"),
            Seen::Exited(status) => writeln!(self.console, "ELF {name} exit={status}{verdict}"),
            Seen::Faulted(vector) => writeln!(self.console, "ELF {name} fault={vector}{verdict}"),
            Seen::Killed => writeln!(self.console, "ELF {name} killed{verdict}"),
        };
        Ok(())
    }

    fn img(&mut self, name: &str, img: &Img, expected: Seen) -> Result<(), &'static str> {
        self.case(name, img.base as u64, img.len as u64, expected)
    }
}

const NOEXEC: Seen = Seen::Refused(absd_abi::syscall::ERROR_NOT_EXECUTABLE);
const INVALID: Seen = Seen::Refused(absd_abi::syscall::ERROR_INVALID);
const OK: Seen = Seen::Exited(42);
const PF: Seen = Seen::Faulted(PAGE_FAULT);

fn main(start: MultiStart<'_>) -> i32 {
    let mut console = start.console;
    match start
        .handles
        .first()
        .ok_or("matrix input handle")
        .and_then(|&input| run(start.console, input))
    {
        Ok((cases, 0)) => {
            let _ = writeln!(console, "ELF MATRIX OK cases={cases}");
            0
        }
        Ok((cases, mismatches)) => {
            let _ = writeln!(
                console,
                "ELF MATRIX FAILED cases={cases} mismatches={mismatches}"
            );
            1
        }
        Err(step) => {
            let _ = writeln!(console, "ELF MATRIX FAILED at {step}");
            1
        }
    }
}

fn run(console: absd_user::Console, input: u64) -> Result<(u32, u32), &'static str> {
    // The qualification supplies empty input. EOF proves init has completed
    // its setup handle closes before our exact instantaneous census begins.
    // Keep the reader open; accepting nonempty input would hide a bad fixture.
    let mut byte = [0u8; 1];
    if Pipe::from_raw(input).read_timeout(&mut byte, 500) != Ok(0) {
        return Err("matrix initial input EOF");
    }
    let control = control_image();
    let mut run = Run {
        console,
        control: &control,
        last_pid: 0,
        cases: 0,
        mismatches: 0,
    };
    // The sentinel: an unrelated child that has exited and is not yet
    // reaped. Its PID seeds the contiguity chain; its outcome must survive.
    let raw = spawn_raw(control.as_ptr() as u64, control.len() as u64);
    if raw < 0 {
        return Err("sentinel");
    }
    let sentinel = Child::from_raw(raw as u64);
    run.last_pid = info(Some(sentinel)).map_err(|_| "sentinel info")?.pid;
    // Establish the documented terminal-but-unreaped sentinel baseline.
    // Its retained outcome and PID remain independently checked at the end.
    let begin = time();
    while info(Some(sentinel))
        .map_err(|_| "sentinel terminal info")?
        .state
        != absd_user::INFO_STATE_TERMINAL
    {
        if time().wrapping_sub(begin) >= 500 {
            return Err("sentinel terminal deadline");
        }
        yield_now();
    }

    let base = map(BUFFER_PAGES).map_err(|_| "map")?;
    let mut img = Img {
        base,
        capacity: BUFFER_BYTES,
        len: 0,
    };
    let at = base as u64;

    // The template itself, and its header-field mutations.
    img.template(&DEFAULT_CHECKS);
    run.img("template", &img, OK)?;
    for (name, length) in [
        ("len-1", 1u64),
        ("len-63", 63),
        ("len-64", 64),
        ("ph-truncated", 64 + 56 + 10),
    ] {
        run.case(name, at, length, NOEXEC)?;
    }
    let header_cases: [(&str, usize, u8, Seen); 11] = [
        ("magic", 1, b'X', NOEXEC),
        ("class-32", 4, 1, NOEXEC),
        ("class-3", 4, 3, NOEXEC),
        ("endian-big", 5, 2, NOEXEC),
        ("type-dyn", 16, 3, NOEXEC),
        ("type-rel", 16, 1, NOEXEC),
        ("machine-386", 18, 3, NOEXEC),
        ("version-0", 20, 0, NOEXEC),
        ("version-2", 20, 2, NOEXEC),
        // Fields the parser never reads: accepted unchanged.
        ("ident-version-0", 6, 0, OK),
        ("osabi-255", 7, 255, OK),
    ];
    for (name, offset, value, expected) in header_cases {
        img.template(&DEFAULT_CHECKS);
        img.bytes()[offset] = value;
        run.img(name, &img, expected)?;
    }
    img.template(&DEFAULT_CHECKS);
    img.put16(52, 0xffff);
    run.img("ehsize-ffff", &img, OK)?;
    for (name, size) in [
        ("phentsize-0", 0u16),
        ("phentsize-55", 55),
        ("phentsize-57", 57),
        ("phentsize-ffff", 0xffff),
    ] {
        img.template(&DEFAULT_CHECKS);
        img.put16(54, size);
        run.img(name, &img, NOEXEC)?;
    }
    for (name, count) in [("phnum-0", 0u16), ("phnum-ffff", 0xffff)] {
        img.template(&DEFAULT_CHECKS);
        img.phnum(count);
        run.img(name, &img, NOEXEC)?;
    }
    for (name, offset) in [
        ("phoff-overflow", u64::MAX - 8),
        ("phoff-at-end", TEMPLATE_BYTES as u64),
        ("phoff-straddles-end", TEMPLATE_BYTES as u64 - 56),
    ] {
        img.template(&DEFAULT_CHECKS);
        img.put64(32, offset);
        run.img(name, &img, NOEXEC)?;
    }
    // An unaligned table one byte later is read bytewise and accepted.
    img.template(&DEFAULT_CHECKS);
    let table: [u8; 112] = img.bytes()[64..176].try_into().unwrap();
    img.bytes()[65..177].copy_from_slice(&table);
    img.put64(32, 65);
    run.img("phoff-unaligned", &img, OK)?;

    // Arithmetic and bounds on one data segment (ph 1).
    let data_cases: [(&str, usize, u64, Seen); 9] = [
        ("offset-overflow", 8, u64::MAX - 0xf, NOEXEC),
        (
            "offset-beyond-image",
            8,
            TEMPLATE_BYTES as u64 - 0xf,
            NOEXEC,
        ),
        (
            "filesz-beyond-image",
            32,
            (TEMPLATE_BYTES - DATA_OFFSET) as u64 + 1,
            NOEXEC,
        ),
        ("filesz-gt-memsz", 32, 0x2001, NOEXEC),
        ("vaddr-overflow", 16, 0xffff_ffff_ffff_f000, NOEXEC),
        ("memsz-huge", 40, 1 << 63, NOEXEC),
        ("memsz-0", 40, 0, NOEXEC),
        ("vaddr-noncanonical", 16, 0x8000_0000_0000_0000, NOEXEC),
        ("vaddr-kernel-half", 16, 0xffff_8000_0000_0000, NOEXEC),
    ];
    for (name, field, value, expected) in data_cases {
        img.template(&DEFAULT_CHECKS);
        img.ph_field(1, field, value);
        if field == 16 {
            img.ph_field(1, 24, value);
        }
        run.img(name, &img, expected)?;
    }
    // vaddr + memsz == u64::MAX exactly: no add overflow, so only the
    // window check stands between it and page rounding.
    img.template(&DEFAULT_CHECKS);
    img.ph(
        1,
        PT_LOAD,
        R | W,
        DATA_OFFSET as u64,
        0xffff_ffff_ffff_f000,
        0x10,
        0xfff,
        0x1000,
    );
    run.img("end-at-u64-max", &img, NOEXEC)?;
    // The data occupies the last file byte exactly.
    img.template(&DEFAULT_CHECKS);
    img.len = DATA_OFFSET + 0x10;
    run.img("filesz-at-image-end", &img, OK)?;
    // The window's last page, and one byte past it.
    let last = USER_IMAGE_MAX - 0x1000;
    img.template(&[Op::Check(last, DATA_WORD), Op::Check(last + 0xffc, 0)]);
    img.ph(
        1,
        PT_LOAD,
        R | W,
        DATA_OFFSET as u64,
        last,
        0x10,
        0x1000,
        0x1000,
    );
    run.img("window-last-page", &img, OK)?;
    img.ph_field(1, 40, 0x1001);
    run.img("window-past-end", &img, NOEXEC)?;
    img.template(&DEFAULT_CHECKS);
    img.ph(
        1,
        PT_LOAD,
        R | W,
        DATA_OFFSET as u64,
        BASE - 0x1000,
        0x10,
        0x1000,
        0x1000,
    );
    run.img("window-below-start", &img, NOEXEC)?;

    // Segment relationships (ph 2 added).
    img.template(&[Op::Check(DATA_VA, 0), Op::Check(DATA_VA + 0x1ffc, 0)]);
    img.ph_field(1, 32, 0);
    run.img("filesz-0-bss-only", &img, OK)?;
    let pair_cases: [(&str, u32, u64, u64, u64, u64, Seen); 6] = [
        // (name, flags, offset, vaddr, filesz, memsz)
        (
            "overlap-bytes",
            R | W,
            0x2000,
            DATA_VA + 0x1000,
            0x10,
            0x1000,
            NOEXEC,
        ),
        (
            "same-start-conflicting",
            R | X,
            0x2000,
            DATA_VA,
            0x10,
            0x1000,
            NOEXEC,
        ),
        (
            "same-start-identical",
            R | W,
            0x2000,
            DATA_VA,
            0x10,
            0x2000,
            NOEXEC,
        ),
        (
            "disjoint-bytes-shared-page",
            R | W,
            0x2800,
            DATA_VA + 0x1800,
            0x10,
            0x10,
            NOEXEC,
        ),
        ("overlap-code", R | W, 0x1000, CODE_VA, 0x10, 0x10, NOEXEC),
        ("memsz-0-extra", R, 0x2000, DATA_VA + 0x4000, 0, 0, NOEXEC),
    ];
    for (name, flags, offset, va, filesz, memsz, expected) in pair_cases {
        img.template(&DEFAULT_CHECKS);
        img.phnum(3);
        img.ph(2, PT_LOAD, flags, offset, va, filesz, memsz, 0x1000);
        run.img(name, &img, expected)?;
    }
    let mut checks = [Op::Check(0, 0); 6];
    checks[..5].copy_from_slice(&DEFAULT_CHECKS);
    checks[5] = Op::Check(DATA_VA + 0x2000, DATA_WORD);
    img.template(&checks);
    img.phnum(3);
    img.ph(
        2,
        PT_LOAD,
        R | W,
        0x2000,
        DATA_VA + 0x2000,
        0x10,
        0x1000,
        0x1000,
    );
    run.img("adjacent-pages", &img, OK)?;
    img.template(&DEFAULT_CHECKS);
    let table: [u8; 112] = img.bytes()[64..176].try_into().unwrap();
    img.bytes()[64..120].copy_from_slice(&table[56..]);
    img.bytes()[120..176].copy_from_slice(&table[..56]);
    run.img("descending-order", &img, OK)?;
    // Eight loads (the limit), nine, and eight with PT_NULL between them.
    for (name, count, nulls, expected) in [
        ("loads-8", 8usize, false, OK),
        ("loads-9", 9, false, NOEXEC),
        ("loads-8-with-null", 8, true, OK),
    ] {
        img.template(&DEFAULT_CHECKS);
        let mut slot = 2;
        for index in 2..count {
            if nulls && index == 4 {
                img.ph(slot, PT_NULL, 0, 0, 0, 0, 0, 0);
                slot += 1;
            }
            let va = DATA_VA + 0x10000 * index as u64;
            img.ph(slot, PT_LOAD, R | W, 0, va, 0, 0x1000, 0x1000);
            slot += 1;
        }
        img.phnum(slot as u16);
        run.img(name, &img, expected)?;
    }
    img.template(&DEFAULT_CHECKS);
    img.phnum(3);
    img.ph(2, PT_GNU_STACK, R | W, 0, 0, 0, 0, 0x10);
    run.img("gnu-stack", &img, NOEXEC)?;
    img.template(&DEFAULT_CHECKS);
    img.ph_field(1, 4, u64::from(R | W | 8));
    run.img("flags-unknown-bit", &img, NOEXEC)?;

    // Alignment.
    for (name, align, expected) in [
        ("align-0", 0u64, NOEXEC),
        ("align-3", 3, NOEXEC),
        ("align-1", 1, OK),
        ("align-2m-incongruent", 0x20_0000, NOEXEC),
        ("align-2-63", 1 << 63, NOEXEC),
    ] {
        img.template(&DEFAULT_CHECKS);
        img.ph_field(1, 48, align);
        run.img(name, &img, expected)?;
    }
    img.template(&DEFAULT_CHECKS);
    img.ph_field(1, 16, DATA_VA + 4);
    img.ph_field(1, 24, DATA_VA + 4);
    run.img("vaddr-offset-incongruent", &img, NOEXEC)?;
    // A congruent segment whose four file bytes straddle a page boundary
    // in both the file and memory: the copy splits correctly.
    img.template(&[
        Op::Check(DATA_VA + 0xffe, 0x0403_0201),
        Op::Check(DATA_VA + 0x1002, 0),
    ]);
    img.ph(1, PT_LOAD, R | W, 0x2ffe, DATA_VA + 0xffe, 4, 8, 0x1000);
    img.len = 0x3002 + 0x10;
    img.bytes()[0x2ffe..0x3002].copy_from_slice(&[1, 2, 3, 4]);
    img.bytes()[0x3002..0x3012].fill(GARBAGE);
    run.img("straddle-page-copy", &img, OK)?;

    // Permissions: the loader forwards W and X to the page tables; there is
    // no W^X rule, and x86 cannot express a present page that is unreadable.
    img.template(&[Op::Store(CODE_VA, 0x90)]);
    run.img("perm-rx-write", &img, PF)?;
    img.template(&[Op::Jump(DATA_VA)]);
    run.img("perm-rw-exec", &img, PF)?;
    for (name, flags, ops, expected) in [
        ("perm-r-read", R, &[Op::Check(DATA_VA, DATA_WORD)][..], OK),
        ("perm-r-write", R, &[Op::Store(DATA_VA, 1)][..], PF),
        ("perm-r-exec", R, &[Op::Jump(DATA_VA)][..], PF),
        (
            "perm-none-read",
            0,
            &[Op::Check(DATA_VA, DATA_WORD)][..],
            OK,
        ),
        ("perm-none-write", 0, &[Op::Store(DATA_VA, 1)][..], PF),
        ("perm-x-read", X, &[Op::Check(DATA_VA, DATA_WORD)][..], OK),
        (
            "perm-rwx-write",
            R | W | X,
            &[
                Op::Store(DATA_VA + 4, 0x33),
                Op::Check(DATA_VA + 4, 0x5555_5533),
            ][..],
            OK,
        ),
    ] {
        img.template(ops);
        img.ph_field(1, 4, flags as u64);
        run.img(name, &img, expected)?;
    }
    // Write-then-execute in an R+W+X segment: `mov edi, 42; exit` stored at
    // runtime, then jumped to. Permitted by the current policy.
    let stub = [0xbfu8, 42, 0, 0, 0, 0xb8, 3, 0, 0, 0, 0xcd, 0x80];
    let mut ops = [Op::Jump(0); 13];
    for (index, byte) in stub.iter().enumerate() {
        ops[index] = Op::Store(DATA_VA + 0x100 + index as u64, *byte);
    }
    ops[12] = Op::Jump(DATA_VA + 0x100);
    img.template(&ops);
    img.ph_field(1, 4, (R | W | X) as u64);
    run.img("perm-rwx-write-exec", &img, OK)?;

    // Entry points.
    for (name, entry, expected) in [
        ("entry-in-rw", DATA_VA, NOEXEC),
        ("entry-unmapped", BASE + 0x8000, NOEXEC),
        ("entry-at-segment-end", CODE_VA + 0x1000, NOEXEC),
        ("entry-zero", 0, NOEXEC),
        ("entry-noncanonical", 0x8000_0000_0000_0000, NOEXEC),
        ("entry-kernel", 0xffff_ffff_8000_0000, NOEXEC),
        // Inside the executable segment but past its file bytes: accepted;
        // zeroed memory decodes as `add [rax], al` with RAX zero.
        ("entry-in-x-bss", CODE_VA + 0x800, PF),
        ("entry-last-byte", CODE_VA + 0xfff, PF),
    ] {
        img.template(&DEFAULT_CHECKS);
        img.entry(entry);
        run.img(name, &img, expected)?;
    }
    // An executable segment outside the window carrying the entry.
    for (name, va) in [
        ("x-segment-noncanonical", 0x8000_0000_0000_0000u64),
        ("x-segment-kernel", 0xffff_8000_0000_0000),
        ("x-segment-identity-map", 0x10_0000),
    ] {
        img.template(&DEFAULT_CHECKS);
        img.ph_field(0, 16, va);
        img.ph_field(0, 24, va);
        img.entry(va);
        run.img(name, &img, NOEXEC)?;
    }

    // Partial failure: seven segments map (many pages each) before the
    // eighth descriptor fails in the loader, after the parser accepted it.
    for (name, eighth_va, eighth_memsz) in [
        ("late-overlap", DATA_VA + 0x10000 * 3 + 0x8000, 0x1000u64),
        ("late-past-window", USER_IMAGE_MAX - 0x1000, 0x2000),
    ] {
        img.template(&DEFAULT_CHECKS);
        for index in 2..7usize {
            let va = DATA_VA + 0x10000 * index as u64;
            img.ph(index, PT_LOAD, R | W, 0, va, 0, 0x10000, 0x1000);
        }
        img.ph(7, PT_LOAD, R | W, 0, eighth_va, 0, eighth_memsz, 0x1000);
        img.phnum(8);
        run.img(name, &img, NOEXEC)?;
    }

    // Image size: exactly the limit (the data segment's file bytes are the
    // last 16 bytes of 32 MiB), then one byte over.
    unmap(base, BUFFER_PAGES).map_err(|_| "unmap")?;
    // `map` takes at most MAX_MAP_PAGES at a time; first fit in the now
    // empty heap window makes the chunks contiguous.
    let pages = MAX_SPAWN_IMAGE_BYTES / 4096;
    let big = map(MAX_MAP_PAGES).map_err(|_| "map 32 MiB")?;
    for chunk in 1..pages / MAX_MAP_PAGES {
        let next = map(MAX_MAP_PAGES).map_err(|_| "map 32 MiB")?;
        if next as u64 != big as u64 + chunk * MAX_MAP_PAGES * 4096 {
            return Err("32 MiB not contiguous");
        }
    }
    let mut img = Img {
        base: big,
        capacity: MAX_SPAWN_IMAGE_BYTES as usize,
        len: 0,
    };
    let tail = MAX_SPAWN_IMAGE_BYTES as usize - 0x10;
    img.template(&[
        Op::Check(DATA_VA + 0xff0, DATA_WORD),
        Op::Check(DATA_VA + 0x1000, 0),
        Op::Check(DATA_VA + 0x1ffc, 0),
    ]);
    img.ph(
        1,
        PT_LOAD,
        R | W,
        tail as u64,
        DATA_VA + 0xff0,
        0x10,
        0x1010,
        0x1000,
    );
    img.bytes()[DATA_OFFSET..TEMPLATE_BYTES].fill(0);
    img.put32(tail, DATA_WORD);
    img.bytes()[tail + 4..tail + 0x10].fill(0x55);
    img.len = MAX_SPAWN_IMAGE_BYTES as usize;
    run.img("image-exactly-max", &img, OK)?;
    run.case(
        "image-max-plus-1",
        big as u64,
        MAX_SPAWN_IMAGE_BYTES + 1,
        INVALID,
    )?;
    for chunk in 0..pages / MAX_MAP_PAGES {
        let address = unsafe { big.add((chunk * MAX_MAP_PAGES * 4096) as usize) };
        unmap(address, MAX_MAP_PAGES).map_err(|_| "unmap 32 MiB")?;
    }

    // The unrelated sentinel is still terminal with its original outcome.
    let state = info(Some(sentinel))
        .map_err(|_| "sentinel info after")?
        .state;
    let outcome = wait(Some(sentinel)).map_err(|_| "sentinel wait")?;
    let mut console = console;
    let _ = writeln!(
        console,
        "ELF sentinel state={state} outcome={}",
        if outcome == Outcome::Exited(42) {
            "exit=42"
        } else {
            "changed"
        }
    );
    if outcome != Outcome::Exited(42) {
        return Err("sentinel outcome");
    }
    Ok((run.cases, run.mismatches))
}
