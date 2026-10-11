//! The C library symbols the bundled SQLite amalgamation links against
//! (measured with `nm -u` on a freestanding build): heap, string, sort, and
//! the two libm functions FTS5 ranking uses. `memcpy`/`memmove`/`memset`/
//! `memcmp` already come from `absd-runtime`.

use std::alloc::{self, Layout};
use std::ffi::{c_char, c_int, c_void};
use std::ptr;

const HEADER: usize = 16;

fn heap_layout(size: usize) -> Option<Layout> {
    Layout::from_size_align(size.checked_add(HEADER)?, HEADER).ok()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    let Some(layout) = heap_layout(size) else { return ptr::null_mut() };
    let base = unsafe { alloc::alloc(layout) };
    if base.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        (base as *mut usize).write(size);
        base.add(HEADER) as *mut c_void
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    unsafe {
        let base = (pointer as *mut u8).sub(HEADER);
        let size = (base as *const usize).read();
        alloc::dealloc(base, heap_layout(size).unwrap());
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(pointer: *mut c_void, size: usize) -> *mut c_void {
    if pointer.is_null() {
        return unsafe { malloc(size) };
    }
    let Some(_) = heap_layout(size) else { return ptr::null_mut() };
    unsafe {
        let base = (pointer as *mut u8).sub(HEADER);
        let old = (base as *const usize).read();
        let grown = alloc::realloc(base, heap_layout(old).unwrap(), size + HEADER);
        if grown.is_null() {
            return ptr::null_mut();
        }
        (grown as *mut usize).write(size);
        grown.add(HEADER) as *mut c_void
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(text: *const c_char) -> usize {
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    length
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncmp(left: *const c_char, right: *const c_char, limit: usize) -> c_int {
    for index in 0..limit {
        let (a, b) = unsafe { (*left.add(index) as u8, *right.add(index) as u8) };
        if a != b {
            return c_int::from(a) - c_int::from(b);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(left: *const c_char, right: *const c_char) -> c_int {
    unsafe { strncmp(left, right, usize::MAX) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(text: *const c_char, wanted: c_int) -> *mut c_char {
    let wanted = wanted as u8;
    let mut cursor = text;
    loop {
        let byte = unsafe { *cursor } as u8;
        if byte == wanted {
            return cursor as *mut c_char;
        }
        if byte == 0 {
            return ptr::null_mut();
        }
        cursor = unsafe { cursor.add(1) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strrchr(text: *const c_char, wanted: c_int) -> *mut c_char {
    let wanted = wanted as u8;
    let mut found = ptr::null_mut();
    let mut cursor = text;
    loop {
        let byte = unsafe { *cursor } as u8;
        if byte == wanted {
            found = cursor as *mut c_char;
        }
        if byte == 0 {
            return found;
        }
        cursor = unsafe { cursor.add(1) };
    }
}

unsafe fn span(text: *const c_char, set: *const c_char, inside: bool) -> usize {
    let mut length = 0;
    loop {
        let byte = unsafe { *text.add(length) };
        if byte == 0 || unsafe { !strchr(set, c_int::from(byte as u8)).is_null() } != inside {
            return length;
        }
        length += 1;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strspn(text: *const c_char, accept: *const c_char) -> usize {
    unsafe { span(text, accept, true) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcspn(text: *const c_char, reject: *const c_char) -> usize {
    unsafe { span(text, reject, false) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memchr(bytes: *const c_void, wanted: c_int, count: usize) -> *mut c_void {
    let bytes = bytes as *const u8;
    for index in 0..count {
        if unsafe { *bytes.add(index) } == wanted as u8 {
            return unsafe { bytes.add(index) } as *mut c_void;
        }
    }
    ptr::null_mut()
}

type Compare = Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>;

/// Heapsort: in place, no allocation, O(n log n).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qsort(base: *mut c_void, count: usize, size: usize, compare: Compare) {
    let Some(compare) = compare else { return };
    if count < 2 || size == 0 {
        return;
    }
    let base = base as *mut u8;
    let at = |index: usize| unsafe { base.add(index * size) };
    let less = |a: usize, b: usize| unsafe { compare(at(a) as *const c_void, at(b) as *const c_void) < 0 };
    let swap = |a: usize, b: usize| unsafe { ptr::swap_nonoverlapping(at(a), at(b), size) };
    let sift = |mut root: usize, end: usize| loop {
        let mut child = 2 * root + 1;
        if child >= end {
            break;
        }
        if child + 1 < end && less(child, child + 1) {
            child += 1;
        }
        if !less(root, child) {
            break;
        }
        swap(root, child);
        root = child;
    };
    for start in (0..count / 2).rev() {
        sift(start, count);
    }
    for end in (1..count).rev() {
        swap(0, end);
        sift(0, end);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fabs(value: f64) -> f64 {
    f64::from_bits(value.to_bits() & !(1 << 63))
}

/// Natural logarithm: `x = m * 2^e` with `m` in `[sqrt(1/2), sqrt(2))`,
/// then `ln m = 2 atanh((m - 1) / (m + 1))` summed to convergence.
#[unsafe(no_mangle)]
pub extern "C" fn log(value: f64) -> f64 {
    if value.is_nan() || value < 0.0 {
        return f64::NAN;
    }
    if value == 0.0 {
        return f64::NEG_INFINITY;
    }
    if value.is_infinite() {
        return value;
    }
    let mut value = value;
    let mut exponent = 0i64;
    if value < f64::MIN_POSITIVE {
        value *= (1u64 << 54) as f64;
        exponent -= 54;
    }
    let bits = value.to_bits();
    exponent += ((bits >> 52) & 0x7ff) as i64 - 1023;
    let mut mantissa = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if mantissa > core::f64::consts::SQRT_2 {
        mantissa /= 2.0;
        exponent += 1;
    }
    let s = (mantissa - 1.0) / (mantissa + 1.0);
    let square = s * s;
    let mut term = s;
    let mut sum = 0.0;
    let mut denominator = 1.0;
    for _ in 0..40 {
        let next = term / denominator;
        sum += next;
        if fabs(next) <= 1e-18 * fabs(sum) {
            break;
        }
        term *= square;
        denominator += 2.0;
    }
    2.0 * sum + exponent as f64 * core::f64::consts::LN_2
}
