/// Move bytes between valid ranges, including overlapping ranges.
///
/// # Safety
/// For a nonzero count, both ranges must be valid for the requested byte
/// accesses. The ranges may contain uninitialized bytes, including padding.
/// MaybeUninit preserves their initialization state; volatile operations keep
/// lowering from calling memmove itself.
pub unsafe fn move_bytes(destination: *mut u8, source: *const u8, count: usize) -> *mut u8 {
    if count == 0 || core::ptr::eq(destination.cast_const(), source) {
        return destination;
    }
    if (destination as usize) < (source as usize) {
        let mut index = 0;
        while index < count {
            unsafe {
                destination
                    .cast::<core::mem::MaybeUninit<u8>>()
                    .add(index)
                    .write_volatile(
                        source
                            .cast::<core::mem::MaybeUninit<u8>>()
                            .add(index)
                            .read_volatile(),
                    );
            }
            index += 1;
        }
    } else {
        let mut index = count;
        while index != 0 {
            index -= 1;
            unsafe {
                destination
                    .cast::<core::mem::MaybeUninit<u8>>()
                    .add(index)
                    .write_volatile(
                        source
                            .cast::<core::mem::MaybeUninit<u8>>()
                            .add(index)
                            .read_volatile(),
                    );
            }
        }
    }
    destination
}

// The expected images are built element by element on purpose: the oracle
// stays an independent model of a move, not a library slice copy.
#[allow(clippy::manual_memcpy)]
#[cfg(test)]
mod tests {
    use super::move_bytes;

    #[test]
    fn every_valid_small_buffer_move_matches_snapshot() {
        for size in 0..=32 {
            for count in 0..=size {
                for source in 0..=size - count {
                    for destination in 0..=size - count {
                        let initial: [u8; 32] = core::array::from_fn(|i| (i * 37 + 11) as u8);
                        let mut actual = initial;
                        let mut expected = initial;
                        for index in 0..count {
                            expected[destination + index] = initial[source + index];
                        }
                        let returned = unsafe {
                            move_bytes(
                                actual.as_mut_ptr().add(destination),
                                actual.as_ptr().add(source),
                                count,
                            )
                        };
                        assert_eq!(returned, unsafe { actual.as_mut_ptr().add(destination) });
                        assert_eq!(
                            actual, expected,
                            "size={size} count={count} src={source} dst={destination}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn zero_length_never_dereferences_null() {
        let null = core::ptr::null_mut();
        let mut byte = 9;
        assert_eq!(unsafe { move_bytes(null, null, 0) }, null);
        assert_eq!(unsafe { move_bytes(null, &byte, 0) }, null);
        assert_eq!(
            unsafe { move_bytes(&mut byte, null, 0) },
            &mut byte as *mut u8
        );
        assert_eq!(byte, 9);
    }

    #[test]
    fn partially_initialized_ranges_preserve_known_bytes() {
        use core::mem::MaybeUninit;
        for count in 0..=16 {
            for source in 0..=16 - count {
                for destination in 0..=16 - count {
                    let initial: [Option<u8>; 16] = core::array::from_fn(|index| {
                        (index % 3 == 0).then_some((index * 37 + 11) as u8)
                    });
                    let mut actual = [MaybeUninit::<u8>::uninit(); 16];
                    for (index, value) in initial.iter().enumerate() {
                        if let Some(value) = value {
                            actual[index].write(*value);
                        }
                    }
                    let mut expected = initial;
                    for index in 0..count {
                        expected[destination + index] = initial[source + index];
                    }
                    unsafe {
                        move_bytes(
                            actual.as_mut_ptr().add(destination).cast(),
                            actual.as_ptr().add(source).cast(),
                            count,
                        );
                    }
                    for (index, value) in expected.iter().enumerate() {
                        if let Some(value) = value {
                            assert_eq!(unsafe { actual[index].assume_init() }, *value);
                        }
                    }
                }
            }
        }
    }
}
