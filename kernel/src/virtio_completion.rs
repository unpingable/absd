//! Completion boundary for the ARM lane's single-outstanding split queues.
pub fn valid(
    next: u16,
    published: u16,
    used: u16,
    head: u32,
    expected_head: u32,
    length: u32,
    bounds: (u32, u32),
) -> bool {
    published.wrapping_sub(next) == 1
        && used.wrapping_sub(next) == 1
        && head == expected_head
        && (bounds.0..=bounds.1).contains(&length)
}

#[cfg(test)]
mod tests {
    use super::valid;

    #[test]
    fn completion_wrap_does_not_change_ownership_or_length_bounds() {
        assert!(valid(65535, 0, 0, 0, 0, 513, (513, 513)));
        assert!(!valid(0, 0, 1, 0, 0, 513, (513, 513)));
        assert!(!valid(0, 1, 2, 0, 0, 513, (513, 513)));
        assert!(!valid(0, 1, 1, 3, 0, 513, (513, 513)));
        assert!(!valid(0, 1, 1, 0, 0, 512, (513, 513)));
        assert!(!valid(0, 1, 1, 0, 0, 514, (513, 513)));
        assert!(valid(0, 1, 1, 0, 0, 0, (0, 0)));
    }
}
