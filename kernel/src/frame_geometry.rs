//! Shared loader geometry for construction validation and exact linked-image budgets.
use crate::{elf, layout};
pub const MAX_LEAF_TABLES: usize = 32;

/// Exact initial loader charge: mapped image pages, initial stack, distinct
/// 2-MiB leaves, three upper tables, and the contiguous kernel stack.
/// Reject overlapping rounded segments just as the actual mapper does.
pub fn construction_frames(image: &elf::Image) -> Option<usize> {
    charge(image, false)
}
/// Conservative full-window budget for a catalog service, recalculated for
/// the exact linked image. Includes every image, heap and grow-down stack page.
pub fn service_frames(image: &elf::Image) -> Option<usize> {
    charge(image, true)
}
fn charge(image: &elf::Image, full_windows: bool) -> Option<usize> {
    let mut leaves = [false; 512];
    let mut pages = 0usize;
    for (i, segment) in image.segments[..image.segment_count].iter().enumerate() {
        let start = segment.virtual_address & !4095;
        let end = segment
            .virtual_address
            .checked_add(segment.memory_size as u64)?
            .checked_add(4095)?
            & !4095;
        if start < layout::USER_IMAGE_MIN || end > layout::USER_IMAGE_MAX {
            return None;
        }
        for previous in &image.segments[..i] {
            let a = previous.virtual_address & !4095;
            let b = previous
                .virtual_address
                .checked_add(previous.memory_size as u64)?
                .checked_add(4095)?
                & !4095;
            if start < b && a < end {
                return None;
            }
        }
        for address in (start..end).step_by(4096) {
            leaves[((address - layout::USER_REGION_BASE) >> 21) as usize] = true;
            pages += 1;
        }
    }
    let stack = if full_windows {
        layout::USER_STACK_BASE
    } else {
        layout::USER_STACK_TOP - layout::USER_STACK_PAGES as u64 * 4096
    };
    for address in (stack..layout::USER_STACK_TOP).step_by(4096) {
        leaves[((address - layout::USER_REGION_BASE) >> 21) as usize] = true;
        pages += 1;
    }
    if full_windows {
        for address in (layout::USER_HEAP_BASE..layout::USER_HEAP_END).step_by(4096) {
            leaves[((address - layout::USER_REGION_BASE) >> 21) as usize] = true;
            pages += 1;
        }
    }
    let tables = leaves.iter().filter(|&&used| used).count();
    if tables > MAX_LEAF_TABLES {
        return None;
    }
    Some(pages + tables + 3 + layout::KERNEL_STACK_PAGES)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_service_image_budgets_and_changed_leaf_geometry() {
        for (image_pages, expected) in [(87, 9333), (188, 9434), (189, 9435)] {
            let mut image = elf::Image {
                entry: layout::USER_IMAGE_MIN,
                segments: [elf::LoadSegment::EMPTY; elf::MAX_LOAD_SEGMENTS],
                segment_count: 1,
            };
            image.segments[0].virtual_address = layout::USER_IMAGE_MIN;
            image.segments[0].memory_size = image_pages * 4096;
            assert_eq!(service_frames(&image), Some(expected));
            assert_eq!(construction_frames(&image), Some(image_pages + 15));
            image.segments[0].virtual_address += (2 << 20) - 4096;
            assert_eq!(service_frames(&image), Some(expected + 1));
        }
    }
}
