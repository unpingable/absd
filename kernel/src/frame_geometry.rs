//! Shared loader geometry for construction validation and exact linked-image budgets.
use crate::{elf, layout};
/// Leaf tables one process may own. The accepted bound is 32. The #115
/// builder profile derives its bound from the windows themselves: a full
/// 60 MiB image, 4 MiB stack and 384 MiB heap use 30 + 2 + 192 = 224 leaves,
/// and the envelope's 2 GiB heap gives 30 + 2 + 1024 = 1056.
#[cfg(not(feature = "builder-profile"))]
pub const MAX_LEAF_TABLES: usize = 32;
#[cfg(feature = "builder-profile")]
pub const MAX_LEAF_TABLES: usize = window_leaves(layout::USER_IMAGE_MIN, layout::USER_IMAGE_MAX)
    + window_leaves(layout::USER_STACK_BASE, layout::USER_STACK_TOP)
    + window_leaves(layout::USER_HEAP_BASE, layout::MAX_HEAP_END);

#[cfg(feature = "builder-profile")]
const fn window_leaves(start: u64, end: u64) -> usize {
    (end.div_ceil(1 << 21) - start / (1 << 21)) as usize
}
#[cfg(all(feature = "builder-profile", not(feature = "builder-class-heap")))]
const _: () = assert!(layout::USER_HEAP_PAGES != 98304 || MAX_LEAF_TABLES == 224);

/// Served init's fixed admission commitment, a layout bound rather than a
/// measured peak: every mapped image/heap/user-stack page the leaf limit
/// allows (MAX_LEAF_TABLES x 512), those leaf tables, the root, PDPT and
/// page directories, and the kernel stack. 16,427 by default; 114,931 under
/// the builder profile (224 leaves, 16-page kernel stack).
pub const SERVED_INIT_FRAMES: usize = MAX_LEAF_TABLES * 512
    + MAX_LEAF_TABLES
    + 2
    + layout::USER_DIRECTORIES
    + layout::KERNEL_STACK_PAGES;
#[cfg(not(feature = "builder-profile"))]
const _: () = assert!(SERVED_INIT_FRAMES == 16427);

/// Exact initial loader charge: mapped image pages, initial stack, distinct
/// 2-MiB leaves, three upper tables, and the contiguous kernel stack.
/// Reject overlapping rounded segments just as the actual mapper does.
pub fn construction_frames(image: &elf::Image) -> Option<usize> {
    charge(image, false)
}
/// End of the heap search for `map`: a process holding a frame reservation
/// stays inside the heap its budget charged; others use the whole window.
pub fn heap_search_end(reserved: bool) -> u64 {
    if reserved {
        layout::SERVICE_HEAP_END
    } else {
        layout::USER_HEAP_END
    }
}

/// Conservative budget for a catalog service, recalculated for the exact
/// linked image. Includes every image and grow-down stack page and the
/// service heap prefix (the whole window unless the builder envelope).
pub fn service_frames(image: &elf::Image) -> Option<usize> {
    charge(image, true)
}
fn charge(image: &elf::Image, full_windows: bool) -> Option<usize> {
    let mut leaves = [false; layout::USER_LEAVES];
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
        for address in (layout::USER_HEAP_BASE..layout::SERVICE_HEAP_END).step_by(4096) {
            leaves[((address - layout::USER_REGION_BASE) >> 21) as usize] = true;
            pages += 1;
        }
    }
    let tables = leaves.iter().filter(|&&used| used).count();
    if tables > MAX_LEAF_TABLES {
        return None;
    }
    // Root, PDPT, and each page directory holding at least one leaf.
    let directories = leaves
        .chunks(512)
        .filter(|d| d.iter().any(|&used| used))
        .count();
    Some(pages + tables + 2 + directories + layout::KERNEL_STACK_PAGES)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_stack_is_charged_at_its_allocated_size() {
        let mut image = elf::Image {
            entry: layout::USER_IMAGE_MIN,
            segments: [elf::LoadSegment::EMPTY; elf::MAX_LOAD_SEGMENTS],
            segment_count: 1,
        };
        image.segments[0].virtual_address = layout::USER_IMAGE_MIN;
        image.segments[0].memory_size = 4096;
        // One image, two initial user-stack pages, two leaves, three upper
        // tables, and the kernel stack: 8 pages, or 16 in the builder profile.
        let stack = if cfg!(feature = "builder-profile") {
            16
        } else {
            8
        };
        assert_eq!(layout::KERNEL_STACK_PAGES, stack);
        assert_eq!(construction_frames(&image), Some(8 + stack));
    }
    #[test]
    #[cfg(not(feature = "builder-profile"))]
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
        assert_eq!(MAX_LEAF_TABLES, 32);
        assert_eq!(SERVED_INIT_FRAMES, 16427);
    }
    #[test]
    #[cfg(all(
        feature = "builder-profile",
        not(feature = "builder-large-envelope"),
        not(feature = "builder-class-heap")
    ))]
    fn builder_profile_service_budgets() {
        // The 384 MiB heap adds 90,112 data pages and 176 leaf tables to the
        // accepted vectors (9333, 9434, 9435); the 16-page kernel stack adds
        // eight more frames.
        for (image_pages, expected) in [(87, 99629), (188, 99730), (189, 99731)] {
            let mut image = elf::Image {
                entry: layout::USER_IMAGE_MIN,
                segments: [elf::LoadSegment::EMPTY; elf::MAX_LOAD_SEGMENTS],
                segment_count: 1,
            };
            image.segments[0].virtual_address = layout::USER_IMAGE_MIN;
            image.segments[0].memory_size = image_pages * 4096;
            assert_eq!(service_frames(&image), Some(expected));
            assert!(expected as u64 <= crate::syscall::MAX_FRAME_ADMISSION_FRAMES);
            assert_eq!(construction_frames(&image), Some(image_pages + 23));
            image.segments[0].virtual_address += (2 << 20) - 4096;
            assert_eq!(service_frames(&image), Some(expected + 1));
        }
        assert_eq!(MAX_LEAF_TABLES, 224);
        assert_eq!(SERVED_INIT_FRAMES, 224 * 512 + 224 + 3 + 16);
        assert!(SERVED_INIT_FRAMES as u64 <= crate::syscall::MAX_FRAME_ADMISSION_FRAMES);
    }
    #[test]
    #[cfg(feature = "builder-large-envelope")]
    fn builder_large_envelope_budgets() {
        // The service budget backs only the 384 MiB heap prefix: the same
        // pages and leaves as the 384 MiB profile (99629, 99730, 99731),
        // plus one page directory, because the heap now starts in GiB 1.
        assert_eq!(MAX_LEAF_TABLES, 1056);
        assert_eq!(layout::USER_LEAVES, 1536);
        for (image_pages, expected) in [(87usize, 99630), (188, 99731), (189, 99732)] {
            let mut image = elf::Image {
                entry: layout::USER_IMAGE_MIN,
                segments: [elf::LoadSegment::EMPTY; elf::MAX_LOAD_SEGMENTS],
                segment_count: 1,
            };
            image.segments[0].virtual_address = layout::USER_IMAGE_MIN;
            image.segments[0].memory_size = image_pages * 4096;
            assert_eq!(service_frames(&image), Some(expected));
            assert!(expected as u64 <= crate::syscall::MAX_FRAME_ADMISSION_FRAMES);
            // Construction never charges the heap window, so it is unchanged.
            assert_eq!(construction_frames(&image), Some(image_pages + 23));
        }
    }
    #[test]
    #[cfg(feature = "builder-class-heap")]
    fn builder_class_heap_budgets() {
        // Services keep the 384 MiB profile's budgets (99629, 99730, 99731):
        // only the builder class's 512 MiB window raises the leaf bound.
        assert_eq!(layout::USER_HEAP_PAGES, 98304);
        assert_eq!(layout::BUILDER_CLASS_HEAP_PAGES, 131072);
        assert_eq!(MAX_LEAF_TABLES, 30 + 2 + 256);
        assert_eq!(heap_search_end(false), layout::USER_HEAP_END);
        assert_eq!(heap_search_end(true), layout::USER_HEAP_END);
        for (image_pages, expected) in [(87, 99629), (188, 99730), (189, 99731)] {
            let mut image = elf::Image {
                entry: layout::USER_IMAGE_MIN,
                segments: [elf::LoadSegment::EMPTY; elf::MAX_LOAD_SEGMENTS],
                segment_count: 1,
            };
            image.segments[0].virtual_address = layout::USER_IMAGE_MIN;
            image.segments[0].memory_size = image_pages * 4096;
            assert_eq!(service_frames(&image), Some(expected));
            assert_eq!(construction_frames(&image), Some(image_pages + 23));
        }
        // The builder budgets fit the unchanged ceiling.
        assert!(
            crate::builder_class::COMPILER_FRAMES as u64
                <= crate::syscall::MAX_FRAME_ADMISSION_FRAMES
        );
    }
}
