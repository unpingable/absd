#![cfg(feature = "frame-admission-core")]
extern crate std;
use crate::memory::{AdmissionError, Frame, FrameAllocator, FrameOwner, FrameState, PAGE_SIZE};
use std::vec::Vec;

fn pool(pages: usize) -> FrameAllocator {
    let mut f = FrameAllocator::new();
    f.add_usable(PAGE_SIZE, (pages as u64 + 1) * PAGE_SIZE);
    f
}

#[test]
fn commitment_covers_all_roles_and_excludes_even_kernel_and_contiguous_requests() {
    let mut f = pool(32);
    f.admit(1, 12).unwrap();
    f.admit(2, 8).unwrap();
    let b = f.allocate_contiguous(12, FrameOwner::UserPage(3)).unwrap();
    assert_eq!(f.allocate(FrameOwner::Kernel), None);
    assert_eq!(f.allocate(FrameOwner::PageTable(3)), None);
    assert_eq!(f.admit(4, 1), Err(AdmissionError::NoCapacity));
    for role in [
        FrameOwner::PageTable(1),
        FrameOwner::UserPage(1),
        FrameOwner::KernelStack(1),
    ] {
        f.allocate_contiguous(4, role).unwrap();
    }
    assert_eq!(f.allocate(FrameOwner::UserPage(1)), None);
    assert_eq!(f.idle_reserved_frames(), 8);
    assert_eq!(f.retire_reservation(1), Err(AdmissionError::StillOwned));
    assert!(f.free(b, FrameOwner::UserPage(2)).is_err());
    assert_eq!(f.reservation(2), Some((8, 0)));
    for page in 0..12 {
        f.free(Frame(b.0 + page * PAGE_SIZE), FrameOwner::UserPage(3))
            .unwrap();
    }
    assert_eq!(f.free_frames(), 20);
}

#[test]
fn admission_is_atomic_accounts_existing_frames_and_retirement_requires_actual_return() {
    let mut f = pool(8);
    let page = f.allocate(FrameOwner::UserPage(1)).unwrap();
    assert_eq!(f.admit(1, 9), Err(AdmissionError::NoCapacity));
    assert_eq!(f.reservation(1), None);
    assert_eq!(f.idle_reserved_frames(), 0);
    f.admit(1, 8).unwrap();
    assert_eq!(f.reservation(1), Some((8, 1)));
    assert_eq!(f.admit(1, 1), Err(AdmissionError::AlreadyAdmitted));
    assert!(!f.reserve(PAGE_SIZE, PAGE_SIZE * 9));
    assert_eq!(f.free_frames(), 7);
    assert_eq!(f.retire_reservation(1), Err(AdmissionError::StillOwned));
    f.free(page, FrameOwner::UserPage(1)).unwrap();
    f.retire_reservation(1).unwrap();
    f.admit(2, 8).unwrap();
    assert_eq!(f.reservation(1), None);
    assert_eq!(f.allocate(FrameOwner::UserPage(1)), None);
    assert!(f.allocate(FrameOwner::UserPage(2)).is_some());
}

#[test]
fn quota_is_backing_and_fragmentation_is_explicitly_outside_single_frame_promise() {
    let mut f = pool(16);
    f.set_quota(Some(8));
    assert_eq!(f.admit(1, 9), Err(AdmissionError::NoCapacity));
    f.admit(1, 8).unwrap();
    assert_eq!(f.allocate(FrameOwner::Kernel), None);
    let mut f = pool(16);
    let pages: Vec<_> = (0..16)
        .map(|_| f.allocate(FrameOwner::Kernel).unwrap())
        .collect();
    for i in (0..16).step_by(2) {
        f.free(pages[i], FrameOwner::Kernel).unwrap();
    }
    f.admit(1, 8).unwrap();
    assert_eq!(f.allocate_contiguous(2, FrameOwner::KernelStack(1)), None);
    for _ in 0..8 {
        assert!(f.allocate(FrameOwner::UserPage(1)).is_some());
    }
}

#[test]
fn repeated_independent_transition_histories_match_owned_tags_and_never_lose_backing() {
    for seed in 1..=64u64 {
        let mut f = pool(64);
        let mut rng = seed;
        let mut held = Vec::<(Frame, FrameOwner)>::new();
        for _ in 0..2000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let pid = ((rng >> 32) % 4 + 1) as u32;
            match (rng >> 40) % 4 {
                0 => {
                    let total = ((rng >> 48) % 33 + 1) as usize;
                    let before = (
                        f.free_frames(),
                        f.idle_reserved_frames(),
                        f.reservation(pid),
                    );
                    if f.admit(pid, total).is_err() {
                        assert_eq!(
                            (
                                f.free_frames(),
                                f.idle_reserved_frames(),
                                f.reservation(pid)
                            ),
                            before
                        );
                    }
                }
                1 | 2 => {
                    let owner = if rng & 1 == 0 {
                        FrameOwner::PageTable(pid)
                    } else {
                        FrameOwner::UserPage(pid)
                    };
                    let promised = f.reservation(pid).is_some_and(|(total, used)| used < total);
                    let page = f.allocate(owner);
                    if promised {
                        assert!(page.is_some());
                    }
                    if let Some(page) = page {
                        held.push((page, owner));
                    }
                }
                _ => {
                    if let Some(i) = held.iter().position(|(_, o)| o.pid() == Some(pid)) {
                        let (frame, owner) = held.swap_remove(i);
                        f.free(frame, owner).unwrap();
                        assert_eq!(f.state(frame), FrameState::Free);
                    }
                    if f.frames_owned_by(pid) == 0 {
                        f.retire_reservation(pid).unwrap();
                    }
                }
            }
            for &(frame, owner) in &held {
                assert_eq!(f.state(frame), FrameState::Allocated(owner));
            }
            let mut unused = 0;
            for p in 1..=4 {
                if let Some((total, used)) = f.reservation(p) {
                    assert_eq!(
                        used,
                        held.iter().filter(|(_, o)| o.pid() == Some(p)).count()
                    );
                    assert!(used <= total);
                    unused += total - used;
                }
            }
            assert_eq!(unused, f.idle_reserved_frames());
            assert!(unused <= f.free_frames());
            assert_eq!(f.free_frames() + held.len(), 64);
        }
        for (frame, owner) in held {
            f.free(frame, owner).unwrap();
        }
        for p in 1..=4 {
            f.retire_reservation(p).unwrap();
        }
        assert_eq!((f.free_frames(), f.idle_reserved_frames()), (64, 0));
    }
}

#[test]
fn admission_refuses_invalid_identity_capacity_and_full_metadata_without_side_effects() {
    let mut f = pool(32);
    assert_eq!(f.admit(0, 1), Err(AdmissionError::Invalid));
    assert_eq!(f.admit(1, 0), Err(AdmissionError::Invalid));
    assert_eq!(
        f.admit(crate::memory::MAX_OWNER_ID + 1, 1),
        Err(AdmissionError::Invalid)
    );
    for pid in 1..=16 {
        f.admit(pid, 1).unwrap();
    }
    assert_eq!(f.admit(17, 1), Err(AdmissionError::NoRecord));
    assert_eq!((f.free_frames(), f.idle_reserved_frames()), (32, 16));
    f.retire_reservation(8).unwrap();
    f.admit(17, 1).unwrap();
    assert_eq!(f.reservation(8), None);
    assert_eq!(f.reservation(17), Some((1, 0)));
}
