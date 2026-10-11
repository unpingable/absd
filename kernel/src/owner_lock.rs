//! Architecture-neutral serialization ownership; protected state is published
//! by Release unlock and consumed by successful Acquire lock acquisition.
use core::sync::atomic::{AtomicU8, Ordering};
pub const FREE: u8 = u8::MAX;
pub struct OwnerLock(AtomicU8);
impl Default for OwnerLock {
    fn default() -> Self {
        Self::new()
    }
}
impl OwnerLock {
    pub const fn new() -> Self {
        Self(AtomicU8::new(FREE))
    }
    pub fn load(&self, order: Ordering) -> u8 {
        self.0.load(order)
    }
    /// Bootstrap only, before concurrent consumers are admitted.
    pub fn initialize(&self, owner: u8) {
        assert_eq!(self.load(Ordering::Relaxed), FREE);
        self.0.store(owner, Ordering::Relaxed);
    }
    pub fn try_acquire(&self, owner: u8) -> Result<(), u8> {
        assert_ne!(owner, FREE);
        self.0
            .compare_exchange_weak(FREE, owner, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| ())
    }
    pub fn release(&self, owner: u8) {
        assert_eq!(self.load(Ordering::Relaxed), owner);
        self.0.store(FREE, Ordering::Release);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialized_ownership_is_exclusive_and_reusable() {
        let lock = OwnerLock::new();
        while lock.try_acquire(0).is_err() {}
        assert_eq!(lock.try_acquire(1), Err(0));
        lock.release(0);
        while lock.try_acquire(1).is_err() {}
        assert_eq!(lock.load(Ordering::Acquire), 1);
        lock.release(1);
        assert_eq!(lock.load(Ordering::Acquire), FREE);
    }
}
