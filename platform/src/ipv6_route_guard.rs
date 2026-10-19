//! Private invocation guard for this diagnostic, not a new network service API.
use super::fixture::Budget;
use absd_net::{
    FRAME_MAX, Link, LinkReading, NicLink,
    ipv6::channel::{KernelPipe, Pipe},
};
use std::{cell::RefCell, rc::Rc};
#[derive(Clone)]
pub struct Guard {
    budget: Rc<RefCell<Budget>>,
    nic: Option<(u64, u64)>,
}
impl Guard {
    pub fn new(start: u64, stop: u64) -> Result<Self, String> {
        let guard = Self {
            budget: Rc::new(RefCell::new(Budget::new(start, stop)?)),
            nic: None,
        };
        guard.check()?;
        Ok(guard)
    }
    pub fn with_nic(&self, handle: u64) -> Result<Self, String> {
        self.check()?;
        let info = absd_runtime::nic::info(handle);
        let after = self.check();
        let info = info.map_err(|e| format!("NIC baseline {e}"))?;
        after?;
        let r = absd_net::reading_from_info(&info);
        if !r.link_up || r.disabled {
            self.fault();
            return Err("NIC baseline unhealthy".into());
        }
        let next = Self {
            budget: self.budget.clone(),
            nic: Some((handle, r.rx_missed)),
        };
        next.check()?;
        Ok(next)
    }
    pub fn check(&self) -> Result<u64, String> {
        self.budget
            .borrow_mut()
            .check(absd_runtime::boot_millis())
            .map_err(|e| format!("budget {e:?}"))?;
        if let Some((handle, missed)) = self.nic {
            let reading = absd_runtime::nic::info(handle);
            let clock = self.budget.borrow_mut().check(absd_runtime::boot_millis());
            if reading
                .as_ref()
                .ok()
                .map(absd_net::reading_from_info)
                .is_none_or(|r| !r.link_up || r.disabled || r.rx_missed != missed)
            {
                self.fault();
                return Err("NIC reading/fault/counter changed".into());
            }
            clock.map_err(|e| format!("budget after NIC reading {e:?}"))?;
        }
        self.budget
            .borrow_mut()
            .check(absd_runtime::boot_millis())
            .map_err(|e| format!("budget {e:?}"))
    }
    pub fn fault(&self) {
        self.budget.borrow_mut().fault();
    }
    pub fn io<T>(&self, operation: impl FnOnce(u64) -> Result<T, i64>) -> Result<T, i64> {
        let left = self.check().map_err(|_| -125)?;
        let result = operation(left);
        self.after(result)
    }
    fn before(&self) -> Result<(), i64> {
        self.check().map(|_| ()).map_err(|_| -125)
    }
    fn after<T>(&self, result: Result<T, i64>) -> Result<T, i64> {
        let checked = self.before();
        if result.is_err() {
            self.fault();
        }
        match result {
            Err(e) => Err(e),
            Ok(value) => checked.map(|_| value),
        }
    }
}
pub struct BoundLink {
    pub inner: NicLink,
    pub guard: Guard,
}
impl Link for BoundLink {
    fn mac(&self) -> [u8; 6] {
        self.inner.mac()
    }
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn send(&mut self, b: &[u8]) -> Result<(), i64> {
        self.guard.before()?;
        let r = self.inner.send(b);
        self.guard.after(r)
    }
    fn receive(&mut self, b: &mut [u8; FRAME_MAX], timeout: u64) -> Result<Option<usize>, i64> {
        let left = self.guard.check().map_err(|_| -125)?;
        let r = self.inner.receive(b, timeout.min(left));
        self.guard.after(r)
    }
    fn pause(&self, ms: u64) {
        if let Ok(left) = self.guard.check() {
            self.inner.pause(ms.min(left));
            let _ = self.guard.check();
        }
    }
    fn read(&self) -> Option<LinkReading> {
        self.guard.before().ok()?;
        let r = self.inner.read();
        let after = self.guard.before();
        if r.is_none() {
            self.guard.fault();
        }
        after.ok()?;
        r
    }
}
pub struct BoundPipe {
    pub inner: KernelPipe,
    pub guard: Guard,
}
impl Pipe for BoundPipe {
    fn now_ms(&self) -> u64 {
        absd_runtime::boot_millis()
    }
    fn read(&mut self, b: &mut [u8]) -> Result<Option<usize>, i64> {
        self.guard.before()?;
        let r = self.inner.read(b);
        self.guard.after(r)
    }
    fn write(&mut self, b: &[u8]) -> Result<Option<usize>, i64> {
        self.guard.before()?;
        let r = self.inner.write(b);
        self.guard.after(r)
    }
}
