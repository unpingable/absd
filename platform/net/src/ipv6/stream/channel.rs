//! The same strictly bounded V2 framing loop carries a scoped stream handler.
use super::*;
#[cfg(target_os = "absd")]
pub use crate::ipv6::channel::KernelPipe;
pub use crate::ipv6::channel::{FRAME_TIMEOUT_MS, Handler, Pipe, transact};
impl Handler for Session {
    fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; MAX_MESSAGE],
    ) -> usize {
        self.request(stack, request, reply)
    }
    fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.revoke(stack)
    }
}
pub struct Channel {
    inner: crate::ipv6::channel::Channel<Session>,
}
impl Channel {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self {
            inner: crate::ipv6::channel::Channel::new(Session::grant(stack, grant)?),
        })
    }
    pub fn live(&self) -> bool {
        self.inner.live()
    }
    pub fn poll<L: Link, P: Pipe>(&mut self, stack: &mut Stack<L>, pipe: &mut P) -> bool {
        self.inner.poll(stack, pipe)
    }
    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        self.inner.revoke(stack)
    }
}
