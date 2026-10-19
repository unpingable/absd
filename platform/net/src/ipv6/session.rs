//! Version 2 scoped IPv6 datagram messages. The owning channel selects the
//! grant; neither an address nor a scope in request bytes creates authority.
use super::*;

pub const VERSION: u8 = 2;
pub const FAMILY: u8 = 6;
pub const HEADER: usize = 28;
pub const MAX_MESSAGE: usize = HEADER + MAX_DATAGRAM;
pub use super::feedback::FEEDBACK;
pub use crate::datagram::{CLOSE, RECEIVE, SEND};

pub struct Session {
    endpoint: Endpoint,
}

impl Session {
    pub fn grant<L: Link>(stack: &mut Stack<L>, grant: Grant) -> Result<Self, Error> {
        Ok(Self {
            endpoint: stack.ipv6_bind(grant)?,
        })
    }

    pub(super) fn feedback_endpoint(&self) -> Endpoint {
        self.endpoint
    }

    pub fn revoke<L: Link>(&mut self, stack: &mut Stack<L>) {
        let _ = stack.ipv6_close(self.endpoint);
    }

    /// Header: version, opcode, status/reserved, family, address[16],
    /// owner scope BE32, port BE16, length BE16. SEND alone carries data.
    /// RECEIVE/CLOSE request address, scope and port must be zero. Responses
    /// use the same layout; failed operations have no body or peer address.
    pub fn request<L: Link>(
        &mut self,
        stack: &mut Stack<L>,
        request: &[u8],
        reply: &mut [u8; MAX_MESSAGE],
    ) -> usize {
        reply[..HEADER].fill(0);
        reply[0] = VERSION;
        reply[1] = request.get(1).copied().unwrap_or(0);
        reply[3] = FAMILY;
        let result = (|| {
            if request.len() < HEADER
                || request[0] != VERSION
                || request[2] != 0
                || request[3] != FAMILY
            {
                return Err(Error::Invalid);
            }
            let length = u16::from_be_bytes(request[26..28].try_into().unwrap()) as usize;
            match request[1] {
                SEND => {
                    if request.len() != HEADER + length {
                        return Err(Error::Invalid);
                    }
                    let peer = Address {
                        ip: request[4..20].try_into().unwrap(),
                        scope: u32::from_be_bytes(request[20..24].try_into().unwrap()),
                        port: u16::from_be_bytes(request[24..26].try_into().unwrap()),
                    };
                    stack.ipv6_send(self.endpoint, peer, &request[HEADER..])?;
                    Ok(0)
                }
                RECEIVE => {
                    if request.len() != HEADER || request[4..26] != [0; 22] || length > MAX_DATAGRAM
                    {
                        return Err(Error::Invalid);
                    }
                    let (n, peer) =
                        stack.ipv6_receive(self.endpoint, &mut reply[HEADER..HEADER + length])?;
                    reply[4..20].copy_from_slice(&peer.ip);
                    reply[20..24].copy_from_slice(&peer.scope.to_be_bytes());
                    reply[24..26].copy_from_slice(&peer.port.to_be_bytes());
                    reply[26..28].copy_from_slice(&(n as u16).to_be_bytes());
                    Ok(n)
                }
                FEEDBACK => {
                    if request.len() != HEADER || request[4..HEADER] != [0; HEADER - 4] {
                        return Err(Error::Invalid);
                    }
                    let observation = stack.ipv6_feedback(self.endpoint)?.ok_or(Error::Again)?;
                    reply[HEADER..HEADER + feedback::WIRE_LEN]
                        .copy_from_slice(&observation.encode());
                    reply[26..28].copy_from_slice(&(feedback::WIRE_LEN as u16).to_be_bytes());
                    Ok(feedback::WIRE_LEN)
                }
                CLOSE => {
                    if request.len() != HEADER || request[4..28] != [0; 24] {
                        return Err(Error::Invalid);
                    }
                    stack.ipv6_close(self.endpoint)?;
                    Ok(0)
                }
                _ => Err(Error::Invalid),
            }
        })();
        match result {
            Ok(n) => HEADER + n,
            Err(e) => {
                reply[2] = e.code();
                if let Error::TooSmall { needed } = e {
                    reply[26..28].copy_from_slice(&(needed as u16).to_be_bytes());
                }
                HEADER
            }
        }
    }
}
