//! Owner-configured /128 IPv6 routing for one exact UDP/TCP peer. The route is
//! configuration, not a grant: only an issued endpoint enables ingress
//! or next-hop ND. Received NA never changes the route or peer authority.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Unicast router in the configured local prefix, distinct from self.
    pub router: [u8; 16],
    /// One off-link unicast IP, transport port and owner-issued interface scope.
    pub peer: Address,
}

pub(crate) struct State {
    pub(crate) route: Route,
    pub(super) ports: [Option<u16>; MAX_ENDPOINTS],
}

impl State {
    pub(crate) fn active(&self, tcp: &[Option<stream::Flow>; stream::MAX_ENDPOINTS]) -> bool {
        self.ports.iter().any(Option::is_some)
            || tcp.iter().flatten().any(|flow| flow.peer == self.route.peer)
    }

    pub(super) fn bound(&mut self, slot: usize, grant: Grant) {
        self.ports[slot] = (grant.peer == self.route.peer).then_some(grant.local_port);
    }

    /// Narrow routed ingress; smoltcp still validates the UDP checksum.
    /// Ethernet source identity is unauthenticated ND, not a new trust claim.
    pub(crate) fn ingress(&self, frame: &[u8], config: Option<Config>) -> bool {
        let Some(config) = config else { return false };
        if frame.len() < 62
            || frame[12..14] != [0x86, 0xdd]
            || frame[14] >> 4 != 6
            || frame[20] != 17
            || frame[22..38] != self.route.peer.ip
            || frame[38..54] != config.address
        {
            return false;
        }
        let length = usize::from(u16::from_be_bytes([frame[18], frame[19]]));
        (8..=8 + MAX_DATAGRAM).contains(&length)
            && frame.len() >= 54 + length
            && usize::from(u16::from_be_bytes([frame[58], frame[59]])) == length
            && u16::from_be_bytes([frame[54], frame[55]]) == self.route.peer.port
            && self
                .ports
                .contains(&Some(u16::from_be_bytes([frame[56], frame[57]])))
    }
}

impl<L: Link> Stack<L> {
    /// Install exactly once with no active IPv6 grant. No default route,
    /// discovery, replacement or delegated route-administration operation.
    /// A route alone admits no transport or ND. Routed TCP retains the explicit
    /// construction-time IP MTU condition (default 1500, opt-in 1280); Echo
    /// authority is unchanged and this does not discover a path MTU.
    pub fn configure_ipv6_route(&mut self, route: Route) -> Result<(), Error> {
        let config = self.ipv6_config().ok_or(Error::Denied)?;
        if route.peer.scope != config.scope
            || route.peer.port == 0
            || !usable_address(route.router)
            || route.router == config.address
            || !same_prefix(config.address, route.router, config.prefix_len)
            || !usable_address(route.peer.ip)
            || route.peer.ip[0] == 0xfe
            || same_prefix(config.address, route.peer.ip, config.prefix_len)
        {
            return Err(Error::Denied);
        }
        if self.port.ipv6_route.is_some()
            || self.ipv6_datagrams.active()
            || self.ipv6_streams.active()
            || self.port.ipv6_echo.is_some()
        {
            return Err(Error::InUse);
        }
        self.ipv6_live()?;
        let mut added = false;
        self.iface.routes_mut().update(|routes| {
            added = routes
                .push(smoltcp::iface::Route {
                    cidr: IpCidr::new(IpAddress::Ipv6(Ipv6Address::from(route.peer.ip)), 128),
                    via_router: IpAddress::Ipv6(Ipv6Address::from(route.router)),
                    preferred_until: None,
                    expires_at: None,
                })
                .is_ok();
        });
        if !added {
            return Err(Error::Exhausted);
        }
        self.port.ipv6_route = Some(State {
            route,
            ports: [None; MAX_ENDPOINTS],
        });
        Ok(())
    }

    pub fn ipv6_route(&self) -> Option<Route> {
        self.port.ipv6_route.as_ref().map(|state| state.route)
    }
}

#[cfg(test)]
mod tests;
