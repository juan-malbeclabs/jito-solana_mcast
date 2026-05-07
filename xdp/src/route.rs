use {
    crate::netlink::{
        netlink_get_neighbors, netlink_get_routes, MacAddress, NeighborEntry, RouteEntry,
    },
    libc::{AF_INET, AF_INET6},
    std::{
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    },
    thiserror::Error,
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("no route found to destination {0}")]
    NoRouteFound(IpAddr),

    #[error("missing output interface in route")]
    MissingOutputInterface,

    #[error("could not resolve MAC address")]
    MacResolutionError,
}

#[derive(Debug)]
pub struct NextHop {
    pub mac_addr: Option<MacAddress>,
    pub ip_addr: IpAddr,
    pub if_index: u32,
}

fn lookup_route(routes: &[RouteEntry], dest: IpAddr) -> Option<&RouteEntry> {
    let mut best_match = None;

    let family = match dest {
        IpAddr::V4(_) => AF_INET as u8,
        IpAddr::V6(_) => AF_INET6 as u8,
    };

    for route in routes.iter().filter(|r| r.family == family) {
        match (dest, route.destination) {
            // this is the default route
            (_, None) => {
                if best_match.is_none() {
                    best_match = Some((route, 0));
                }
            }

            (IpAddr::V4(dest_addr), Some(IpAddr::V4(route_addr))) => {
                let prefix_len = route.dst_len;
                if !is_ipv4_match(dest_addr, route_addr, prefix_len) {
                    continue;
                }

                if best_match.is_none() || prefix_len > best_match.unwrap().1 {
                    best_match = Some((route, prefix_len));
                }
            }

            (IpAddr::V6(dest_addr), Some(IpAddr::V6(route_addr))) => {
                let prefix_len = route.dst_len;
                if !is_ipv6_match(dest_addr, route_addr, prefix_len) {
                    continue;
                }

                if best_match.is_none() || prefix_len > best_match.unwrap().1 {
                    best_match = Some((route, prefix_len));
                }
            }

            // mixed address families - can't match
            _ => continue,
        }
    }

    best_match.map(|(route, _)| route)
}

fn is_ipv4_match(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }

    let mask = 0xFFFFFFFF << 32u32.saturating_sub(prefix_len as u32);
    let addr_bits = u32::from(addr) & mask;
    let network_bits = u32::from(network) & mask;

    addr_bits == network_bits
}

fn is_ipv6_match(addr: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }

    let addr_segments = addr.segments();
    let network_segments = network.segments();

    let full_segments = (prefix_len / 16) as usize;
    if addr_segments[..full_segments] != network_segments[..full_segments] {
        return false;
    }

    if let Some(remaining_bits) = prefix_len.checked_rem(16).filter(|&b| b != 0) {
        let mask = 0xFFFF_u16 << 16u16.saturating_sub(remaining_bits as u16);
        if (addr_segments[full_segments] & mask) != (network_segments[full_segments] & mask) {
            return false;
        }
    }

    true
}

pub struct Router {
    arp_table: ArpTable,
    routes: Vec<RouteEntry>,
}

impl Router {
    pub fn new() -> Result<Self, io::Error> {
        Ok(Self {
            arp_table: ArpTable::new()?,
            routes: netlink_get_routes(AF_INET as u8)?,
        })
    }

    pub fn default(&self) -> Result<NextHop, RouteError> {
        let default_route = self
            .routes
            .iter()
            .find(|r| r.destination.is_none())
            .ok_or(RouteError::NoRouteFound(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))?;

        let if_index = default_route
            .out_if_index
            .ok_or(RouteError::MissingOutputInterface)? as u32;

        let next_hop_ip = match default_route.gateway {
            Some(gateway) => gateway,
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        let mac_addr = self.arp_table.lookup(next_hop_ip).cloned();

        Ok(NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index,
        })
    }

    pub fn route(&self, dest_ip: IpAddr) -> Result<NextHop, RouteError> {
        let route = lookup_route(&self.routes, dest_ip).ok_or(RouteError::NoRouteFound(dest_ip))?;

        let if_index = route
            .out_if_index
            .ok_or(RouteError::MissingOutputInterface)? as u32;

        let next_hop_ip = match route.gateway {
            Some(gateway) => gateway,
            None => dest_ip,
        };

        let mac_addr = self.arp_table.lookup(next_hop_ip).cloned();

        Ok(NextHop {
            ip_addr: next_hop_ip,
            mac_addr,
            if_index,
        })
    }

    /// Returns true if there is a non-default route (prefix_len > 0) in the kernel
    /// route table that matches `dest_ip`. The default route (destination unset,
    /// or 0.0.0.0/0) is intentionally excluded.
    pub fn has_specific_route(&self, dest_ip: IpAddr) -> bool {
        let family = match dest_ip {
            IpAddr::V4(_) => AF_INET as u8,
            IpAddr::V6(_) => AF_INET6 as u8,
        };

        self.routes.iter().any(|route| {
            if route.family != family || route.destination.is_none() || route.dst_len == 0 {
                return false;
            }
            match (dest_ip, route.destination) {
                (IpAddr::V4(addr), Some(IpAddr::V4(net))) => {
                    is_ipv4_match(addr, net, route.dst_len)
                }
                (IpAddr::V6(addr), Some(IpAddr::V6(net))) => {
                    is_ipv6_match(addr, net, route.dst_len)
                }
                _ => false,
            }
        })
    }
}

struct ArpTable {
    neighbors: Vec<NeighborEntry>,
}

impl ArpTable {
    pub fn new() -> Result<Self, io::Error> {
        let neighbors = netlink_get_neighbors(None, AF_INET as u8)?;
        Ok(Self { neighbors })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<&MacAddress> {
        self.neighbors
            .iter()
            .find(|n| n.destination == Some(ip))
            .and_then(|n| n.lladdr.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_match() {
        assert!(is_ipv4_match(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));

        assert!(!is_ipv4_match(
            Ipv4Addr::new(192, 168, 2, 10),
            Ipv4Addr::new(192, 168, 1, 0),
            24
        ));

        // Match with default route
        assert!(is_ipv4_match(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(0, 0, 0, 0),
            0
        ));
    }

    #[test]
    fn test_ipv6_match() {
        assert!(is_ipv6_match(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0xabcd, 0xef01, 0x2345, 0x6789),
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 0),
            64
        ));

        assert!(!is_ipv6_match(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1235, 0x5678, 0xabcd, 0xef01, 0x2345, 0x6789),
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 0),
            64
        ));

        // Match with partial segment
        assert!(is_ipv6_match(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x6700, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x6600, 0, 0, 0, 0),
            52
        ));

        assert!(!is_ipv6_match(
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x6700, 0, 0, 0, 0),
            Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0x5600, 0, 0, 0, 0),
            52
        ));
    }

    #[test]
    fn test_router() {
        let router = Router::new().unwrap();
        let next_hop = router.route("1.1.1.1".parse().unwrap()).unwrap();
        eprintln!("{next_hop:?}");
    }

    #[test]
    fn test_has_specific_route() {
        let mut router = Router::new().unwrap();

        // Pick a unique private /32 unlikely to have an existing specific route.
        let target = Ipv4Addr::new(10, 255, 254, 99);
        let target_ip = IpAddr::V4(target);

        // No specific route yet — only the default (if any) might match.
        assert!(!router.has_specific_route(target_ip));

        // Insert a /24 that covers the target.
        let route = RouteEntry {
            destination: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 254, 0))),
            gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 254, 1))),
            pref_src: None,
            out_if_index: Some(1),
            in_if_index: None,
            priority: None,
            table: None,
            protocol: 0,
            scope: 0,
            type_: 0,
            family: AF_INET as u8,
            dst_len: 24,
        };
        router.routes.push(route);
        assert!(router.has_specific_route(target_ip));

        // Remove and confirm the match disappears.
        router.routes.pop();
        assert!(!router.has_specific_route(target_ip));
    }

    #[test]
    fn test_has_specific_route_excludes_default() {
        // Build a router with only a default route and confirm has_specific_route
        // returns no match. (Direct test of the filter logic — does not depend on
        // kernel state.)
        let mut router = Router::new().unwrap();
        router.routes.clear();
        router.routes.push(RouteEntry {
            destination: None,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
            pref_src: None,
            out_if_index: Some(1),
            in_if_index: None,
            priority: None,
            table: None,
            protocol: 0,
            scope: 0,
            type_: 0,
            family: AF_INET as u8,
            dst_len: 0,
        });
        assert!(!router.has_specific_route(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
