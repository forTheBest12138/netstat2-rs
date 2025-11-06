use std::net::IpAddr;
use crate::integrations::*;
use crate::types::error::Error;
use crate::types::*;

/// Retrieve sockets information as a vector.
/// Short-circuits on any error along the way.
pub fn get_sockets_info(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<Vec<SocketInfo>, Error> {
    iterate_sockets_info(af_flags, proto_flags)?.collect()
}

pub fn match_ip_addr(ipaddr: &IpAddr, ipv46: &[u8]) -> bool {
    match ipaddr {
        IpAddr::V4(ip4) => {
            ip4.octets() == ipv46
        }
        IpAddr::V6(ip6) => {
            ip6.octets() == ipv46
        }
    }
}
