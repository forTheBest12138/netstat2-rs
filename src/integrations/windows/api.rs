use crate::integrations::windows::ffi::*;
use crate::integrations::windows::socket_table_iterator::SocketTableIterator;
use crate::match_ip_addr;
use crate::types::error::*;
use crate::types::*;

/// Iterate through sockets information.
pub fn iterate_sockets_info(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let ipv4 = af_flags.contains(AddressFamilyFlags::IPV4);
    let ipv6 = af_flags.contains(AddressFamilyFlags::IPV6);
    let tcp = proto_flags.contains(ProtocolFlags::TCP);
    let udp = proto_flags.contains(ProtocolFlags::UDP);
    let mut iterators = Vec::with_capacity(4);
    if ipv4 {
        if tcp {
            iterators.push(SocketTableIterator::new::<MIB_TCPTABLE_OWNER_PID>()?);
        }
        if udp {
            iterators.push(SocketTableIterator::new::<MIB_UDPTABLE_OWNER_PID>()?);
        }
    }
    if ipv6 {
        if tcp {
            iterators.push(SocketTableIterator::new::<MIB_TCP6TABLE_OWNER_PID>()?);
        }
        if udp {
            iterators.push(SocketTableIterator::new::<MIB_UDP6TABLE_OWNER_PID>()?);
        }
    }

    Ok(iterators.into_iter().flatten())
}

/// Iterate through sockets information. Works on older versions of Windows (like XP and 2003).
pub fn iterate_sockets_info_without_pids(
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    let tcp = proto_flags.contains(ProtocolFlags::TCP);
    let udp = proto_flags.contains(ProtocolFlags::UDP);

    let mut iterators = Vec::with_capacity(4);
    if tcp {
        iterators.push(SocketTableIterator::new::<MIB_TCPTABLE>()?);
    }
    if udp {
        iterators.push(SocketTableIterator::new::<MIB_UDPTABLE>()?);
    }

    Ok(iterators.into_iter().flatten())
}

pub fn port_to_pid(is_ipv4: bool, is_tcp: bool, ipv46: &[u8], port: u16) -> core::result::Result<isize, Box<dyn std::error::Error>> {
    let table: SocketTableIterator;
    if is_ipv4 {
        table = if is_tcp { SocketTableIterator::new::<MIB_TCPTABLE_OWNER_PID>()? } else { SocketTableIterator::new::<MIB_UDPTABLE_OWNER_PID>()? };
    } else {
        table = if is_tcp { SocketTableIterator::new::<MIB_TCP6TABLE_OWNER_PID>()? } else { SocketTableIterator::new::<MIB_UDP6TABLE_OWNER_PID>()? };
    }
    for i in table {
        if let Ok(info) = i {
            match info.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_info) => {
                    if tcp_info.local_port == port && match_ip_addr(&tcp_info.local_addr, ipv46) {
                        return Ok(info.associated_pids[0] as isize);
                    }
                }
                ProtocolSocketInfo::Udp(udp_info) => {
                    if udp_info.local_port == port && match_ip_addr(&udp_info.local_addr, ipv46) {
                        return Ok(info.associated_pids[0] as isize);
                    }
                }
            }
        }
    }
    Ok(-1)
}