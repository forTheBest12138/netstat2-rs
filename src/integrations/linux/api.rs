use crate::integrations::linux::netlink_iterator::*;
use crate::integrations::linux::procfs::*;
use crate::types::error::Error;
use crate::types::*;
use netlink_packet_sock_diag::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP};
use std::fs::{read_dir, read_link};

/// Iterate through sockets information.
pub fn iterate_sockets_info(
    af_flags: AddressFamilyFlags,
    proto_flags: ProtocolFlags,
) -> Result<impl Iterator<Item = Result<SocketInfo, Error>>, Error> {
    Ok(attach_pids(iterate_sockets_info_without_pids(
        af_flags,
        proto_flags,
    )?))
}

/// Iterate through sockets information without attaching PID.
pub fn iterate_sockets_info_without_pids(
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
            iterators.push(NetlinkIterator::new(AF_INET as u8, IPPROTO_TCP as u8)?);
        }
        if udp {
            iterators.push(NetlinkIterator::new(AF_INET as u8, IPPROTO_UDP as u8)?);
        }
    }
    if ipv6 {
        if tcp {
            iterators.push(NetlinkIterator::new(AF_INET6 as u8, IPPROTO_TCP as u8)?);
        }
        if udp {
            iterators.push(NetlinkIterator::new(AF_INET6 as u8, IPPROTO_UDP as u8)?);
        }
    }
    Ok(iterators.into_iter().flatten())
}

fn attach_pids(
    sockets_info: impl Iterator<Item = Result<SocketInfo, Error>>,
) -> impl Iterator<Item = Result<SocketInfo, Error>> {
    let mut pids_by_inode = build_hash_of_pids_by_inode();
    sockets_info.map(move |r| {
        r.map(|socket_info| SocketInfo {
            associated_pids: pids_by_inode
                .remove(&socket_info.inode)
                .unwrap_or_default()
                .iter()
                .map(|x| *x)
                .collect(),
            ..socket_info
        })
    })
}

pub fn port_to_pid(
    is_ipv4: bool,
    is_tcp: bool,
    ipv46: &[u8],
    port: u16,
) -> core::result::Result<isize, Box<dyn std::error::Error>> {
    let inet = if is_ipv4 {
        AF_INET as u8
    } else {
        AF_INET6 as u8
    };
    let proto = if is_tcp {
        IPPROTO_TCP as u8
    } else {
        IPPROTO_UDP as u8
    };
    for info in NetlinkIterator::new(inet, proto)?.into_iter().flatten() {
        let mut inode = 0;
        if is_tcp {
            if let ProtocolSocketInfo::Tcp(tcp_info) = info.protocol_socket_info {
                if tcp_info.local_port == port && crate::match_ip_addr(&tcp_info.local_addr, ipv46)
                {
                    inode = info.inode
                }
            }
        } else {
            if let ProtocolSocketInfo::Udp(udp_info) = info.protocol_socket_info {
                if udp_info.local_port == port && crate::match_ip_addr(&udp_info.local_addr, ipv46)
                {
                    inode = info.inode
                }
            }
        }
        if inode > 0 {
            return check_inode(inode);
        }
    }
    Ok(-1)
}

fn check_inode(inode: u32) -> Result<isize, Box<dyn std::error::Error>> {
    for i in read_dir("/proc")? {
        if let Ok(dir) = i {
            if let Some(file) = dir.file_name().to_str() {
                if let Ok(pid) = file.parse::<isize>() {
                    if let Ok(fds) = read_dir(format!("/proc/{pid}/fd")) {
                        for fd_rst in fds {
                            if let Some(fd) = fd_rst.ok() {
                                if let Some(name) = fd.file_name().to_str() {
                                    if let Ok(link) = read_link(format!("/proc/{pid}/fd/{name}")) {
                                        if let Some(socket) = link.to_str() {
                                            if socket.starts_with("socket:[") {
                                                let inode_str = &socket[8..socket.len() - 1];
                                                if let Ok(pid_inode) = inode_str.parse::<u32>() {
                                                    if pid_inode == inode {
                                                        return Ok(pid);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(-1)
}
