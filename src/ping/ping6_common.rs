/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::{
    io::Write,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::{Duration, Instant},
};

use anyhow::Context;
use log::{debug, error, info, warn};
use pnet::packet::{
    icmpv6::{Icmpv6Packet, Icmpv6Types},
    Packet,
};
use socket2::{SockAddr, Socket};

use crate::{
    iputils_common::is_running,
    ping::{
        ping_common::{
            bind_to_interface_or_ip, print_response_cached_with_ident, print_titile,
            set_record_route_option, set_socket_option, timeout_or_count_exit, IcmpEchoRequest,
        },
        ping_types::{PingConfig, PingStats},
    },
};

// IPv6 套接字创建
fn create_icmpv6_socket(pgConfig: &mut PingConfig) -> anyhow::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV6),
    )?;

    // Verbose output for IPv6 socket information will be shown later
    // 设置 IPv6 专用选项
    // socket.set_only_v6(true)?;

    if pgConfig.send_buffer_size > 0 {
        debug!("Setting send buffer size to {}", pgConfig.send_buffer_size);
        socket
            .set_send_buffer_size(pgConfig.send_buffer_size)
            .context("Failed to set send buffer size")?;
    }

    // 设置了 interface 参数
    if !pgConfig.interface.is_empty() {
        debug!("Binding to interface: {}", pgConfig.interface);
        let (ip_addr, interface_name) = bind_to_interface_or_ip(&socket, &pgConfig.interface)
            .context("Failed to bind to interface")?;
        pgConfig.setInterfaceInfo(ip_addr.to_string(), interface_name);
    }

    // 严格源地址
    if !pgConfig.strictsource.is_empty() {
        debug!("Setting strict source");
        let strictsource_ip = pgConfig
            .strictsource
            .parse::<Ipv6Addr>()
            .context("Invalid IPv4 address")?;
        let source_addr = SocketAddr::new(IpAddr::V6(strictsource_ip), 0);
        let source_sockaddr = SockAddr::from(source_addr);
        socket
            .bind(&source_sockaddr)
            .context("Failed to bind to strict source")?;
        pgConfig.setInterfaceInfo(strictsource_ip.to_string(), "".to_string());
    }

    // 设置 mark 参数
    if let Some(mark) = pgConfig.mark {
        if mark > 0 {
            info!("Setting mark");
            socket.set_mark(mark).context("Failed to set mark")?;
        }
    }

    if let Some(tclass) = pgConfig.tclass {
        if tclass > 0 {
            info!("Setting tclass");
            socket
                .set_tclass_v6(tclass)
                .context("Failed to set tclass")?;
        }
    }

    // 禁用回环
    if pgConfig.loop_multicast_back {
        socket
            .set_multicast_loop_v6(false)
            .context("Failed to disable multicast loop")?;
    }

    debug!("Setting IPv6 unicast hops to {}", pgConfig.ttl);
    socket.set_unicast_hops_v6(pgConfig.ttl)?; // IPv6 的 TTL 称为 Hop Limit

    // 设置超时
    socket
        .set_read_timeout(Some(pgConfig.timeout))
        .context("Failed to set timeout")?;

    // 设置调试模式
    if pgConfig.debug {
        info!("Enabling debug mode");
        set_socket_option(&socket, libc::SOL_SOCKET, libc::SO_DEBUG, 1)
            .context("Failed to enable debug mode")?;
    }

    // 设置 PMTU 发现
    if !pgConfig.pmtudisc.is_empty() {
        info!("Setting PMTU discovery");
        let optval = match pgConfig.pmtudisc.as_str() {
            "do" => libc::IPV6_PMTUDISC_DO,
            "dont" => libc::IPV6_PMTUDISC_DONT,
            "want" => libc::IPV6_PMTUDISC_WANT,
            "probe" => libc::IPV6_PMTUDISC_PROBE,
            _ => unreachable!(),
        };

        set_socket_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, optval)
            .context("Failed to set PMTU discovery")?;
    }

    // 设置记录路由
    if pgConfig.record_route {
        info!("Setting record route");
        set_record_route_option(&socket, true)?;
    }

    // 设置时间戳
    if !pgConfig.timestamp.is_empty() {
        anyhow::bail!("timestamp only supports IPv4");
    }

    // 设置流标签
    if let Some(flowlabel) = pgConfig.flowlabel {
        if flowlabel > 0 {
            info!("Setting flowlabel IPv6");
            //设置 flowlabel
            set_socket_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_FLOWINFO_SEND, 1)?;
        }
    }

    Ok(socket)
}

pub fn send_icmpv6_request(
    socket: &Socket,
    target: Ipv6Addr,
    packet: Vec<u8>,
    pgConfig: &PingConfig,
) -> Result<usize, anyhow::Error> {
    let mut flowinfo = 0;
    if let Some(flowlabel) = pgConfig.flowlabel {
        if flowlabel > 0 {
            flowinfo = flowlabel & 0x000FFFFF;
        }
    }

    let target_addr = SocketAddrV6::new(target, 0, flowinfo, 0);
    let sock_addr = SockAddr::from(target_addr);

    let bytes_sent = socket.send_to(&packet, &sock_addr)?;
    Ok(bytes_sent)
}

fn receive_icmpv6_reply(
    socket: &Socket,
    identifier: u16,
) -> Result<(u16, usize, Ipv6Addr), anyhow::Error> {
    debug!("Receiving ICMP reply");
    let mut buffer = Box::new([std::mem::MaybeUninit::<u8>::uninit(); 1500]);

    let mut msgErr: String = String::new();

    loop {
        match socket.recv_from(&mut *buffer) {
            Ok((size, addr)) => {
                debug!("Received packet of size {}", size);

                let packet = Icmpv6Packet::new(unsafe {
                    std::slice::from_raw_parts(buffer.as_ptr() as *const u8, size)
                })
                .ok_or(anyhow::anyhow!("Invalid ICMPv6 packet"))?;
                debug!("Received ICMPv6 packet: {:?}", packet);
                let ipv6Type = packet.get_icmpv6_type();
                match ipv6Type {
                    Icmpv6Types::EchoReply => {
                        debug!("Received ICMPv6 Echo Reply");
                        let echo_reply =
                            pnet::packet::icmpv6::echo_reply::EchoReplyPacket::new(packet.packet())
                                .ok_or(anyhow::anyhow!("Invalid ICMPv6 Echo Reply packet"))?;
                        debug!("Echo reply: {:?}", echo_reply);
                        if echo_reply.get_identifier() != identifier {
                            warn!("Mismatched identifier");
                            continue;
                        }

                        let src_addr =
                            addr.as_socket_ipv6()
                                .map(|addr| *addr.ip())
                                .ok_or_else(|| {
                                    anyhow::anyhow!("Received packet from non-IPv6 address")
                                })?;
                        return Ok((echo_reply.get_sequence_number(), size, src_addr));
                    }
                    Icmpv6Types::DestinationUnreachable => {
                        let src_addr =
                            addr.as_socket_ipv6()
                                .map(|addr| *addr.ip())
                                .ok_or_else(|| {
                                    anyhow::anyhow!("Received packet from non-IPv6 address")
                                })?;

                        // 获取ICMPv6错误代码来确定具体的错误原因
                        let code = packet.get_icmpv6_code().0;
                        let reason = match code {
                            0 => "No route to destination",
                            1 => "Communication with destination administratively prohibited",
                            2 => "Beyond scope of source address",
                            3 => "Address unreachable",
                            4 => "Port unreachable",
                            5 => "Source address failed ingress/egress policy",
                            6 => "Reject route to destination",
                            _ => "Destination unreachable",
                        };

                        // 创建详细的错误消息，与原生ping格式一致
                        let error_msg = format!(
                            "From {} icmp_seq={} Destination unreachable: {}",
                            src_addr,
                            1, // 这里应该从嵌入的原始包中获取seq，暂时用1
                            reason
                        );
                        println!("{}", error_msg);
                        return Err(anyhow::anyhow!("Destination unreachable"));
                    }
                    Icmpv6Types::PacketTooBig => {
                        let src_addr =
                            addr.as_socket_ipv6()
                                .map(|addr| *addr.ip())
                                .ok_or_else(|| {
                                    anyhow::anyhow!("Received packet from non-IPv6 address")
                                })?;

                        let error_msg = format!("From {} icmp_seq={} Packet too big", src_addr, 1);
                        println!("{}", error_msg);
                        return Err(anyhow::anyhow!("Packet too big"));
                    }
                    Icmpv6Types::TimeExceeded => {
                        let src_addr =
                            addr.as_socket_ipv6()
                                .map(|addr| *addr.ip())
                                .ok_or_else(|| {
                                    anyhow::anyhow!("Received packet from non-IPv6 address")
                                })?;

                        let error_msg = format!("From {} icmp_seq={} Time exceeded", src_addr, 1);
                        println!("{}", error_msg);
                        return Err(anyhow::anyhow!("Time exceeded"));
                    }
                    _ => {
                        let message = format!("ingroe type: {:?}", ipv6Type);
                        debug!("{}", message);
                        continue;
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    if !msgErr.is_empty() {
                        warn!("timeout exit, receive error: {}", msgErr);
                        return Err(anyhow::anyhow!(msgErr));
                    }
                    return Err(e.into());
                    // return Err(anyhow::anyhow!("Timeout"));
                } else if e.kind() == std::io::ErrorKind::WouldBlock {
                    if !msgErr.is_empty() {
                        warn!("timeout exit, receive error: {}", msgErr);
                        return Err(anyhow::anyhow!(msgErr));
                    }
                    warn!("Receive error: {} {}", msgErr, e);
                    continue;
                    // return Err(e.into());
                } else {
                    warn!("else error: {} {}", msgErr, e);
                    return Err(e.into());
                }
            }
        }
    }
}

fn send_icmpv6_requests(
    socket: &Socket,
    target: Ipv6Addr,
    pgConfig: &PingConfig,
    seq: u16,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    let mut start_seq = seq;
    for _ in 0..pgConfig.preload {
        let request = IcmpEchoRequest::new(start_seq, pgConfig.identifier, pgConfig.packet_size);
        let packet = request.build_packet_V6(pgConfig);
        status.record_sent_time(start_seq);

        if let Err(e) = send_icmpv6_request(socket, target, packet, pgConfig) {
            error!("Failed to send ICMP request: {}", e);
        }
        start_seq = start_seq.wrapping_add(1);
    }
    Ok(())
}

fn receive_icmpv6_replies(
    socket: &Socket,
    identifier: u16,
    pgConfig: &PingConfig,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    debug!("Receiving ICMP replies: {:?}", status.sent_times);
    for _ in 0..pgConfig.preload {
        if !is_running() {
            break;
        }
        match receive_icmpv6_reply(socket, identifier) {
            Ok((receive_seq, size, src)) => {
                if let Some(sent_time) = status.get_sent_time(receive_seq) {
                    let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0; // 转换为毫秒
                    print_response_cached_with_ident(
                        &IpAddr::V6(src),
                        receive_seq,
                        rtt,
                        pgConfig.ttl as u8,
                        pgConfig,
                        pgConfig.identifier,
                    );
                    status.update(rtt);
                    if pgConfig.audible {
                        print!("\x07");
                        let _ = std::io::stdout().flush();
                    }
                    debug!("ICMP reply received: size={}, src={}", size, src);
                } else {
                    error!("Failed to find sent time for seq={}", receive_seq);
                }
            }
            Err(e) => {
                error!("Failed to receive ICMP reply: {}", e);
            }
        }

        if let Some(count) = pgConfig.count {
            if status.transmitted >= count {
                debug!("Ping count reached, stopping...");
                break;
            }
        }
    }
    Ok(())
}

fn preload_send_and_receive(
    socket: &Socket,
    target: Ipv6Addr,
    pgConfig: &PingConfig,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    send_icmpv6_requests(socket, target, pgConfig, 1, status)?;
    receive_icmpv6_replies(socket, pgConfig.identifier, pgConfig, status)?;
    Ok(())
}

fn flood_ping_v6(
    socket: &Socket,
    target: Ipv6Addr,
    pgConfig: &PingConfig,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    let mut start_seq = 1;
    loop {
        if !is_running() {
            info!("exit flood mode");
            break;
        }
        let request = IcmpEchoRequest::new(start_seq, pgConfig.identifier, pgConfig.packet_size);
        let packet = request.build_packet_V6(pgConfig);
        status.record_sent_time(start_seq);

        if let Err(e) = send_icmpv6_request(socket, target, packet, pgConfig) {
            error!("Failed to send ICMP request: {}", e);
        }

        // Print a dot for each sent packet
        print!(".");
        let _ = std::io::stdout().flush();

        match receive_icmpv6_reply(socket, pgConfig.identifier) {
            Ok((receive_seq, _size, _src)) => {
                if let Some(sent_time) = status.get_sent_time(receive_seq) {
                    let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0; // 转换为毫秒
                                                                               // print_response(&IpAddr::V4(src), receive_seq, rtt, pgConfig);
                    status.update(rtt);
                    // Print a backspace for each received packet
                    print!("\x08");
                    let _ = std::io::stdout().flush();
                } else {
                    error!("Failed to find sent time for seq={}", receive_seq);
                }
            }
            Err(e) => {
                error!("Failed to receive ICMP reply: {}", e);
            }
        }

        start_seq = start_seq.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(25));

        if timeout_or_count_exit(pgConfig, status) {
            break;
        }
    }

    Ok(())
}
