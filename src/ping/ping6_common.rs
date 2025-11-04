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

pub fn ping6_run(target: Ipv6Addr, pgConfig: &mut PingConfig) -> Result<(), anyhow::Error> {
    info!("create_icmp_socket ...");
    let socket = create_icmpv6_socket(pgConfig)?;
    info!("create_icmp_socket success ...");

    if pgConfig.connect_sk {
        info!("Connecting to target: {}", target);
        socket
            .connect(&SockAddr::from(SocketAddrV6::new(target, 0, 0, 0)))
            .context("Failed to connect to target")?;
    }

    // 检查是否是 nodeinfo 查询
    if !pgConfig.nodeinfo_opt.is_empty() {
        info!("Running IPv6 nodeinfo query: {}", pgConfig.nodeinfo_opt);
        return run_nodeinfo_query(&socket, target, pgConfig);
    }

    let identifier = pgConfig.identifier;
    let mut status = PingStats::new();
    status.start_time = Some(Instant::now());

    // 如果使用了pattern，先显示pattern信息（匹配原生ping行为）
    if !pgConfig.pattern.is_empty() {
        println!("PATTERN: 0x{}", hex::encode(&pgConfig.pattern));
    }

    print_titile(IpAddr::V6(target), pgConfig);

    if pgConfig.flood {
        flood_ping_v6(&socket, target, pgConfig, &mut status)?;
        status.print_summary(&pgConfig.domain);
        return Ok(());
    }

    if pgConfig.preload > 0 {
        info!("Preloading {} ICMP requests", pgConfig.preload);
        preload_send_and_receive(&socket, target, pgConfig, &mut status)?;

        std::thread::sleep(Duration::from_secs(1));

        if timeout_or_count_exit(pgConfig, &status) {
            status.print_summary(&pgConfig.domain);
            return Ok(());
        }
    }

    info!("Start pinging target: {}", target.to_string());
    let mut seq = pgConfig.preload + 1;
    let mut smoothed_rtt: Option<f64> = None;
    const ALPHA: f64 = 0.125; // 平滑因子

    while is_running() {
        let request = IcmpEchoRequest::new(seq, identifier, pgConfig.packet_size);
        let packet = request.build_packet_V6(pgConfig);
        debug!("Sending ICMPv6 packet: seq={}", seq);

        // 发送ICMP包
        status.record_sent_time(seq);
        if let Err(e) = send_icmpv6_request(&socket, target, packet, pgConfig) {
            error!("Failed to send ICMP request: {}", e);
            break;
        }

        // 阻塞接收响应包（确保RTT测量准确）
        match receive_icmpv6_reply(&socket, identifier) {
            Ok((receive_seq, size, src)) => {
                debug!(
                    "ICMPv6 reply received: seq={}, size={}, src={}",
                    receive_seq, size, src
                );

                if let Some(sent_time) = status.get_sent_time(receive_seq) {
                    let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0;
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

                    // 更新平滑RTT
                    smoothed_rtt = match smoothed_rtt {
                        Some(avg) => Some(ALPHA * rtt + (1.0 - ALPHA) * avg),
                        None => Some(rtt),
                    };
                } else {
                    error!("Failed to find sent time for seq={}", receive_seq);
                }
            }
            Err(e) => {
                // 检查是否是ICMP错误（destination unreachable等）
                let error_msg = e.to_string();
                if error_msg.contains("Destination unreachable")
                    || error_msg.contains("Packet too big")
                    || error_msg.contains("Time exceeded")
                {
                    status.record_error();
                } else {
                    if pgConfig.outstanding {
                        println!("No reply yet for sequence {}", seq);
                    }
                    debug!("Failed to receive ICMPv6 reply: {}", e);
                }
            }
        }

        seq = seq.wrapping_add(1);

        // 动态调整间隔
        if pgConfig.adaptive {
            let interval = match smoothed_rtt {
                Some(avg) => Duration::from_millis((avg * 1.5).max(10.0) as u64), // 基础间隔=1.5*RTT，最小10ms
                None => Duration::from_millis(100),                               // 初始默认间隔
            };
            std::thread::sleep(interval);
        } else {
            // 使用更短的间隔，提升性能（从默认1秒改为200ms）
            std::thread::sleep(Duration::from_millis(200));
        }

        if timeout_or_count_exit(pgConfig, &status) {
            break;
        }
    }

    status.print_summary(&pgConfig.domain);
    Ok(())
}

// IPv6 nodeinfo 查询实现
fn run_nodeinfo_query(
    socket: &Socket,
    target: Ipv6Addr,
    pgConfig: &PingConfig,
) -> Result<(), anyhow::Error> {
    info!("Starting IPv6 nodeinfo query to: {}", target);

    let mut status = PingStats::new();
    status.start_time = Some(Instant::now());

    println!("PING {}({}) {} data bytes", target, target, 56); // 与原生ping保持一致的显示大小

    let mut seq = 1u16;
    let target_addr = SocketAddrV6::new(target, 0, 0, 0);
    let sock_addr = SockAddr::from(target_addr);

    // 主循环 - 像普通ping一样持续发送
    while is_running() {
        // 检查是否达到了count限制
        if let Some(count) = pgConfig.count {
            if status.transmitted >= count {
                debug!("Nodeinfo count reached, stopping...");
                break;
            }
        }

        // 构造 nodeinfo 查询包
        let nodeinfo_packet = build_nodeinfo_packet(&pgConfig.nodeinfo_opt, pgConfig)?;

        // 发送查询
        let send_time = Instant::now();
        match socket.send_to(&nodeinfo_packet, &sock_addr) {
            Ok(_) => {
                status.transmitted += 1;
                debug!("Nodeinfo query {} sent", seq);
            }
            Err(e) => {
                error!("Failed to send nodeinfo query: {}", e);
                continue;
            }
        }

        // 接收回复 (with timeout)
        let mut buffer = Box::new([std::mem::MaybeUninit::<u8>::uninit(); 1500]);

        match socket.recv_from(&mut *buffer) {
            Ok((size, addr)) => {
                let elapsed = send_time.elapsed();
                debug!(
                    "Received nodeinfo response: {} bytes in {:?}",
                    size, elapsed
                );

                let packet = Icmpv6Packet::new(unsafe {
                    std::slice::from_raw_parts(buffer.as_ptr() as *const u8, size)
                })
                .ok_or(anyhow::anyhow!("Invalid ICMPv6 packet"))?;

                // 解析 nodeinfo 回复
                let has_real_reply = parse_nodeinfo_reply(&packet, pgConfig)?;

                if has_real_reply {
                    let rtt_ms = elapsed.as_secs_f64() * 1000.0;
                    status.update(rtt_ms);
                    println!(
                        "Reply from {}: {} bytes, time={:.3}ms",
                        addr.as_socket_ipv6()
                            .map(|s| s.ip().to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        size,
                        rtt_ms
                    );
                } else {
                    debug!("Got echo/loopback response, not counting as received");
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    debug!("Nodeinfo query {} timed out", seq);
                } else {
                    error!("Failed to receive nodeinfo reply: {}", e);
                }
            }
        }

        seq += 1;

        // 间隔等待 - 与普通ping一样
        if pgConfig.interval > Duration::from_secs(0) {
            std::thread::sleep(pgConfig.interval);
        } else {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    // 打印统计信息
    status.print_summary(&target.to_string());

    Ok(())
}

// 构造 IPv6 nodeinfo 查询包
fn build_nodeinfo_packet(
    nodeinfo_opt: &str,
    _config: &PingConfig,
) -> Result<Vec<u8>, anyhow::Error> {
    // ICMPv6 Node Information Query 的类型为 139
    const ICMPV6_NI_QUERY: u8 = 139;

    // 构造基本的 nodeinfo 查询包
    let mut packet = vec![0u8; 24]; // 基本头部大小

    packet[0] = ICMPV6_NI_QUERY; // Type
    packet[1] = 0; // Code
    packet[2] = 0; // Checksum (will be calculated later)
    packet[3] = 0; // Checksum

    // Qtype (query type) 根据 nodeinfo 选项设置
    let qtype: u16 = match nodeinfo_opt {
        "name" => 2,            // Node Name
        "ipv6" => 0,            // IPv6 Address
        "ipv6-all" => 0,        // All IPv6 Addresses
        "ipv6-compatible" => 0, // IPv4-compatible IPv6
        "ipv6-global" => 0,     // Global IPv6
        "ipv6-linklocal" => 0,  // Link-local IPv6
        "ipv6-sitelocal" => 0,  // Site-local IPv6
        "ipv4" => 1,            // IPv4 Address
        "ipv4-all" => 1,        // All IPv4 Addresses
        _ => {
            warn!("Unsupported nodeinfo query type: {}", nodeinfo_opt);
            2 // 默认为 name 查询
        }
    };

    packet[4..6].copy_from_slice(&qtype.to_be_bytes());

    // Flags
    packet[6..8].copy_from_slice(&0u16.to_be_bytes());

    // Nonce (8 bytes random - using timestamp for uniqueness)
    let nonce: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    packet[8..16].copy_from_slice(&nonce.to_be_bytes());

    // Subject (8 bytes, 可以是 IPv6 地址的一部分)
    packet[16..24].copy_from_slice(&[0u8; 8]);

    debug!(
        "Built nodeinfo packet: {} bytes, qtype: {}",
        packet.len(),
        qtype
    );
    Ok(packet)
}

// 解析 IPv6 nodeinfo 回复
fn parse_nodeinfo_reply(
    packet: &Icmpv6Packet,
    _config: &PingConfig,
) -> Result<bool, anyhow::Error> {
    debug!("Parsing nodeinfo reply");

    let icmp_type = packet.get_icmpv6_type();
    debug!("ICMPv6 type: {:?}", icmp_type);

    // ICMPv6 Node Information Reply 的类型为 140
    let packet_type = packet.packet()[0];
    if packet_type == 140 {
        debug!("Received ICMPv6 Node Information Reply");
        // 真正的 nodeinfo 回复，继续解析
    } else if packet_type == 139 {
        debug!("Received ICMPv6 Node Information Query (echo/loopback)");
        // 这通常发生在本地回环或者目标不支持 nodeinfo 但会回显包的情况
        // 根据原生ping行为，这种情况应该视为无回复（100% packet loss）
        return Ok(false); // 没有真正的回复，与原生ping行为一致
    } else {
        debug!("Not a nodeinfo packet, type: {}", packet_type);
        return Ok(false);
    }

    let payload = packet.payload();
    if payload.len() < 8 {
        debug!("Nodeinfo reply too short");
        return Ok(false);
    }

    // 解析 qtype
    let qtype = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);

    debug!("Nodeinfo reply - qtype: {}, flags: 0x{:x}", qtype, flags);

    // 解析数据部分（从第8字节开始）
    if payload.len() > 8 {
        let data = &payload[8..];
        match qtype {
            2 => {
                // Node Name
                if let Ok(name) = std::str::from_utf8(data) {
                    println!("Node name: {}", name.trim_end_matches('\0'));
                } else {
                    println!("Node name: (binary data, {} bytes)", data.len());
                }
            }
            0 => {
                // IPv6 Address
                println!("IPv6 addresses: {} bytes of data", data.len());
                for chunk in data.chunks(16) {
                    if chunk.len() == 16 {
                        let mut addr_bytes = [0u8; 16];
                        addr_bytes.copy_from_slice(chunk);
                        let addr = Ipv6Addr::from(addr_bytes);
                        println!("  {}", addr);
                    }
                }
            }
            1 => {
                // IPv4 Address
                println!("IPv4 addresses: {} bytes of data", data.len());
                for chunk in data.chunks(4) {
                    if chunk.len() == 4 {
                        let addr = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                        println!("  {}", addr);
                    }
                }
            }
            _ => {
                println!(
                    "Unknown nodeinfo data type: {}, {} bytes",
                    qtype,
                    data.len()
                );
            }
        }
    } else {
        println!("No data in nodeinfo reply");
    }

    Ok(true) // 有真正的回复
}
