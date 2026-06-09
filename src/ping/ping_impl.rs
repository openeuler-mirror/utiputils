/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use anyhow::{Context, Result};
use log::{debug, error, info};
use pnet::packet::{
    icmp::{echo_reply::EchoReplyPacket, IcmpPacket, IcmpTypes},
    ipv4::{Ipv4OptionNumbers, Ipv4Packet},
    Packet,
};
use socket2::{SockAddr, Socket};
use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    thread,
    time::{Duration, Instant},
};

use trust_dns_resolver::{proto::rr::RecordType, Resolver};

use crate::ping::ping6_common::ping6_run;
use crate::{
    iputils_common::{init_logger, initialize_signal_handler, is_running, lookup_and_extend_ips},
    ping::{
        ping_common::{
            bind_to_interface_or_ip, parse_record_route_option, print_response_cached_with_ident,
            print_titile, set_record_route_option, set_socket_option, set_timestamp_option,
            timeout_or_count_exit, IcmpEchoRequest,
        },
        ping_types::{PingConfig, PingStats},
    },
};

const PACKET_SIZE: usize = 1024;

// 定义 ICMP 回复结果结构体，替代复杂的元组返回类型
#[derive(Debug)]
pub struct IcmpReply {
    pub sequence: u16,
    pub bytes_received: usize,
    pub source_ip: Ipv4Addr,
    pub ttl: u8,
    pub ip_options: Option<Vec<u8>>,
}

// 为复杂的返回类型定义类型别名
type IcmpReplyResult = Result<IcmpReply, anyhow::Error>;

pub fn main() {
    // 初始化日志记录器
    init_logger();

    info!("init command ...");

    // 直接使用合并后的 PingConfig 解析命令行参数
    let mut pgconfig = PingConfig::from_args();

    debug!("Config: {:?}", pgconfig);

    initialize_signal_handler();
    pgconfig.init_start_time();

    if let Err(err) = main_ping(&mut pgconfig) {
        eprintln!("ping: {}", err);
        error!("Error running ping: {}", err);
        std::process::exit(1);
    }
}

fn main_ping(pg_config: &mut PingConfig) -> Result<(), anyhow::Error> {
    let mut ips: Vec<IpAddr> = Vec::new();

    // Verbose output for socket information (before DNS resolution)
    if pg_config.verbose {
        // 原生 ping 显示两个 socket fd，我们简化为显示协议族信息
        println!("ping: sock4.fd: 3 (socktype: SOCK_RAW), sock6.fd: 4 (socktype: SOCK_RAW), hints.ai_family: AF_UNSPEC");
        println!();
    }

    // 解析目标地址
    let host = pg_config.host.as_ref().unwrap(); // 在这里已经验证过 host 不为 None

    // 如果启用 IPv6 且是 nodeinfo 查询，使用特殊处理
    if pg_config.force_ipv6 && !pg_config.nodeinfo_opt.is_empty() {
        info!("Running IPv6 nodeinfo query");
        // 对于 nodeinfo 查询，直接解析地址而不进行扩展查找
        match host.parse::<IpAddr>() {
            Ok(ip) => {
                if let IpAddr::V6(ipv6) = ip {
                    return ping6_run(ipv6, pg_config);
                } else {
                    anyhow::bail!("{}: Address family for hostname not supported", host);
                }
            }
            Err(_) => {
                anyhow::bail!("{}: Address family for hostname not supported", host);
            }
        }
    }

    // 普通ping流程：查找并扩展IP地址
    match host.parse::<IpAddr>() {
        Ok(ip) => {
            // 输入是IP地址
            info!("Target is an IP address: {}", ip);
            pg_config.is_direct_ip_input = true;
            ips.push(ip);

            // Verbose output for IP address
            if pg_config.verbose {
                let family = if ip.is_ipv4() { "AF_INET" } else { "AF_INET6" };
                println!("ai->ai_family: {}, ai->ai_canonname: '{}'", family, host);
            }
        }
        Err(_) => {
            // 输入是域名，需要DNS解析
            info!("Target is a domain name: {}", host);
            pg_config.is_direct_ip_input = false;
            let resolver = Resolver::from_system_conf().context("Failed to create resolver")?;

            // 先查询 CNAME 记录获取 canonical name
            let canonical_name = resolver
                .lookup(host, RecordType::CNAME)
                .ok()
                .and_then(|r| r.into_iter().next())
                .map(|c| c.to_string().trim_end_matches('.').to_string())
                .unwrap_or_else(|| host.to_string());

            // 更新配置中的域名为canonical name
            pg_config.domain = canonical_name.clone();

            // 根据强制选项确定查询类型
            match (pg_config.force_ipv4, pg_config.force_ipv6) {
                (true, _) => {
                    // 只查询IPv4
                    lookup_and_extend_ips(&resolver, host, RecordType::A, &mut ips)?;
                    if pg_config.verbose && !ips.is_empty() {
                        println!(
                            "ai->ai_family: AF_INET, ai->ai_canonname: '{}'",
                            canonical_name
                        );
                    }
                }
                (_, true) => {
                    // 只查询IPv6
                    lookup_and_extend_ips(&resolver, host, RecordType::AAAA, &mut ips)?;
                    if pg_config.verbose && !ips.is_empty() {
                        println!(
                            "ai->ai_family: AF_INET6, ai->ai_canonname: '{}'",
                            canonical_name
                        );
                    }
                }
                _ => {
                    // 查询IPv6和IPv4，根据域名确定优先级
                    // 对于localhost，保持IPv6优先（符合现代系统配置）
                    // 对于其他域名，优先IPv4（确保更好的连通性）

                    if host == "localhost" {
                        // localhost特殊处理：IPv6优先
                        if let Err(e) =
                            lookup_and_extend_ips(&resolver, host, RecordType::AAAA, &mut ips)
                        {
                            debug!("IPv6 lookup failed for localhost: {}", e);
                        }

                        if let Err(e) =
                            lookup_and_extend_ips(&resolver, host, RecordType::A, &mut ips)
                        {
                            debug!("IPv4 lookup failed for localhost: {}", e);
                        }
                    } else {
                        // 其他域名：IPv4优先，提高连通性
                        if let Err(e) =
                            lookup_and_extend_ips(&resolver, host, RecordType::A, &mut ips)
                        {
                            debug!("IPv4 lookup failed: {}", e);
                        }

                        if let Err(e) =
                            lookup_and_extend_ips(&resolver, host, RecordType::AAAA, &mut ips)
                        {
                            debug!("IPv6 lookup failed: {}", e);
                        }
                    }

                    // 对于 verbose 输出，我们延迟到确定实际使用的地址族后再显示
                    // 这样就可以与原生 ping 保持一致，只显示实际使用的地址族
                }
            }

            ips.dedup();
        }
    }

    // 检查解析结果
    if ips.is_empty() {
        anyhow::bail!("ping: {}: Name or service not known", host);
    }

    // 根据强制选项过滤IP
    let filtered_ips: Vec<IpAddr> = if pg_config.force_ipv4 {
        ips.into_iter().filter(|ip| ip.is_ipv4()).collect()
    } else if pg_config.force_ipv6 {
        ips.into_iter().filter(|ip| ip.is_ipv6()).collect()
    } else {
        ips
    };

    if filtered_ips.is_empty() && (pg_config.force_ipv4 || pg_config.force_ipv6) {
        anyhow::bail!("{}: Address family for hostname not supported", host);
    }

    // 使用第一个可用的IP地址进行ping
    let target_ip = filtered_ips[0];

    // 如果是域名解析且没有强制指定地址族，现在显示实际使用的地址族信息
    if pg_config.verbose
        && host.parse::<IpAddr>().is_err()
        && !pg_config.force_ipv4
        && !pg_config.force_ipv6
    {
        // 先查询 CNAME 记录获取 canonical name
        if let Ok(resolver) = Resolver::from_system_conf() {
            let canonical_name = resolver
                .lookup(host, RecordType::CNAME)
                .ok()
                .and_then(|r| r.into_iter().next())
                .map(|c| c.to_string().trim_end_matches('.').to_string())
                .unwrap_or_else(|| host.to_string());

            let family = if target_ip.is_ipv4() {
                "AF_INET"
            } else {
                "AF_INET6"
            };
            println!(
                "ai->ai_family: {}, ai->ai_canonname: '{}'",
                family, canonical_name
            );
        }
    }

    match target_ip {
        IpAddr::V4(ipv4) => {
            info!("Running ping4 for address: {}", ipv4);
            if let Err(e) = ping4_run(ipv4, pg_config) {
                // 检查是否是权限错误
                let error_msg = e.to_string();
                if error_msg.contains("Permission denied")
                    || error_msg.contains("Operation not permitted")
                    || error_msg.contains("Failed to create socket")
                {
                    eprintln!("utping: socket: Operation not permitted");
                    std::process::exit(1);
                } else {
                    eprintln!("utping: {}", e);
                    std::process::exit(1);
                }
            }
            info!("Ping4 run completed");
        }
        IpAddr::V6(ipv6) => {
            info!("Running ping6 for address: {}", ipv6);
            if let Err(e) = ping6_run(ipv6, pg_config) {
                // 检查是否是权限错误
                let error_msg = e.to_string();
                if error_msg.contains("Permission denied")
                    || error_msg.contains("Operation not permitted")
                    || error_msg.contains("Failed to create socket")
                {
                    eprintln!("utping: socket: Operation not permitted");
                    std::process::exit(1);
                } else {
                    eprintln!("utping: {}", e);
                    std::process::exit(1);
                }
            }
            info!("Ping6 run completed");
        }
    }

    Ok(())
}

pub fn create_icmpv4_socket(pg_config: &mut PingConfig) -> Result<socket2::Socket, anyhow::Error> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .context("Failed to create socket")?;

    // Verbose output for socket information will be shown later

    // 设置 TTL
    socket.set_ttl(pg_config.ttl).context("Failed to set TTL")?;

    if pg_config.send_buffer_size > 0 {
        debug!("Setting send buffer size to {}", pg_config.send_buffer_size);
        socket
            .set_send_buffer_size(pg_config.send_buffer_size)
            .context("Failed to set send buffer size")?;
    }

    // 设置了 interface 参数
    if !pg_config.interface.is_empty() {
        debug!("Binding to interface: {}", pg_config.interface);
        let (ip_addr, interface_name) = bind_to_interface_or_ip(&socket, &pg_config.interface)
            .context("Failed to bind to interface")?;
        pg_config.set_interface_info(ip_addr.to_string(), interface_name);
    }

    // 严格源地址
    if !pg_config.strictsource.is_empty() {
        debug!("Setting strict source");
        let strictsource_ip = pg_config
            .strictsource
            .parse::<Ipv4Addr>()
            .context("Invalid IPv4 address")?;
        let source_addr = SocketAddr::new(IpAddr::V4(strictsource_ip), 0);
        let source_sockaddr = SockAddr::from(source_addr);
        socket
            .bind(&source_sockaddr)
            .context("Failed to bind to strict source")?;
        pg_config.set_interface_info(strictsource_ip.to_string(), "".to_string());
    }

    // 设置 mark 参数
    if let Some(mark) = pg_config.mark {
        if mark > 0 {
            info!("Setting mark");
            socket.set_mark(mark).context("Failed to set mark")?;
        }
    }

    if let Some(tclass) = pg_config.tclass {
        if tclass > 0 {
            info!("Setting tclass");
            socket.set_tos(tclass).context("Failed to set tclass")?;
        }
    }

    // 禁用回环
    if pg_config.loop_multicast_back {
        socket
            .set_multicast_loop_v4(false)
            .context("Failed to disable multicast loop")?;
    }

    // 设置超时
    socket
        .set_read_timeout(Some(pg_config.timeout))
        .context("Failed to set timeout")?;

    if pg_config.flood {
        debug!("Setting flood");
        // 不设置非阻塞模式，而是在接收时使用短超时
        // socket.set_nonblocking(true)?;
    }

    // // 绑定网络接口
    // if let Some(interface) = &config.interface {
    //     socket.bind_device(Some(interface.as_bytes().into()))
    //         .context("Failed to bind device")?;
    // }

    // 启用广播（如果需要）
    if pg_config.broadcast {
        socket
            .set_broadcast(true)
            .context("Failed to enable broadcast")?;
    }

    // 设置调试模式
    if pg_config.debug {
        info!("Enabling debug mode");
        set_socket_option(&socket, libc::SOL_SOCKET, libc::SO_DEBUG, 1)
            .context("Failed to enable debug mode")?;
    }

    // 设置 PMTU 发现
    if !pg_config.pmtudisc.is_empty() {
        info!("Setting PMTU discovery");
        let optval = match pg_config.pmtudisc.as_str() {
            "do" => libc::IP_PMTUDISC_DO,
            "dont" => libc::IP_PMTUDISC_DONT,
            "want" => libc::IP_PMTUDISC_WANT,
            "probe" => libc::IP_PMTUDISC_PROBE,
            _ => unreachable!(),
        };
        set_socket_option(&socket, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, optval)
            .context("Failed to set PMTU discovery")?;
    }

    // 设置记录路由
    if pg_config.record_route {
        info!("Setting record route");
        set_record_route_option(&socket, false).context("Failed to set record route")?;
    }

    // 设置时间戳
    if !pg_config.timestamp.is_empty() {
        info!("Setting timestamp");
        set_timestamp_option(&socket, &pg_config.timestamp)?;
    }

    Ok(socket)
}

pub fn send_icmp_request(
    socket: &Socket,
    target: Ipv4Addr,
    packet: &[u8],
) -> Result<usize, anyhow::Error> {
    let target_addr = SocketAddrV4::new(target, 0);
    let sock_addr = SockAddr::from(target_addr);

    let bytes_sent = socket.send_to(packet, &sock_addr)?;
    Ok(bytes_sent)
}

// 发送带时间戳选项的完整IP包
pub fn send_ip_packet_with_timestamp(
    tx: &mut pnet::transport::TransportSender,
    target: Ipv4Addr,
    source: Ipv4Addr,
    packet: &mut [u8],
) -> Result<usize, anyhow::Error> {
    // 设置IP包的源地址和目标地址
    if let Some(mut ip_packet) = pnet::packet::ipv4::MutableIpv4Packet::new(packet) {
        ip_packet.set_source(source);
        ip_packet.set_destination(target);

        // 重新计算IP头校验和
        ip_packet.set_checksum(0);
        let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);
    }

    let bytes_sent = tx.send_to(
        pnet::packet::ipv4::Ipv4Packet::new(packet).unwrap(),
        IpAddr::V4(target),
    )?;
    Ok(bytes_sent)
}

// 带超时的ICMP回复接收函数
fn receive_icmp_reply_with_timeout(
    socket: &Socket,
    identifier: u16,
    timeout: Duration,
) -> Result<IcmpReply, anyhow::Error> {
    socket.set_read_timeout(Some(timeout))?;
    let result = receive_icmp_reply(socket, identifier);
    socket.set_read_timeout(None)?; // 重置为阻塞模式
    result
}

fn receive_icmp_reply(socket: &Socket, identifier: u16) -> IcmpReplyResult {
    debug!("Receiving ICMP reply");
    let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); PACKET_SIZE];

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, _addr)) => {
                debug!("Received packet of size {}", size);

                // 解析 IPv4 头部
                let ipv4_packet = Ipv4Packet::new(unsafe {
                    &*(&buffer[..size] as *const [std::mem::MaybeUninit<u8>] as *const [u8])
                })
                .ok_or(anyhow::anyhow!("Invalid IPv4 packet"))?;

                // 提取 ICMP 负载
                let icmp_payload = ipv4_packet.payload();
                let icmp_packet =
                    IcmpPacket::new(icmp_payload).ok_or(anyhow::anyhow!("Invalid ICMP packet"))?;
                debug!("Received ICMP packet: {:?}", icmp_packet);

                match icmp_packet.get_icmp_type() {
                    IcmpTypes::EchoReply => {
                        let echo_reply = EchoReplyPacket::new(icmp_packet.packet())
                            .ok_or(anyhow::anyhow!("Invalid Echo Reply packet"))?;

                        debug!(
                            "Received identifier: {}, expected: {}",
                            echo_reply.get_identifier(),
                            identifier
                        );
                        if echo_reply.get_identifier() != identifier {
                            debug!(
                                "Mismatched ID. Expected: ID={}, got: {}",
                                identifier,
                                echo_reply.get_identifier()
                            );
                            continue;
                        }

                        // 获取源 IP 地址和TTL
                        let src_ip = ipv4_packet.get_source();
                        let ttl = ipv4_packet.get_ttl();

                        let rr_option_data = if !ipv4_packet.get_options().is_empty() {
                            let mut bytes: Vec<u8> = Vec::new();
                            for opt in ipv4_packet.get_options_iter() {
                                bytes.extend_from_slice(opt.packet());
                            }
                            Some(bytes)
                        } else {
                            None
                        };

                        return Ok(IcmpReply {
                            sequence: echo_reply.get_sequence_number(),
                            bytes_received: size,
                            source_ip: src_ip,
                            ttl,
                            ip_options: rr_option_data,
                        });
                    }
                    IcmpTypes::DestinationUnreachable => {
                        return Err(anyhow::anyhow!("Destination unreachable"));
                    }
                    IcmpTypes::TimeExceeded => {
                        return Err(anyhow::anyhow!("Time exceeded"));
                    }
                    IcmpTypes::ParameterProblem => {
                        return Err(anyhow::anyhow!("Parameter problem"));
                    }
                    _ => {
                        debug!(
                            "Received non-reply ICMP type: {:?}",
                            icmp_packet.get_icmp_type()
                        );
                        continue;
                    }
                }
            }
            Err(e) => {
                debug!("Failed to receive packet: {}", e);
                return Err(e.into());
            }
        }
    }
}

fn extract_ipv4_option(option_data: &[u8], option_type: u8) -> Option<Vec<u8>> {
    if option_data.is_empty() {
        return None;
    }

    let mut pos = 0;
    while pos < option_data.len() {
        let ty = option_data[pos];

        // End of Option List
        if ty == 0 {
            break;
        }

        // NOP
        if ty == 1 {
            pos += 1;
            continue;
        }

        if pos + 1 >= option_data.len() {
            break;
        }

        let len = option_data[pos + 1] as usize;
        if len < 2 || pos + len > option_data.len() {
            break;
        }

        if ty == option_type {
            return Some(option_data[pos..pos + len].to_vec());
        }

        pos += len;
    }

    None
}

// 解析和显示时间戳信息 - 修正时间戳计算逻辑
fn print_timestamp_info(option_data: &[u8], _config: &PingConfig) {
    if option_data.len() < 4 {
        return;
    }

    let length = option_data[1] as usize;
    let pointer = option_data[2] as usize;
    let flags = option_data[3];
    let flag = flags & 0x0F;

    debug!(
        "Timestamp Option: length={}, pointer={}, flags=0x{:x}, len={}",
        length,
        pointer,
        flags,
        option_data.len()
    );

    let effective_len = length.min(option_data.len());
    if effective_len < 4 {
        return;
    }
    let timestamp_data = &option_data[4..effective_len];

    if flag == 0 {
        // tsonly 模式：仅时间戳
        let max_timestamps = timestamp_data.len() / 4;
        let pointer_clamped = pointer.min(length.saturating_add(1));
        let filled = pointer_clamped.saturating_sub(5) / 4;
        let filled = filled.min(max_timestamps);

        debug!(
            "tsonly: max_timestamps={}, pointer={}, filled={}",
            max_timestamps, pointer, filled
        );

        if filled == 0 {
            return;
        }

        let read_ts = |i: usize| -> u32 {
            let off = i * 4;
            u32::from_be_bytes([
                timestamp_data[off],
                timestamp_data[off + 1],
                timestamp_data[off + 2],
                timestamp_data[off + 3],
            ])
        };

        let first_timestamp = read_ts(0);
        println!("TS:     {} absolute", first_timestamp);

        let mut prev = first_timestamp as i64;
        for i in 1..filled {
            let curr = read_ts(i) as i64;
            println!("        {}", curr - prev);
            prev = curr;
        }
    } else if flag == 1 {
        // tsandaddr 模式：时间戳和地址交替
        let max_pairs = timestamp_data.len() / 8;
        let pointer_clamped = pointer.min(length.saturating_add(1));
        let filled_pairs = pointer_clamped.saturating_sub(5) / 8;
        let filled_pairs = filled_pairs.min(max_pairs);

        debug!(
            "tsandaddr: max_pairs={}, pointer={}, filled_pairs={}",
            max_pairs, pointer, filled_pairs
        );

        if filled_pairs == 0 {
            return;
        }

        let read_pair = |i: usize| -> (Ipv4Addr, u32) {
            let off = i * 8;
            let addr = Ipv4Addr::new(
                timestamp_data[off],
                timestamp_data[off + 1],
                timestamp_data[off + 2],
                timestamp_data[off + 3],
            );
            let ts = u32::from_be_bytes([
                timestamp_data[off + 4],
                timestamp_data[off + 5],
                timestamp_data[off + 6],
                timestamp_data[off + 7],
            ]);
            (addr, ts)
        };

        let (first_addr, first_timestamp) = read_pair(0);
        println!("TS:     {}     {} absolute", first_addr, first_timestamp);

        let mut prev = first_timestamp as i64;
        for i in 1..filled_pairs {
            let (addr, ts) = read_pair(i);
            let curr = ts as i64;
            println!("        {}     {}", addr, curr - prev);
            prev = curr;
        }
    } else {
        debug!("Unsupported timestamp flag: {}", flag);
    }
}

fn send_icmp_requests(
    socket: &Socket,
    target: Ipv4Addr,
    pg_config: &PingConfig,
    seq: u16,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    let mut start_seq = seq;
    for _ in 0..pg_config.preload {
        let request = IcmpEchoRequest::new(start_seq, pg_config.identifier, pg_config.packet_size);
        let packet = request.build_packet(pg_config);

        // 重新设置 RR 选项，确保每个包的指针都从 4 开始
        if pg_config.record_route {
            // 忽略可能的错误，因为部分系统内核可能不支持重复设置
            let _ = set_record_route_option(socket, false);
        }

        status.record_sent_time(start_seq);

        if let Err(e) = send_icmp_request(socket, target, &packet) {
            error!("Failed to send ICMP request: {}", e);
        }
        start_seq = start_seq.wrapping_add(1);
    }
    Ok(())
}

fn receive_icmp_replies(
    socket: &Socket,
    identifier: u16,
    pg_config: &PingConfig,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    debug!("Receiving ICMP replies: {:?}", status.sent_times);
    for _ in 0..pg_config.preload {
        if !is_running() {
            break;
        }
        match receive_icmp_reply(socket, identifier) {
            Ok(reply) => {
                let receive_seq = reply.sequence;
                if let Some(sent_time) = status.get_sent_time(receive_seq) {
                    let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0; // 转换为毫秒
                    print!(".");
                    let _ = std::io::stdout().flush();

                    if pg_config.audible {
                        print!("\x07");
                        let _ = std::io::stdout().flush();
                    }
                    print!("\x08");
                    let _ = std::io::stdout().flush();

                    // 显示Record Route信息
                    if let Some(data) = reply.ip_options {
                        parse_record_route_option(&data, pg_config);
                    }

                    status.update(rtt);
                    debug!(
                        "ICMP reply received: seq={}, size={}, src={}, ttl={}",
                        reply.sequence, reply.bytes_received, reply.source_ip, reply.ttl
                    );
                } else {
                    error!("Failed to find sent time for seq={}", receive_seq);
                }
            }
            Err(e) => {
                // 检查是否是ICMP错误（destination unreachable等）
                let error_msg = e.to_string();
                if error_msg.contains("Destination unreachable")
                    || error_msg.contains("Time exceeded")
                    || error_msg.contains("Parameter problem")
                {
                    status.record_error();
                } else {
                    error!("Failed to receive ICMP reply: {}", e);
                }
            }
        }

        if timeout_or_count_exit(pg_config, status) {
            break;
        }
    }
    Ok(())
}

fn preload_send_and_receive(
    socket: &Socket,
    target: Ipv4Addr,
    pg_config: &PingConfig,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    send_icmp_requests(socket, target, pg_config, 1, status)?;
    receive_icmp_replies(socket, pg_config.identifier, pg_config, status)?;
    Ok(())
}

fn flood_ping(
    socket: &Socket,
    target: Ipv4Addr,
    pg_config: &PingConfig,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    let mut start_seq = 1;
    loop {
        if !is_running() {
            info!("exit flood mode");
            break;
        }
        let request = IcmpEchoRequest::new(start_seq, pg_config.identifier, pg_config.packet_size);
        let packet = request.build_packet(pg_config);

        // 重新设置 RR 选项，确保每个包的指针都从 4 开始
        if pg_config.record_route {
            // 忽略可能的错误，因为部分系统内核可能不支持重复设置
            let _ = set_record_route_option(socket, false);
        }

        status.record_sent_time(start_seq);

        if let Err(e) = send_icmp_request(socket, target, &packet) {
            error!("Failed to send ICMP request: {}", e);
        }

        // Print a dot for each sent packet
        print!(".");
        let _ = std::io::stdout().flush();

        // 洪水模式使用短超时接收，避免阻塞太久
        match receive_icmp_reply_with_timeout(
            socket,
            pg_config.identifier,
            Duration::from_millis(10),
        ) {
            Ok(reply) => {
                let receive_seq = reply.sequence;
                if let Some(sent_time) = status.get_sent_time(receive_seq) {
                    let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0;

                    print!("\x08");
                    let _ = std::io::stdout().flush();

                    // 更新统计信息
                    status.update(rtt);

                    // 显示Record Route信息
                    if let Some(data) = reply.ip_options {
                        parse_record_route_option(&data, pg_config);
                    }
                } else {
                    error!("Failed to find sent time for seq={}", receive_seq);
                }
            }
            Err(e) => {
                // 检查是否是ICMP错误（destination unreachable等）
                let error_msg = e.to_string();
                if error_msg.contains("Destination unreachable")
                    || error_msg.contains("Time exceeded")
                    || error_msg.contains("Parameter problem")
                {
                    status.record_error();
                } else {
                    // 在洪水模式下，超时是正常的，不需要记录错误
                    debug!("Failed to receive ICMP reply in flood mode: {}", e);
                }
            }
        }

        start_seq = start_seq.wrapping_add(1);
        thread::sleep(Duration::from_millis(25));

        if timeout_or_count_exit(pg_config, status) {
            break;
        }
    }

    Ok(())
}

fn ping4_run(target: Ipv4Addr, pg_config: &mut PingConfig) -> Result<(), anyhow::Error> {
    info!("create_icmp_socket ...");

    let mut status = PingStats::new();
    status.start_time = Some(Instant::now());

    // 先创建socket，这样权限错误会在显示标题前捕获
    let socket = create_icmpv4_socket(pg_config)?;

    // 如果使用了pattern，先显示pattern信息（匹配原生ping行为）
    if !pg_config.pattern.is_empty() {
        println!("PATTERN: 0x{}", hex::encode(&pg_config.pattern));
    }

    // 只有socket创建成功才显示标题
    print_titile(IpAddr::V4(target), pg_config);

    if pg_config.connect_sk {
        info!("Connecting to target: {}", target);
        socket
            .connect(&SockAddr::from(SocketAddrV4::new(target, 0)))
            .context("Failed to connect to target")?;
    }

    // 洪水模式
    if pg_config.flood {
        flood_ping(&socket, target, pg_config, &mut status)?;
        status.print_summary(&pg_config.domain);
        return Ok(());
    }

    // 预加载模式
    if pg_config.preload > 0 {
        info!("Preloading {} ICMP requests", pg_config.preload);
        preload_send_and_receive(&socket, target, pg_config, &mut status)?;

        thread::sleep(Duration::from_secs(1));

        if timeout_or_count_exit(pg_config, &status) {
            status.print_summary(&pg_config.domain);
            return Ok(());
        }
    }

    info!("Start pinging target: {}", target.to_string());
    let mut seq = pg_config.preload + 1;
    let smoothed_rtt: Option<f64> = None;

    while is_running() {
        let request = IcmpEchoRequest::new(seq, pg_config.identifier, pg_config.packet_size);
        let packet = request.build_packet(pg_config);
        debug!("Sending ICMP packet: seq={}", seq);
        debug!(
            "Built packet length: {}, first 16 bytes: {:?}",
            packet.len(),
            &packet[..std::cmp::min(16, packet.len())]
        );

        // 重新设置 RR 选项，确保每个包的指针都从 4 开始，放在发送之前
        if pg_config.record_route {
            // 忽略可能的错误，因为部分系统内核可能不支持重复设置
            if let Err(e) = set_record_route_option(&socket, false) {
                debug!("reset RR option failed: {}", e);
            }
        }

        // 发送ICMP包
        status.record_sent_time(seq);
        if let Err(e) = send_icmp_request(&socket, target, &packet) {
            error!("Failed to send ICMP request: {}", e);
            break;
        }

        // 根据是否启用时间戳选择不同的接收方式
        if !pg_config.timestamp.is_empty() {
            // 时间戳模式：使用特殊的接收函数解析时间戳
            match receive_icmp_reply_with_timestamp(&socket, pg_config.identifier, pg_config) {
                Ok(reply) => {
                    let receive_seq = reply.sequence;
                    if let Some(sent_time) = status.get_sent_time(receive_seq) {
                        let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0;

                        if pg_config.audible {
                            print!("\x07");
                            let _ = std::io::stdout().flush();
                        }

                        // 时间戳模式显示
                        let message = format!(
                            "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
                            pg_config.packet_size + 8,
                            reply.source_ip,
                            receive_seq,
                            reply.ttl,
                            rtt
                        );
                        println!("{}", message);

                        // 显示 timestamp 选项输出（匹配 iputils `ping -T` 行为）
                        if let Some(all_opts) = reply.ip_options.as_deref() {
                            // 68 == IPOPT_TS (0x44)
                            if let Some(ts_opt) = extract_ipv4_option(all_opts, 68) {
                                print_timestamp_info(&ts_opt, pg_config);
                            }
                        }

                        // 显示Record Route信息 (在回复信息后)
                        if let Some(data) = reply.ip_options {
                            parse_record_route_option(&data, pg_config);
                        }

                        status.update(rtt);
                    }
                }
                Err(e) => {
                    // 检查是否是ICMP错误（destination unreachable等）
                    let error_msg = e.to_string();
                    if error_msg.contains("Destination unreachable")
                        || error_msg.contains("Time exceeded")
                        || error_msg.contains("Parameter problem")
                    {
                        status.record_error();
                    } else {
                        if pg_config.outstanding {
                            println!("No reply yet for sequence {}", seq);
                        }
                        debug!("Failed to receive ICMP reply with timestamp: {}", e);
                    }
                }
            }
        } else {
            // 普通模式 - 尝试接收回复，设置适当的超时时间
            match receive_icmp_reply_with_timeout(
                &socket,
                pg_config.identifier,
                Duration::from_millis(1000),
            ) {
                Ok(reply) => {
                    let receive_seq = reply.sequence;
                    if let Some(sent_time) = status.get_sent_time(receive_seq) {
                        let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0;

                        if pg_config.audible {
                            print!("\x07");
                            let _ = std::io::stdout().flush();
                        }

                        print_response_cached_with_ident(
                            &IpAddr::V4(reply.source_ip),
                            receive_seq,
                            rtt,
                            reply.ttl,
                            pg_config,
                            pg_config.identifier,
                        );

                        // 显示Record Route信息 (在回复信息后)
                        if let Some(data) = reply.ip_options {
                            parse_record_route_option(&data, pg_config);
                        }

                        // 如果是 -c 模式，统一在这里输出换行  必须换行
                        if pg_config.count.is_some() {
                            println!();
                        }

                        status.update(rtt);
                    } else {
                        error!("Failed to find sent time for seq={}", receive_seq);
                    }
                }
                Err(e) => {
                    // 检查是否是ICMP错误（destination unreachable等）
                    let error_msg = e.to_string();
                    if error_msg.contains("Destination unreachable")
                        || error_msg.contains("Time exceeded")
                        || error_msg.contains("Parameter problem")
                    {
                        status.record_error();
                    } else {
                        if pg_config.outstanding {
                            println!("No reply yet for sequence {}", seq);
                        }
                        debug!("Failed to receive ICMP reply: {}", e);
                    }
                }
            }
        }

        seq = seq.wrapping_add(1);

        // 动态调整间隔
        if pg_config.adaptive {
            let interval = match smoothed_rtt {
                Some(avg) => Duration::from_millis((avg * 1.5).max(10.0) as u64),
                None => Duration::from_millis(100),
            };
            std::thread::sleep(interval);
        } else {
            std::thread::sleep(Duration::from_millis(200));
        }

        if timeout_or_count_exit(pg_config, &status) {
            break;
        }
    }

    // 在主循环结束后，额外监听一段时间收集可能延迟到达的错误消息
    let final_listen_start = Instant::now();
    while final_listen_start.elapsed() < Duration::from_millis(500) {
        if let Ok(reply) = receive_icmp_reply_with_timeout(
            &socket,
            pg_config.identifier,
            Duration::from_millis(100),
        ) {
            if let Some(sent_time) = status.get_sent_time(reply.sequence) {
                let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0;
                print_response_cached_with_ident(
                    &IpAddr::V4(reply.source_ip),
                    reply.sequence,
                    rtt,
                    reply.ttl,
                    pg_config,
                    pg_config.identifier,
                );
                status.update(rtt);

                // 显示Record Route信息
                if let Some(data) = reply.ip_options {
                    parse_record_route_option(&data, pg_config);
                }
            }
        }
    }

    status.print_summary(&pg_config.domain);
    Ok(())
}

// 新增：使用常规socket接收带时间戳的回复
fn receive_icmp_reply_with_timestamp(
    socket: &Socket,
    identifier: u16,
    _config: &PingConfig,
) -> IcmpReplyResult {
    debug!("Receiving ICMP reply with timestamp using socket");
    let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); PACKET_SIZE];

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, _addr)) => {
                debug!("Received packet of size {}", size);

                // 解析 IPv4 头部
                let ipv4_packet = Ipv4Packet::new(unsafe {
                    &*(&buffer[..size] as *const [std::mem::MaybeUninit<u8>] as *const [u8])
                })
                .ok_or(anyhow::anyhow!("Invalid IPv4 packet"))?;

                let rr_option_data = if !ipv4_packet.get_options().is_empty() {
                    let mut bytes: Vec<u8> = Vec::new();
                    for opt in ipv4_packet.get_options_iter() {
                        bytes.extend_from_slice(opt.packet());
                    }
                    Some(bytes)
                } else {
                    None
                };

                // 检查IP选项中的时间戳和Record Route
                if !ipv4_packet.get_options().is_empty() {
                    debug!(
                        "Packet has IP options, length: {}",
                        ipv4_packet.get_options().len()
                    );
                    for option in ipv4_packet.get_options_iter() {
                        debug!("Option type: {:?}", option.get_number());
                        if option.get_number() == Ipv4OptionNumbers::TS {
                            debug!("Found timestamp option in reply");
                        } else if option.get_number().0 == 7 {
                            debug!("Found Record Route option");
                        }
                    }
                }

                // 提取 ICMP 负载
                let icmp_payload = ipv4_packet.payload();
                let icmp_packet =
                    IcmpPacket::new(icmp_payload).ok_or(anyhow::anyhow!("Invalid ICMP packet"))?;
                debug!("Received ICMP packet: {:?}", icmp_packet);

                match icmp_packet.get_icmp_type() {
                    IcmpTypes::EchoReply => {
                        let echo_reply = EchoReplyPacket::new(icmp_packet.packet())
                            .ok_or(anyhow::anyhow!("Invalid Echo Reply packet"))?;

                        if echo_reply.get_identifier() != identifier {
                            debug!("Mismatched ID. Expected: ID={}", identifier);
                            continue;
                        }

                        let src_ip = ipv4_packet.get_source();
                        let ttl = ipv4_packet.get_ttl();

                        // 返回结果，优先返回Record Route数据
                        return Ok(IcmpReply {
                            sequence: echo_reply.get_sequence_number(),
                            bytes_received: size,
                            source_ip: src_ip,
                            ttl,
                            ip_options: rr_option_data,
                        });
                    }
                    IcmpTypes::DestinationUnreachable => {
                        return Err(anyhow::anyhow!("Destination unreachable"));
                    }
                    IcmpTypes::TimeExceeded => {
                        return Err(anyhow::anyhow!("Time exceeded"));
                    }
                    IcmpTypes::ParameterProblem => {
                        return Err(anyhow::anyhow!("Parameter problem"));
                    }
                    _ => {
                        debug!(
                            "Received non-reply ICMP type: {:?}",
                            icmp_packet.get_icmp_type()
                        );
                        continue;
                    }
                }
            }
            Err(e) => {
                debug!("Failed to receive packet: {}", e);
                return Err(e.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ping::ping_types::{parse_hex, parse_u32};

    #[test]
    fn test_parse_u32_decimal() {
        assert_eq!(parse_u32("123"), Ok(123));
        assert_eq!(parse_u32("0"), Ok(0));
        assert_eq!(parse_u32("4294967295"), Ok(4294967295)); // u32 max
    }

    #[test]
    fn test_parse_u32_hex() {
        assert_eq!(parse_u32("0x1a"), Ok(0x1a));
        assert_eq!(parse_u32("0XFF"), Ok(0xff));
        assert_eq!(parse_u32("0xFFFFFFFF"), Ok(0xFFFFFFFF)); // u32 max in hex
    }

    #[test]
    fn test_parse_u32_invalid() {
        assert!(parse_u32("abc").is_err());
        assert!(parse_u32("0xzz").is_err());
        assert!(parse_u32("").is_err());
        assert!(parse_u32("4294967296").is_err()); // u32 overflow
    }

    #[test]
    fn test_parse_hex_valid() {
        assert_eq!(
            parse_hex("48656c6c6f"),
            Ok(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f])
        ); // "Hello"
        assert_eq!(parse_hex(""), Ok(vec![]));
        assert_eq!(parse_hex("deadbeef"), Ok(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn test_parse_hex_invalid() {
        assert!(parse_hex("zz").is_err());
        assert!(parse_hex("0x123").is_err()); // hex crate doesn't support 0x prefix
        assert!(parse_hex("123 ").is_err());
        assert!(parse_hex("abcg").is_err());
    }

    #[test]
    fn test_parse_hex_odd_length() {
        // 现在支持奇数长度的十六进制字符串（匹配原生ping行为）
        assert_eq!(parse_hex("a"), Ok(vec![0x0a])); // "a" -> "0a"
        assert_eq!(parse_hex("123"), Ok(vec![0x12, 0x03])); // "123" -> "1203"
        assert_eq!(parse_hex("f"), Ok(vec![0x0f])); // "f" -> "0f"
        assert_eq!(parse_hex("12345"), Ok(vec![0x12, 0x34, 0x05])); // "12345" -> "123405"
    }
}
