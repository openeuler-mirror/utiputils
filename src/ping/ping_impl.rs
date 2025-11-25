/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#![allow(unused_variables)]
use anyhow::{Context, Result};
use log::{debug, error, info};
use pnet::packet::{
    icmp::{echo_reply::EchoReplyPacket, IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
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

fn nodeinfo_optUsage() -> String {
    let help_text = [
        "ping -6 -N <nodeinfo opt>",
        "Help:",
        "  help",
        "Query:",
        "  name",
        "  ipv6",
        "  ipv6-all",
        "  ipv6-compatible",
        "  ipv6-global",
        "  ipv6-linklocal",
        "  ipv6-sitelocal",
        "  ipv4",
        "  ipv4-all",
        "Subject:",
        "  subject-ipv6=addr",
        "  subject-ipv4=addr",
        "  subject-name=name",
        "  subject-fqdn=name",
    ];

    help_text.join("\n")
}

pub fn main() {
    // 初始化日志记录器
    init_logger();

    info!("init command ...");

    // 直接使用合并后的 PingConfig 解析命令行参数
    let mut pgconfig = PingConfig::from_args();

    debug!("Config: {:?}", pgconfig);

    initialize_signal_handler();
    pgconfig.initStartTime();

    if let Err(err) = main_ping(&mut pgconfig) {
        eprintln!("ping: {}", err);
        error!("Error running ping: {}", err);
        std::process::exit(1);
    }
}

fn parseflow(str: &str) -> Result<u32, anyhow::Error> {
    let val = if str.starts_with("0x") || str.starts_with("0X") {
        u32::from_str_radix(&str[2..], 16)?
    } else {
        str.parse::<u32>()?
    };

    Ok(val)
}

fn main_ping(pgConfig: &mut PingConfig) -> Result<(), anyhow::Error> {
    let mut ips: Vec<IpAddr> = Vec::new();

    // Verbose output for socket information (before DNS resolution)
    if pgConfig.verbose {
        // 原生 ping 显示两个 socket fd，我们简化为显示协议族信息
        println!("ping: sock4.fd: 3 (socktype: SOCK_RAW), sock6.fd: 4 (socktype: SOCK_RAW), hints.ai_family: AF_UNSPEC");
        println!();
    }

    // 解析目标地址
    let host = pgConfig.host.as_ref().unwrap(); // 在这里已经验证过 host 不为 None

    // 如果启用 IPv6 且是 nodeinfo 查询，使用特殊处理
    if pgConfig.force_ipv6 && !pgConfig.nodeinfo_opt.is_empty() {
        info!("Running IPv6 nodeinfo query");
        // 对于 nodeinfo 查询，直接解析地址而不进行扩展查找
        // match host.parse::<IpAddr>() {
        //     Ok(ip) => {
        //         if let IpAddr::V6(ipv6) = ip {
        //             return ping6_run(ipv6, pgConfig);
        //         } else {
        //             anyhow::bail!("{}: Address family for hostname not supported", host);
        //         }
        //     }
        //     Err(_) => {
        //         anyhow::bail!("{}: Address family for hostname not supported", host);
        //     }
        // }
    }

    // 普通ping流程：查找并扩展IP地址
    match host.parse::<IpAddr>() {
        Ok(ip) => {
            // 输入是IP地址
            info!("Target is an IP address: {}", ip);
            pgConfig.is_direct_ip_input = true;
            ips.push(ip);

            // Verbose output for IP address
            if pgConfig.verbose {
                let family = if ip.is_ipv4() { "AF_INET" } else { "AF_INET6" };
                println!("ai->ai_family: {}, ai->ai_canonname: '{}'", family, host);
            }
        }
        Err(_) => {
            // 输入是域名，需要DNS解析
            info!("Target is a domain name: {}", host);
            pgConfig.is_direct_ip_input = false;
            let resolver = Resolver::from_system_conf().context("Failed to create resolver")?;

            // 先查询 CNAME 记录获取 canonical name
            let canonical_name = resolver
                .lookup(host, RecordType::CNAME)
                .ok()
                .and_then(|r| r.into_iter().next())
                .map(|c| c.to_string().trim_end_matches('.').to_string())
                .unwrap_or_else(|| host.to_string());

            // 更新配置中的域名为canonical name
            pgConfig.domain = canonical_name.clone();

            // 根据强制选项确定查询类型
            match (pgConfig.force_ipv4, pgConfig.force_ipv6) {
                (true, _) => {
                    // 只查询IPv4
                    lookup_and_extend_ips(&resolver, host, RecordType::A, &mut ips)?;
                    if pgConfig.verbose && !ips.is_empty() {
                        println!(
                            "ai->ai_family: AF_INET, ai->ai_canonname: '{}'",
                            canonical_name
                        );
                    }
                }
                (_, true) => {
                    // 只查询IPv6
                    lookup_and_extend_ips(&resolver, host, RecordType::AAAA, &mut ips)?;
                    if pgConfig.verbose && !ips.is_empty() {
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
    let filtered_ips: Vec<IpAddr> = if pgConfig.force_ipv4 {
        ips.into_iter().filter(|ip| ip.is_ipv4()).collect()
    } else if pgConfig.force_ipv6 {
        ips.into_iter().filter(|ip| ip.is_ipv6()).collect()
    } else {
        ips
    };

    if filtered_ips.is_empty() && (pgConfig.force_ipv4 || pgConfig.force_ipv6) {
        anyhow::bail!("{}: Address family for hostname not supported", host);
    }

    // 使用第一个可用的IP地址进行ping
    let target_ip = filtered_ips[0];

    // 如果是域名解析且没有强制指定地址族，现在显示实际使用的地址族信息
    if pgConfig.verbose
        && host.parse::<IpAddr>().is_err()
        && !pgConfig.force_ipv4
        && !pgConfig.force_ipv6
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
            // if let Err(e) = ping4_run(ipv4, pgConfig) {
            //     // 检查是否是权限错误
            //     let error_msg = e.to_string();
            //     if error_msg.contains("Permission denied")
            //         || error_msg.contains("Operation not permitted")
            //         || error_msg.contains("Failed to create socket")
            //     {
            //         eprintln!("utping: socket: Operation not permitted");
            //         std::process::exit(1);
            //     } else {
            //         eprintln!("utping: {}", e);
            //         std::process::exit(1);
            //     }
            // }
            info!("Ping4 run completed");
        }
        IpAddr::V6(ipv6) => {
            info!("Running ping6 for address: {}", ipv6);
            // if let Err(e) = ping6_run(ipv6, pgConfig) {
            //     // 检查是否是权限错误
            //     let error_msg = e.to_string();
            //     if error_msg.contains("Permission denied")
            //         || error_msg.contains("Operation not permitted")
            //         || error_msg.contains("Failed to create socket")
            //     {
            //         eprintln!("utping: socket: Operation not permitted");
            //         std::process::exit(1);
            //     } else {
            //         eprintln!("utping: {}", e);
            //         std::process::exit(1);
            //     }
            // }
            info!("Ping6 run completed");
        }
    }

    Ok(())
}

pub fn create_icmpv4_socket(pgConfig: &mut PingConfig) -> Result<socket2::Socket, anyhow::Error> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::ICMPV4),
    )
    .context("Failed to create socket")?;

    // Verbose output for socket information will be shown later

    // 设置 TTL
    socket.set_ttl(pgConfig.ttl).context("Failed to set TTL")?;

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
            .parse::<Ipv4Addr>()
            .context("Invalid IPv4 address")?;
        let source_addr = SocketAddr::new(IpAddr::V4(strictsource_ip), 0);
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
            socket.set_tos(tclass).context("Failed to set tclass")?;
        }
    }

    // 禁用回环
    if pgConfig.loop_multicast_back {
        socket
            .set_multicast_loop_v4(false)
            .context("Failed to disable multicast loop")?;
    }

    // 设置超时
    socket
        .set_read_timeout(Some(pgConfig.timeout))
        .context("Failed to set timeout")?;

    if pgConfig.flood {
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
    if pgConfig.broadcast {
        socket
            .set_broadcast(true)
            .context("Failed to enable broadcast")?;
    }

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
    if pgConfig.record_route {
        info!("Setting record route");
        set_record_route_option(&socket, false).context("Failed to set record route")?;
    }

    // 设置时间戳
    if !pgConfig.timestamp.is_empty() {
        info!("Setting timestamp");
        set_timestamp_option(&socket, &pgConfig.timestamp)?;
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

// 接收带时间戳选项的IP包回复
fn receive_ip_reply_with_timestamp(
    rx: &mut pnet::transport::TransportReceiver,
    identifier: u16,
    _config: &PingConfig,
) -> Result<IcmpReply, anyhow::Error> {
    debug!("Receiving IP reply with timestamp");

    let mut iter = pnet::transport::ipv4_packet_iter(rx);
    let timeout = Duration::from_secs(1);

    match iter.next_with_timeout(timeout) {
        Ok(Some((packet, addr))) => {
            debug!(
                "Received IP packet from {}: len={}",
                addr,
                packet.packet().len()
            );

            let mut timestamp_option_data = None;

            // 检查是否有时间戳选项
            if !packet.get_options().is_empty() {
                debug!("Packet has IP options");
                for option in packet.get_options_iter() {
                    if option.get_number() == Ipv4OptionNumbers::TS {
                        debug!("Found timestamp option in reply");
                        timestamp_option_data = Some(option.packet().to_vec());
                    }
                }
            }

            // 处理ICMP内容
            if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                let icmp_packet = IcmpPacket::new(packet.payload())
                    .ok_or(anyhow::anyhow!("Invalid ICMP packet"))?;

                if icmp_packet.get_icmp_type() == IcmpTypes::EchoReply {
                    let echo_reply = EchoReplyPacket::new(icmp_packet.packet())
                        .ok_or(anyhow::anyhow!("Invalid Echo Reply packet"))?;

                    if echo_reply.get_identifier() == identifier {
                        let src_ip = if let IpAddr::V4(ipv4) = addr {
                            ipv4
                        } else {
                            return Err(anyhow::anyhow!("Expected IPv4 address"));
                        };

                        return Ok(IcmpReply {
                            sequence: echo_reply.get_sequence_number(),
                            bytes_received: icmp_packet.packet().len(), // 使用ICMP包大小，不是IP包大小
                            source_ip: src_ip,
                            ttl: packet.get_ttl(),
                            ip_options: timestamp_option_data,
                        });
                    }
                }
            }

            Err(anyhow::anyhow!("No matching echo reply found"))
        }
        Ok(None) => Err(anyhow::anyhow!("Timeout waiting for reply")),
        Err(e) => Err(anyhow::anyhow!("Error receiving packet: {}", e)),
    }
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

    let timestamp_data = &option_data[4..];

    if flag == 0 {
        // tsonly 模式：仅时间戳
        if timestamp_data.len() >= 4 {
            // 解析第一个时间戳
            let first_timestamp = u32::from_be_bytes([
                timestamp_data[0],
                timestamp_data[1],
                timestamp_data[2],
                timestamp_data[3],
            ]);

            // 显示时间戳信息，使用英文以匹配原生ping
            println!("TS:     {} absolute", first_timestamp);

            // 收集所有有效的时间戳
            let mut timestamps = vec![first_timestamp];

            // 计算最大可能的时间戳数量（基于选项长度）
            let max_timestamps = (length - 4) / 4; // 减去头部4字节，除以每个时间戳4字节
            debug!("Max possible timestamps: {}", max_timestamps);

            // 尝试解析更多时间戳，目标是获得4个时间戳以匹配原生ping
            for i in 1..max_timestamps.min(9) {
                // 最多解析9个时间戳
                let offset = i * 4;
                if offset + 3 < timestamp_data.len() {
                    let ts = u32::from_be_bytes([
                        timestamp_data[offset],
                        timestamp_data[offset + 1],
                        timestamp_data[offset + 2],
                        timestamp_data[offset + 3],
                    ]);

                    timestamps.push(ts);
                    debug!("Timestamp {}: {}", i + 1, ts);

                    // 如果我们已经有4个时间戳且找到合理的停止点，就停止
                    if timestamps.len() >= 4 {
                        // 检查后续时间戳是否都是0，如果是则可以停止
                        let mut all_zero_after = true;
                        for j in i + 1..max_timestamps.min(9) {
                            let next_offset = j * 4;
                            if next_offset + 3 < timestamp_data.len() {
                                let next_ts = u32::from_be_bytes([
                                    timestamp_data[next_offset],
                                    timestamp_data[next_offset + 1],
                                    timestamp_data[next_offset + 2],
                                    timestamp_data[next_offset + 3],
                                ]);
                                if next_ts != 0 {
                                    all_zero_after = false;
                                    break;
                                }
                            }
                        }
                        if all_zero_after {
                            break;
                        }
                    }
                }
            }

            debug!("Found {} timestamps", timestamps.len());

            // 显示时间戳的相对差值
            for i in 1..timestamps.len() {
                let diff = timestamps[i] as i64 - timestamps[i - 1] as i64;

                // 检测异常大的差值，可能表明时间戳未被正确填充
                if diff.abs() > 1000000 {
                    // 如果差值超过1000秒，可能是异常值
                    debug!("Detected abnormal timestamp diff: {}, stopping", diff);
                    break;
                }

                println!("        {}", diff);
            }
        }
    } else if flag == 1 {
        // tsandaddr 模式：时间戳和地址交替
        if timestamp_data.len() >= 8 {
            // 至少需要一个地址(4字节) + 时间戳(4字节)

            // 解析第一对：地址 + 时间戳
            let first_addr = Ipv4Addr::new(
                timestamp_data[0],
                timestamp_data[1],
                timestamp_data[2],
                timestamp_data[3],
            );
            let first_timestamp = u32::from_be_bytes([
                timestamp_data[4],
                timestamp_data[5],
                timestamp_data[6],
                timestamp_data[7],
            ]);

            // 显示第一行：地址 + 时间戳 + absolute
            println!("TS:     {}     {} absolute", first_addr, first_timestamp);

            // 收集所有地址和时间戳对
            let mut timestamps = vec![first_timestamp];
            let max_pairs = (length - 4) / 8; // 每对占用8字节
            debug!("Max possible address-timestamp pairs: {}", max_pairs);

            // 解析后续的地址-时间戳对
            for i in 1..max_pairs.min(9) {
                let offset = i * 8;
                if offset + 7 < timestamp_data.len() {
                    let addr = Ipv4Addr::new(
                        timestamp_data[offset],
                        timestamp_data[offset + 1],
                        timestamp_data[offset + 2],
                        timestamp_data[offset + 3],
                    );
                    let ts = u32::from_be_bytes([
                        timestamp_data[offset + 4],
                        timestamp_data[offset + 5],
                        timestamp_data[offset + 6],
                        timestamp_data[offset + 7],
                    ]);

                    timestamps.push(ts);
                    debug!("Address-Timestamp pair {}: {} - {}", i + 1, addr, ts);

                    // 计算与前一个时间戳的差值
                    let diff = ts as i64 - timestamps[timestamps.len() - 2] as i64;

                    // 检测异常差值
                    if diff.abs() > 1000000 {
                        debug!("Detected abnormal timestamp diff: {}, stopping", diff);
                        break;
                    }

                    // 显示：地址 + 差值
                    println!("        {}     {}", addr, diff);
                }
            }
        }
    } else {
        debug!("Unsupported timestamp flag: {}", flag);
    }
}

fn send_icmp_requests(
    socket: &Socket,
    target: Ipv4Addr,
    pgConfig: &PingConfig,
    seq: u16,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    let mut start_seq = seq;
    for _ in 0..pgConfig.preload {
        let request = IcmpEchoRequest::new(start_seq, pgConfig.identifier, pgConfig.packet_size);
        let packet = request.build_packet(pgConfig);

        // 重新设置 RR 选项，确保每个包的指针都从 4 开始
        if pgConfig.record_route {
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
    pgConfig: &PingConfig,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    debug!("Receiving ICMP replies: {:?}", status.sent_times);
    for _ in 0..pgConfig.preload {
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

                    if pgConfig.audible {
                        print!("\x07");
                        let _ = std::io::stdout().flush();
                    }
                    print!("\x08");
                    let _ = std::io::stdout().flush();

                    // 显示Record Route信息
                    if let Some(data) = reply.ip_options {
                        parse_record_route_option(&data, pgConfig);
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

        if timeout_or_count_exit(pgConfig, status) {
            break;
        }
    }
    Ok(())
}

fn preload_send_and_receive(
    socket: &Socket,
    target: Ipv4Addr,
    pgConfig: &PingConfig,
    status: &mut PingStats,
) -> Result<(), anyhow::Error> {
    send_icmp_requests(socket, target, pgConfig, 1, status)?;
    receive_icmp_replies(socket, pgConfig.identifier, pgConfig, status)?;
    Ok(())
}

fn flood_ping(
    socket: &Socket,
    target: Ipv4Addr,
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
        let packet = request.build_packet(pgConfig);

        // 重新设置 RR 选项，确保每个包的指针都从 4 开始
        if pgConfig.record_route {
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
            pgConfig.identifier,
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
                        parse_record_route_option(&data, pgConfig);
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

        if timeout_or_count_exit(pgConfig, status) {
            break;
        }
    }

    Ok(())
}

fn ping4_run(target: Ipv4Addr, pgConfig: &mut PingConfig) -> Result<(), anyhow::Error> {
    info!("create_icmp_socket ...");

    let mut status = PingStats::new();
    status.start_time = Some(Instant::now());

    // 先创建socket，这样权限错误会在显示标题前捕获
    let socket = create_icmpv4_socket(pgConfig)?;

    // 如果使用了pattern，先显示pattern信息（匹配原生ping行为）
    if !pgConfig.pattern.is_empty() {
        println!("PATTERN: 0x{}", hex::encode(&pgConfig.pattern));
    }

    // 只有socket创建成功才显示标题
    print_titile(IpAddr::V4(target), pgConfig);

    if pgConfig.connect_sk {
        info!("Connecting to target: {}", target);
        socket
            .connect(&SockAddr::from(SocketAddrV4::new(target, 0)))
            .context("Failed to connect to target")?;
    }

    // 洪水模式
    if pgConfig.flood {
        flood_ping(&socket, target, pgConfig, &mut status)?;
        status.print_summary(&pgConfig.domain);
        return Ok(());
    }

    // 预加载模式
    if pgConfig.preload > 0 {
        info!("Preloading {} ICMP requests", pgConfig.preload);
        preload_send_and_receive(&socket, target, pgConfig, &mut status)?;

        thread::sleep(Duration::from_secs(1));

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
        let request = IcmpEchoRequest::new(seq, pgConfig.identifier, pgConfig.packet_size);
        let packet = request.build_packet(pgConfig);
        debug!("Sending ICMP packet: seq={}", seq);
        debug!(
            "Built packet length: {}, first 16 bytes: {:?}",
            packet.len(),
            &packet[..std::cmp::min(16, packet.len())]
        );

        // 重新设置 RR 选项，确保每个包的指针都从 4 开始，放在发送之前
        if pgConfig.record_route {
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
        if !pgConfig.timestamp.is_empty() {
            // 时间戳模式：使用特殊的接收函数解析时间戳
            match receive_icmp_reply_with_timestamp(&socket, pgConfig.identifier, pgConfig) {
                Ok(reply) => {
                    let receive_seq = reply.sequence;
                    if let Some(sent_time) = status.get_sent_time(receive_seq) {
                        let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0;

                        if pgConfig.audible {
                            print!("\x07");
                            let _ = std::io::stdout().flush();
                        }

                        // 时间戳模式显示
                        let message = format!(
                            "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
                            pgConfig.packet_size + 8,
                            reply.source_ip,
                            receive_seq,
                            reply.ttl,
                            rtt
                        );
                        println!("{}", message);

                        // 显示Record Route信息 (在回复信息后)
                        if let Some(data) = reply.ip_options {
                            parse_record_route_option(&data, pgConfig);
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
                        if pgConfig.outstanding {
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
                pgConfig.identifier,
                Duration::from_millis(1000),
            ) {
                Ok(reply) => {
                    let receive_seq = reply.sequence;
                    if let Some(sent_time) = status.get_sent_time(receive_seq) {
                        let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0;

                        if pgConfig.audible {
                            print!("\x07");
                            let _ = std::io::stdout().flush();
                        }

                        print_response_cached_with_ident(
                            &IpAddr::V4(reply.source_ip),
                            receive_seq,
                            rtt,
                            reply.ttl,
                            pgConfig,
                            pgConfig.identifier,
                        );

                        // 显示Record Route信息 (在回复信息后)
                        if let Some(data) = reply.ip_options {
                            parse_record_route_option(&data, pgConfig);
                        }

                        // 如果是 -c 模式，统一在这里输出换行  必须换行
                        if pgConfig.count.is_some() {
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
                        if pgConfig.outstanding {
                            println!("No reply yet for sequence {}", seq);
                        }
                        debug!("Failed to receive ICMP reply: {}", e);
                    }
                }
            }
        }

        seq = seq.wrapping_add(1);

        // 动态调整间隔
        if pgConfig.adaptive {
            let interval = match smoothed_rtt {
                Some(avg) => Duration::from_millis((avg * 1.5).max(10.0) as u64),
                None => Duration::from_millis(100),
            };
            std::thread::sleep(interval);
        } else {
            std::thread::sleep(Duration::from_millis(200));
        }

        if timeout_or_count_exit(pgConfig, &status) {
            break;
        }
    }

    // 在主循环结束后，额外监听一段时间收集可能延迟到达的错误消息
    let final_listen_start = Instant::now();
    while final_listen_start.elapsed() < Duration::from_millis(500) {
        if let Ok(reply) = receive_icmp_reply_with_timeout(
            &socket,
            pgConfig.identifier,
            Duration::from_millis(100),
        ) {
            if let Some(sent_time) = status.get_sent_time(reply.sequence) {
                let rtt: f64 = sent_time.elapsed().as_secs_f64() * 1000.0;
                print_response_cached_with_ident(
                    &IpAddr::V4(reply.source_ip),
                    reply.sequence,
                    rtt,
                    reply.ttl,
                    pgConfig,
                    pgConfig.identifier,
                );
                status.update(rtt);

                // 显示Record Route信息
                if let Some(data) = reply.ip_options {
                    parse_record_route_option(&data, pgConfig);
                }
            }
        }
    }

    status.print_summary(&pgConfig.domain);
    Ok(())
}

// 获取访问目标的本地IP地址
fn get_local_ip_for_target(target: Ipv4Addr) -> Result<Ipv4Addr, anyhow::Error> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(format!("{}:53", target))?;
    let local_addr = socket.local_addr()?;
    match local_addr.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        _ => Err(anyhow::anyhow!("Expected IPv4 address")),
    }
}

// 新增：使用常规socket接收带时间戳的回复
fn receive_icmp_reply_with_timestamp(
    socket: &Socket,
    identifier: u16,
    config: &PingConfig,
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

                let mut timestamp_option_data = None;
                let rr_option_data = if !ipv4_packet.get_options().is_empty() {
                    let mut bytes: Vec<u8> = Vec::new();
                    for opt in ipv4_packet.get_options_iter() {
                        if opt.get_number() == Ipv4OptionNumbers::TS {
                            timestamp_option_data = Some(opt.packet().to_vec());
                        }
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

                        // 如果找到时间戳选项，显示时间戳信息
                        if let Some(data) = &rr_option_data {
                            parse_record_route_option(data, config);
                        }

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
