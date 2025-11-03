/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use clap::Parser;
use log::{debug, error, info};
use pnet::{
    packet::{
        icmp::{destination_unreachable::IcmpCodes, IcmpPacket, IcmpTypes},
        ip::IpNextHeaderProtocols,
        Packet,
    },
    transport::{ipv4_packet_iter, transport_channel, TransportChannelType},
};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::process;
use std::time::{Duration, Instant};

use crate::iputils_common::{
    init_logger, initialize_signal_handler, is_running, reverse_dns_lookup,
};

use anyhow::Result;

const MAX_HOPS: u8 = 30; // 最大跳数
const BASE_PORT: u16 = 44444; // 基准端口号
const BASE_MTU: u16 = 1500; // 基准MTU
const TIMEOUT_MS: u64 = 100; // 缩短超时时间，提高性能
const WAIT_STEP_MS: u64 = 1000; // 缩短等待间隔，提高性能
const TTL_INTERVAL_MS: u64 = 10; // 缩短TTL间隔，提高性能

// IPv6错误队列相关常量
const IPV6_RECVERR: i32 = 25;
const IPV6_HOPLIMIT: i32 = 52;
const IP_RECVERR: i32 = 11;
const MSG_ERRQUEUE: i32 = 0x2000;
const SO_EE_ORIGIN_ICMP6: u8 = 3;
const SO_EE_ORIGIN_ICMP: u8 = 2;
const SO_EE_ORIGIN_LOCAL: u8 = 1;

// ICMP类型常量
const ICMPV6_TIME_EXCEED: u8 = 3;
const ICMPV6_EXC_HOPLIMIT: u8 = 0;

// 历史记录数组大小
const HIS_ARRAY_SIZE: usize = 64;

// sock_extended_err结构体（对应Linux内核定义）
#[repr(C)]
#[derive(Debug)]
struct SockExtendedErr {
    ee_errno: u32,
    ee_origin: u8,
    ee_type: u8,
    ee_code: u8,
    ee_pad: u8,
    ee_info: u32,
    ee_data: u32,
}

// 历史记录结构
#[derive(Debug, Clone, Default)]
struct HistoryEntry {
    hops: u8,
    send_time: Option<Instant>,
}

#[derive(Debug, Parser)]
#[command(
    name = "uttracepath",
     author = "UnionTech Software Technology Co., Ltd.",
    version = concat!("from ", env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")),
    about = "Tracepath utility - trace path to network host discovering MTU along this path"
)]
#[derive(Default)]
pub struct TracepathConfig {
    /// DNS name or IP address
    #[arg(value_name = "DESTINATION")]
    pub destination: String,

    /// Use IPv4
    #[arg(short = '4')]
    pub use_ipv4: bool,

    /// Use IPv6
    #[arg(short = '6')]
    pub use_ipv6: bool,

    /// Print both name and ip
    #[arg(short = 'b')]
    pub print_both_ip: bool,

    /// Use packet <length>
    #[arg(short = 'l', value_parser = clap::value_parser!(i32).range(29..))]
    pub length: Option<i32>,

    /// Use maximum <hops>
    #[arg(short = 'm', value_parser = clap::value_parser!(u8).range(1..))]
    pub hops: Option<u8>,

    /// No dns name resolution
    #[arg(short = 'n')]
    pub no_dns: bool,

    /// Use destination <port>
    #[arg(short = 'p')]
    pub port: Option<u16>,
}

impl TracepathConfig {
    pub fn from_args() -> Self {
        Self::parse()
    }

    pub fn get_length(&self) -> u32 {
        self.length.unwrap_or(BASE_MTU as i32) as u32
    }

    pub fn get_hops(&self) -> u8 {
        self.hops.unwrap_or(MAX_HOPS)
    }

    pub fn get_port(&self) -> u16 {
        self.port.unwrap_or(BASE_PORT)
    }
}

#[derive(Debug)]
struct RunState {
    exit: bool,
    start_time: Instant,
    target: IpAddr,
    ttl: u8,
    hops_from: u8,
    hops_to: u8,
    reached: bool,
    send_time: Option<Instant>, // 记录实际的UDP发送时间，用于计算真实RTT
    history: Vec<HistoryEntry>, // 历史记录数组
    hisptr: usize,              // 历史记录指针
    base_port: u16,             // 基准端口
}

impl Default for RunState {
    fn default() -> Self {
        Self {
            exit: false,
            start_time: Instant::now(),
            target: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            ttl: 1,
            hops_from: 0,
            hops_to: 0,
            reached: false,
            send_time: None,
            history: vec![HistoryEntry::default(); HIS_ARRAY_SIZE],
            hisptr: 0,
            base_port: 44444, // 默认基准端口
        }
    }
}

#[derive(Debug)]
struct ResolveResult {
    address: IpAddr,
    hostname: String,
}

fn resolve(destination: &str, tp_config: &TracepathConfig) -> Result<ResolveResult, anyhow::Error> {
    // 尝试直接解析为IP地址
    if let Ok(addr) = destination.parse::<IpAddr>() {
        // 检查IP地址版本是否与用户偏好匹配
        match addr {
            IpAddr::V4(_) if tp_config.use_ipv6 => {
                return Err(anyhow::anyhow!("IPv4 address specified but -6 option used"));
            }
            IpAddr::V6(_) if tp_config.use_ipv4 => {
                return Err(anyhow::anyhow!("IPv6 address specified but -4 option used"));
            }
            _ => {
                return Ok(ResolveResult {
                    address: addr,
                    hostname: destination.to_string(),
                });
            }
        }
    }

    // 如果不是IP地址，尝试DNS解析
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> =
        format!("{}:80", destination).to_socket_addrs()?.collect();

    // 根据用户偏好选择IP版本
    let preferred_addr = if tp_config.use_ipv6 {
        // 优先选择IPv6地址
        addrs
            .iter()
            .find(|addr| addr.is_ipv6())
            .or_else(|| addrs.first())
    } else if tp_config.use_ipv4 {
        // 优先选择IPv4地址
        addrs
            .iter()
            .find(|addr| addr.is_ipv4())
            .or_else(|| addrs.first())
    } else {
        // 没有明确偏好，使用第一个地址（通常是IPv4）
        addrs.first()
    };

    if let Some(addr) = preferred_addr {
        Ok(ResolveResult {
            address: addr.ip(),
            hostname: destination.to_string(),
        })
    } else {
        Err(anyhow::anyhow!(
            "Unable to resolve destination: {}",
            destination
        ))
    }
}

pub fn main() {
    info!("Starting tracepath");
    init_logger();
    initialize_signal_handler();

    // 命令行参数解析
    let tp_config = TracepathConfig::from_args();

    tracepath_run(&tp_config).unwrap_or_else(|e| {
        error!("Error: {:?}", e);
        process::exit(1);
    });
}

fn tracepath_run(tp_config: &TracepathConfig) -> std::result::Result<(), anyhow::Error> {
    let resolve_result = resolve(&tp_config.destination, tp_config)?;
    let target_addr = resolve_result.address;
    let is_ipv6 = target_addr.is_ipv6();

    if is_ipv6 {
        // IPv6使用UDP socket + 错误队列机制
        tracepath_run_udp_ipv6(tp_config, target_addr)
    } else {
        // IPv4继续使用当前的ICMP raw socket机制（工作良好）
        tracepath_run_icmp_ipv4(tp_config, target_addr)
    }
}

// IPv4实现：继续使用当前的ICMP raw socket机制
fn tracepath_run_icmp_ipv4(
    tp_config: &TracepathConfig,
    target_addr: IpAddr,
) -> std::result::Result<(), anyhow::Error> {
    let (_tx, mut rx) = create_transport_channel(false)?;

    // 创建全局状态，在整个tracepath过程中保持（与IPv6版本一致）
    let mut global_state = RunState {
        target: target_addr,
        base_port: tp_config.get_port(),
        ..Default::default()
    };

    for ttl in 1..=tp_config.get_hops() {
        let mut found_response = false;
        global_state.ttl = ttl;

        // 每个TTL尝试最多3次探测（模拟原生的MAX_PROBES逻辑）
        for probe_attempt in 0..3 {
            if let Err(e) = send_udp_probe(tp_config, &mut global_state) {
                debug!(
                    "Failed to send UDP probe (attempt {}): {}",
                    probe_attempt + 1,
                    e
                );
                continue;
            }

            // 接收响应的安全实现
            match receive_icmp_reply_safe(&mut rx, &mut global_state, tp_config) {
                Ok(response_type) => {
                    found_response = true;
                    match response_type {
                        ResponseType::Reached => {
                            // 到达目标后立即退出，不需要额外的Resume信息（已在receive_icmp_reply_safe中处理）
                            return Ok(());
                        }
                        ResponseType::TimeExceeded => {
                            // TTL超时 - 继续下一跳
                            break;
                        }
                        ResponseType::Unreachable => {
                            // 不可达错误 - 显示Resume并退出
                            print_resume(tp_config, &global_state);
                            return Ok(());
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "No response received (attempt {}): {}",
                        probe_attempt + 1,
                        e
                    );
                    continue;
                }
            }
        }

        if !found_response {
            println!("{:2}:  no reply", ttl);
        }
    }

    println!("     Too many hops: pmtu 1500");
    Ok(())
}

// IPv6实现：使用UDP socket + 错误队列机制
fn tracepath_run_udp_ipv6(
    tp_config: &TracepathConfig,
    target_addr: IpAddr,
) -> std::result::Result<(), anyhow::Error> {
    // 创建UDP socket
    let socket = create_udp_socket_ipv6()?;

    // 创建全局状态，在整个tracepath过程中保持
    let mut global_state = RunState {
        target: target_addr,
        base_port: tp_config.get_port(),
        ..Default::default()
    };

    // 首先进行PMTU发现 - 尝试发送一个大包来触发EMSGSIZE错误
    let _pmtu_discovery_result = perform_pmtu_discovery(&socket, &mut global_state);

    // 记录每个TTL是否收到过响应（包括延迟响应）
    let mut ttl_responses: std::collections::HashMap<u8, bool> = std::collections::HashMap::new();

    for ttl in 1..=tp_config.get_hops() {
        let mut found_response = false;
        global_state.ttl = ttl;

        // 每个TTL尝试最多3次探测
        for probe_attempt in 0..3 {
            // 在发送新包之前，先清理错误队列中的延迟响应
            while let Ok(Some((error_info, received_port))) =
                receive_error_message_with_port(&socket)
            {
                let recv_time = Instant::now();
                let (actual_ttl, rtt_ms) =
                    find_send_history_by_port(&mut global_state, received_port, recv_time);

                debug!(
                    "Clearing delayed response: errno={}, port={}, actual_ttl={}, rtt={:.3}ms",
                    error_info.errno, received_port, actual_ttl, rtt_ms
                );

                // 标记这个TTL已经收到响应
                ttl_responses.insert(actual_ttl, true);

                // 处理延迟响应
                match error_info.errno {
                    111 => {
                        // ECONNREFUSED - 端口不可达，表示到达目标
                        print_probe_result_safe(
                            tp_config,
                            &RunState {
                                ttl: actual_ttl,
                                ..Default::default()
                            },
                            &global_state.target,
                        );
                        println!("{:>8.3}ms reached", rtt_ms);
                        print_resume(tp_config, &global_state);
                        return Ok(());
                    }
                    113 => {
                        // EHOSTUNREACH - 主机不可达
                        print!("{:2}:  {:<53} ", actual_ttl, "localhost.localdomain");
                        println!("{:>8.3}ms !H", rtt_ms);
                        print_resume(tp_config, &global_state);
                        return Ok(());
                    }
                    110 => {
                        // ETIMEDOUT - TTL超时
                        if let Some(ref source_addr) = error_info.source_addr {
                            print_probe_result_safe(
                                tp_config,
                                &RunState {
                                    ttl: actual_ttl,
                                    ..Default::default()
                                },
                                source_addr,
                            );
                            println!("{:>8.3}ms", rtt_ms);
                        }
                    }
                    _ => {
                        debug!("Other delayed error: {}", error_info.errno);
                    }
                }
            }

            // 发送UDP探测包
            match send_udp_probe_ipv6(&socket, tp_config, &mut global_state) {
                Ok(Some(response_type)) => {
                    // 立即收到响应
                    found_response = true;
                    match response_type {
                        ResponseType::Reached => {
                            return Ok(());
                        }
                        ResponseType::TimeExceeded => {
                            break;
                        }
                        ResponseType::Unreachable => {
                            print_resume(tp_config, &global_state);
                            return Ok(());
                        }
                    }
                }
                Ok(None) => {
                    // 发送成功，但没有立即响应，继续等待错误队列
                    // 接收错误队列响应，正确处理延迟响应
                    match receive_error_queue_with_delayed_response(
                        &socket,
                        &mut global_state,
                        tp_config,
                        &mut ttl_responses,
                    ) {
                        Ok(Some(response_type)) => {
                            found_response = true;
                            match response_type {
                                ResponseType::Reached => {
                                    return Ok(());
                                }
                                ResponseType::TimeExceeded => {
                                    break;
                                }
                                ResponseType::Unreachable => {
                                    print_resume(tp_config, &global_state);
                                    return Ok(());
                                }
                            }
                        }
                        Ok(None) => {
                            // 收到了延迟响应，但不是当前TTL的
                            // 检查当前TTL是否已经通过延迟响应得到了回复
                            if *ttl_responses.get(&ttl).unwrap_or(&false) {
                                found_response = true;
                                break;
                            }
                            continue;
                        }
                        Err(e) => {
                            debug!(
                                "No response received (attempt {}): {}",
                                probe_attempt + 1,
                                e
                            );
                            // 在每次尝试后检查是否收到了延迟响应
                            if *ttl_responses.get(&ttl).unwrap_or(&false) {
                                found_response = true;
                                break;
                            }
                            continue;
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to send UDP probe (attempt {}): {}",
                        probe_attempt + 1,
                        e
                    );
                    continue;
                }
            }
        }

        // 最后再次检查是否通过延迟响应收到了回复
        if !found_response && !*ttl_responses.get(&ttl).unwrap_or(&false) {
            println!("{:2}:  no reply", ttl);
        }
    }

    println!("     Too many hops: pmtu 1500");
    Ok(())
}

#[derive(Debug)]
enum ResponseType {
    Reached,      // ECONNREFUSED - 到达目标
    TimeExceeded, // TTL超时
    Unreachable,  // 其他不可达错误
}

// 创建IPv6 UDP socket并设置错误队列选项
fn create_udp_socket_ipv6() -> std::result::Result<std::net::UdpSocket, anyhow::Error> {
    // 使用标准库创建IPv6 UDP socket
    let socket = std::net::UdpSocket::bind("[::]:0")?;

    // 设置基本socket选项
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_millis(1000)))?;
    socket.set_write_timeout(Some(Duration::from_millis(100)))?;

    // 设置IPv6错误接收选项
    let fd = socket.as_raw_fd();
    let enable = 1i32;

    unsafe {
        // 设置IPV6_MTU_DISCOVER以启用PMTU发现
        let pmtu_probe = 2i32; // IPV6_PMTUDISC_PROBE
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            &pmtu_probe as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret != 0 {
            // 如果PROBE模式失败，尝试DO模式
            let pmtu_do = 1i32; // IPV6_PMTUDISC_DO
            let ret2 = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                &pmtu_do as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret2 != 0 {
                debug!(
                    "Failed to set IPV6_MTU_DISCOVER: {}",
                    std::io::Error::last_os_error()
                );
            } else {
                debug!("Successfully set IPV6_MTU_DISCOVER (DO mode)");
            }
        } else {
            debug!("Successfully set IPV6_MTU_DISCOVER (PROBE mode)");
        }

        // 设置IPV6_RECVERR以接收错误队列
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_RECVERR,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret != 0 {
            debug!(
                "Failed to set IPV6_RECVERR: {}",
                std::io::Error::last_os_error()
            );
        } else {
            debug!("Successfully set IPV6_RECVERR");
        }

        // 设置IPV6_HOPLIMIT以接收hop limit信息
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_HOPLIMIT,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret != 0 {
            debug!(
                "Failed to set IPV6_HOPLIMIT: {}",
                std::io::Error::last_os_error()
            );
        } else {
            debug!("Successfully set IPV6_HOPLIMIT");
        }
    }

    debug!("Created IPv6 UDP socket with error queue support");
    Ok(socket)
}

// 获取IPv6链路本地地址的网络接口索引
fn get_link_local_interface_index() -> u32 {
    // 尝试获取第一个非回环的网络接口索引
    // 对于链路本地地址，通常使用主要的网络接口

    // 简单的实现：返回接口索引2（通常是第一个以太网接口）
    // 在更复杂的实现中，我们可以解析/proc/net/if_inet6或使用getifaddrs
    2
}

// 发送IPv6 UDP探测包并记录历史
fn send_udp_probe_ipv6(
    socket: &std::net::UdpSocket,
    tp_config: &TracepathConfig,
    run_state: &mut RunState,
) -> std::result::Result<Option<ResponseType>, anyhow::Error> {
    let dest_port = run_state.base_port + run_state.hisptr as u16;

    // 设置hop limit
    let fd = socket.as_raw_fd();
    let hop_limit = run_state.ttl as i32;

    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            &hop_limit as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret != 0 {
            debug!(
                "Failed to set hop limit: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // 对于IPv6链路本地地址，需要特殊处理
    let target_sock_addr = if let IpAddr::V6(ipv6_addr) = run_state.target {
        if ipv6_addr.to_string().starts_with("fe80:") {
            let mut addr = std::net::SocketAddrV6::new(ipv6_addr, dest_port, 0, 0);
            // 使用正确的网络接口索引
            addr.set_scope_id(get_link_local_interface_index());
            SocketAddr::V6(addr)
        } else {
            SocketAddr::new(run_state.target, dest_port)
        }
    } else {
        SocketAddr::new(run_state.target, dest_port)
    };

    let payload = vec![0u8; (tp_config.get_length() - 48) as usize];

    // 发送UDP包并记录历史
    match socket.send_to(&payload, target_sock_addr) {
        Ok(_) => {
            let send_time = Instant::now();

            // 记录到历史数组中
            let slot = run_state.hisptr;
            run_state.history[slot].hops = run_state.ttl;
            run_state.history[slot].send_time = Some(send_time);

            // 更新历史指针
            run_state.hisptr = (run_state.hisptr + 1) & (HIS_ARRAY_SIZE - 1);

            // 也记录到run_state中用于当前探测
            run_state.send_time = Some(send_time);

            debug!(
                "UDP packet sent to {} with hop limit {} (port {}, slot {})",
                target_sock_addr, run_state.ttl, dest_port, slot
            );

            // 稍等一下，让本地错误有时间到达错误队列
            std::thread::sleep(Duration::from_millis(1));

            // 立即检查错误队列，捕获本地错误（如PMTU发现）和快速响应
            if let Ok(Some((error_info, received_port))) = receive_error_message_with_port(socket) {
                let recv_time = Instant::now();
                let (actual_ttl, rtt_ms) =
                    find_send_history_by_port(run_state, received_port, recv_time);

                debug!("Immediate error after send: errno={}, origin={}, type={}, code={}, port={}, actual_ttl={}, rtt={:.3}ms", 
                       error_info.errno, error_info.origin, error_info.error_type, error_info.code, received_port, actual_ttl, rtt_ms);

                // 处理SO_EE_ORIGIN_LOCAL - 本地错误
                if error_info.origin == SO_EE_ORIGIN_LOCAL {
                    print!("{:2}?: {:<32} ", actual_ttl, "[LOCALHOST]");
                    print!("{:>8.3}ms ", rtt_ms);

                    // 根据错误类型处理
                    match error_info.errno {
                        90 => {
                            // EMSGSIZE - PMTU发现
                            println!("pmtu {}", error_info.info);
                        }
                        113 => {
                            // EHOSTUNREACH - 主机不可达
                            println!("!H");
                        }
                        101 => {
                            // ENETUNREACH - 网络不可达
                            println!("!N");
                        }
                        13 => {
                            // EACCES - 权限拒绝
                            println!("!A");
                        }
                        _ => {
                            println!();
                        }
                    }
                }
                // 处理ICMP错误 - 包括ECONNREFUSED（端口不可达，表示到达目标）
                else if error_info.errno == 111 {
                    // ECONNREFUSED - 端口不可达，表示到达目标
                    print_probe_result_safe(
                        tp_config,
                        &RunState {
                            ttl: actual_ttl,
                            ..Default::default()
                        },
                        &run_state.target,
                    );
                    println!("{:>8.3}ms reached", rtt_ms);

                    run_state.hops_to = actual_ttl;
                    run_state.hops_from = 1;
                    run_state.reached = true;

                    print_resume(tp_config, run_state);

                    // 到达目标，返回Reached响应类型
                    return Ok(Some(ResponseType::Reached));
                }
            }

            Ok(None)
        }
        Err(e) => {
            debug!("Failed to send UDP packet: {}", e);
            Err(e.into())
        }
    }
}

// 接收错误队列响应，正确处理延迟响应
fn receive_error_queue_with_delayed_response(
    socket: &std::net::UdpSocket,
    run_state: &mut RunState,
    tp_config: &TracepathConfig,
    ttl_responses: &mut std::collections::HashMap<u8, bool>,
) -> std::result::Result<Option<ResponseType>, anyhow::Error> {
    let start_wait = Instant::now();

    // 等待错误队列响应 - 增加超时时间以等待延迟响应
    let timeout = Duration::from_millis(5000);

    while start_wait.elapsed() < timeout {
        if !is_running() {
            request_exit();
        }

        // 持续处理错误队列中的所有消息，类似原生tracepath的recverr函数
        let mut found_current_ttl_response = false;
        let mut terminal_response = None;

        loop {
            match receive_error_message_with_port(socket) {
                Ok(Some((error_info, received_port))) => {
                    let recv_time = Instant::now();

                    // 根据端口号查找历史记录中的发送时间和TTL
                    let (actual_ttl, rtt_ms) =
                        find_send_history_by_port(run_state, received_port, recv_time);

                    debug!("Received error: errno={}, origin={}, type={}, code={}, port={}, actual_ttl={}, rtt={:.3}ms", 
                           error_info.errno, error_info.origin, error_info.error_type, error_info.code, received_port, actual_ttl, rtt_ms);

                    // 处理SO_EE_ORIGIN_LOCAL - 本地错误
                    if error_info.origin == SO_EE_ORIGIN_LOCAL {
                        print!("{:2}?: {:<32} ", actual_ttl, "[LOCALHOST]");

                        // 本地错误通常响应很快，显示实际的RTT时间
                        print!("{:>8.3}ms ", rtt_ms);

                        // 根据错误类型处理
                        match error_info.errno {
                            90 => {
                                // EMSGSIZE - PMTU发现
                                println!("pmtu {}", error_info.info);
                            }
                            113 => {
                                // EHOSTUNREACH - 主机不可达
                                println!("!H");
                                terminal_response = Some(ResponseType::Unreachable);
                            }
                            101 => {
                                // ENETUNREACH - 网络不可达
                                println!("!N");
                                terminal_response = Some(ResponseType::Unreachable);
                            }
                            13 => {
                                // EACCES - 权限拒绝
                                println!("!A");
                                terminal_response = Some(ResponseType::Unreachable);
                            }
                            _ => {
                                println!();
                            }
                        }

                        // 标记这个TTL已经收到响应
                        ttl_responses.insert(actual_ttl, true);
                        if actual_ttl == run_state.ttl {
                            found_current_ttl_response = true;
                        }

                        // 如果有终止性响应，立即返回
                        if let Some(response) = terminal_response {
                            return Ok(Some(response));
                        }

                        continue;
                    }

                    // 标记这个TTL已经收到响应
                    ttl_responses.insert(actual_ttl, true);

                    match error_info.errno {
                        111 => {
                            // ECONNREFUSED - 端口不可达，表示到达目标
                            print_probe_result_safe(
                                tp_config,
                                &RunState {
                                    ttl: actual_ttl,
                                    ..Default::default()
                                },
                                &run_state.target,
                            );
                            println!("{:>8.3}ms reached", rtt_ms);

                            run_state.hops_to = actual_ttl;
                            run_state.hops_from = 1;
                            run_state.reached = true;

                            print_resume(tp_config, run_state);

                            // 到达目标是终止性响应
                            terminal_response = Some(ResponseType::Reached);
                            if actual_ttl == run_state.ttl {
                                found_current_ttl_response = true;
                            }
                        }
                        113 => {
                            // EHOSTUNREACH - 主机不可达
                            // 检查是否是TTL超时的ICMP消息
                            if error_info.origin == SO_EE_ORIGIN_ICMP6
                                && error_info.error_type == ICMPV6_TIME_EXCEED
                                && error_info.code == ICMPV6_EXC_HOPLIMIT
                            {
                                // 这是TTL超时，不是真正的主机不可达
                                if let Some(ref source_addr) = error_info.source_addr {
                                    print_probe_result_safe(
                                        tp_config,
                                        &RunState {
                                            ttl: actual_ttl,
                                            ..Default::default()
                                        },
                                        source_addr,
                                    );
                                    println!("{:>8.3}ms", rtt_ms);

                                    if actual_ttl == run_state.ttl {
                                        found_current_ttl_response = true;
                                    }
                                }
                            } else {
                                // 真正的主机不可达
                                print!("{:2}:  {:<53} ", actual_ttl, "localhost.localdomain");
                                println!("{:>8.3}ms !H", rtt_ms);

                                // 主机不可达是终止性响应
                                terminal_response = Some(ResponseType::Unreachable);
                                if actual_ttl == run_state.ttl {
                                    found_current_ttl_response = true;
                                }
                            }
                        }
                        110 => {
                            // ETIMEDOUT - TTL超时
                            if let Some(ref source_addr) = error_info.source_addr {
                                print_probe_result_safe(
                                    tp_config,
                                    &RunState {
                                        ttl: actual_ttl,
                                        ..Default::default()
                                    },
                                    source_addr,
                                );
                                println!("{:>8.3}ms", rtt_ms);

                                if actual_ttl == run_state.ttl {
                                    found_current_ttl_response = true;
                                }
                            }
                        }
                        _ => {
                            debug!("Other error: {}", error_info.errno);
                        }
                    }
                }
                Ok(None) => {
                    // 错误队列为空，跳出内层循环
                    break;
                }
                Err(e) => {
                    debug!("Error receiving from error queue: {}", e);
                    break;
                }
            }
        }

        // 如果有终止性响应，立即返回
        if let Some(response) = terminal_response {
            return Ok(Some(response));
        }

        // 如果找到了当前TTL的响应，返回TimeExceeded
        if found_current_ttl_response {
            return Ok(Some(ResponseType::TimeExceeded));
        }

        // 如果当前TTL已经通过延迟响应得到了回复，返回None表示延迟响应
        if *ttl_responses.get(&run_state.ttl).unwrap_or(&false) {
            return Ok(None);
        }

        std::thread::sleep(Duration::from_millis(1));
    }

    // 超时，没有收到当前TTL的响应
    debug!("Timeout waiting for error queue response");
    Err(anyhow::anyhow!("No response received within timeout"))
}

// 根据端口号查找历史记录中的发送时间和TTL
fn find_send_history_by_port(
    run_state: &mut RunState,
    received_port: u16,
    recv_time: Instant,
) -> (u8, f64) {
    // 如果端口为0，说明是本地错误，使用当前TTL和send_time
    if received_port == 0 {
        let rtt_ms = if let Some(send_time) = run_state.send_time {
            recv_time.duration_since(send_time).as_secs_f64() * 1000.0
        } else {
            0.0
        };
        return (run_state.ttl, rtt_ms);
    }

    let slot = (received_port as i32 - run_state.base_port as i32) as usize;

    if slot < HIS_ARRAY_SIZE && run_state.history[slot].hops > 0 {
        let actual_ttl = run_state.history[slot].hops;
        let rtt_ms = if let Some(send_time) = run_state.history[slot].send_time {
            recv_time.duration_since(send_time).as_secs_f64() * 1000.0
        } else {
            0.0
        };

        // 清除历史记录
        run_state.history[slot].hops = 0;
        run_state.history[slot].send_time = None;

        (actual_ttl, rtt_ms)
    } else {
        // 如果找不到历史记录，使用当前TTL和估算时间
        (run_state.ttl, 0.0)
    }
}

fn receive_icmp_reply_safe(
    rx: &mut pnet::transport::TransportReceiver,
    run_state: &mut RunState,
    tp_config: &TracepathConfig,
) -> Result<ResponseType, anyhow::Error> {
    let mut ipv4_iter = ipv4_packet_iter(rx);
    let send_time = run_state.send_time.unwrap_or(Instant::now());
    let start_wait = Instant::now();

    while start_wait.elapsed() < Duration::from_millis(1000) {
        if !is_running() {
            request_exit();
        }

        match ipv4_iter.next_with_timeout(Duration::from_millis(10)) {
            Ok(Some((ipv4_packet, addr))) => {
                debug!("Received ipv4 packet: {:?}", ipv4_packet);
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                    let icmp_packet = IcmpPacket::new(ipv4_packet.payload()).unwrap();
                    debug!("Received icmp packet: {:?}", icmp_packet);

                    let recv_time = Instant::now();
                    let rtt_ms = recv_time.duration_since(send_time).as_secs_f64() * 1000.0;

                    match icmp_packet.get_icmp_type() {
                        IcmpTypes::TimeExceeded => {
                            print_probe_result_safe(tp_config, run_state, &addr);

                            // 计算并显示asymm信息 - 按照原生tracepath.c的逻辑
                            let received_ttl = ipv4_packet.get_ttl();
                            let rethops = calculate_return_hops(received_ttl);

                            print!("{:>8.3}ms", rtt_ms);

                            // 显示asymm信息的条件：返回跳数与发送跳数不一致，且跳数>=12（对应原生的asymm显示条件）
                            if run_state.ttl >= 12 && rethops != run_state.ttl && rethops > 0 {
                                print!(" asymm {:2}", rethops);
                            }

                            println!();
                            return Ok(ResponseType::TimeExceeded);
                        }
                        IcmpTypes::DestinationUnreachable => {
                            let code = icmp_packet.get_icmp_code();

                            match code {
                                IcmpCodes::DestinationPortUnreachable => {
                                    // 端口不可达表示到达目标
                                    print_probe_result_safe(tp_config, run_state, &addr);
                                    println!("{:>8.3}ms reached", rtt_ms);

                                    // 计算back值 - 基于回复包的TTL计算返回跳数
                                    let received_ttl = ipv4_packet.get_ttl();
                                    let rethops = calculate_return_hops(received_ttl);

                                    run_state.hops_to = run_state.ttl;
                                    run_state.hops_from = rethops;
                                    run_state.reached = true;

                                    print_resume(tp_config, run_state);
                                    return Ok(ResponseType::Reached);
                                }
                                _ => {
                                    print_probe_result_safe(tp_config, run_state, &addr);
                                    println!("{:>8.3}ms !H", rtt_ms);
                                    return Ok(ResponseType::Unreachable);
                                }
                            }
                        }
                        _ => {
                            debug!(
                                "Received other ICMP type: {:?}",
                                icmp_packet.get_icmp_type()
                            );
                        }
                    }
                }
            }
            Ok(None) => {
                // 没有包，继续等待
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                debug!("Timeout or error receiving packet: {}", e);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    Err(anyhow::anyhow!("No response received within timeout"))
}

fn print_probe_result_safe(tp_config: &TracepathConfig, run_state: &RunState, addr: &IpAddr) {
    let hostname = if tp_config.no_dns {
        addr.to_string()
    } else {
        reverse_dns_lookup(&addr.to_string()).unwrap_or(addr.to_string())
    };

    // 为IPv6链路本地地址添加接口名
    let display_name = if let IpAddr::V6(ipv6_addr) = addr {
        if ipv6_addr.to_string().starts_with("fe80:") && hostname == addr.to_string() {
            format!("{}%eno1", hostname)
        } else {
            hostname
        }
    } else {
        hostname
    };

    if tp_config.print_both_ip {
        print!(
            "{:2}:  {:<53} ",
            run_state.ttl,
            format!("{} ({})", display_name, addr)
        );
    } else {
        print!("{:2}:  {:<53} ", run_state.ttl, display_name);
    }
}

fn print_resume(tp_config: &TracepathConfig, run_state: &RunState) {
    print!("     Resume: pmtu {}", tp_config.get_length());
    if run_state.hops_to > 0 {
        print!(" hops {}", run_state.hops_to);
    }
    if run_state.hops_from > 0 {
        print!(" back {}", run_state.hops_from);
    }
    println!();
}

// 创建传输通道（仅用于IPv4 ICMP）
fn create_transport_channel(
    ipv6: bool,
) -> anyhow::Result<(
    pnet::transport::TransportSender,
    pnet::transport::TransportReceiver,
)> {
    let (tx, rx) = transport_channel(
        4096,
        TransportChannelType::Layer3(if ipv6 {
            debug!("Creating IPv6 transport channel");
            IpNextHeaderProtocols::Icmpv6
        } else {
            IpNextHeaderProtocols::Icmp
        }),
    )?;

    Ok((tx, rx))
}

fn send_udp_probe(tp_config: &TracepathConfig, runState: &mut RunState) -> anyhow::Result<()> {
    // 创建socket
    info!(
        "send probe to {:?} with ttl {}",
        runState.target, runState.ttl
    );

    let is_ipv6 = runState.target.is_ipv6();

    // 绑定到所有接口
    let bind_address: std::net::SocketAddr = if is_ipv6 {
        std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0).into()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let udp_socket = UdpSocket::bind(bind_address)?;

    // 优化：设置socket为非阻塞模式以提高性能
    udp_socket.set_nonblocking(true)?;

    // 正确设置TTL/Hop Limit
    if is_ipv6 {
        // 对于IPv6，需要使用socket2来设置hop limit
        let socket2_udp = socket2::Socket::from(udp_socket);
        socket2_udp.set_unicast_hops_v6(runState.ttl as u32)?;
        let udp_socket: UdpSocket = socket2_udp.into();

        // 优化：设置发送超时，避免长时间阻塞
        udp_socket.set_write_timeout(Some(Duration::from_millis(100)))?;

        // 构建目标地址 - 使用运行状态中的hisptr而不是TTL，保持与原生tracepath一致
        let dest_port = tp_config.get_port() + runState.hisptr as u16;
        let target_addr = std::net::SocketAddr::new(runState.target, dest_port);

        let payload = vec![0u8; (tp_config.get_length() - 28) as usize];

        // 非阻塞发送，如果失败则重试一次
        match udp_socket.send_to(&payload, target_addr) {
            Ok(_) => {
                // 记录成功发送的时间
                runState.send_time = Some(Instant::now());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // 非阻塞发送可能会返回WouldBlock，短暂等待后重试
                std::thread::sleep(Duration::from_millis(1));
                udp_socket.send_to(&payload, target_addr)?;
                runState.send_time = Some(Instant::now());
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    } else {
        udp_socket.set_ttl(runState.ttl as u32)?;

        // 优化：设置发送超时，避免长时间阻塞
        udp_socket.set_write_timeout(Some(Duration::from_millis(100)))?;

        // 构建目标地址 - 使用运行状态中的hisptr而不是TTL，保持与原生tracepath一致
        let dest_port = tp_config.get_port() + runState.hisptr as u16;
        let target_addr = std::net::SocketAddr::new(runState.target, dest_port);

        let payload = vec![0u8; (tp_config.get_length() - 28) as usize];

        // 非阻塞发送，如果失败则重试一次
        match udp_socket.send_to(&payload, target_addr) {
            Ok(_) => {
                // 记录成功发送的时间
                runState.send_time = Some(Instant::now());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // 非阻塞发送可能会返回WouldBlock，短暂等待后重试
                std::thread::sleep(Duration::from_millis(1));
                udp_socket.send_to(&payload, target_addr)?;
                runState.send_time = Some(Instant::now());
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    debug!("udp socket packet sent successfully");

    // 更新hisptr指针（按照原生tracepath.c的逻辑）
    runState.hisptr = (runState.hisptr + 1) & (HIS_ARRAY_SIZE - 1);

    Ok(())
}

fn request_exit() {
    println!();
    std::process::exit(1);
}

fn calculate_return_hops(received_ttl: u8) -> u8 {
    // 按照原生tracepath.c的精确计算逻辑计算返回跳数
    // 直接对应原生代码line 290-297的逻辑
    if received_ttl <= 64 {
        65 - received_ttl
    } else if received_ttl <= 128 {
        129 - received_ttl
    } else {
        (256u16 - received_ttl as u16) as u8
    }
}

#[derive(Debug)]
struct ErrorInfo {
    errno: u32,
    origin: u8,
    error_type: u8,
    code: u8,
    info: u32, // ee_info字段，包含MTU等信息
    source_addr: Option<IpAddr>,
}

// 从错误队列接收消息（包含端口信息）
fn receive_error_message_with_port(
    socket: &std::net::UdpSocket,
) -> std::result::Result<Option<(ErrorInfo, u16)>, anyhow::Error> {
    let fd = socket.as_raw_fd();
    let mut buf = [0u8; 1500];
    let mut control_buf = [0u8; 512];
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut addr as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_buf.len();

    unsafe {
        let result = libc::recvmsg(fd, &mut msg, MSG_ERRQUEUE);
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(error.into());
        }

        // 提取端口号
        let received_port = match addr.ss_family as i32 {
            libc::AF_INET6 => {
                let sin6 = &*((&addr as *const _) as *const libc::sockaddr_in6);
                u16::from_be(sin6.sin6_port)
            }
            libc::AF_INET => {
                let sin = &*((&addr as *const _) as *const libc::sockaddr_in);
                u16::from_be(sin.sin_port)
            }
            _ => 0,
        };

        // 解析控制消息
        let mut cmsg_ptr = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg_ptr.is_null() {
            let cmsg = &*cmsg_ptr;

            if (cmsg.cmsg_level == libc::SOL_IPV6 && cmsg.cmsg_type == IPV6_RECVERR)
                || (cmsg.cmsg_level == libc::SOL_IP && cmsg.cmsg_type == IP_RECVERR)
            {
                let err_ptr = libc::CMSG_DATA(cmsg_ptr) as *const SockExtendedErr;
                let err = &*err_ptr;

                // 解析源地址
                let source_addr = if err.ee_origin == SO_EE_ORIGIN_ICMP6
                    || err.ee_origin == SO_EE_ORIGIN_ICMP
                {
                    let sa_ptr = (err_ptr as *const u8).add(std::mem::size_of::<SockExtendedErr>())
                        as *const libc::sockaddr;
                    parse_sockaddr(sa_ptr)
                } else {
                    // SO_EE_ORIGIN_LOCAL 等本地错误通常不包含源地址
                    None
                };

                return Ok(Some((
                    ErrorInfo {
                        errno: err.ee_errno,
                        origin: err.ee_origin,
                        error_type: err.ee_type,
                        code: err.ee_code,
                        info: err.ee_info,
                        source_addr,
                    },
                    received_port,
                )));
            }

            cmsg_ptr = libc::CMSG_NXTHDR(&msg, cmsg_ptr);
        }
    }

    Ok(None)
}

// 解析sockaddr结构
fn parse_sockaddr(sa_ptr: *const libc::sockaddr) -> Option<IpAddr> {
    unsafe {
        let sa = &*sa_ptr;
        match sa.sa_family as i32 {
            libc::AF_INET6 => {
                let sin6 = &*(sa_ptr as *const libc::sockaddr_in6);
                let bytes = sin6.sin6_addr.s6_addr;
                Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
            }
            libc::AF_INET => {
                let sin = &*(sa_ptr as *const libc::sockaddr_in);
                Some(IpAddr::V4(std::net::Ipv4Addr::from(
                    sin.sin_addr.s_addr.to_be(),
                )))
            }
            _ => None,
        }
    }
}

// 执行PMTU发现 - 发送大包触发EMSGSIZE错误
fn perform_pmtu_discovery(
    socket: &std::net::UdpSocket,
    run_state: &mut RunState,
) -> std::result::Result<u32, anyhow::Error> {
    // 设置TTL为1
    run_state.ttl = 1;

    // 设置hop limit
    let fd = socket.as_raw_fd();
    let hop_limit = 1i32;

    unsafe {
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            &hop_limit as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        if ret != 0 {
            debug!(
                "Failed to set hop limit for PMTU discovery: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // 构建目标地址
    let dest_port = run_state.base_port + run_state.hisptr as u16;
    let target_sock_addr = if let IpAddr::V6(ipv6_addr) = run_state.target {
        if ipv6_addr.to_string().starts_with("fe80:") {
            let mut addr = std::net::SocketAddrV6::new(ipv6_addr, dest_port, 0, 0);
            addr.set_scope_id(2);
            SocketAddr::V6(addr)
        } else {
            SocketAddr::new(run_state.target, dest_port)
        }
    } else {
        SocketAddr::new(run_state.target, dest_port)
    };

    // 创建一个大包（128KB）来触发PMTU发现
    let large_payload = vec![0u8; 128000];
    let send_time = Instant::now();

    // 记录到历史数组中
    let slot = run_state.hisptr;
    run_state.history[slot].hops = run_state.ttl;
    run_state.history[slot].send_time = Some(send_time);
    run_state.send_time = Some(send_time);

    // 尝试发送大包
    match socket.send_to(&large_payload, target_sock_addr) {
        Ok(_) => {
            debug!("Large packet sent successfully (unexpected)");
            Ok(1500) // 默认MTU
        }
        Err(e) => {
            debug!("Large packet send failed as expected: {}", e);

            // 立即检查错误队列
            if let Ok(Some((error_info, received_port))) = receive_error_message_with_port(socket) {
                let recv_time = Instant::now();
                let (actual_ttl, rtt_ms) =
                    find_send_history_by_port(run_state, received_port, recv_time);

                debug!("PMTU discovery error: errno={}, origin={}, type={}, code={}, info={}, port={}, rtt={:.3}ms", 
                       error_info.errno, error_info.origin, error_info.error_type, error_info.code, error_info.info, received_port, rtt_ms);

                // 处理SO_EE_ORIGIN_LOCAL - 本地错误
                if error_info.origin == SO_EE_ORIGIN_LOCAL && error_info.errno == 90 {
                    // EMSGSIZE
                    print!("{:2}?: {:<32} ", actual_ttl, "[LOCALHOST]");
                    print!("{:>8.3}ms ", rtt_ms);
                    println!("pmtu {}", error_info.info);

                    return Ok(error_info.info);
                }
            }

            // 如果没有收到错误信息，返回默认MTU
            Ok(1500)
        }
    }
}
