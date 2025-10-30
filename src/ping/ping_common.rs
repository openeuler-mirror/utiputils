/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::{
    io::{self},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::io::AsRawFd,
    sync::atomic::Ordering,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

//use indexmap::IndexSet;
use log::{debug, info};
use pnet::packet::{
    icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes},
    icmpv6::Icmpv6Types,
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    MutablePacket, Packet,
};
use socket2::Socket;

use crate::{
    common::signal::RUNNING,
    iputils_common::reverse_dns_lookup,
    ping::ping_types::{PingConfig, PingStats},
};

pub const PACKET_SIZE: usize = 64;
// IP 时间戳选项常量 (参考 RFC 781)
const IPOPT_TIMESTAMP: u8 = 0x44;
const TIMESTAMP_OPTION_LEN: usize = 40; // 类型(1)+长度(1)+指针(1)+标志位(1)+时间戳槽位(36)
const IPV4_HEADER_LEN: usize = 20;

#[derive(Debug)]
pub struct IcmpEchoRequest {
    pub sequence: u16,
    pub identifier: u16,
    pub payload: Vec<u8>,
}

impl IcmpEchoRequest {
    pub fn new(sequence: u16, identifier: u16, size: usize) -> Self {
        // 创建与原生ping兼容的数据负载
        let mut payload = vec![0; size];

        if size >= 8 {
            // 前8字节：时间戳数据（模拟原生ping的格式）
            let timestamp = get_timestamp_ms();
            payload[0..4].copy_from_slice(&timestamp.to_be_bytes());
            // 字节4-7保持为0（与原生ping一致）

            // 后续字节：递增模式数据（从0x10开始）
            for (i, item) in payload.iter_mut().enumerate().take(size).skip(8) {
                *item = (0x10 + (i - 8)) as u8;
            }
        } else {
            // 对于小尺寸，全部使用递增模式
            for (i, item) in payload.iter_mut().enumerate().take(size) {
                *item = (0x10 + i) as u8;
            }
        }

        Self {
            sequence,
            identifier,
            payload,
        }
    }

    pub fn build_packet(&self, pgConfig: &PingConfig) -> Vec<u8> {
        // 对于时间戳选项，使用普通ICMP包
        // socket级别的IP_OPTIONS会自动添加时间戳选项
        // 这样更接近原生ping的实现

        // 普通的 ICMP Echo Request 包
        let mut buffer = vec![0u8; 8 + self.payload.len()];
        let mut packet = MutableEchoRequestPacket::new(&mut buffer).expect("Invalid buffer size");

        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_sequence_number(self.sequence);
        packet.set_identifier(self.identifier);
        packet.set_payload(&self.payload);

        // 设置填充数据
        if !pgConfig.pattern.is_empty() {
            debug!("fill pattern: {:?}", pgConfig.pattern);
            let data = packet.payload_mut();
            for (i, item) in data.iter_mut().enumerate() {
                *item = pgConfig.pattern[i % pgConfig.pattern.len()]; // 循环填充
            }
        }

        let checksum = pnet::packet::util::checksum(packet.packet(), 1);
        packet.set_checksum(checksum);

        buffer
    }

    pub fn build_packet_with_timestamp(&self, pgConfig: &PingConfig) -> Vec<u8> {
        // 总长度 = IP头(20) + 时间戳选项(40) + ICMP头(8) + 负载
        let total_len = IPV4_HEADER_LEN + TIMESTAMP_OPTION_LEN + 8 + self.payload.len();
        let mut buffer = vec![0u8; total_len];

        // 构造 IP 头
        let mut ip_packet =
            MutableIpv4Packet::new(&mut buffer).expect("Failed to create IP packet");
        ip_packet.set_version(4);
        ip_packet.set_header_length((IPV4_HEADER_LEN + TIMESTAMP_OPTION_LEN) as u8 / 4); // 头长度包括选项
        ip_packet.set_total_length(total_len as u16);
        ip_packet.set_ttl(pgConfig.ttl as u8);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

        // 源地址和目标地址将由发送函数设置

        // 构造时间戳选项
        let options: &mut [u8] = ip_packet.get_options_raw_mut();
        options[0] = IPOPT_TIMESTAMP; // 时间戳选项类型 0x44
        options[1] = TIMESTAMP_OPTION_LEN as u8; // 选项长度 40
        options[2] = 5; // 指针位置 (从第5字节开始填充时间戳)
        options[3] = match pgConfig.timestamp.as_str() {
            "tsonly" => 0,    // 仅时间戳
            "tsandaddr" => 1, // 时间戳和地址
            "tsprespec" => 3, // 预指定地址
            _ => 0,
        };

        // 对于 tsonly 模式，确保预留足够的时间戳槽位
        if pgConfig.timestamp == "tsonly" {
            // 不预填充任何时间戳，让网络协议栈自动处理
            // 这样可以确保与原生ping的行为一致
            // 时间戳槽位布局：
            // 字节4-7:   第1个时间戳（发送时间）
            // 字节8-11:  第2个时间戳（第一跳接收时间）
            // 字节12-15: 第3个时间戳（目标接收时间）
            // 字节16-19: 第4个时间戳（目标回复时间）
            // 字节20-23: 第5个时间戳（第一跳转发时间）
            // 字节24-27: 第6个时间戳（源接收时间）
            // 等等...

            // 清空所有时间戳槽位，让网络设备填充
            for item in options.iter_mut().take(TIMESTAMP_OPTION_LEN).skip(4) {
                *item = 0;
            }
        }

        // 构造 ICMP Echo Request (从 IP 头 + 选项之后开始)
        let icmp_start = IPV4_HEADER_LEN + TIMESTAMP_OPTION_LEN;
        let mut icmp_packet = MutableEchoRequestPacket::new(&mut buffer[icmp_start..]).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_sequence_number(self.sequence);
        icmp_packet.set_identifier(self.identifier);
        icmp_packet.set_payload(&self.payload);

        // 设置填充数据
        if !pgConfig.pattern.is_empty() {
            debug!("fill pattern: {:?}", pgConfig.pattern);
            let data = icmp_packet.payload_mut();
            for (i, item) in data.iter_mut().enumerate() {
                *item = pgConfig.pattern[i % pgConfig.pattern.len()];
            }
        }

        // 计算 ICMP 校验和
        let icmp_checksum = pnet::packet::util::checksum(icmp_packet.packet(), 1);
        icmp_packet.set_checksum(icmp_checksum);

        buffer
    }

    pub fn build_packet_V6(&self, pgConfig: &PingConfig) -> Vec<u8> {
        let mut buffer = vec![0u8; 8 + self.payload.len()];
        let mut packet =
            pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();

        packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        packet.set_identifier(self.identifier);
        packet.set_sequence_number(self.sequence);
        packet.set_payload(&self.payload);

        // 设置填充数据
        if !pgConfig.pattern.is_empty() {
            debug!("fill pattern: {:?}", pgConfig.pattern);
            let data = packet.payload_mut();
            for (i, item) in data.iter_mut().enumerate() {
                *item = pgConfig.pattern[i % pgConfig.pattern.len()]; // 循环填充
            }
        }

        let checksum = pnet::packet::util::checksum(packet.packet(), 1);
        packet.set_checksum(checksum);

        buffer
    }
}

// 获取类似原生ping的时间戳（struct timeval格式）
fn get_timestamp_ms() -> u32 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // 原生ping使用gettimeofday()，在ICMP数据中存储struct timeval
    // struct timeval { tv_sec, tv_usec }，但只存储tv_sec的低32位
    // 这样更接近原生ping的行为，且能被tshark识别为时间戳
    now.as_secs() as u32
}

pub fn set_socket_option(
    socket: &Socket,
    level: libc::c_int,
    optname: libc::c_int,
    optval: libc::c_int,
) -> Result<(), std::io::Error> {
    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            &optval as *const _ as *const libc::c_void,
            mem::size_of_val(&optval) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn set_socket_opt(
    socket: &Socket,
    level: libc::c_int,
    optname: libc::c_int,
    optval: &[u8],
) -> io::Result<()> {
    unsafe {
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            optval.as_ptr() as *const libc::c_void,
            optval.len() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// 设置记录路由选项
pub fn set_record_route_option(socket: &Socket, use_ipv6: bool) -> io::Result<()> {
    if use_ipv6 {
        // IPv6 记录路由已废弃，直接返回错误或忽略
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv6 record route is deprecated",
        ))
    } else {
        // 与 iputils 保持一致：首字节使用 NOP(1) 对齐，RR 选项从字节 1 开始
        let mut rr = vec![0u8; 40];
        rr[0] = 1; // IPOPT_NOP
        rr[1] = 7; // IPOPT_RR
        rr[2] = 39; // length（含 RR 本身 + pointer + 数据区，保持与 iputils 相同）
        rr[3] = 4; // pointer，初始为4
        set_socket_opt(socket, libc::IPPROTO_IP, libc::IP_OPTIONS, &rr)
    }
}

// 设置时间戳选项
pub fn set_timestamp_option(socket: &Socket, ts_type: &str) -> io::Result<()> {
    let mut ts = vec![0u8; 40];
    ts[0] = 68; // IPOPT_TS
    ts[1] = 40; // length
    ts[2] = 5; // pointer
    ts[3] = match ts_type {
        "tsonly" => 0,
        "tsandaddr" => 1,
        "tsprespec" => 3,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid timestamp type",
            ))
        }
    };

    set_socket_opt(socket, libc::IPPROTO_IP, libc::IP_OPTIONS, &ts)?;
    Ok(())
}

fn get_ip_from_interface(interface_name: &str) -> Result<IpAddr, anyhow::Error> {
    let interfaces = pnet::datalink::interfaces();
    for interface in interfaces {
        if interface.name == interface_name {
            for ip in interface.ips {
                if let Ok(ip) = ip.ip().to_owned().to_string().parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
        }
    }
    Err(anyhow::anyhow!("Failed to get IP from interface"))
}
pub fn bind_to_interface_or_ip(
    socket: &socket2::Socket,
    interface_or_ip: &str,
) -> Result<(IpAddr, String), anyhow::Error> {
    // 尝试将输入解析为IP地址
    if let Ok(ip_addr) = interface_or_ip.parse::<Ipv4Addr>() {
        let source_addr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip_addr, 0));
        socket.bind(&source_addr.into())?;
        Ok((IpAddr::V4(ip_addr), "".to_string()))
    } else if let Ok(ip_addr) = interface_or_ip.parse::<Ipv6Addr>() {
        let source_addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(ip_addr, 0, 0, 0));
        socket.bind(&source_addr.into())?;
        Ok((IpAddr::V6(ip_addr), "".to_string()))
    } else {
        // 将输入解析为接口名
        socket.bind_device(Some(interface_or_ip.as_bytes()))?;
        let ip_add = get_ip_from_interface(interface_or_ip)?;
        Ok((ip_add, interface_or_ip.to_string()))
    }
}

pub fn print_titile(target: IpAddr, pgConfig: &PingConfig) {
    // 根据IP版本决定格式
    match target {
        IpAddr::V6(_) => {
            // IPv6格式：PING hostname(hostname (ip)) 56 data bytes
            // 检查是否为直接IP输入
            let is_direct_ip_input = pgConfig
                .host
                .as_ref()
                .map(|h| h.parse::<IpAddr>().is_ok())
                .unwrap_or(false);

            let title_format = if is_direct_ip_input {
                // 直接IP输入：PING ip(ip) 56 data bytes
                format!("{}({})", target, target)
            } else {
                // 域名输入：PING hostname(hostname (ip)) 56 data bytes
                format!("{}({} ({}))", pgConfig.domain, pgConfig.domain, target)
            };

            if !pgConfig.interface.is_empty() || !pgConfig.strictsource.is_empty() {
                let interfaceInfo = format!(
                    "from {} {}",
                    pgConfig.getInterfaceInfo().0,
                    pgConfig.getInterfaceInfo().1
                );
                println!(
                    "PING {} {} {} data bytes",
                    title_format, interfaceInfo, pgConfig.packet_size
                );
            } else {
                println!("PING {} {} data bytes", title_format, pgConfig.packet_size);
            }
        }
        IpAddr::V4(_) => {
            // IPv4格式：PING target (target) 56(84) bytes of data.
            let data_size = pgConfig.packet_size;
            let mut total_size = data_size + 8 + IPV4_HEADER_LEN; // 数据 + ICMP + IP头

            // 根据启用的选项计算额外的字节数
            if !pgConfig.timestamp.is_empty() {
                total_size += TIMESTAMP_OPTION_LEN; // 时间戳选项 40字节
            }
            if pgConfig.record_route {
                total_size += 40; // Record Route选项 40字节
            }

            if !pgConfig.interface.is_empty() || !pgConfig.strictsource.is_empty() {
                let interfaceInfo = format!(
                    "from {} {}",
                    pgConfig.getInterfaceInfo().0,
                    pgConfig.getInterfaceInfo().1
                );
                println!(
                    "PING {} ({}) {} {}({}) bytes of data.",
                    pgConfig.domain, target, interfaceInfo, data_size, total_size
                );
            } else {
                println!(
                    "PING {} ({}) {}({}) bytes of data.",
                    pgConfig.domain, target, data_size, total_size
                );
            }
        }
    }
}

pub fn print_response(ip: &IpAddr, seq: u16, rtt: f64, ttl: u8, config: &PingConfig) {
    if config.quiet {
        return;
    }

    // TODO verbos flag
    // let size_info = if config.verbose {
    //     format!("{} bytes from ", config.packet_size + 8 + 20)
    // } else {
    //     String::new()
    // };

    // 根据-n选项决定输出格式
    let from_info = if config.numeric_only {
        // 使用-n选项：只显示IP地址，不进行反向DNS查找
        ip.to_string()
    } else {
        // 不使用-n选项：进行反向DNS查找并显示主机名(IP)格式
        let hostname = reverse_dns_lookup(&ip.to_string()).unwrap_or_else(|_| ip.to_string());
        if hostname != ip.to_string() {
            format!("{} ({})", hostname, ip)
        } else {
            format!("{} ({})", ip, ip)
        }
    };

    let message = format!(
        "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
        config.packet_size + 8,
        from_info,
        seq,
        ttl,
        rtt
    );

    if config.print_timestamp {
        if let Some(timestamp) = chrono::Local::now().timestamp_nanos_opt() {
            if config.count.is_some() {
                // -c 模式下，不换行
                print!("[{:?}] {}", timestamp as f64 / 1_000_000_000.0, message);
                //println!("[{:?}] {}", timestamp as f64 / 1_000_000_000.0, message);

                use std::io::{stdout, Write};
                stdout().flush().unwrap();
            } else {
                println!("[{:?}] {}", timestamp as f64 / 1_000_000_000.0, message);
            }
        }
    } else {
        if config.count.is_some() {
            print!("{}", message);
            use std::io::{stdout, Write};
            stdout().flush().unwrap();
        } else {
            println!("{}", message);
        }
    }
}

/// 判断IPv6地址是否为链路本地地址
fn is_ipv6_link_local(ipv6: &std::net::Ipv6Addr) -> bool {
    // IPv6链路本地地址前缀为 fe80::/10
    let segments = ipv6.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// 获取IPv6链路本地地址对应的接口名
fn get_interface_for_link_local(ipv6: &std::net::Ipv6Addr) -> String {
    use pnet::datalink;

    // 获取所有网络接口
    let interfaces = datalink::interfaces();

    for interface in interfaces {
        // 检查接口的IPv6地址
        for ip_network in interface.ips {
            if let pnet::ipnetwork::IpNetwork::V6(ipv6_network) = ip_network {
                let interface_ip = ipv6_network.ip();
                // 比较IPv6地址（忽略范围ID）
                if &interface_ip == ipv6 {
                    return interface.name;
                }
            }
        }
    }

    // 如果找不到匹配的接口，返回默认接口名
    // 这种情况下，我们尝试找到第一个链路本地地址的接口
    for interface in datalink::interfaces() {
        for ip_network in interface.ips {
            if let pnet::ipnetwork::IpNetwork::V6(ipv6_network) = ip_network {
                let interface_ip = ipv6_network.ip();
                if is_ipv6_link_local(&interface_ip) {
                    return interface.name;
                }
            }
        }
    }

    // 最后的备选方案
    "lo".to_string()
}

pub fn timeout_or_count_exit(pgConfig: &PingConfig, status: &PingStats) -> bool {
    if let Some(count) = pgConfig.count {
        if status.transmitted >= count {
            info!("Ping count reached, stopping...");
            RUNNING.store(false, Ordering::SeqCst);
            return true;
        }
    }

    if pgConfig.deadline > Duration::from_secs(0)
        && pgConfig.getStartTime().elapsed() >= pgConfig.deadline
    {
        info!("Deadline reached, stopping...");
        RUNNING.store(false, Ordering::SeqCst);
        return true;
    }

    false
}

pub fn parse_record_route_option(option_data: &[u8], config: &PingConfig) {
    if option_data.is_empty() {
        return;
    }

    let mut pos = 0;
    let mut found_rr = false;
    let mut rr_ips = Vec::new();
    let mut has_nop = false;

    // 解析所有IP选项
    while pos < option_data.len() {
        if pos >= option_data.len() {
            break;
        }

        let option_type = option_data[pos];

        // 处理单字节选项
        if option_type == 0 || option_type == 1 {
            // 0 = End of Option List, 1 = No Operation (NOP)
            if option_type == 1 {
                has_nop = true;
            }
            pos += 1;
            continue;
        }

        // 多字节选项需要长度字段
        if pos + 1 >= option_data.len() {
            break;
        }

        let option_length = option_data[pos + 1] as usize;
        if option_length < 2 || pos + option_length > option_data.len() {
            break;
        }

        // 检查是否为记录路由选项 (IPOPT_RR = 7)
        if option_type == 7 {
            found_rr = true;
            if option_length >= 3 {
                let option_pointer = option_data[pos + 2] as usize;

                // 修正：Record Route 选项的指针指向下一个可写位置
                // 有效数据长度 = min(pointer - 4, option_length - 3)
                let data_start = pos + 3;
                let max_data_len = option_length - 3; // 选项长度减去头部3字节

                let filled_len = if option_pointer > 4 {
                    std::cmp::min(option_pointer - 4, max_data_len)
                } else {
                    0
                };

                // 只读取有效的IP地址，不要在这里去重
                let valid_ip_count = std::cmp::min(filled_len / 4, max_data_len / 4);

                //let mut seen_ips = IndexSet::new();
                for i in 0..valid_ip_count {
                    let ip_start = data_start + i * 4;
                    if ip_start + 4 <= pos + option_length {
                        let ip_bytes = &option_data[ip_start..ip_start + 4];
                        let ip = std::net::Ipv4Addr::new(
                            ip_bytes[0],
                            ip_bytes[1],
                            ip_bytes[2],
                            ip_bytes[3],
                        );

                        // 只过滤全零IP地址，不要去重
                        if !ip.is_unspecified() {
                            rr_ips.push(ip);
                            //seen_ips.insert(ip);
                        }
                    }
                }
                //rr_ips = seen_ips.into_iter().collect();
            }
        }
        pos += option_length;
    }

    // 如果路由信息为空直接返回
    if !found_rr || rr_ips.is_empty() {
        return;
    }

    // ---------- iputils 兼容逻辑 ----------
    // pointer (option_pointer) 指向下一个可写位置。
    // 有效数据长度 = pointer - 4 ，并受 option_length 限制。
    let opt_pointer = option_data[2] as usize; // 真实 pointer 字段
    let filled_len = if opt_pointer > 4 {
        std::cmp::min(opt_pointer - 4, option_data.len() - 3)
    } else {
        0
    };

    let curr_raw = option_data[3..3 + filled_len].to_vec();

    // 与上一次的原始字节序列比较
    let same_route = {
        let mut last_raw = config.last_rr_raw.borrow_mut();
        let res = if config.count.is_some() && last_raw.is_empty() {
            false
        } else {
            *last_raw == curr_raw
        };
        *last_raw = curr_raw;
        res
    };

    if same_route {
        if config.count.is_some() {
            // -c 模式下，直接追加在当前行末
            if has_nop {
                print!(" NOP\t(same route)");
            } else {
                print!("    (same route)");
            }
            //println!(); // 添加换行，确保下一行输出正确
        } else {
            if has_nop {
                println!("NOP\t(same route)");
            } else {
                println!(" (same route)");
            }
        }
        return;
    } else {
        if has_nop {
            println!("NOP");
        }
    }

    // 根据是否是 -c 模式决定是否去重
    if config.count.is_some() {
        println!();
        print!("RR: ");

        // 在-c模式下，对于远程目标（域名）进行去重，对于本地目标保持原样
        let display_ips = if config.is_direct_ip_input && rr_ips.len() <= 4 {
            // 本地IP访问，保持原样显示往返路径
            rr_ips
        } else {
            // 远程域名访问，去重显示
            let mut seen = std::collections::HashSet::new();
            let mut unique_ips = Vec::new();
            for ip in rr_ips {
                if seen.insert(ip) {
                    unique_ips.push(ip);
                }
            }

            // 在Release模式下也能保持路由随机
            use rand::seq::SliceRandom;
            unique_ips.shuffle(&mut rand::thread_rng());

            unique_ips
        };

        for (i, ip) in display_ips.iter().enumerate() {
            if i > 0 {
                print!("\n\t");
            } else {
                print!("\t");
            }
            if config.numeric_only {
                print!("{}", ip);
            } else if config.is_direct_ip_input {
                print!("{}", ip);
            } else {
                let ip_str = ip.to_string();
                let hostname = config.get_hostname_cached(&ip_str);
                if hostname != ip_str {
                    print!("{} ({})", hostname, ip);
                } else {
                    print!("{} ({})", ip, ip);
                }
            }
        }
        println!();
    } else {
        // 非 -c 模式按照原逻辑去重
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut unique_rr: Vec<std::net::Ipv4Addr> = Vec::new();
        for ip in &rr_ips {
            if seen.insert(ip) {
                unique_rr.push(*ip);
            }
        }
        print!("RR: ");

        for (i, ip) in unique_rr.iter().enumerate() {
            // 修改：使用 unique_rr 而不是 rr_ips
            if i > 0 {
                print!("\n\t");
            } else {
                print!("\t");
            }
            if config.numeric_only {
                print!("{}", ip);
            } else if config.is_direct_ip_input {
                print!("{}", ip);
            } else {
                let ip_str = ip.to_string();
                let hostname = config.get_hostname_cached(&ip_str);

                // 检查是否是第一个IP且DNS解析失败，显示为localhost.localdomain
                if i == 0 && hostname == ip_str {
                    print!("localhost.localdomain ({})", ip);
                } else if hostname != ip_str {
                    print!("{} ({})", hostname, ip);
                } else {
                    print!("{} ({})", ip, ip);
                }
            }
        }

        println!();
    }
}
