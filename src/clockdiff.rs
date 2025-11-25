/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr},
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::Local;
use clap::Parser;
use log::{debug, info};
use pnet::{
    packet::{
        icmp::{
            echo_request::MutableEchoRequestPacket, IcmpCode, IcmpPacket, IcmpTypes,
            MutableIcmpPacket,
        },
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4OptionNumbers, Ipv4Packet, MutableIpv4Packet},
        Packet,
    },
    transport::{icmp_packet_iter, transport_channel, TransportChannelType},
    util::checksum,
};

use crate::iputils_common::{get_ipv4_addr, init_logger, initialize_signal_handler, is_running};

// IP 时间戳选项类型（RFC 781）
const IPOPT_TIMESTAMP: u8 = 0x44;
const OPTIONS_LEN: usize = 36; // 类型(1)+长度(1)+指针(1)+标志位(1)+(地址(4)+时间戳(4))*4
const OPTIONS_LEN_THREE: usize = 28; // 类型(1)+长度(1)+指针(1)+标志位(1)+(地址(4)+时间戳(4))*3

const MSGS: usize = 50;

const ICMP_HEADER_LEN: usize = 8;
const TIMESTAMP_LEN: usize = 12; // 3个u32时间戳
const IPV4_HEADER_LEN: usize = 20;

#[derive(Debug, Default)]
struct ClockDiffResult {
    local_send_time: i64,
    remote_recv_time: i64,
    remote_send_time: i64,
    local_recv_time: i64,
}

// 执行结果

#[derive(Debug, Default)]
struct SumResult {
    host: String,
    delta1: Vec<i64>,
    delta2: Vec<i64>,
    rtt_sum: Vec<i64>,
    rtt_min: Option<i64>,
    time_format: Option<String>,
}
impl SumResult {
    fn new(host: &str, time_format: Option<String>) -> SumResult {
        SumResult {
            host: host.to_string(),
            time_format,
            ..Default::default()
        }
    }

    fn add(&mut self, delta1: i64, delta2: i64, rtt: i64) {
        self.delta1.push(delta1);
        self.delta2.push(delta2);

        self.rtt_sum.push(rtt);
        if rtt < self.rtt_min.unwrap_or(i64::MAX) {
            self.rtt_min = Some(rtt);
        }
    }

    fn print_summary(&self) {
        let datetime = Local::now();

        if self.rtt_sum.is_empty() {
            println!("clockdiff: {} is down", self.host);
            return;
        }

        let count = self.rtt_sum.len() as i64;
        let avg_rtt = self.rtt_sum.iter().sum::<i64>() / count;
        let avg_std = self.standard_deviation(&self.rtt_sum);

        let avg_delta1 = self.delta1.iter().sum::<i64>() / count;
        let avg_delta2 = self.delta2.iter().sum::<i64>() / count;

        let format = match self.time_format.as_deref() {
            Some("iso") => "%Y-%m-%dT%H:%M:%S%z",
            Some("ctime") => "%a %b %e %H:%M:%S %Y",
            _ => "%c",
        };
        // 构建输出字符串
        let display_summery = format!(
            "\nhost={} rtt={}({})ms/{}ms delta={}ms/{}ms {}\n",
            self.host,
            avg_rtt,
            avg_std,
            self.rtt_min.unwrap_or(0),
            avg_delta1,
            avg_delta2,
            datetime.format(format)
        );
        print!("{}", display_summery);
    }

    // 计算标准差（样本标准差，n-1）
    fn standard_deviation(&self, data: &[i64]) -> i64 {
        let avg = data.iter().sum::<i64>() / data.len() as i64;

        let variance = data
            .iter()
            .map(|v| ((*v - avg) as f64).powi(2))
            .sum::<f64>()
            / (data.len() - 1) as f64;
        variance.sqrt() as i64
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "utclockdiff",
    author = "xiaolong <longqiang@uniontech.com>",
    version = concat!("from ", env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")),
)]
pub struct ClockdiffConfig {
    /// DNS name or IP address
    #[arg(value_name = "DESTINATION")]
    pub destination: String,

    /// Use ip timestamp and icmp echo
    #[arg(short = 'o')]
    pub ip_timestamp: bool,

    /// Use three-term ip timestamp and icmp echo
    #[arg(short = '1')]
    pub three_timestamps: bool,

    /// Specify display time format, ctime is the default
    #[arg(short = 'T', value_parser = ["ctime", "iso"], default_value = "ctime")]
    pub time_format: String,

    /// Alias of --time-format=iso
    #[arg(short = 'I')]
    pub iso_format: bool,
}

impl Default for ClockdiffConfig {
    fn default() -> Self {
        Self {
            destination: String::new(),
            ip_timestamp: false,
            three_timestamps: false,
            time_format: "ctime".to_string(),
            iso_format: false,
        }
    }
}

impl ClockdiffConfig {
    pub fn from_args() -> Self {
        let mut config = Self::parse();

        // 处理 iso_format 选项
        if config.iso_format {
            config.time_format = "iso".to_string();
        }

        // 如果指定了 --o1，自动启用 ip_timestamp
        if config.three_timestamps {
            config.ip_timestamp = true;
        }

        config
    }

    pub fn get_time_format(&self) -> Option<String> {
        Some(self.time_format.clone())
    }
}

pub fn main() {
    info!("Starting clockdiff");
    init_logger();
    initialize_signal_handler();

    // 命令行参数解析
    let mut clockdiff_config = ClockdiffConfig::from_args();

    // 解析输入地址是否为ipv4地址
    let target_ip = clockdiff_config.destination.clone();

    let (target_cname, target_ips) = get_ipv4_addr(&target_ip).unwrap_or_else(|e| {
        eprintln!(
            "utclockdiff: Failed to resolve target IP '{}': {}",
            target_ip, e
        );
        process::exit(1);
    });
    debug!("Target CNAME: {}", target_cname);
    debug!("Target IPs: {:?}", target_ips);

    for ip in target_ips {
        if !is_running() {
            break;
        }
        if let Err(e) = clockdiff_run(ip, &mut clockdiff_config) {
            eprintln!("utclockdiff: Failed to run clockdiff for {}: {}", ip, e);
            process::exit(1);
        }
        info!("clockdiff finished: {}", ip.to_string());
    }
}

fn get_default_ip() -> Ipv4Addr {
    let interfaces = pnet::datalink::interfaces();
    for iface in interfaces {
        if !iface.is_loopback() && iface.is_running() {
            for ip in iface.ips {
                if ip.is_ipv4() {
                    info!("use default ip: {}", ip.ip());
                    return match ip.ip() {
                        IpAddr::V4(ipv4) => ipv4,
                        _ => continue,
                    };
                }
            }
        }
    }
    Ipv4Addr::new(127, 0, 0, 1)
}

fn clockdiff_run(
    ip: Ipv4Addr,
    options: &mut ClockdiffConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // 创建ICMP传输通道
    let (mut tx, mut rx) = create_icmp_channel()?;

    let mut sumResult = SumResult::new(&ip.to_string(), options.get_time_format());

    let sourceIP = get_default_ip();

    let identifier = process::id() as u16;
    for index in 0..MSGS {
        if !is_running() {
            break;
        }

        if options.ip_timestamp {
            // 构造IP时间戳选项
            info!("build ip timestamp packet");
            let buffer =
                build_ipv4_packet_with_timestamp(options, index as u16, identifier, sourceIP, ip);

            let ip_packet = Ipv4Packet::new(&buffer).ok_or("Failed to create IPv4 packet")?;
            tx.send_to(ip_packet, IpAddr::V4(ip))?;
        } else {
            // 构造ICMP Timestamp请求
            info!("build icmp timestamp packet");

            let buffer = match build_icmp_timestamp_packet(sourceIP, ip, identifier, index as u16) {
                Ok(buf) => buf,
                Err(e) => {
                    return Err(format!("Failed to build ICMP timestamp packet: {}", e).into())
                }
            };

            info!(
                "Sending ICMP Timestamp request to {}, packet: {:?}",
                ip, buffer
            );
            let icmp_packet =
                Ipv4Packet::new(&buffer).ok_or("Failed to create IPv4 packet for ICMP")?;
            tx.send_to(icmp_packet, IpAddr::V4(ip))?;
        }

        info!("Waiting for ICMP Timestamp reply...");
        // 接收响应
        let mut iter = icmp_packet_iter(&mut rx);
        let timeout = Duration::from_secs(1);

        print!(".");
        let _ = std::io::stdout().flush();

        match iter.next_with_timeout(timeout) {
            Ok(Some((raw_data, addr))) => {
                if let Some(ip_pkt) = Ipv4Packet::new(raw_data.packet()) {
                    debug!("Received ICMP packet from {}: {:?}", addr, ip_pkt);
                    if ip_pkt.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                        debug!("is icmp packet");

                        if let Some(icmp_pkt) = IcmpPacket::new(ip_pkt.payload()) {
                            debug!("icmp packet type: {:?}", icmp_pkt);

                            if icmp_pkt.get_icmp_type() == IcmpTypes::TimestampReply {
                                debug!("is timestamp reply");

                                let payload = icmp_pkt.payload();
                                let result = parse_timestamps(payload)?;
                                let (delta1, delta2) = calculate_delta(&result);
                                let rtt = calculate_rtt(&result);
                                debug!("delta1: {:?}, delta2: {} rtt: {:?}", delta1, delta2, rtt);
                                sumResult.add(delta1, delta2, rtt);
                            }
                        }
                    }

                    if options.ip_timestamp && !ip_pkt.get_options().is_empty() {
                        debug!("is ip reply options: {:?}", ip_pkt.get_options());
                        ip_pkt.get_options_iter().for_each(|opt| {
                            if opt.get_number() == Ipv4OptionNumbers::TS {
                                let data = opt.packet();
                                let (rtt, delta1, delta2) = parse_timestamp_option(data);
                                sumResult.add(delta1, delta2, rtt);
                            }
                        });
                    }
                }
            }
            Ok(None) => {
                info!("not received icmp packet");
                continue;
            }
            Err(e) => return Err(Box::new(e)),
        }
    }
    sumResult.print_summary();
    Ok(())
}

// 创建ICMP传输通道
fn create_icmp_channel() -> Result<
    (
        pnet::transport::TransportSender,
        pnet::transport::TransportReceiver,
    ),
    Box<dyn std::error::Error>,
> {
    let (tx, rx) = transport_channel(
        4096,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
    ).map_err(|e| {
        // 检查是否是权限错误
        if e.to_string().contains("Operation not permitted") || e.to_string().contains("Permission denied") {
"Permission denied: clockdiff requires root privileges to send raw ICMP packets. Try running with sudo.".to_string()
        } else {
            format!("Failed to create ICMP socket: {}", e)
        }
    })?;
    Ok((tx, rx))
}

fn get_timestamp() -> u32 {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (since_epoch.as_millis() % 86400000) as u32 // 86400000 ms = 1天
}

fn build_icmp_timestamp_packet(
    source: Ipv4Addr,
    target: Ipv4Addr,
    id: u16,
    seq: u16,
) -> anyhow::Result<Vec<u8>> {
    // Build ICMP packet
    // 计算总长度：IPv4头部 + ICMP头部 + 时间戳数据
    let total_length = IPV4_HEADER_LEN + ICMP_HEADER_LEN + TIMESTAMP_LEN;
    let mut buffer = vec![0u8; total_length];

    let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer[..IPV4_HEADER_LEN])
        .ok_or_else(|| anyhow::anyhow!("Failed to create mutable IPv4 packet"))?;
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(total_length as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_source(source);
    ipv4_packet.set_destination(target);

    // 构造 ICMP 时间戳请求（Type 13）
    let icmp_start = IPV4_HEADER_LEN;
    let mut icmp_buffer = &mut buffer[icmp_start..];
    let mut icmp_packet = MutableIcmpPacket::new(icmp_buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to create mutable ICMP packet"))?;
    icmp_packet.set_icmp_type(IcmpTypes::Timestamp);
    icmp_packet.set_icmp_code(IcmpCode::new(0));

    let mut timestamp = get_timestamp();
    let mut payload = vec![0u8; TIMESTAMP_LEN + 4];
    debug!("send timestamp: {:?}", timestamp);
    payload[0..2].copy_from_slice(&id.to_be_bytes());
    payload[2..4].copy_from_slice(&seq.to_be_bytes());
    payload[4..8].copy_from_slice(&timestamp.to_be_bytes());
    // payload[8..12].copy_from_slice(&timestamp.to_be_bytes());

    icmp_packet.set_payload(&payload);

    let icmp_checksum = checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(icmp_checksum);

    debug!("icmp packet: {:?}", icmp_packet.payload());
    debug!("buffer : {:?}", buffer);
    Ok(buffer)
}

fn parse_timestamps(payload: &[u8]) -> Result<ClockDiffResult, Box<dyn std::error::Error>> {
    if payload.len() < TIMESTAMP_LEN {
        return Err("Invalid payload length".into());
    }
    debug!("paylod: {:?}", payload);

    // 解析时间戳（大端序），已知前4个字节是identifier和seq, 后面是时间戳，故从第5个字节开始解析
    let t1 = u32::from_be_bytes(payload[4..8].try_into()?) as i64;
    let t2 = u32::from_be_bytes(payload[8..12].try_into()?) as i64;
    let t3 = u32::from_be_bytes(payload[12..].try_into()?) as i64;
    let t4 = get_timestamp() as i64;

    debug!("t1: {:?}, t2: {:?}, t3: {:?}, t4: {:?}", t1, t2, t3, t4);

    Ok(ClockDiffResult {
        local_send_time: t1,
        remote_recv_time: t2,
        remote_send_time: t3,
        local_recv_time: t4,
    })
}

fn calculate_delta(res: &ClockDiffResult) -> (i64, i64) {
    let t1 = res.local_send_time;
    let t2 = res.remote_recv_time;
    let t3 = res.remote_send_time;
    let t4 = res.local_recv_time;

    let delta1 = t2 - t1; // 正向延迟
    let delta2 = t4 - t3; // 反向延迟
    (delta1, delta2)
}

fn calculate_rtt(res: &ClockDiffResult) -> i64 {
    let t1 = res.local_send_time;
    let t2 = res.remote_recv_time;
    let t3 = res.remote_send_time;
    let t4 = res.local_recv_time;

    (t4 - t1) - (t3 - t2)
}

fn build_ipv4_packet_with_timestamp(
    options: &mut ClockdiffConfig,
    seq: u16,
    identifier: u16,
    source: Ipv4Addr,
    dest: Ipv4Addr,
) -> Vec<u8> {
    let option_len = if options.three_timestamps {
        OPTIONS_LEN_THREE
    } else {
        OPTIONS_LEN
    };

    // 总长度 = IP头 + 选项 + ICMP头 + 数据
    let total_len = IPV4_HEADER_LEN + option_len + ICMP_HEADER_LEN + TIMESTAMP_LEN;
    let mut ip_buffer = vec![0u8; total_len];

    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).expect("Failed to create IP packet");

    // 设置 IP 头基本字段
    ip_packet.set_version(4);
    ip_packet.set_header_length((IPV4_HEADER_LEN + OPTIONS_LEN) as u8 / 4); // 5个32位字（20字节） + 3个选项字（12字节）
    ip_packet.set_total_length(total_len as u16); // IP头 + 选项 + ICMP头+负载
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_packet.set_source(source);
    ip_packet.set_destination(dest);

    let options: &mut [u8] = ip_packet.get_options_raw_mut();
    options[0] = IPOPT_TIMESTAMP; // 时间戳选项
    options[1] = option_len as u8; // 选项长度
    options[2] = 13; // 指针位置
    options[3] = 0x03; // 标志位 (仅时间戳)
    let timestamp = get_timestamp();
    debug!("timestamp: {:?}", timestamp);
    options[4..8].copy_from_slice(&source.octets()); // 地址（初始为0，等待目标主机填充）
    options[8..12].copy_from_slice(&timestamp.to_be_bytes()); // 发起时间
    options[12..16].copy_from_slice(&dest.octets());
    options[16..20].copy_from_slice(&[0u8; 4]); // 接收时间
    options[20..24].copy_from_slice(&source.octets());
    options[24..28].copy_from_slice(&[0u8; 4]); // 传输时间（初始为0，等待目标主机填充）

    // 计算 IP 头校验和
    ip_packet.set_checksum(0);
    let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);

    // 构造ICMP Echo请求（从IP头部之后开始）
    let icmp_start = IPV4_HEADER_LEN + OPTIONS_LEN;
    let mut echo_packet = MutableEchoRequestPacket::new(&mut ip_buffer[icmp_start..])
        .expect("Failed to create ICMP echo request packet");
    echo_packet.set_icmp_type(IcmpTypes::EchoRequest);
    echo_packet.set_icmp_code(IcmpCode::new(0));
    echo_packet.set_identifier(identifier);
    echo_packet.set_sequence_number(seq);
    let checksum = pnet::util::checksum(echo_packet.packet(), 1);
    echo_packet.set_checksum(checksum);

    debug!("ip buffer: {:?}", ip_buffer);
    ip_buffer
}

fn parse_timestamp_option(option_data: &[u8]) -> (i64, i64, i64) {
    if option_data.len() < 4 {
        eprintln!("Invalid timestamp option: too short");
    }

    let length = option_data[1] as usize;
    let pointer = option_data[2] as usize;
    let flags = option_data[3];
    let overflow = (flags >> 4) & 0x0F; // 溢出计数器
    let flag = flags & 0x0F; // 标志位（0x01=仅时间戳）

    debug!("Timestamp Option:");
    debug!("  Length: {} bytes", length);
    debug!("  Pointer: {}", pointer);
    debug!("  Flags: Overflow={}, Flag=0x{:x}", overflow, flag);

    // 时间戳数据解析（从第4字节开始）
    let timestamp_data = &option_data[4..];
    let timestamps: Vec<u32> = timestamp_data
        .chunks(4)
        .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    match flag {
        0x01 => {
            // 仅包含发起时间戳
            if !timestamps.is_empty() {
                debug!("  Origin Timestamp: {} ms", timestamps[0]);
            }
            (0, 0, 0)
        }
        0x03 => {
            // 包含发起、接收、传输时间戳
            if timestamps.len() >= 3 {
                debug!("Timestamp: {:?} ", timestamps);
                let t1 = timestamps[1] as i64;
                let t2 = timestamps[3] as i64;
                let t3 = timestamps[5] as i64;
                let t4 = get_timestamp() as i64;

                debug!("  Origin Timestamp: {} ms", t1);
                debug!("  Receive Timestamp: {} ms", t2);
                debug!("  Transmit Timestamp: {} ms", t3);
                debug!("  Local Timestamp: {} ms", t4);

                let rtt = t4 - t1; // 往返时间
                let delta1 = t2 - t1; // 时钟差1
                let delta2 = if t3 == 0 {
                    // 未收到时间戳，使用 T3=T2
                    t4 - t2
                } else {
                    t4 - t3
                };

                return (rtt, delta1, delta2);
            }
            debug!("timestamps: {:?}", timestamps);
            (0, 0, 0)
        }
        _ => {
            eprintln!("Unknown timestamp flag: 0x{:x}", flag);
            (0, 0, 0)
        }
    }
}
