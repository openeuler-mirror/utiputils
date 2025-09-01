/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use clap::Parser;
use log::{debug, error, info};

use pnet::{
    datalink::{self, Channel, NetworkInterface},
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        MutablePacket, Packet,
    },
    util::MacAddr,
};

use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    process, thread,
    time::{Duration, Instant},
};

// ARP 包结构长度常量
const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;
const TOTAL_PACKET_LEN: usize = ETHERNET_HEADER_LEN + ARP_PACKET_LEN;

#[derive(Debug, Parser)]
#[command(
    name = "utarping",
     author = "UnionTech Software Technology Co., Ltd.",
    version = concat!("from ", env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")),
    about = "ARPing utility - send ARP REQUEST to a neighbor host"
)]
#[derive(Default)]
pub struct ArpingConfig {
    /// DNS name or IP address
    #[arg(value_name = "DESTINATION")]
    pub destination: String,

    /// Quit on first reply
    #[arg(short = 'f')]
    pub quit_on_first_reply: bool,

    /// Be quiet
    #[arg(short = 'q')]
    pub quiet: bool,

    /// Keep on broadcasting, do not unicast
    #[arg(short = 'b')]
    pub broadcast_only: bool,

    /// Duplicate address detection mode
    #[arg(short = 'D')]
    pub duplicate_address_detection: bool,

    /// Unsolicited ARP mode, update your neighbours
    #[arg(short = 'U')]
    pub unsolicited_arp: bool,

    /// ARP answer mode, update your neighbours
    #[arg(short = 'A', requires = "device")]
    pub arp_answer: bool,

    /// How many packets to send
    #[arg(short = 'c')]
    pub count: Option<u32>,

    /// Set interval between packets (default: 1 second)
    #[arg(short = 'i')]
    pub interval: Option<u32>,

    /// How long to wait for a reply
    #[arg(short = 'w')]
    pub timeout: Option<u32>,

    /// Which ethernet device to use
    #[arg(short = 'I')]
    pub device: Option<String>,

    /// Source IP address to use
    #[arg(short = 's')]
    pub source: Option<String>,
}

impl ArpingConfig {
    pub fn from_args() -> Self {
        Self::parse()
    }
}

struct ArgState {
    target_mac: Option<MacAddr>, // 目标 MAC 地址
    last_update: Instant,        // 最后更新时间
}

impl ArgState {
    fn new() -> Self {
        ArgState {
            target_mac: None,
            last_update: Instant::now(),
        }
    }

    // 是否需要发送广播（首次或缓存过期）
    fn should_broadcast(&self) -> bool {
        self.target_mac.is_none() || self.last_update.elapsed() > Duration::from_secs(60)
    }

    // 更新缓存
    fn update(&mut self, mac: MacAddr) {
        self.target_mac = Some(mac);
        self.last_update = Instant::now();
    }

    fn is_expired(&self, timeout: u32) -> bool {
        self.last_update.elapsed().as_secs() > timeout as u64
    }
}

fn validate_ip_on_interface(interface: &NetworkInterface, ip: IpAddr) -> bool {
    for ip_network in &interface.ips {
        if ip_network.ip() == ip {
            return true;
        }
    }
    false
}

fn validate_source_ip_on_interface(interface: &NetworkInterface, source_ip: Ipv4Addr) -> bool {
    for ip_network in &interface.ips {
        if let IpAddr::V4(_ipv4) = ip_network.ip() {
            // 检查源IP是否在同一网络段内
            if ip_network.contains(IpAddr::V4(source_ip)) {
                return true;
            }
        }
    }
    false
}

fn print_summary(sent_count: u32, reply_count: u32, broadcast_count: u32) {
    println!(
        "Sent {} probes ({} broadcast(s)) \nReceived {} response(s)",
        sent_count, broadcast_count, reply_count
    );
}

// 工具函数
fn find_interface(name: &str) -> NetworkInterface {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .unwrap_or_else(|| {
            eprintln!("utarping: Interface {} not found", name);
            process::exit(1);
        })
}

/// 为目标IP地址找到最佳的网络接口
fn find_best_interface_for_target(target_ip: Ipv4Addr) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    // 首先尝试找到与目标IP在同一网段的接口
    for interface in &interfaces {
        if !is_interface_suitable(interface) {
            continue;
        }

        for ip_network in &interface.ips {
            if let IpAddr::V4(_ipv4) = ip_network.ip() {
                // 检查目标IP是否在此接口的网络段内
                if ip_network.contains(IpAddr::V4(target_ip)) {
                    debug!(
                        "Found interface {} for target {} (same network)",
                        interface.name, target_ip
                    );
                    return Some(interface.clone());
                }
            }
        }
    }

    // 如果没有找到同网段的接口，选择默认路由接口
    find_default_route_interface(&interfaces).or_else(|| find_first_suitable_interface(&interfaces))
}

/// 检查接口是否适合用于ARP操作
fn is_interface_suitable(interface: &NetworkInterface) -> bool {
    // 跳过回环接口
    if interface.is_loopback() {
        return false;
    }

    // 必须有MAC地址
    if interface.mac.is_none() {
        return false;
    }

    // 必须有IPv4地址
    let has_ipv4 = interface
        .ips
        .iter()
        .any(|ip| matches!(ip.ip(), IpAddr::V4(_)));
    if !has_ipv4 {
        return false;
    }

    // 接口必须是UP状态
    if !interface.is_up() {
        return false;
    }

    true
}

/// 尝试找到默认路由接口
fn find_default_route_interface(interfaces: &[NetworkInterface]) -> Option<NetworkInterface> {
    // 常见的默认接口名称优先级
    let preferred_names = ["eth0", "eno1", "enp", "ens", "em1", "wlan0", "wlp", "wlo"];

    for preferred in &preferred_names {
        for interface in interfaces {
            if !is_interface_suitable(interface) {
                continue;
            }

            if interface.name.starts_with(preferred) {
                debug!("Selected preferred interface: {}", interface.name);
                return Some(interface.clone());
            }
        }
    }

    None
}

/// 找到第一个合适的接口
fn find_first_suitable_interface(interfaces: &[NetworkInterface]) -> Option<NetworkInterface> {
    for interface in interfaces {
        if is_interface_suitable(interface) {
            debug!("Selected first suitable interface: {}", interface.name);
            return Some(interface.clone());
        }
    }
    None
}

fn get_interface_ip(interface: &NetworkInterface) -> Option<Ipv4Addr> {
    interface.ips.iter().find_map(|ip| {
        if let IpAddr::V4(ipv4) = ip.ip() {
            Some(ipv4)
        } else {
            None
        }
    })
}

fn build_arp_packet(
    options: &mut ArpingConfig,
    state: &ArgState,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> [u8; TOTAL_PACKET_LEN] {
    let mut buffer = [0u8; TOTAL_PACKET_LEN];

    // 根据目标 MAC 地址是否过期决定是否发送广播
    let dst_mac = match state.should_broadcast() {
        true => MacAddr::broadcast(),       // 广播模式
        false => state.target_mac.unwrap(), // 单播模式
    };

    // 处理 -A 选项，使用 Reply 类型
    let operation = if options.arp_answer {
        ArpOperations::Reply
    } else {
        ArpOperations::Request
    };

    // 构建以太网帧头
    let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    eth_packet.set_destination(dst_mac);
    eth_packet.set_source(src_mac);
    eth_packet.set_ethertype(EtherTypes::Arp);

    // 构建 ARP 包
    let mut arp_packet = MutableArpPacket::new(eth_packet.payload_mut()).unwrap();
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(operation);
    arp_packet.set_sender_hw_addr(src_mac);
    arp_packet.set_sender_proto_addr(src_ip);

    // 设定目标硬件地址：与 iputils 行为保持一致
    // 1. 首包（广播）时，target_hw_addr 也使用广播地址 FF:FF:FF:FF:FF:FF
    //    某些设备在 target_hw_addr 为 00:00:00:00:00:00 时可能不返回应答，
    //    这会导致收到的 reply 数量比 arping 少 1 次。
    // 2. 后续单播包则写入已学到的目标 MAC。
    let target_hw = match state.should_broadcast() {
        true => MacAddr::broadcast(),
        false => state.target_mac.unwrap_or(MacAddr::zero()),
    };
    arp_packet.set_target_hw_addr(target_hw);

    arp_packet.set_target_proto_addr(dst_ip);

    buffer
}

fn parse_arp_reply(packet: &[u8], target_ip: Ipv4Addr) -> Option<MacAddr> {
    // 解析以太网帧
    let eth_packet = EthernetPacket::new(packet)?;

    // 检查以太网帧的类型是否为 ARP
    if eth_packet.get_ethertype() != EtherTypes::Arp {
        // debug!("not arp: {}",eth_packet.get_ethertype());
        return None;
    }

    // 解析 ARP 包
    let arp_packet = ArpPacket::new(eth_packet.payload())?;
    if arp_packet.get_operation() != ArpOperations::Reply {
        debug!(
            "Received non-ARP reply packet with operation: {:?}",
            arp_packet.get_operation()
        );
        return None;
    }

    // 检查 ARP 包的目标 IP 地址是否匹配
    if arp_packet.get_sender_proto_addr() != target_ip {
        debug!(
            "Received ARP reply for different target IP: {:?}",
            arp_packet.get_sender_proto_addr()
        );
        return None;
    }

    // 返回发送者的 MAC 地址
    Some(arp_packet.get_sender_hw_addr())
}
