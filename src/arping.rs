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
