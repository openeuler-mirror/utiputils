/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use clap::Parser;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::Result;

const MAX_HOPS: u8 = 30; // 最大跳数
const BASE_PORT: u16 = 44444; // 基准端口号
const BASE_MTU: u16 = 1500; // 基准MTU
const TIMEOUT_MS: u64 = 100; // 缩短超时时间，提高性能
const WAIT_STEP_MS: u64 = 1000; // 缩短等待间隔，提高性能
const TTL_INTERVAL_MS: u64 = 10; // 缩短TTL间隔，提高性能

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
