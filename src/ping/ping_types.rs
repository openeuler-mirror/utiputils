/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::vec;
pub use std::{
    cell::RefCell,
    collections::HashMap,
    ffi::CStr,
    fmt,
    io::{self, Write},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::raw::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ushort, c_void},
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use clap::{Parser, ValueEnum};
use nix::sys::socket::SockType;

const DEFDATALEN: usize = 64 - 8;
const MAXWAIT: u64 = 10;
const MININTERVAL: u64 = 10;
const MINUSERINTERVAL: u64 = 2;
const IDENTIFIER_MAX: u16 = 0xFFFF;
const MAX_DUP_CHK: usize = 0x10000;
const BITMAP_SHIFT: usize = if cfg!(target_pointer_width = "64") {
    6
} else {
    5
};

type Bitmap = u64;

pub fn parse_u32(s: &str) -> Result<u32, String> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex_str, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u32>().map_err(|e| e.to_string())
    }
}

pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    // 如果字符串长度为奇数，匹配原生ping的行为：
    // 在最后一个字符前面插入0
    let padded = if s.len() % 2 == 1 {
        if s.len() == 1 {
            // 单个字符：在前面补0
            format!("0{}", s)
        } else {
            // 多个字符：在最后一个字符前插入0
            let mut chars: Vec<char> = s.chars().collect();
            chars.insert(chars.len() - 1, '0');
            chars.into_iter().collect()
        }
    } else {
        s.to_string()
    };

    hex::decode(padded).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, ValueEnum)]
pub enum PmtuDisc {
    Do,
    Dont,
    Want,
}

impl PmtuDisc {
    pub fn as_str(&self) -> &'static str {
        match self {
            PmtuDisc::Do => "do",
            PmtuDisc::Dont => "dont",
            PmtuDisc::Want => "want",
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
pub enum TimestampType {
    Tsonly,
    Tsandaddr,
    Tsprespec,
}

impl TimestampType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TimestampType::Tsonly => "tsonly",
            TimestampType::Tsandaddr => "tsandaddr",
            TimestampType::Tsprespec => "tsprespec",
        }
    }
}

#[derive(Debug, Parser, Default)]
#[command(
    name = "utping",
    author = "UnionTech Software Technology Co., Ltd.",
    version = concat!("from ", env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")),
    about = "Ping tool implemented in Rust"
)]
pub struct PingConfig {
    /// DNS name or IP address
    #[arg(value_name = "DESTINATION")]
    pub host: Option<String>,

    /// Stop after <count> replies
    #[arg(short = 'c')]
    pub count: Option<u32>,

    /// Define identifier for ping session, default is random for SOCK_RAW and kernel defined for SOCK_DGRAM
    /// Imply using SOCK_RAW (for IPv4 only for identifier 0)
    #[arg(short = 'e')]
    pub identifier_arg: Option<u16>,

    /// Flood ping
    #[arg(short = 'f')]
    pub flood: bool,

    /// Either interface name or address
    #[arg(short = 'I')]
    interface_arg: Option<String>,

    /// Seconds between sending each packet
    #[arg(short = 'i', default_value = "1.0")]
    interval_secs: f64,

    /// Send <preload> number of packages while waiting replies
    #[arg(short = 'l')]
    preload_arg: Option<u16>,

    /// Tag the packets going out
    #[arg(short = 'm')]
    pub mark: Option<u32>,

    /// Contents of padding byte
    #[arg(short = 'p')]
    pattern_arg: Option<String>,

    /// Use quality of service <tclass> bits
    #[arg(short = 'Q', value_parser = parse_u32)]
    pub tclass: Option<u32>,

    /// Time to wait for response
    #[arg(short = 'W', default_value = "1.0")]
    timeout_secs: f64,

    /// Reply wait <deadline> in seconds
    #[arg(short = 'w')]
    deadline_secs: Option<f64>,

    /// Define time to live
    #[arg(short = 't', default_value = "64", value_parser = clap::value_parser!(u32).range(1..255))]
    pub ttl: u32,

    /// Use <size> as number of data bytes to be sent
    #[arg(short = 's', default_value = "56")]
    pub packet_size: usize,

    /// Use <size> as SO_SNDBUF socket option value
    #[arg(short = 'S')]
    send_buffer_size_arg: Option<usize>,

    /// Use audible ping
    #[arg(short = 'a')]
    pub audible: bool,

    /// Use adaptive ping
    #[arg(short = 'A')]
    pub adaptive: bool,

    /// Sticky source address
    #[arg(short = 'B')]
    strictsource_arg: Option<String>,

    /// Define mtu discovery, can be one of <do|dont|want>
    #[arg(short = 'M')]
    pmtudisc_arg: Option<PmtuDisc>,

    /// Call connect() syscall on socket creation
    #[arg(short = 'C')]
    pub connect_sk: bool,

    /// Use SO_DEBUG socket option
    #[arg(short = 'd')]
    pub debug: bool,

    /// Report outstanding replies
    #[arg(short = 'O')]
    pub outstanding: bool,

    /// Verbose output
    #[arg(short = 'v')]
    pub verbose: bool,

    /// Quiet output
    #[arg(short = 'q')]
    pub quiet: bool,

    /// Print timestamps
    #[arg(short = 'D')]
    pub print_timestamp: bool,

    /// Suppress loopback of multicast packets
    #[arg(short = 'L')]
    pub loop_multicast_back: bool,

    /// Print user-to-user latency
    #[arg(short = 'U')]
    pub user_timeout: bool,

    /// No dns name resolution
    #[arg(short = 'n')]
    pub numeric_only: bool,

    /// Use IPv4
    #[arg(
        short = '4',
        conflicts_with = "force_ipv6",
        help_heading = "IPv4 options"
    )]
    pub force_ipv4: bool,

    /// Allow pinging broadcast
    #[arg(short = 'b', help_heading = "IPv4 options")]
    pub broadcast: bool,

    /// Record route
    #[arg(short = 'R', help_heading = "IPv4 options")]
    pub record_route: bool,

    /// Define timestamp, can be one of <tsonly|tsandaddr|tsprespec>
    #[arg(short = 'T', help_heading = "IPv4 options")]
    timestamp_arg: Option<TimestampType>,

    /// Use IPv6
    #[arg(
        short = '6',
        conflicts_with = "force_ipv4",
        help_heading = "IPv6 options"
    )]
    pub force_ipv6: bool,

    /// Define flow label, default is random
    #[arg(short = 'F', value_parser = parse_u32, help_heading = "IPv6 options")]
    pub flowlabel: Option<u32>,

    /// Use icmp6 node info query, try <help> as argument
    #[arg(short = 'N', help_heading = "IPv6 options")]
    nodeinfo_opt_arg: Option<String>,

    // 运行时字段（不从命令行解析）
    #[arg(skip)]
    pub domain: String,

    #[arg(skip)]
    pub interface: String,

    #[arg(skip)]
    pub interval: Duration,

    #[arg(skip)]
    pub timeout: Duration,

    #[arg(skip)]
    pub deadline: Duration,

    #[arg(skip)]
    pub identifier: u16,

    #[arg(skip)]
    pub preload: u16,

    #[arg(skip)]
    pub send_buffer_size: usize,

    #[arg(skip)]
    pub pattern: vec::Vec<u8>,

    #[arg(skip)]
    pub strictsource: String,

    #[arg(skip)]
    pub pmtudisc: String,

    #[arg(skip)]
    pub timestamp: String,

    #[arg(skip)]
    pub nodeinfo_opt: String,

    #[arg(skip)]
    pub starttime: Option<Instant>,

    #[arg(skip)]
    pub local_ip: String,

    #[arg(skip)]
    pub interface_name: String,

    // DNS缓存：避免重复查询相同IP的域名
    #[arg(skip)]
    pub dns_cache: RefCell<HashMap<String, String>>,

    // 标识原始输入是否为IP地址
    #[arg(skip)]
    pub is_direct_ip_input: bool,

    // 缓存上一条 RR 原始字节序列，用于判断 "(same route)"
    #[arg(skip)]
    pub last_rr_raw: RefCell<Vec<u8>>, // empty 表示未缓存
}
