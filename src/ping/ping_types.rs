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

use crate::iputils_common::reverse_dns_lookup;

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

impl PingConfig {
    /// 解析命令行参数并初始化运行时字段
    pub fn from_args() -> Self {
        let mut config = Self::parse();

        // 特殊处理：如果 -N help，显示帮助并退出
        if let Some(ref nodeinfo) = config.nodeinfo_opt_arg {
            if nodeinfo == "help" {
                Self::print_nodeinfo_help();
                std::process::exit(0);
            }
        }

        // 验证必需的参数
        if config.host.is_none() {
            eprintln!("error: the following required arguments were not provided:");
            eprintln!("  <DESTINATION>");
            eprintln!();
            eprintln!("Usage: utping [OPTIONS] <DESTINATION>");
            eprintln!();
            eprintln!("For more information, try '--help'.");
            std::process::exit(2);
        }

        config.init_runtime_fields();
        config
    }

    /// 创建一个用于测试的默认配置
    pub fn new_for_test() -> Self {
        Self {
            host: Some("localhost".to_string()),
            force_ipv4: false,
            force_ipv6: false,
            count: None,
            identifier_arg: None,
            flood: false,
            interval_secs: 1.0,
            preload_arg: None,
            mark: None,
            pattern_arg: None,
            tclass: None,
            timeout_secs: 1.0,
            deadline_secs: None,
            ttl: 64,
            packet_size: 56,
            send_buffer_size_arg: None,
            audible: false,
            adaptive: false,
            strictsource_arg: None,
            pmtudisc_arg: None,
            connect_sk: false,
            debug: false,
            outstanding: false,
            verbose: false,
            quiet: false,
            print_timestamp: false,
            loop_multicast_back: false,
            user_timeout: false,
            numeric_only: false,
            broadcast: false,
            record_route: false,
            timestamp_arg: None,
            flowlabel: None,
            nodeinfo_opt_arg: None,
            interface_arg: None,
            domain: "localhost".to_string(),
            interface: String::new(),
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            deadline: Duration::from_secs(0),
            identifier: 0,
            preload: 0,
            send_buffer_size: 0,
            pattern: Vec::new(),
            strictsource: String::new(),
            pmtudisc: String::new(),
            timestamp: String::new(),
            nodeinfo_opt: String::new(),
            starttime: None,
            local_ip: String::new(),
            interface_name: String::new(),
            dns_cache: RefCell::new(HashMap::new()),
            is_direct_ip_input: false,
            last_rr_raw: RefCell::new(Vec::new()),
        }
    }

    /// 初始化运行时字段
    fn init_runtime_fields(&mut self) {
        // 当设置了 IPv4 特有的选项时，自动启用 force_ipv4
        if self.broadcast || self.record_route || self.timestamp_arg.is_some() {
            self.force_ipv4 = true;
        }

        // 当设置了 IPv6 特有的选项时，自动启用 force_ipv6
        if self.flowlabel.is_some() || self.nodeinfo_opt_arg.is_some() {
            self.force_ipv6 = true;
        }

        // 设置域名（初始等于host）
        self.domain = self.host.as_ref().unwrap_or(&String::new()).clone();

        // 设置接口
        self.interface = self
            .interface_arg
            .as_ref()
            .unwrap_or(&String::new())
            .clone();

        // 设置时间间隔
        self.interval = Duration::from_secs_f64(self.interval_secs);
        self.timeout = Duration::from_secs_f64(self.timeout_secs);
        self.deadline = Duration::from_secs_f64(self.deadline_secs.unwrap_or(0.0));

        // 设置标识符
        self.identifier = self.identifier_arg.unwrap_or_else(rand::random::<u16>);

        // 设置预加载
        self.preload = self.preload_arg.map(|p| p.min(10)).unwrap_or(0);

        // 设置缓冲区大小
        self.send_buffer_size = self.send_buffer_size_arg.unwrap_or(0);

        // 设置模式
        self.pattern = if let Some(pattern_str) = &self.pattern_arg {
            parse_hex(pattern_str).unwrap_or_else(|e| {
                eprintln!("ping: invalid pattern: {}", e);
                std::process::exit(2);
            })
        } else {
            Vec::new()
        };

        // 设置字符串选项
        self.strictsource = self
            .strictsource_arg
            .as_ref()
            .unwrap_or(&String::new())
            .clone();
        self.pmtudisc = self
            .pmtudisc_arg
            .as_ref()
            .map(|p| p.as_str().to_string())
            .unwrap_or_default();
        self.timestamp = self
            .timestamp_arg
            .as_ref()
            .map(|t| t.as_str().to_string())
            .unwrap_or_default();
        self.nodeinfo_opt = self
            .nodeinfo_opt_arg
            .as_ref()
            .unwrap_or(&String::new())
            .clone();

        // 初始化运行时字段
        self.starttime = None;
        self.local_ip = String::new();
        self.interface_name = String::new();
        self.dns_cache = RefCell::new(HashMap::new());
        self.is_direct_ip_input = self
            .host
            .as_ref()
            .map(|h| {
                h.chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == ':')
            })
            .unwrap_or(false);
        // 清空上一次 RR 记录
        self.last_rr_raw.borrow_mut().clear();
    }

    pub fn initStartTime(&mut self) {
        self.starttime = Some(Instant::now());
    }

    pub fn getStartTime(&self) -> Instant {
        self.starttime.unwrap()
    }

    pub fn setInterfaceInfo(&mut self, ip: String, interface_name: String) {
        self.local_ip = ip;
        self.interface_name = interface_name;
    }

    pub fn getInterfaceInfo(&self) -> (String, String) {
        (self.local_ip.clone(), self.interface_name.clone())
    }

    /// 获取IP对应的主机名，使用缓存避免重复DNS查询
    pub fn get_hostname_cached(&self, ip: &str) -> String {
        // 如果使用-n选项，直接返回IP
        if self.numeric_only {
            return ip.to_string();
        }

        // 检查缓存
        if let Some(cached_hostname) = self.dns_cache.borrow().get(ip) {
            return cached_hostname.clone();
        }

        // 缓存中没有，进行DNS查询
        let hostname = reverse_dns_lookup(ip).unwrap_or_else(|_| ip.to_string());

        // 将结果缓存（限制缓存大小避免内存泄漏）
        if self.dns_cache.borrow().len() < 1000 {
            self.dns_cache
                .borrow_mut()
                .insert(ip.to_string(), hostname.clone());
        }

        hostname
    }

    /// 显示 nodeinfo 帮助信息
    fn print_nodeinfo_help() {
        println!("ping -6 -N <nodeinfo opt>");
        println!("Help:");
        println!("  help");
        println!("Query:");
        println!("  name");
        println!("  ipv6");
        println!("  ipv6-all");
        println!("  ipv6-compatible");
        println!("  ipv6-global");
        println!("  ipv6-linklocal");
        println!("  ipv6-sitelocal");
        println!("  ipv4");
        println!("  ipv4-all");
        println!("Subject:");
        println!("  subject-ipv6=addr");
        println!("  subject-ipv4=addr");
        println!("  subject-name=name");
        println!("  subject-fqdn=name");
    }
}

#[derive(Debug, Default)]
pub struct PingStats {
    pub transmitted: u32,
    pub received: u32,
    pub errors: u32, // 错误计数，如destination unreachable等
    pub total_rtt: f64,
    pub total_rtt_squared: f64, // 用于计算标准差
    pub min_rtt: f64,
    pub max_rtt: f64,
    pub start_time: Option<Instant>,
    pub sent_times: HashMap<u16, Instant>,
}

impl PingStats {
    pub fn new() -> Self {
        Self {
            min_rtt: f64::MAX,
            max_rtt: f64::MIN,
            ..Default::default()
        }
    }
    pub fn record_sent_time(&mut self, seq: u16) {
        self.sent_times.insert(seq, Instant::now());
        self.transmitted += 1;
    }
    pub fn get_sent_time(&mut self, seq: u16) -> Option<Instant> {
        self.sent_times.remove(&seq)
    }

    pub fn update(&mut self, rtt: f64) {
        self.received += 1;
        self.total_rtt += rtt;
        self.total_rtt_squared += rtt * rtt;
        self.min_rtt = self.min_rtt.min(rtt);
        self.max_rtt = self.max_rtt.max(rtt);
    }

    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    fn summary(&self, domain: &str) -> String {
        let loss_percent = if self.transmitted > 0 {
            let lost = self.transmitted - self.received;
            (lost as f64 / self.transmitted as f64) * 100.0
        } else {
            0.0
        };

        let avg_rtt = if self.received > 0 {
            self.total_rtt / self.received as f64
        } else {
            0.0
        };

        let duration = self.start_time.map(|st| st.elapsed()).unwrap_or_default();

        let mut result = if self.errors > 0 {
            format!(
                "\n--- {} ping statistics ---\n{} packets transmitted, {} received, +{} errors, {:.1}% packet loss, time {}ms",
                domain,
                self.transmitted,
                self.received,
                self.errors,
                loss_percent,
                duration.as_millis()
            )
        } else {
            format!(
                "\n--- {} ping statistics ---\n{} packets transmitted, {} received, {:.1}% packet loss, time {}ms",
                domain,
                self.transmitted,
                self.received,
                loss_percent,
                duration.as_millis()
            )
        };

        // 添加RTT统计信息（仅在有收到回复时显示）
        if self.received > 0 {
            // 计算标准差 (样本标准差)
            let variance = if self.received > 1 {
                let mean_of_squares = self.total_rtt_squared / self.received as f64;
                let square_of_mean = avg_rtt * avg_rtt;
                (mean_of_squares - square_of_mean).max(0.0)
            } else {
                0.0
            };
            let mdev = variance.sqrt();

            result.push_str(&format!(
                "\nrtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms",
                self.min_rtt, avg_rtt, self.max_rtt, mdev
            ));
        }

        result.push('\n');
        result
    }

    pub fn print_summary(&self, domain: &str) {
        println!("{}", self.summary(domain));
    }
}

pub struct SocketSt {
    pub fd: std::os::unix::io::RawFd,
    pub socktype: SockType,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_force_ipv4_with_broadcast() {
        let mut config = PingConfig::new_for_test();
        config.broadcast = true;
        config.init_runtime_fields();
        assert!(
            config.force_ipv4,
            "broadcast option should automatically enable force_ipv4"
        );
    }

    #[test]
    fn test_auto_force_ipv4_with_record_route() {
        let mut config = PingConfig::new_for_test();
        config.record_route = true;
        config.init_runtime_fields();
        assert!(
            config.force_ipv4,
            "record_route option should automatically enable force_ipv4"
        );
    }

    #[test]
    fn test_auto_force_ipv4_with_timestamp() {
        let mut config = PingConfig::new_for_test();
        config.timestamp_arg = Some(TimestampType::Tsonly);
        config.init_runtime_fields();
        assert!(
            config.force_ipv4,
            "timestamp option should automatically enable force_ipv4"
        );
    }

    #[test]
    fn test_no_auto_force_ipv4_without_options() {
        let mut config = PingConfig::new_for_test();
        config.init_runtime_fields();
        assert!(
            !config.force_ipv4,
            "force_ipv4 should not be enabled without IPv4-specific options"
        );
    }

    #[test]
    fn test_auto_force_ipv4_with_multiple_options() {
        let mut config = PingConfig::new_for_test();
        config.broadcast = true;
        config.record_route = true;
        config.timestamp_arg = Some(TimestampType::Tsandaddr);
        config.init_runtime_fields();
        assert!(
            config.force_ipv4,
            "multiple IPv4 options should automatically enable force_ipv4"
        );
    }

    #[test]
    fn test_auto_force_ipv6_with_flowlabel() {
        let mut config = PingConfig::new_for_test();
        config.flowlabel = Some(12345);
        config.init_runtime_fields();
        assert!(
            config.force_ipv6,
            "flowlabel option should automatically enable force_ipv6"
        );
    }

    #[test]
    fn test_auto_force_ipv6_with_nodeinfo() {
        let mut config = PingConfig::new_for_test();
        config.nodeinfo_opt_arg = Some("name".to_string());
        config.init_runtime_fields();
        assert!(
            config.force_ipv6,
            "nodeinfo option should automatically enable force_ipv6"
        );
    }

    #[test]
    fn test_no_auto_force_ipv6_without_options() {
        let mut config = PingConfig::new_for_test();
        config.init_runtime_fields();
        assert!(
            !config.force_ipv6,
            "force_ipv6 should not be enabled without IPv6-specific options"
        );
    }

    #[test]
    fn test_auto_force_ipv6_with_multiple_options() {
        let mut config = PingConfig::new_for_test();
        config.flowlabel = Some(54321);
        config.nodeinfo_opt_arg = Some("ipv6".to_string());
        config.init_runtime_fields();
        assert!(
            config.force_ipv6,
            "multiple IPv6 options should automatically enable force_ipv6"
        );
    }
}
