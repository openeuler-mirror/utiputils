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
    common::signal::RUNNING, iputils_common::reverse_dns_lookup, ping::ping_types::PingConfig,
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
}

// 获取类似原生ping的时间戳（struct timeval格式）
fn get_timestamp_ms() -> u32 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // 原生ping使用gettimeofday()，在ICMP数据中存储struct timeval
    // struct timeval { tv_sec, tv_usec }，但只存储tv_sec的低32位
    // 这样更接近原生ping的行为，且能被tshark识别为时间戳
    now.as_secs() as u32
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
