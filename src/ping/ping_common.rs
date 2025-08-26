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
