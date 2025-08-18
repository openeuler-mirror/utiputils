/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use log::info;
use pnet::datalink;
use std::net::{IpAddr, Ipv4Addr};

/// 获取默认IP地址和接口名称
pub fn get_default_ip() -> (Ipv4Addr, String) {
    let interfaces = datalink::interfaces();
    for iface in interfaces {
        if !iface.is_loopback() && iface.is_running() {
            for ip in iface.ips {
                if ip.is_ipv4() {
                    info!("use default ip: {}", ip.ip());
                    return (
                        match ip.ip() {
                            IpAddr::V4(ipv4) => ipv4,
                            _ => continue,
                        },
                        iface.name.clone(),
                    );
                }
            }
        }
    }
    (Ipv4Addr::new(127, 0, 0, 1), String::new())
}

/// 获取网络接口的MTU值
pub fn get_interface_mtu(interface: &str) -> Option<u32> {
    let output = std::process::Command::new("ip")
        .args(["link", "show", interface])
        .output()
        .ok()?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    // 更精确的MTU提取逻辑
    output_str
        .lines() // 按行处理
        .next()? // 只处理第一行
        .split_whitespace()
        .find(|word| *word == "mtu") // 精确匹配"mtu"单词
        .and_then(|_| output_str.split("mtu").nth(1)) // 获取mtu后面的部分
        .and_then(|s| s.split_whitespace().next()) // 取第一个单词(MTU值)
        .and_then(|mtu| mtu.parse::<u32>().ok()) // 解析为数字
}
