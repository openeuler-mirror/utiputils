/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use anyhow::Context;
use log::{debug, info};
use std::net::{IpAddr, Ipv4Addr};
use trust_dns_resolver::proto::rr::RData;
use trust_dns_resolver::{proto::rr::RecordType, Resolver};

/// DNS解析辅助函数
pub fn lookup_and_extend_ips(
    resolver: &Resolver,
    host: &str,
    record_type: RecordType,
    ips: &mut Vec<IpAddr>,
) -> Result<(), anyhow::Error> {
    let records = resolver
        .lookup(host, record_type)
        .context(format!("Failed to lookup {:?} address", record_type))?;

    ips.extend(records.iter().filter_map(|ip| match ip {
        RData::A(ipv4) => Some(IpAddr::V4(*ipv4)),
        RData::AAAA(ipv6) => Some(IpAddr::V6(*ipv6)),
        _ => None,
    }));
    Ok(())
}

/// 解析输入地址是否为IPv4地址，如果是域名则进行DNS解析
pub fn resolve_ipv4_addr(ipstring: &str) -> Result<(String, Vec<Ipv4Addr>), anyhow::Error> {
    match ipstring.parse::<IpAddr>() {
        Ok(ip) => {
            info!("Target is an IP address: {}", ip);
            if !ip.is_ipv4() {
                return Err(anyhow::anyhow!("Invalid IPv4 address: {}", ipstring));
            }

            if let IpAddr::V4(ipv4) = ip {
                Ok((ipv4.to_string(), vec![ipv4]))
            } else {
                unreachable!()
            }
        }
        Err(_) => {
            // 输入是域名，需要DNS解析
            info!("Target is a domain name: {}", ipstring);
            let resolver = Resolver::from_system_conf().context("Failed to create DNS resolver")?;

            // 查询CNAME
            let cname = resolver
                .lookup(ipstring, RecordType::CNAME)
                .ok()
                .and_then(|r| r.into_iter().next())
                .map(|c| c.to_string().trim_end_matches('.').to_string())
                .unwrap_or_else(|| ipstring.to_string());

            // 查询IP地址
            let mut ips: Vec<IpAddr> = Vec::new();
            lookup_and_extend_ips(&resolver, ipstring, RecordType::A, &mut ips)?;
            ips.dedup();

            if ips.is_empty() {
                return Err(anyhow::anyhow!("No IP addresses found for {}", ipstring));
            }

            let ipv4s: Vec<Ipv4Addr> = ips
                .into_iter()
                .filter_map(|ip| {
                    if let IpAddr::V4(ipv4) = ip {
                        Some(ipv4)
                    } else {
                        None
                    }
                })
                .collect();
            Ok((cname, ipv4s))
        }
    }
}

/// 反向DNS查询，支持IPv4和IPv6
pub fn reverse_dns_lookup(ip: &str) -> Result<String, anyhow::Error> {
    // 解析 IP 地址
    let ip_addr: IpAddr = ip
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid IP address"))?;

    // 根据IP类型构建对应的sockaddr结构
    let (sockaddr_ptr, sockaddr_len) = match ip_addr {
        IpAddr::V4(ipv4) => {
            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(ipv4).to_be(),
                },
                sin_zero: [0; 8],
            };
            (
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        IpAddr::V6(ipv6) => {
            let addr = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: ipv6.octets(),
                },
                sin6_scope_id: 0,
            };
            (
                &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };

    let host =
        match utiputils_sys::dns::getnameinfo_host(sockaddr_ptr, sockaddr_len, libc::NI_NAMEREQD) {
            Ok(host) => host,
            Err(code) => {
                debug!("getnameinfo failed: {}", code);
                return Ok(ip.to_string());
            }
        };
    debug!("reverse DNS lookup: {} -> {}", ip, host);
    Ok(host)
}
