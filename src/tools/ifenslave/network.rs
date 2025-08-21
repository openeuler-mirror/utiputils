/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use futures::{StreamExt, TryStreamExt};
use mac_address::MacAddress;
use rtnetlink::{
    new_connection,
    packet_route::{
        address::AddressAttribute,
        link::{LinkAttribute, LinkFlags, LinkMessage},
        AddressFamily,
    },
    Error, Handle,
};
use std::{fs, io, path::Path, str::FromStr};

pub struct NetworkInterface {
    handle: Handle,
    verbose: bool,
    abi_ver: i32,
    hwaddr_set: bool,
}

impl NetworkInterface {
    pub fn new(verbose: bool) -> io::Result<Self> {
        // Create a new rtnetlink connection
        let (connection, handle, _) = match new_connection() {
            Ok(conn) => conn,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to create network connection",
                ))
            }
        };

        // Process messages in the background
        tokio::spawn(connection);

        Ok(NetworkInterface {
            handle,
            verbose,
            abi_ver: get_bonding_abi_version().unwrap_or(0),
            hwaddr_set: false,
        })
    }

    // Getters for private fields
    pub fn verbose(&self) -> bool {
        self.verbose
    }

    pub fn abi_ver(&self) -> i32 {
        self.abi_ver
    }

    pub fn hwaddr_set(&self) -> bool {
        self.hwaddr_set
    }

    pub fn set_hwaddr_set(&mut self, value: bool) {
        self.hwaddr_set = value;
    }

    // Check if the interface exists and get its index
    pub async fn get_link_index(&self, name: &str) -> Result<u32, Error> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        if let Some(link) = links.try_next().await? {
            return Ok(link.header.index);
        }

        Err(Error::RequestFailed)
    }

    // Get interface information
    pub async fn get_link_info(&self, name: &str) -> Result<LinkMessage, Error> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        if let Some(link) = links.try_next().await? {
            return Ok(link);
        }

        Err(Error::RequestFailed)
    }

    // Get interface flags
    pub async fn get_interface_flags(&self, name: &str) -> Result<u32, Error> {
        let link = self.get_link_info(name).await?;
        Ok(link.header.flags.bits())
    }

    // Set interface flags
    pub async fn set_interface_flags(&self, name: &str, flags: u32) -> Result<(), Error> {
        let index = self.get_link_index(name).await?;

        let mut link_message = LinkMessage::default();
        link_message.header.index = index;
        link_message.header.flags = LinkFlags::from_bits_truncate(flags);
        link_message.header.change_mask = LinkFlags::from_bits_truncate(flags);

        self.handle.link().set(link_message).execute().await?;

        if self.verbose {
            println!("Interface '{}': Flags set to {:08X}.", name, flags);
        }

        Ok(())
    }

    // Get interface MAC address
    pub async fn get_interface_mac(&self, name: &str) -> Result<MacAddress, Error> {
        let link = self.get_link_info(name).await?;

        for nla in link.attributes.iter() {
            if let LinkAttribute::Address(addr) = nla {
                if addr.len() == 6 {
                    let mut address = [0u8; 6];
                    address.copy_from_slice(&addr[..6]);

                    if let Ok(mac) = MacAddress::from_str(&format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        address[0], address[1], address[2], address[3], address[4], address[5]
                    )) {
                        if self.verbose {
                            println!("Interface '{}': MAC address is {}", name, mac);
                        }
                        return Ok(mac);
                    }
                }
            }
        }

        Err(Error::InvalidAddress(vec![], vec![]))
    }

    // Set interface MAC address
    pub async fn set_interface_mac(&self, name: &str, mac: &MacAddress) -> Result<(), Error> {
        // Convert MacAddress to byte array
        let mac_bytes = mac.bytes().to_vec();

        let index = self.get_link_index(name).await?;
        let mut link_message = LinkMessage::default();
        link_message.header.index = index;
        link_message
            .attributes
            .push(LinkAttribute::Address(mac_bytes));

        self.handle.link().set(link_message).execute().await?;

        if self.verbose {
            println!("Interface '{}': MAC address set to {}", name, mac);
        }

        Ok(())
    }

    // Get interface MTU
    pub async fn get_interface_mtu(&self, name: &str) -> Result<u32, Error> {
        let link = self.get_link_info(name).await?;

        if let Some(mtu) = link.attributes.iter().find_map(|attr| {
            if let LinkAttribute::Mtu(mtu) = attr {
                Some(*mtu)
            } else {
                None
            }
        }) {
            if self.verbose {
                println!("Interface '{}': MTU is {}", name, mtu);
            }
            return Ok(mtu);
        }

        Err(Error::RequestFailed)
    }

    // Set interface MTU
    pub async fn set_interface_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        let index = self.get_link_index(name).await?;

        let mut link_message = LinkMessage::default();
        link_message.header.index = index;
        link_message.attributes.push(LinkAttribute::Mtu(mtu));

        self.handle.link().set(link_message).execute().await?;

        if self.verbose {
            println!("Interface '{}': MTU set to {}", name, mtu);
        }

        Ok(())
    }

    // Enable interface
    pub async fn set_interface_up(&self, name: &str) -> Result<(), Error> {
        let index = self.get_link_index(name).await?;

        let mut link_message = LinkMessage::default();
        link_message.header.index = index;
        link_message.header.flags |= LinkFlags::Up;
        link_message.header.change_mask |= LinkFlags::Up;

        self.handle.link().set(link_message).execute().await?;

        if self.verbose {
            println!("Interface '{}': Enabled", name);
        }

        Ok(())
    }

    // Disable interface
    pub async fn set_interface_down(&self, name: &str) -> Result<(), Error> {
        let index = self.get_link_index(name).await?;

        let mut link_message = LinkMessage::default();
        link_message.header.index = index;
        link_message.header.flags &= !LinkFlags::Up;
        link_message.header.change_mask |= LinkFlags::Up;

        self.handle.link().set(link_message).execute().await?;

        if self.verbose {
            println!("Interface '{}': Disabled", name);
        }

        Ok(())
    }

    // Clear interface IP address
    pub async fn clear_interface_address(&self, name: &str) -> Result<(), Error> {
        let index = self.get_link_index(name).await?;
        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();

        while let Some(addr) = addresses.try_next().await? {
            if addr.header.family == AddressFamily::Inet {
                self.handle.address().del(addr).execute().await?;
            }
        }

        if self.verbose {
            println!("Interface '{}': Address cleared", name);
        }

        Ok(())
    }

    // Copy IP configuration from master interface to slave interface
    pub async fn copy_address_config(&self, master: &str, slave: &str) -> Result<(), Error> {
        let master_index = self.get_link_index(master).await?;
        let slave_index = self.get_link_index(slave).await?;

        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(master_index)
            .execute();

        // Collect all addresses of the master interface
        let mut addr_configs = Vec::new();
        while let Some(_addr) = addresses.next().await {
            while let Some(addr) = addresses.try_next().await? {
                if addr.header.family == AddressFamily::Inet {
                    addr_configs.push(addr);
                }
            }
        }

        // Clear the addresses of the slave interface first
        self.clear_interface_address(slave).await?;

        // Apply the addresses of the master interface to the slave interface
        for addr in addr_configs {
            let mut address_message = addr.clone();
            address_message.header.index = slave_index;
            let address = addr
                .attributes
                .iter()
                .find_map(|attr| {
                    if let AddressAttribute::Address(addr) = attr {
                        Some(addr)
                    } else {
                        None
                    }
                })
                .unwrap();
            let prefix_len = addr.header.prefix_len;
            self.handle
                .address()
                .add(slave_index, *address, prefix_len)
                .execute()
                .await?;

            if self.verbose {
                if let Some(local) = addr.attributes.iter().find_map(|attr| {
                    if let AddressAttribute::Address(addr) = attr {
                        Some(addr)
                    } else {
                        None
                    }
                }) {
                    println!("Interface '{}': Set IP address to {}", slave, local);
                }
            }
        }

        Ok(())
    }

    // Check the MAC address status of the master interface
    pub async fn check_master_hwaddr(&mut self, master: &str) -> Result<(), Error> {
        let mac = self.get_interface_mac(master).await?;
        let zero_mac = MacAddress::from_str("00:00:00:00:00:00").unwrap();

        if mac != zero_mac {
            self.hwaddr_set = true;
        }

        Ok(())
    }

    // 显示所有接口或特定接口的信息
    pub async fn show_interfaces(&self, ifname: Option<&str>) -> Result<(), Error> {
        match ifname {
            Some(name) => {
                // 显示特定接口信息
                let link = self.get_link_info(name).await?;
                let ip_addr = self
                    .get_interface_ip(name)
                    .await
                    .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
                display_interface_with_ip(&link, &ip_addr, self.verbose);
            }
            None => {
                // 显示所有接口信息
                let mut links = self.handle.link().get().execute();

                while let Some(link) = links.try_next().await? {
                    let ifname = link
                        .attributes
                        .iter()
                        .find_map(|attr| {
                            if let LinkAttribute::IfName(name) = attr {
                                Some(name.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "unknown".to_string());

                    let ip_addr = self
                        .get_interface_ip(&ifname)
                        .await
                        .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
                    display_interface_with_ip(&link, &ip_addr, self.verbose);
                }
            }
        }

        Ok(())
    }

    // 获取接口IP地址
    pub async fn get_interface_ip(&self, name: &str) -> Result<std::net::Ipv4Addr, Error> {
        let link_index = self.get_link_index(name).await?;
        let mut addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(link_index)
            .execute();

        while let Some(addr) = addresses.try_next().await? {
            if addr.header.family == AddressFamily::Inet {
                if let Some(ip) = addr.attributes.iter().find_map(|attr| {
                    if let AddressAttribute::Address(std::net::IpAddr::V4(ipv4)) = attr {
                        Some(*ipv4)
                    } else {
                        None
                    }
                }) {
                    return Ok(ip);
                }
            }
        }

        // 如果没有找到IP地址，返回默认值
        Ok(std::net::Ipv4Addr::new(0, 0, 0, 0))
    }

    // 获取驱动信息
    pub async fn get_drv_info(&self, name: &str) -> Result<(), Error> {
        // 检查接口是否是bonding master接口
        let flags = self.get_interface_flags(name).await?;

        // 如果不是master接口，返回错误（模拟原生ifenslave的行为）
        if flags & libc::IFF_MASTER as u32 == 0 {
            return Err(Error::RequestFailed);
        }

        Ok(())
    }
}

// Display interface information in native ifenslave format
pub fn display_interface_with_ip(link: &LinkMessage, ip_addr: &std::net::Ipv4Addr, _verbose: bool) {
    let ifname = link
        .attributes
        .iter()
        .find_map(|attr| {
            if let LinkAttribute::IfName(name) = attr {
                Some(name.clone())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Display flags in native format (only lower 16 bits like original ifenslave)
    let flags_value: u32 = link.header.flags.bits();
    println!(
        "The result of SIOCGIFFLAGS on {} is {:x}.",
        ifname,
        flags_value & 0xFFFF
    );

    // Display IP address in native format (as hex bytes with sign extension like original)
    let octets = ip_addr.octets();
    // Simulate the sign extension behavior of original ifenslave
    let format_byte = |b: u8| -> String {
        if b > 127 {
            format!("ffffff{:02x}", b)
        } else {
            format!("{:02x}", b)
        }
    };
    println!(
        "The result of SIOCGIFADDR is {}.{}.{}.{}.",
        format_byte(octets[0]),
        format_byte(octets[1]),
        format_byte(octets[2]),
        format_byte(octets[3])
    );

    // Display MAC address in native format
    if let Some(address) = link.attributes.iter().find_map(|attr| {
        if let LinkAttribute::Address(addr) = attr {
            Some(addr)
        } else {
            None
        }
    }) {
        if address.len() >= 6 {
            // Get the hardware type - convert LinkLayerType to u16
            let hw_type: u16 = link.header.link_layer_type.into();
            println!(
                "The result of SIOCGIFHWADDR is type {}  {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}.",
                hw_type,
                address[0], address[1], address[2], address[3], address[4], address[5]
            );
        }
    }

    // Display metric (usually 0)
    println!("The result of SIOCGIFMETRIC is 0");

    // Display MTU in native format
    if let Some(mtu) = link.attributes.iter().find_map(|attr| {
        if let LinkAttribute::Mtu(mtu) = attr {
            Some(*mtu)
        } else {
            None
        }
    }) {
        println!("The result of SIOCGIFMTU is {}", mtu);
    }
}

// Get bonding ABI version
pub fn get_bonding_abi_version() -> Option<i32> {
    // Check if bonding module exists in /sys/class/net/bonding_masters
    if !Path::new("/sys/class/net/bonding_masters").exists() {
        return None;
    }

    // Check if bonding module is loaded
    match fs::read_to_string("/sys/module/bonding/parameters/abi_version") {
        Ok(version) => version.trim().parse::<i32>().ok(),
        Err(_) => {
            // If version cannot be read directly, try detecting it another way
            // Most modern kernels have a bonding module version of at least 2
            Some(2)
        }
    }
}
