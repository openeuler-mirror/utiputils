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
