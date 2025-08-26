/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use super::network::NetworkInterface;
use log::{debug, info};
use mac_address::MacAddress;
use std::{fs, io, str::FromStr};

impl NetworkInterface {
    // Change the active slave interface
    pub async fn change_active(&self, master: &str, slave: &str) -> Result<(), io::Error> {
        // Validate master and slave interfaces
        let _master_index = match self.get_link_index(master).await {
            Ok(index) => index,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Master interface '{}' not found", master),
                ))
            }
        };

        let _slave_index = match self.get_link_index(slave).await {
            Ok(index) => index,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Slave interface '{}' not found", slave),
                ))
            }
        };

        // Check if it is a master-slave relationship
        let slave_flags = match self.get_interface_flags(slave).await {
            Ok(flags) => flags,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to get flags of slave interface '{}'", slave),
                ))
            }
        };

        // Check if the slave interface is a slave device
        if slave_flags & libc::IFF_SLAVE as u32 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid operation: Specified slave interface '{}' is not a slave device",
                    slave
                ),
            ));
        }

        // Change the active slave interface using the sysfs interface
        let path = format!("/sys/class/net/{}/bonding/active_slave", master);
        let contents = format!("+{}", slave);
        debug!("path: {}, contents: {}", path, contents);
        fs::write(&path, slave)?;

        if self.verbose() {
            println!(
                "Master interface '{}': Active slave interface changed to '{}'",
                master, slave
            );
        }

        Ok(())
    }

    // Add a slave interface to the master interface
    pub async fn enslave(&mut self, master: &str, slave: &str) -> Result<(), io::Error> {
        info!("enslave master: {}, slave: {}", master, slave);

        // Check the status of the slave interface
        let slave_flags = match self.get_interface_flags(slave).await {
            Ok(flags) => flags,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Slave interface '{}' not found", slave),
                ))
            }
        };

        // Check if the slave interface is already a slave device
        if slave_flags & libc::IFF_SLAVE as u32 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid operation: Specified slave interface '{}' is already a slave device",
                    slave
                ),
            ));
        }

        // Disable the slave interface
        if (self.set_interface_down(slave).await).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Slave interface '{}': Failed to disable interface", slave),
            ));
        }

        // Handle IP configuration
        if self.abi_ver() < 2 {
            // Older bonding versions require IP configuration from the master interface
            if (self.copy_address_config(master, slave).await).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Slave interface '{}': Failed to set address", slave),
                ));
            }
        } else {
            // Newer bonding versions require clearing the IP address of the slave interface
            if (self.clear_interface_address(slave).await).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Slave interface '{}': Failed to clear address", slave),
                ));
            }
        }

        // Match MTU
        let master_mtu = match self.get_interface_mtu(master).await {
            Ok(mtu) => mtu,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Master interface '{}': Failed to get MTU", master),
                ))
            }
        };

        let slave_mtu = match self.get_interface_mtu(slave).await {
            Ok(mtu) => mtu,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Slave interface '{}': Failed to get MTU", slave),
                ))
            }
        };

        if master_mtu != slave_mtu && (self.set_interface_mtu(slave, master_mtu).await).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Slave interface '{}': Failed to set MTU", slave),
            ));
        }

        // Handle hardware address
        let master_mac = match self.get_interface_mac(master).await {
            Ok(mac) => mac,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Master interface '{}': Failed to get hardware address",
                        master
                    ),
                ))
            }
        };

        let slave_mac = match self.get_interface_mac(slave).await {
            Ok(mac) => mac,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Slave interface '{}': Failed to get hardware address",
                        slave
                    ),
                ))
            }
        };

        let zero_mac = MacAddress::from_str("00:00:00:00:00:00").unwrap();
        if master_mac != zero_mac {
            self.set_hwaddr_set(true);
        }

        if self.hwaddr_set() {
            // Master interface already has a hardware address
            if self.abi_ver() < 1 {
                // Older ABI requires the application to set the hardware address of the slave interface
                if (self.set_interface_mac(slave, &master_mac).await).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!(
                            "Slave interface '{}': Failed to set hardware address",
                            slave
                        ),
                    ));
                }

                // Older ABI requires re-enabling the slave interface
                if (self.set_interface_up(slave).await).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Slave interface '{}': Failed to enable interface", slave),
                    ));
                }
            }
            // Newer ABI handles hardware address and interface state in the driver
        } else {
            // Master interface does not have a hardware address, use the hardware address of the slave interface
            if self.abi_ver() < 1 {
                // Older ABI requires disabling the master interface first
                if (self.set_interface_down(master).await).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Master interface '{}': Failed to disable interface", master),
                    ));
                }
            }

            // Set the hardware address of the master interface
            if (self.set_interface_mac(master, &slave_mac).await).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Master interface '{}': Failed to set hardware address",
                        master
                    ),
                ));
            }

            if self.abi_ver() < 1 {
                // Older ABI requires re-enabling the master interface
                if (self.set_interface_up(master).await).is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Master interface '{}': Failed to enable interface", master),
                    ));
                }
            }

            self.set_hwaddr_set(true);
        }

        // Perform the actual bonding operation via sysfs
        let path = format!("/sys/class/net/{}/bonding/slaves", master);
        let contents = format!("+{}", slave);
        debug!("path: {}, contents: {}", path, contents);

        let result = fs::write(&path, contents);

        if result.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Master interface '{}': Failed to add slave interface '{}': {}",
                    master,
                    slave,
                    result.unwrap_err()
                ),
            ));
        }

        if self.verbose() {
            println!(
                "Master interface '{}': Successfully added slave interface '{}'",
                master, slave
            );
        }

        Ok(())
    }

    // Release the slave interface from the master interface
    pub async fn release(&self, master: &str, slave: &str) -> Result<(), io::Error> {
        // Check the status of the slave interface
        let slave_flags = match self.get_interface_flags(slave).await {
            Ok(flags) => flags,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Slave interface '{}' not found", slave),
                ))
            }
        };

        // Check if the slave interface is a slave device
        if slave_flags & libc::IFF_SLAVE as u32 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Invalid operation: Specified slave interface '{}' is not a slave device",
                    slave
                ),
            ));
        }

        // Release the slave interface via sysfs
        let path = format!("/sys/class/net/{}/bonding/slaves", master);
        let contents = format!("-{}", slave);
        debug!("path: {}, contents: {}", path, contents);
        let result = fs::write(&path, contents);

        if result.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Master interface '{}': Failed to release slave interface '{}': {}",
                    master,
                    slave,
                    result.unwrap_err()
                ),
            ));
        }

        // Older ABI requires disabling the slave interface
        if self.abi_ver() < 1 && (self.set_interface_down(slave).await).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Slave interface '{}': Failed to disable interface", slave),
            ));
        }

        // Set to default MTU
        if (self.set_interface_mtu(slave, 1500).await).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Slave interface '{}': Failed to set default MTU", slave),
            ));
        }

        if self.verbose() {
            println!(
                "Master interface '{}': Successfully released slave interface '{}'",
                master, slave
            );
        }

        Ok(())
    }
}
