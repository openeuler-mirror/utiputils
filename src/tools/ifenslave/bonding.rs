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
