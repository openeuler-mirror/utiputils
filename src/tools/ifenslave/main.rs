/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use log::{error, info};
use std::io;
use tokio::runtime::Runtime;

use super::config::{parse_command, IfenslaveConfig, HELP_MSG, USAGE_MSG};
use super::network::NetworkInterface;
use crate::common::logging::init_logger;

pub fn main() {
    // Initialize logger
    init_logger();

    let opt_args = parse_command();

    // Handle version information
    if opt_args.verbose || opt_args.version {
        println!("utifenslave:v1.0.0 (Mar 17, 2025)");
        println!("o Donald Becker (becker@cesdis.gsfc.nasa.gov).");
        println!("o Detach support added on 2000/10/02 by Willy Tarreau (willy at meta-x.org).");
        println!(
            "o 2.4 kernel support added on 2001/02/16 by Chad N. Tindel (ctindel at ieee dot org)."
        );
        println!("o Rust implementation by longqiang@uniontech.com (2025-06-12)");

        if opt_args.version {
            std::process::exit(0);
        }
    }

    // Handle usage information
    if opt_args.usage {
        println!("{}", USAGE_MSG);
        std::process::exit(0);
    }

    // Handle detailed help information
    if opt_args.help {
        println!("{}", USAGE_MSG);
        println!("{}", HELP_MSG);
        std::process::exit(0);
    }

    let result = main_run(&opt_args);
    if let Err(e) = result {
        error!("{}", e);
        println!("{}", e);
        std::process::exit(1);
    }
}

fn main_run(opt_args: &IfenslaveConfig) -> Result<(), io::Error> {
    // Runtime
    info!("create new runtime");
    let rt = Runtime::new().expect("Failed to create Tokio runtime");
    let _guard = rt.enter();

    info!("create new network interface");
    // Create network interface object
    let mut network = match NetworkInterface::new(opt_args.verbose) {
        Ok(net) => net,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to initialize network interface: {}", e),
            ))
        }
    };

    // Handle displaying all interfaces
    if opt_args.all_interfaces {
        info!("show all interfaces");
        if opt_args.interfaces.is_empty() {
            // Display all interface information
            return rt.block_on(async {
                match network.show_interfaces(None).await {
                    Ok(_) => Ok(()),
                    Err(e) => Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to display interface information: {:?}", e),
                    )),
                }
            });
        } else {
            // Display usage error
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Error: -a option does not accept interface arguments",
            ));
        }
    }

    // Handle case with no arguments
    if opt_args.interfaces.is_empty() {
        println!("{}", USAGE_MSG);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No interface specified",
        ));
    }

    // Get master interface name
    let master_ifname = opt_args.get_master_interface().unwrap();

    // Get ABI version of the master interface
    rt.block_on(async {
        if let Err(_e) = network.get_drv_info(master_ifname).await {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Master '{}': Error: handshake with driver failed. Aborting",
                    master_ifname
                ),
            ));
        }
        Ok(())
    })?;

    // Handle single master interface case (display interface information)
    if opt_args.is_show_mode() {
        return rt.block_on(async {
            match network.show_interfaces(Some(master_ifname)).await {
                Ok(_) => Ok(()),
                Err(e) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "Failed to display information for interface '{}': {:?}",
                        master_ifname, e
                    ),
                )),
            }
        });
    }

    // Check if the master interface is actually a master interface
    let master_is_master = rt.block_on(async {
        match network.get_interface_flags(master_ifname).await {
            Ok(flags) => flags & libc::IFF_MASTER as u32 != 0,
            Err(_) => false,
        }
    });

    if !master_is_master {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid operation: Specified interface '{}' is not a master interface",
                master_ifname
            ),
        ));
    }

    // Check if the master interface is enabled
    let master_is_up = rt.block_on(async {
        match network.get_interface_flags(master_ifname).await {
            Ok(flags) => flags & libc::IFF_UP as u32 != 0,
            Err(_) => false,
        }
    });

    if !master_is_up {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Invalid operation: Specified master interface '{}' is not enabled",
                master_ifname
            ),
        ));
    }

    // Get slave interface names
    let slave_ifnames = opt_args.get_slave_interfaces();

    // Handle changing active slave interface
    if opt_args.change_active {
        if slave_ifnames.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Error: Change active slave option only accepts one slave interface argument",
            ));
        }

        let slave_ifname = &slave_ifnames[0];
        info!("change active slave interface: {}", slave_ifname);
        return rt.block_on(async {
            match network.change_active(master_ifname, slave_ifname).await {
                Ok(_) => Ok(()),
                Err(e) => Err(io::Error::new(io::ErrorKind::Other,
                    format!("Master interface '{}', Slave interface '{}': Error: Failed to change active slave: {}", 
                        master_ifname, slave_ifname, e)))
            }
        });
    }

    // Handle batch operations (add or detach slave interfaces)
    let mut errors = false;

    for slave_ifname in slave_ifnames {
        if opt_args.detach {
            info!("detach slave interface: {}", slave_ifname);
            // Detach slave interface
            if let Err(e) =
                rt.block_on(async { network.release(master_ifname, slave_ifname).await })
            {
                eprintln!(
                    "Master interface '{}', Slave interface '{}': Error: Detach failed: {}",
                    master_ifname, slave_ifname, e
                );
                errors = true;
            }
        } else {
            info!("enslave slave interface: {}", slave_ifname);
            // Add slave interface
            if let Err(e) =
                rt.block_on(async { network.enslave(master_ifname, slave_ifname).await })
            {
                eprintln!(
                    "Master interface '{}', Slave interface '{}': Error: Add failed: {}",
                    master_ifname, slave_ifname, e
                );
                errors = true;
            }
        }
    }

    if errors {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Errors occurred while processing one or more interfaces",
        ));
    }

    Ok(())
}
