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

fn main(opt_args: &IfenslaveConfig) -> Result<(), io::Error> {
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

    Ok(())
}
