/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

pub use crate::common::dns::{
    lookup_and_extend_ips, resolve_ipv4_addr as get_ipv4_addr, reverse_dns_lookup,
};
pub use crate::common::interface::{get_default_ip, get_interface_mtu};
pub use crate::common::logging::init_logger;
pub use crate::common::signal::{initialize_signal_handler, is_running, RUNNING};
