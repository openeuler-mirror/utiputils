/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// 重新导出公共功能，保持向后兼容性
// 这个模块将被逐步废弃，请直接使用 crate::common 下的具体模块

pub use crate::common::dns::{
    lookup_and_extend_ips, resolve_ipv4_addr as get_ipv4_addr, reverse_dns_lookup,
};
pub use crate::common::interface::{get_default_ip, get_interface_mtu};
pub use crate::common::logging::init_logger;
pub use crate::common::signal::{initialize_signal_handler, is_running, RUNNING};
