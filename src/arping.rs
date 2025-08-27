/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use clap::Parser;

// ARP 包结构长度常量
const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;
const TOTAL_PACKET_LEN: usize = ETHERNET_HEADER_LEN + ARP_PACKET_LEN;

#[derive(Debug, Parser)]
#[command(
    name = "utarping",
     author = "UnionTech Software Technology Co., Ltd.",
    version = concat!("from ", env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")),
    about = "ARPing utility - send ARP REQUEST to a neighbor host"
)]
#[derive(Default)]
pub struct ArpingConfig {
    /// DNS name or IP address
    #[arg(value_name = "DESTINATION")]
    pub destination: String,

    /// Quit on first reply
    #[arg(short = 'f')]
    pub quit_on_first_reply: bool,

    /// Be quiet
    #[arg(short = 'q')]
    pub quiet: bool,

    /// Keep on broadcasting, do not unicast
    #[arg(short = 'b')]
    pub broadcast_only: bool,

    /// Duplicate address detection mode
    #[arg(short = 'D')]
    pub duplicate_address_detection: bool,

    /// Unsolicited ARP mode, update your neighbours
    #[arg(short = 'U')]
    pub unsolicited_arp: bool,

    /// ARP answer mode, update your neighbours
    #[arg(short = 'A', requires = "device")]
    pub arp_answer: bool,

    /// How many packets to send
    #[arg(short = 'c')]
    pub count: Option<u32>,

    /// Set interval between packets (default: 1 second)
    #[arg(short = 'i')]
    pub interval: Option<u32>,

    /// How long to wait for a reply
    #[arg(short = 'w')]
    pub timeout: Option<u32>,

    /// Which ethernet device to use
    #[arg(short = 'I')]
    pub device: Option<String>,

    /// Source IP address to use
    #[arg(short = 's')]
    pub source: Option<String>,
}
