/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::vec;
pub use std::{
    cell::RefCell,
    collections::HashMap,
    ffi::CStr,
    fmt,
    io::{self, Write},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::raw::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ushort, c_void},
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use clap::{Parser, ValueEnum};
use nix::sys::socket::SockType;

const DEFDATALEN: usize = 64 - 8;
const MAXWAIT: u64 = 10;
const MININTERVAL: u64 = 10;
const MINUSERINTERVAL: u64 = 2;
const IDENTIFIER_MAX: u16 = 0xFFFF;
const MAX_DUP_CHK: usize = 0x10000;
const BITMAP_SHIFT: usize = if cfg!(target_pointer_width = "64") {
    6
} else {
    5
};

type Bitmap = u64;

pub fn parse_u32(s: &str) -> Result<u32, String> {
    if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex_str, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u32>().map_err(|e| e.to_string())
    }
}

pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    // 如果字符串长度为奇数，匹配原生ping的行为：
    // 在最后一个字符前面插入0
    let padded = if s.len() % 2 == 1 {
        if s.len() == 1 {
            // 单个字符：在前面补0
            format!("0{}", s)
        } else {
            // 多个字符：在最后一个字符前插入0
            let mut chars: Vec<char> = s.chars().collect();
            chars.insert(chars.len() - 1, '0');
            chars.into_iter().collect()
        }
    } else {
        s.to_string()
    };

    hex::decode(padded).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, ValueEnum)]
pub enum PmtuDisc {
    Do,
    Dont,
    Want,
}

impl PmtuDisc {
    pub fn as_str(&self) -> &'static str {
        match self {
            PmtuDisc::Do => "do",
            PmtuDisc::Dont => "dont",
            PmtuDisc::Want => "want",
        }
    }
}
