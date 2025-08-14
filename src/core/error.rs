/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::fmt;

/// 通用工具错误类型
#[derive(Debug)]
pub enum UtilError {
    /// 网络相关错误
    Network(String),
    /// DNS解析错误
    DnsResolution(String),
    /// 配置错误
    InvalidConfig(String),
    /// IO错误
    Io(std::io::Error),
    /// 其他错误
    Other(String),
}

impl fmt::Display for UtilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtilError::Network(msg) => write!(f, "Network error: {}", msg),
            UtilError::DnsResolution(msg) => write!(f, "DNS resolution failed: {}", msg),
            UtilError::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            UtilError::Io(err) => write!(f, "IO error: {}", err),
            UtilError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for UtilError {}

impl From<std::io::Error> for UtilError {
    fn from(err: std::io::Error) -> Self {
        UtilError::Io(err)
    }
}

impl From<anyhow::Error> for UtilError {
    fn from(err: anyhow::Error) -> Self {
        UtilError::Other(err.to_string())
    }
}

/// 通用结果类型
pub type UtilResult<T> = Result<T, UtilError>;
