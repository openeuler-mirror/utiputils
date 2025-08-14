/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use env_logger::Env;
use std::io::Write;

/// 初始化日志记录器
pub fn init_logger() {
    env_logger::Builder::from_env(Env::default().default_filter_or("off"))
        .format(|buf, record| {
            let level_style = buf.default_level_style(record.level());
            writeln!(
                buf,
                "[{} {}{}\x1b[0m {}:{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                level_style,
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .init();
}
