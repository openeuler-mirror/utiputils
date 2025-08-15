/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use lazy_static::lazy_static;
use log::warn;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

lazy_static! {
    pub static ref RUNNING: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
}

/// 初始化信号处理器
pub fn initialize_signal_handler() {
    let r = RUNNING.clone();
    ctrlc::set_handler(move || {
        warn!("Ctrl-C pressed! Shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");
}

/// 检查程序是否仍在运行
pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}
