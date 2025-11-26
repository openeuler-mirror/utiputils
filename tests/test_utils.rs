/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#![allow(dead_code)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::format_collect)]

use std::process::{Command, Output};
use std::str;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct TestCommand {
    pub command: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

impl TestCommand {
    pub fn new_utping(args: &[&str]) -> Self {
        let mut full_args = vec!["./target/debug/utping".to_string()];
        full_args.extend(args.iter().map(|s| s.to_string()));

        Self {
            command: "sudo".to_string(),
            args: full_args,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn execute(&self) -> Result<TestOutput, String> {
        let output = Command::new(&self.command)
            .args(&self.args)
            .output()
            .map_err(|e| format!("Failed to execute command: {}", e))?;

        Ok(TestOutput::new(output))
    }
}

pub struct TestOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

impl TestOutput {
    fn new(output: Output) -> Self {
        Self {
            stdout: str::from_utf8(&output.stdout)
                .unwrap_or("Invalid UTF-8 in stdout")
                .to_string(),
            stderr: str::from_utf8(&output.stderr)
                .unwrap_or("Invalid UTF-8 in stderr")
                .to_string(),
            success: output.status.success(),
        }
    }

    pub fn assert_contains(&self, text: &str) -> &Self {
        assert!(
            self.stdout.contains(text) || self.stderr.contains(text),
            "Output does not contain '{}'\nSTDOUT:\n{}\nSTDERR:\n{}",
            text,
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn assert_stdout_contains(&self, text: &str) -> &Self {
        assert!(
            self.stdout.contains(text),
            "STDOUT does not contain '{}'\nSTDOUT:\n{}",
            text,
            self.stdout
        );
        self
    }

    pub fn assert_not_contains(&self, text: &str) -> &Self {
        assert!(
            !self.stdout.contains(text) && !self.stderr.contains(text),
            "Output should not contain '{}'\nSTDOUT:\n{}\nSTDERR:\n{}",
            text,
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn assert_stdout_not_contains(&self, text: &str) -> &Self {
        assert!(
            !self.stdout.contains(text),
            "STDOUT should not contain '{}'\nSTDOUT:\n{}",
            text,
            self.stdout
        );
        self
    }

    pub fn find_position(&self, text: &str) -> Option<usize> {
        self.stdout.find(text)
    }

    pub fn assert_order(&self, first: &str, second: &str) -> &Self {
        let first_pos = self
            .find_position(first)
            .unwrap_or_else(|| panic!("First text '{}' not found in output", first));
        let second_pos = self
            .find_position(second)
            .unwrap_or_else(|| panic!("Second text '{}' not found in output", second));

        assert!(
            first_pos < second_pos,
            "'{}' should appear before '{}' in output\nSTDOUT:\n{}",
            first,
            second,
            self.stdout
        );
        self
    }

    pub fn get_lines(&self) -> Vec<&str> {
        self.stdout.lines().collect()
    }

    pub fn find_line_containing(&self, text: &str) -> Option<&str> {
        self.get_lines()
            .into_iter()
            .find(|line| line.contains(text))
    }
}

// 确保 utping 已编译的辅助函数
pub fn ensure_utping_compiled() -> Result<(), String> {
    let output = Command::new("cargo")
        .args(["build", "--bin", "utping"])
        .output()
        .map_err(|e| format!("Failed to run cargo build: {}", e))?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("Unknown error");
        return Err(format!("Failed to compile utping: {}", stderr));
    }

    Ok(())
}

// 检查是否有 sudo 权限
pub fn check_sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

// 网络包捕获和分析工具
pub struct PacketCapture {
    pub interface: String,
    pub host: String,
    pub capture_count: u32,
}

impl PacketCapture {
    pub fn new(host: &str) -> Self {
        Self {
            interface: "any".to_string(),
            host: host.to_string(),
            capture_count: 2,
        }
    }

    pub fn with_count(mut self, count: u32) -> Self {
        self.capture_count = count;
        self
    }

    /// 开始捕获包，返回一个后台任务句柄和结果接收器
    pub fn start_capture(&self) -> Result<Arc<Mutex<Option<String>>>, String> {
        let result = Arc::new(Mutex::new(None));
        let result_clone = Arc::clone(&result);

        let interface = self.interface.clone();
        let host = self.host.clone();
        let count = self.capture_count;

        // 在后台运行tcpdump，等待一点时间确保之前的tcpdump完全停止
        thread::sleep(Duration::from_millis(100));

        thread::spawn(move || {
            let output = Command::new("sudo")
                .args(&[
                    "timeout",
                    "15s",
                    "tcpdump",
                    "-i",
                    &interface,
                    "-X",
                    "-c",
                    &count.to_string(),
                    &format!("icmp and host {}", host),
                ])
                .output();

            match output {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let combined = format!("{}\n{}", stdout, stderr);
                    *result_clone.lock().unwrap() = Some(combined);
                }
                Err(e) => {
                    *result_clone.lock().unwrap() = Some(format!("Error: {}", e));
                }
            }
        });

        // 等待tcpdump启动
        thread::sleep(Duration::from_millis(500));
        Ok(result)
    }

    /// 等待捕获完成并返回结果
    pub fn wait_for_capture(
        &self,
        result: Arc<Mutex<Option<String>>>,
        timeout: Duration,
    ) -> Result<String, String> {
        let start_time = std::time::Instant::now();

        loop {
            {
                let guard = result.lock().unwrap();
                if let Some(ref capture_result) = *guard {
                    return Ok(capture_result.clone());
                }
            }

            if start_time.elapsed() > timeout {
                return Err("Capture timeout".to_string());
            }

            thread::sleep(Duration::from_millis(100));
        }
    }
}

/// 分析捕获的包数据，验证pattern是否存在
pub fn analyze_packet_payload(
    capture_output: &str,
    expected_pattern: &[u8],
) -> Result<bool, String> {
    let lines: Vec<&str> = capture_output.lines().collect();

    // 将预期pattern转换为十六进制字符串
    let expected_hex: String = expected_pattern
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // 分析每个包单独进行
    let mut current_packet_hex = String::new();
    let mut in_packet = false;

    for line in &lines {
        // 检测包的开始（时间戳行）
        if line.contains("ICMP echo request") || line.contains("ICMP echo reply") {
            // 如果之前有包数据，先分析它
            if !current_packet_hex.is_empty() {
                if analyze_single_packet(&current_packet_hex, &expected_hex)? {
                    return Ok(true);
                }
            }
            // 重置，准备分析新包
            current_packet_hex.clear();
            in_packet = true;
            continue;
        }

        // 收集当前包的十六进制数据
        if in_packet && line.trim().starts_with("0x") && line.contains(":") {
            if let Some(hex_part) = line.split(':').nth(1) {
                let hex_only = if let Some(pos) = hex_part.rfind("  ") {
                    &hex_part[..pos]
                } else {
                    hex_part
                };
                current_packet_hex.push_str(&hex_only.replace(" ", ""));
            }
        }

        // 如果遇到空行或tcpdump输出，表示包结束
        if line.trim().is_empty() || line.contains("tcpdump:") {
            if !current_packet_hex.is_empty() {
                if analyze_single_packet(&current_packet_hex, &expected_hex)? {
                    return Ok(true);
                }
                current_packet_hex.clear();
            }
            in_packet = false;
        }
    }

    // 分析最后一个包
    if !current_packet_hex.is_empty() {
        if analyze_single_packet(&current_packet_hex, &expected_hex)? {
            return Ok(true);
        }
    }

    Ok(false)
}

/// 分析单个包的payload
fn analyze_single_packet(packet_hex: &str, expected_hex: &str) -> Result<bool, String> {
    // ICMP payload从第56个字符开始（28字节 = IP头20字节 + ICMP头8字节）
    let icmp_payload_start = 56;

    if packet_hex.len() > icmp_payload_start {
        let actual_payload = &packet_hex[icmp_payload_start..];
        // 检查pattern是否重复出现
        Ok(actual_payload.contains(expected_hex))
    } else {
        Ok(false) // 包太短，跳过
    }
}

/// 验证捕获的包中包含默认的递增pattern
pub fn verify_default_payload(capture_output: &str) -> Result<bool, String> {
    let lines: Vec<&str> = capture_output.lines().collect();

    // 分析每个包单独进行
    let mut current_packet_hex = String::new();
    let mut in_packet = false;

    for line in &lines {
        // 检测包的开始（时间戳行）
        if line.contains("ICMP echo request") || line.contains("ICMP echo reply") {
            // 如果之前有包数据，先分析它
            if !current_packet_hex.is_empty() {
                let has_default = verify_single_packet_default(&current_packet_hex);
                println!(
                    "Checking packet payload: {}",
                    &current_packet_hex[56.min(current_packet_hex.len())..]
                );
                if has_default {
                    return Ok(true);
                }
            }
            // 重置，准备分析新包
            current_packet_hex.clear();
            in_packet = true;
            continue;
        }

        // 收集当前包的十六进制数据
        if in_packet && line.trim().starts_with("0x") && line.contains(":") {
            if let Some(hex_part) = line.split(':').nth(1) {
                let hex_only = if let Some(pos) = hex_part.rfind("  ") {
                    &hex_part[..pos]
                } else {
                    hex_part
                };
                current_packet_hex.push_str(&hex_only.replace(" ", ""));
            }
        }

        // 如果遇到空行或tcpdump输出，表示包结束
        if line.trim().is_empty() || line.contains("tcpdump:") {
            if !current_packet_hex.is_empty() {
                let has_default = verify_single_packet_default(&current_packet_hex);
                println!(
                    "Checking packet payload: {}",
                    &current_packet_hex[56.min(current_packet_hex.len())..]
                );
                if has_default {
                    return Ok(true);
                }
                current_packet_hex.clear();
            }
            in_packet = false;
        }
    }

    // 分析最后一个包
    if !current_packet_hex.is_empty() {
        let has_default = verify_single_packet_default(&current_packet_hex);
        println!(
            "Checking final packet payload: {}",
            &current_packet_hex[56.min(current_packet_hex.len())..]
        );
        if has_default {
            return Ok(true);
        }
    }

    Ok(false)
}

/// 验证单个包是否包含默认递增payload
fn verify_single_packet_default(packet_hex: &str) -> bool {
    // ICMP payload从第56个字符开始
    let icmp_payload_start = 56;

    if packet_hex.len() > icmp_payload_start {
        let actual_payload = &packet_hex[icmp_payload_start..];
        // 查找默认递增pattern: 10111213141516171819...
        // 不能包含重复的自定义pattern（如abcd、1234等）
        let has_default = actual_payload.contains("101112131415161718191a1b")
            || actual_payload.contains("1011121314151617");
        let has_repeating_pattern =
            actual_payload.contains("abcdabcd") || actual_payload.contains("1234123");

        println!(
            "Default pattern check - has_default: {}, has_repeating: {}",
            has_default, has_repeating_pattern
        );

        has_default && !has_repeating_pattern
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_builder() {
        let cmd = TestCommand::new_utping(&["-v", "127.0.0.1", "-c", "1"]);
        assert_eq!(cmd.command, "sudo");
        assert_eq!(
            cmd.args,
            vec!["./target/debug/utping", "-v", "127.0.0.1", "-c", "1"]
        );
    }

    #[test]
    fn test_output_assertions() {
        let output = TestOutput {
            stdout: "Hello world\nTest line".to_string(),
            stderr: String::new(),
            success: true,
        };

        output
            .assert_stdout_contains("Hello")
            .assert_stdout_contains("Test line")
            .assert_stdout_not_contains("Missing")
            .assert_order("Hello", "Test");
    }
}
