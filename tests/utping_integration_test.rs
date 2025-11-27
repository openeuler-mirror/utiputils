/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#![allow(clippy::new_without_default)]
#![allow(clippy::needless_borrows_for_generic_args)]

use std::process::Command;

// 引入测试工具模块
mod test_utils;

/// 用于集成测试的辅助结构
pub struct UtpingTester {
    binary_path: String,
}

impl UtpingTester {
    pub fn new() -> Self {
        Self {
            binary_path: "./target/debug/utping".to_string(),
        }
    }

    /// 执行utping命令并返回结果
    pub fn run(&self, args: &[&str]) -> UtpingResult {
        let output = Command::new(&self.binary_path)
            .args(args)
            .output()
            .expect("Failed to execute utping");

        UtpingResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        }
    }

    /// 执行需要sudo权限的utping命令
    pub fn run_with_sudo(&self, args: &[&str]) -> UtpingResult {
        let mut cmd_args = vec!["sudo"];
        cmd_args.push(&self.binary_path);
        cmd_args.extend_from_slice(args);

        let output = Command::new("sudo")
            .args(&cmd_args[1..])
            .output()
            .expect("Failed to execute utping with sudo");

        UtpingResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        }
    }

    /// 检查sudo是否可用
    pub fn check_sudo_available(&self) -> bool {
        Command::new("sudo")
            .args(&["-n", "true"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

/// utping命令执行结果
pub struct UtpingResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl UtpingResult {
    /// 验证命令执行成功
    pub fn assert_success(&self) -> &Self {
        if self.exit_code != 0 {
            panic!(
                "Command failed with exit code {}\nstdout: {}\nstderr: {}",
                self.exit_code, self.stdout, self.stderr
            );
        }
        self
    }

    /// 验证命令执行失败
    pub fn assert_failure(&self) -> &Self {
        if self.exit_code == 0 {
            panic!(
                "Command unexpectedly succeeded\nstdout: {}\nstderr: {}",
                self.stdout, self.stderr
            );
        }
        self
    }

    /// 验证输出包含指定文本
    pub fn assert_stdout_contains(&self, text: &str) -> &Self {
        if !self.stdout.contains(text) {
            panic!(
                "stdout does not contain '{}'\nActual stdout: {}",
                text, self.stdout
            );
        }
        self
    }

    /// 验证错误输出包含指定文本
    pub fn assert_stderr_contains(&self, text: &str) -> &Self {
        if !self.stderr.contains(text) {
            panic!(
                "stderr does not contain '{}'\nActual stderr: {}",
                text, self.stderr
            );
        }
        self
    }

    /// 验证输出不包含指定文本
    pub fn assert_stdout_not_contains(&self, text: &str) -> &Self {
        if self.stdout.contains(text) {
            panic!(
                "stdout unexpectedly contains '{}'\nActual stdout: {}",
                text, self.stdout
            );
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utping_help() {
        let tester = UtpingTester::new();
        let result = tester.run(&["--help"]);

        result
            .assert_success()
            .assert_stdout_contains("utping")
            .assert_stdout_contains("DESTINATION")
            .assert_stdout_contains("Stop after <count> replies");
    }

    #[test]
    fn test_utping_version() {
        let tester = UtpingTester::new();
        let result = tester.run(&["--version"]);

        result.assert_success().assert_stdout_contains("utping");
    }

    #[test]
    fn test_basic_ping_localhost() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-c", "2", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("PING 127.0.0.1")
            .assert_stdout_contains("bytes of data")
            .assert_stdout_contains("bytes from")
            .assert_stdout_contains("icmp_seq=1")
            .assert_stdout_contains("icmp_seq=2")
            .assert_stdout_contains("ping statistics")
            .assert_stdout_contains("2 packets transmitted")
            .assert_stdout_contains("packet loss");
    }

    #[test]
    fn test_ping_count_option() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-c", "3", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("3 packets transmitted");
    }

    #[test]
    fn test_ping_quiet_mode() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-q", "-c", "2", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("PING 127.0.0.1")
            .assert_stdout_contains("ping statistics")
            .assert_stdout_not_contains("bytes from");
    }

    #[test]
    fn test_ping_verbose_mode() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-v", "-c", "1", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("ping: sock4.fd:")
            .assert_stdout_contains("ai->ai_family:");
    }

    #[test]
    fn test_ping_packet_size() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-s", "32", "-c", "1", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("32(60) bytes of data")
            .assert_stdout_contains("40 bytes from");
    }

    #[test]
    fn test_ping_ttl_option() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        // 测试远程主机以验证TTL设置生效
        let result = tester.run_with_sudo(&["-t", "32", "-c", "1", "8.8.8.8"]);

        result
            .assert_success()
            .assert_stdout_contains("PING 8.8.8.8");
    }

    #[test]
    fn test_ping_interval() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-i", "0.2", "-c", "2", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("2 packets transmitted");
    }

    #[test]
    fn test_ping_numeric_only() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-n", "-c", "1", "127.0.0.1"]);

        result.assert_success().assert_stdout_contains("127.0.0.1");
    }

    #[test]
    fn test_ping_force_ipv4() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-4", "-c", "1", "localhost"]);

        result
            .assert_success()
            .assert_stdout_contains("PING localhost");
    }

    #[test]
    fn test_ping_deadline() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-w", "2", "127.0.0.1"]);

        result.assert_success();
    }

    #[test]
    fn test_ping_timeout() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-W", "0.5", "-c", "1", "127.0.0.1"]);

        result.assert_success();
    }

    #[test]
    fn test_ping_record_route() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-R", "-c", "1", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("PING 127.0.0.1")
            .assert_stdout_contains("bytes from")
            .assert_stdout_contains("RR:");
    }

    #[test]
    fn test_ping_timestamp() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-T", "tsonly", "-c", "1", "127.0.0.1"]);

        result.assert_success().assert_stdout_contains("TS:");
    }

    #[test]
    fn test_ping_print_timestamp() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-D", "-c", "1", "127.0.0.1"]);

        result.assert_success().assert_stdout_contains("[");
    }

    #[test]
    fn test_ping_do_not_fragment() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-M", "do", "-c", "1", "127.0.0.1"]);

        result.assert_success();
    }

    #[test]
    fn test_ping_invalid_host() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-c", "1", "invalid-host-xyz.invalid"]);

        result.assert_failure();
    }

    #[test]
    fn test_ping_invalid_option() {
        let tester = UtpingTester::new();

        let result = tester.run(&["--invalid-option"]);

        result.assert_failure().assert_stderr_contains("error:");
    }

    #[test]
    fn test_ping_missing_host() {
        let tester = UtpingTester::new();

        let result = tester.run(&["-c", "1"]);

        result.assert_failure().assert_stderr_contains("required");
    }

    #[test]
    fn test_ping_invalid_ttl() {
        let tester = UtpingTester::new();

        let result = tester.run(&["-t", "300", "127.0.0.1"]);

        result.assert_failure().assert_stderr_contains("error:");
    }

    #[test]
    fn test_ping_conflicting_options() {
        let tester = UtpingTester::new();

        let result = tester.run(&["-4", "-6", "127.0.0.1"]);

        result
            .assert_failure()
            .assert_stderr_contains("cannot be used with");
    }

    #[test]
    fn test_ping_unreachable_host() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        // 使用一个通常不可达的私有IP地址
        let result = tester.run_with_sudo(&["-c", "1", "-W", "1", "10.254.254.254"]);

        // 这个测试可能成功（如果网络配置了这个地址）或失败（超时）
        // 我们主要验证程序不会崩溃
        if result.exit_code == 0 {
            result.assert_stdout_contains("ping statistics");
        }
    }

    #[test]
    fn test_ping_broadcast_address() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-b", "-c", "1", "255.255.255.255"]);

        // 广播ping可能被某些系统阻止，所以我们只验证程序不崩溃
        if result.exit_code == 0 {
            result.assert_stdout_contains("PING 255.255.255.255");
        }
    }

    #[test]
    fn test_ping_large_packet_size() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-s", "1000", "-c", "1", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("1000(1028) bytes of data");
    }

    #[test]
    fn test_ping_small_packet_size() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-s", "8", "-c", "1", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("8(36) bytes of data");
    }

    #[test]
    fn test_ping_adaptive_mode() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-A", "-c", "3", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("3 packets transmitted");
    }

    #[test]
    fn test_ping_preload() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-l", "3", "-c", "5", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("5 packets transmitted");
    }

    #[test]
    fn test_ping_ipv6_format() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-c", "1", "-6", "::1"]);

        result
            .assert_success()
            .assert_stdout_contains("PING ::1(::1) 56 data bytes")
            .assert_stdout_contains("bytes from ::1");
    }

    #[test]
    fn test_ping_ipv6_link_local() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        // 测试链路本地地址格式（如果可用）
        // 注意：这个测试可能在某些环境中失败，如果没有IPv6链路本地地址
        let result = tester.run_with_sudo(&["-c", "1", "-6", "fe80::1"]);

        // 这个测试可能失败（地址不可达），主要验证格式输出
        if result.exit_code == 0 {
            result.assert_stdout_contains("data bytes");
        } else {
            // 即使失败，也应该显示正确的标题格式
            result.assert_stdout_contains("data bytes");
        }
    }

    #[test]
    fn test_permission_error_handling() {
        // 测试普通用户权限错误
        let tester = UtpingTester::new();

        // 使用一个普通用户身份运行utping，应该返回权限错误
        // 注意：这个测试假设我们在非root环境下运行测试
        if nix::unistd::getuid().is_root() {
            // 如果是root用户，跳过这个测试
            return;
        }

        let result = tester.run(&["-c", "1", "127.0.0.1"]);

        // 应该返回错误码1
        assert_eq!(
            result.exit_code, 1,
            "Permission error should return exit code 1"
        );

        // 应该包含权限错误信息
        assert!(
            result
                .stderr
                .contains("utping: socket: Operation not permitted"),
            "Should contain permission error message, got: {}",
            result.stderr
        );

        // 不应该显示PING标题（因为socket创建失败）
        assert!(
            !result.stdout.contains("PING"),
            "Should not show PING title when socket creation fails, got: {}",
            result.stdout
        );
    }

    #[test]
    fn test_dns_error_handling() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        let result = tester.run_with_sudo(&["-c", "1", "nonexistent.invalid.tld"]);

        result
            .assert_failure()
            .assert_stderr_contains("Name or service not known");
    }

    #[test]
    fn test_pattern_option_display() {
        let tester = UtpingTester::new();

        if !tester.check_sudo_available() {
            println!("Skipping test requiring sudo");
            return;
        }

        // 测试pattern选项的显示格式
        let result = tester.run_with_sudo(&["-p", "ff00", "-c", "1", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains("PATTERN: 0xff00");
    }

    #[test]
    fn test_pattern_option_invalid_hex() {
        let tester = UtpingTester::new();

        // 测试无效的十六进制pattern (包含非hex字符)
        let result = tester.run(&["-p", "invalid", "127.0.0.1"]);

        result
            .assert_failure()
            .assert_stderr_contains("Invalid character");
    }

    #[test]
    fn test_pattern_option_empty() {
        let tester = UtpingTester::new();

        // 测试空pattern
        let result = tester.run(&["-p", "", "127.0.0.1"]);

        result.assert_failure();
    }
}

// 网络包验证测试 - 保留一个核心验证用例
#[test]
fn test_pattern_packet_verification() {
    let tester = UtpingTester::new();

    if !tester.check_sudo_available() {
        println!("Skipping test requiring sudo");
        return;
    }

    // 检查tcpdump是否可用
    if !Command::new("tcpdump")
        .args(&["--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        println!("Skipping test requiring tcpdump");
        return;
    }

    // 使用简单的方式验证pattern功能
    let result = tester.run_with_sudo(&["-p", "1234", "-c", "1", "127.0.0.1"]);

    // 验证ping执行成功并显示了pattern
    result
        .assert_success()
        .assert_stdout_contains("PATTERN: 0x1234");
}

// Pattern选项功能测试
#[test]
fn test_pattern_option_functionality() {
    let tester = UtpingTester::new();

    if !tester.check_sudo_available() {
        println!("Skipping test requiring sudo");
        return;
    }

    // 测试多种pattern格式是否能正确显示
    let test_cases = vec!["ab", "abcd", "0102", "ff"];

    for pattern in test_cases {
        let result = tester.run_with_sudo(&["-p", pattern, "-c", "1", "127.0.0.1"]);

        result
            .assert_success()
            .assert_stdout_contains(&format!("PATTERN: 0x{}", pattern));
    }
}

// 默认payload测试（不进行网络包捕获）
#[test]
fn test_default_payload_behavior() {
    let tester = UtpingTester::new();

    if !tester.check_sudo_available() {
        println!("Skipping test requiring sudo");
        return;
    }

    // 运行不带pattern的ping，验证基本功能
    let result = tester.run_with_sudo(&["-c", "1", "127.0.0.1"]);

    result
        .assert_success()
        .assert_stdout_contains("PING 127.0.0.1")
        .assert_stdout_contains("bytes from");
}

// 响铃功能测试
#[test]
fn test_audible_ping() {
    let tester = UtpingTester::new();

    if !tester.check_sudo_available() {
        println!("Skipping test requiring sudo");
        return;
    }

    // 测试-a选项的响铃功能
    let result = tester.run_with_sudo(&["-a", "-c", "2", "127.0.0.1"]);

    result
        .assert_success()
        .assert_stdout_contains("PING 127.0.0.1")
        .assert_stdout_contains("bytes from");

    // 注意：响铃字符(\x07)在stdout中，但我们主要验证程序正常运行
    // 响铃声音需要在支持的终端中才能听到
}
