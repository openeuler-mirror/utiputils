mod test_utils;

use std::time::Duration;
use test_utils::{ensure_utping_compiled, TestCommand};

#[test]
fn test_verbose_ipv4_socket_info() {
    ensure_utping_compiled().expect("Failed to compile utping");

    let output = TestCommand::new_utping(&["-v", "127.0.0.1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    output
        .assert_stdout_contains("ping: sock4.fd:")
        .assert_stdout_contains("socktype: SOCK_RAW")
        .assert_stdout_contains("hints.ai_family: AF_UNSPEC")
        .assert_stdout_contains("ai->ai_family: AF_INET")
        .assert_stdout_contains("ai->ai_canonname: '127.0.0.1'")
        .assert_stdout_contains("ident=");
}

#[test]
fn test_verbose_ipv6_socket_info() {
    ensure_utping_compiled().expect("Failed to compile utping");

    let output = TestCommand::new_utping(&["-v", "::1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    output
        .assert_stdout_contains("ping: sock4.fd:")
        .assert_stdout_contains("sock6.fd:")
        .assert_stdout_contains("ai->ai_family: AF_INET6")
        .assert_stdout_contains("ai->ai_canonname: '::1'")
        .assert_stdout_contains("ident=");
}

#[test]
fn test_verbose_vs_normal_mode() {
    ensure_utping_compiled().expect("Failed to compile utping");

    // 测试普通模式
    let normal_output = TestCommand::new_utping(&["127.0.0.1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping normal mode");

    // 测试 verbose 模式
    let verbose_output = TestCommand::new_utping(&["-v", "127.0.0.1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping verbose mode");

    // 普通模式不应该包含 socket 信息
    normal_output
        .assert_stdout_not_contains("sock4.fd:")
        .assert_stdout_not_contains("ai->ai_family:")
        .assert_stdout_not_contains("ident=");

    // Verbose 模式应该包含这些信息
    verbose_output
        .assert_stdout_contains("sock4.fd:")
        .assert_stdout_contains("ai->ai_family:")
        .assert_stdout_contains("ident=");

    // 两种模式都应该包含基本的 PING 信息
    normal_output
        .assert_stdout_contains("PING 127.0.0.1")
        .assert_stdout_contains("ping statistics");

    verbose_output
        .assert_stdout_contains("PING 127.0.0.1")
        .assert_stdout_contains("ping statistics");
}

#[test]
fn test_verbose_output_order() {
    ensure_utping_compiled().expect("Failed to compile utping");

    let output = TestCommand::new_utping(&["-v", "127.0.0.1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    // 验证输出顺序：Socket 信息 → DNS 信息 → PING 行
    output
        .assert_order("ping: sock4.fd:", "ai->ai_family:")
        .assert_order("ai->ai_family:", "PING 127.0.0.1");
}

#[test]
fn test_verbose_domain_resolution() {
    ensure_utping_compiled().expect("Failed to compile utping");

    let output = TestCommand::new_utping(&["-v", "localhost", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    output
        .assert_stdout_contains("ai->ai_family: AF_INET")
        .assert_stdout_contains("ai->ai_canonname: 'localhost'")
        .assert_stdout_contains("PING localhost");
}

#[test]
fn test_verbose_nodeinfo() {
    ensure_utping_compiled().expect("Failed to compile utping");

    let output = TestCommand::new_utping(&["-v", "-N", "name", "::1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping nodeinfo");

    output
        .assert_stdout_contains("ping: sock4.fd:")
        .assert_stdout_contains("sock6.fd:")
        .assert_stdout_contains("PING ::1(::1) 56 data bytes");
}

#[test]
fn test_verbose_canonical_names() {
    ensure_utping_compiled().expect("Failed to compile utping");

    // 测试 IPv4 canonical name
    let ipv4_output = TestCommand::new_utping(&["-v", "127.0.0.1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    ipv4_output.assert_stdout_contains("ai->ai_family: AF_INET, ai->ai_canonname: '127.0.0.1'");

    // 测试 IPv6 canonical name
    let ipv6_output = TestCommand::new_utping(&["-v", "::1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    ipv6_output.assert_stdout_contains("ai->ai_family: AF_INET6, ai->ai_canonname: '::1'");
}

#[test]
fn test_verbose_reply_format() {
    ensure_utping_compiled().expect("Failed to compile utping");

    let output = TestCommand::new_utping(&["-v", "127.0.0.1", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    // 查找回复行并验证格式
    let reply_line = output
        .find_line_containing("bytes from")
        .expect("Reply line not found");

    // 验证回复行包含所有必要的字段
    assert!(reply_line.contains("bytes from"));
    assert!(reply_line.contains("icmp_seq="));
    assert!(reply_line.contains("ident="));
    assert!(reply_line.contains("ttl="));
    assert!(reply_line.contains("time="));
}

#[test]
fn test_verbose_performance() {
    ensure_utping_compiled().expect("Failed to compile utping");

    // 测试 verbose 模式不会显著影响性能
    let start = std::time::Instant::now();
    let _output = TestCommand::new_utping(&["-v", "127.0.0.1", "-c", "3"])
        .execute()
        .expect("Failed to execute utping");
    let duration = start.elapsed();

    // Verbose 模式应该在合理时间内完成（5秒内）
    assert!(
        duration.as_secs() < 5,
        "Verbose mode took too long: {:?}",
        duration
    );
}

#[test]
fn test_verbose_error_handling() {
    ensure_utping_compiled().expect("Failed to compile utping");

    // 测试无效主机的 verbose 输出
    let output = TestCommand::new_utping(&["-v", "invalid.host.example", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    // 即使出错，也应该显示 socket 信息
    output.assert_stdout_contains("ping: sock4.fd:");
}

#[test]
fn test_verbose_ipv6_error_messages() {
    ensure_utping_compiled().expect("Failed to compile utping");

    // 测试IPv6不可达错误的verbose输出
    let output = TestCommand::new_utping(&["-v", "-6", "www.baidu.com", "-c", "1"])
        .execute()
        .expect("Failed to execute utping");

    // 应该显示socket信息
    output
        .assert_stdout_contains("ping: sock4.fd:")
        .assert_stdout_contains("sock6.fd:");

    // 如果IPv6不可达，应该显示错误信息和错误统计
    if output.stdout.contains("Destination unreachable") {
        output
            .assert_stdout_contains("From")
            .assert_stdout_contains("icmp_seq=")
            .assert_stdout_contains("Destination unreachable")
            .assert_stdout_contains("+1 errors");
    }
}

#[test]
fn test_ipv6_error_handling() {
    let output = TestCommand::new_utping(&["-6", "-v", "-c", "1", "www.baidu.com"])
        .with_timeout(Duration::from_secs(10))
        .execute()
        .expect("Failed to execute command");

    // Should contain verbose socket information
    output.assert_stdout_contains("sock4.fd:");
    output.assert_stdout_contains("sock6.fd:");

    // Should contain ping statistics with error count if IPv6 is not reachable
    output.assert_stdout_contains("ping statistics");
}

#[test]
fn test_ipv4_error_handling() {
    // 使用一个不存在的内网地址进行测试，这样不会依赖外部网络条件
    let output = TestCommand::new_utping(&["-4", "-v", "-c", "3", "-W", "1", "192.0.2.1"])
        .with_timeout(Duration::from_secs(15))
        .execute()
        .expect("Failed to execute command");

    // Should contain verbose socket information
    output.assert_stdout_contains("sock4.fd:");
    output.assert_stdout_contains("sock6.fd:");

    // Should contain DNS resolution info
    output.assert_stdout_contains("ai->ai_family: AF_INET");
    output.assert_stdout_contains("ai->ai_canonname: '192.0.2.1'");

    // Should contain ping line
    output.assert_stdout_contains("PING 192.0.2.1");

    // Should contain ping statistics
    output.assert_stdout_contains("ping statistics");

    // Should show packet loss since the address is unreachable
    output.assert_stdout_contains("packet loss");
}
