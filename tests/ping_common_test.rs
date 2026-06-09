/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#[cfg(test)]
mod tests {
    use socket2::{Domain, Socket, Type};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};
    use utiputils::ping::ping_common::*;
    use utiputils::ping::ping_types::*;

    #[test]
    fn test_icmp_echo_request_new() {
        let request = IcmpEchoRequest::new(1, 1234, 56);
        assert_eq!(request.sequence, 1);
        assert_eq!(request.identifier, 1234);
        assert_eq!(request.payload.len(), 56);
    }

    #[test]
    fn test_build_packet_ipv4() {
        let mut config = PingConfig::new_for_test();
        config.pattern = vec![0xAB, 0xCD];
        let request = IcmpEchoRequest::new(1, 1234, 8);
        let packet = request.build_packet(&config);
        assert_eq!(packet.len(), 16); // 8 header + 8 payload
    }

    #[test]
    fn test_build_packet_ipv6() {
        let mut config = PingConfig::new_for_test();
        config.pattern = vec![0xAB, 0xCD];
        let request = IcmpEchoRequest::new(1, 1234, 8);
        let packet = request.build_packet_v6(&config);
        assert_eq!(packet.len(), 16); // 8 header + 8 payload
    }

    #[test]
    #[ignore]
    fn test_set_socket_option() {
        let socket = Socket::new(Domain::IPV4, Type::RAW, None).unwrap();
        let result = set_socket_option(&socket, libc::IPPROTO_IP, libc::IP_TTL, 64);
        assert!(result.is_ok());
    }

    #[test]
    #[ignore]
    fn test_bind_to_interface_or_ip_ipv4() {
        let socket = match Socket::new(Domain::IPV4, Type::RAW, None) {
            Ok(s) => s,
            Err(e) if e.raw_os_error() == Some(libc::EPROTONOSUPPORT) => {
                // 如果协议不支持，跳过测试而不是失败
                return;
            }
            Err(e) => panic!("Failed to create socket: {}", e),
        };

        let result = bind_to_interface_or_ip(&socket, "127.0.0.1");
        assert!(result.is_ok());
        assert!(matches!(result.unwrap().0, IpAddr::V4(_)));
    }

    #[test]
    fn test_bind_to_interface_or_ip_ipv6() {
        let socket = match Socket::new(Domain::IPV6, Type::RAW, None) {
            Ok(s) => s,
            Err(e) if e.raw_os_error() == Some(libc::EPROTONOSUPPORT) => {
                return;
            }
            Err(e) => panic!("Failed to create socket: {}", e),
        };

        let result = bind_to_interface_or_ip(&socket, "::1");
        assert!(result.is_ok());
        assert!(matches!(result.unwrap().0, IpAddr::V6(_)));
    }

    #[test]
    fn test_timeout_or_count_exit_count() {
        let mut config = PingConfig::new_for_test();
        config.count = Some(5);
        let stats = PingStats {
            transmitted: 5,
            ..Default::default()
        };
        assert!(timeout_or_count_exit(&config, &stats));
    }

    #[test]
    fn test_timeout_or_count_exit_deadline() {
        let mut config = PingConfig::new_for_test();
        config.deadline = Duration::from_secs(1);
        config.starttime = Some(Instant::now());
        let stats = PingStats {
            transmitted: 0,
            ..Default::default()
        };
        // Need to mock elapsed time for this to work properly
        // This is just demonstrating the test structure
        assert!(!timeout_or_count_exit(&config, &stats));
    }

    #[test]
    fn test_print_title_with_interface() {
        let mut config = PingConfig::new_for_test();
        config.interface = "eth0".to_string();
        config.packet_size = 56;
        config.domain = "example.com".to_string();
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        print_titile(target, &config);
        // Can't easily test stdout, but this verifies it doesn't panic
    }

    #[test]
    fn test_print_response() {
        let mut config = PingConfig::new_for_test();
        config.packet_size = 56;
        config.ttl = 64;
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        print_response(&ip, 1, 12.345, 64, &config);
        // Can't easily test stdout, but this verifies it doesn't panic
    }

    #[test]
    #[ignore]
    fn test_set_record_route_option_ipv4() {
        let socket = Socket::new(Domain::IPV4, Type::RAW, None).unwrap();
        let result = set_record_route_option(&socket, false);
        assert!(result.is_ok());
    }

    #[test]
    #[ignore]
    fn test_set_record_route_option_ipv6() {
        let socket = Socket::new(Domain::IPV6, Type::RAW, None).unwrap();
        let result = set_record_route_option(&socket, true);
        assert!(result.is_err());
    }

    #[test]
    #[ignore]
    fn test_set_timestamp_option() {
        let socket = Socket::new(Domain::IPV4, Type::RAW, None).unwrap();
        let result = set_timestamp_option(&socket, "tsonly");
        assert!(result.is_ok());
    }
}
