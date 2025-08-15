/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use clap::Parser;
use log::debug;

// 应用程序版本信息
pub const APP_VERSION: &str = "1.1.0";
pub const APP_RELDATE: &str = "2025-08-15";
pub const APP_NAME: &str = "utifenslave";

// 帮助信息
pub const HELP_MSG: &str = r#"
       To create a bond device, simply follow these three steps :
       - ensure that the required drivers are properly loaded :
         # modprobe bonding ; modprobe <3c59x|eepro100|pcnet32|tulip|...>
       - assign an IP address to the bond device :
         # ifconfig bond0 <addr> netmask <mask> broadcast <bcast>
       - attach all the interfaces you need to the bond device :
         # utifenslave [{-f|--force}] bond0 eth0 [eth1 [eth2]...]
         If bond0 didn't have a MAC address, it will take eth0's. Then, all
         interfaces attached AFTER this assignment will get the same MAC addr.
         (except for ALB/TLB modes)

       To set the bond device down and automatically release all the slaves :
         # ifconfig bond0 down

       To detach a dead interface without setting the bond device down :
         # utifenslave {-d|--detach} bond0 eth0 [eth1 [eth2]...]

       To change active slave :
         # utifenslave {-c|--change-active} bond0 eth0

       To show master interface info
         # utifenslave bond0

       To show all interfaces info
       # utifenslave {-a|--all-interfaces}

       To be more verbose
       # utifenslave {-v|--verbose} ...

       # utifenslave {-u|--usage}   Show usage
       # utifenslave {-V|--version} Show version
       # utifenslave {-h|--help}    This message

"#;

pub const USAGE_MSG: &str = r#"
Usage: utifenslave [-f] <master-if> <slave-if> [<slave-if>...]
       utifenslave -d   <master-if> <slave-if> [<slave-if>...]
       utifenslave -c   <master-if> <slave-if>
       utifenslave --help
"#;

#[derive(Debug, Parser)]
#[command(
    name = "utifenslave",
    author = "UnionTech Software Technology Co., Ltd.",
    version = concat!("from ", env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")),
    about = "Network interface bonding configuration tool",
    disable_help_flag = true,
    disable_version_flag = true
)]
#[derive(Default)]
pub struct IfenslaveConfig {
    /// Show all interfaces
    #[arg(short = 'a', long = "all-interfaces")]
    pub all_interfaces: bool,

    /// Change active slave interface
    #[arg(short = 'c', long = "change-active")]
    pub change_active: bool,

    /// Detach slave interface
    #[arg(short = 'd', long = "detach")]
    pub detach: bool,

    /// Force operation
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// Show detailed help
    #[arg(short = 'h', long = "help")]
    pub help: bool,

    /// Show usage
    #[arg(short = 'u', long = "usage")]
    pub usage: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Show version information
    #[arg(short = 'V', long = "version")]
    pub version: bool,

    /// Interface names
    #[arg(value_name = "INTERFACES")]
    pub interfaces: Vec<String>,
}

impl IfenslaveConfig {
    pub fn from_args() -> Self {
        Self::parse()
    }

    /// 获取主接口名称
    pub fn get_master_interface(&self) -> Option<&str> {
        self.interfaces.first().map(|s| s.as_str())
    }

    /// 获取从接口名称列表
    pub fn get_slave_interfaces(&self) -> &[String] {
        if self.interfaces.len() > 1 {
            &self.interfaces[1..]
        } else {
            &[]
        }
    }

    /// 检查是否只有主接口（显示信息模式）
    pub fn is_show_mode(&self) -> bool {
        self.interfaces.len() == 1 && !self.all_interfaces
    }
}

pub fn parse_command() -> IfenslaveConfig {
    let opt_args = IfenslaveConfig::from_args();
    debug!("opt_args: {:?}", opt_args);
    opt_args
}
