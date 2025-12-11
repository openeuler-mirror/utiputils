# utiputils - Rust网络工具包

这是一个用Rust重新实现的Linux网络工具包，包含ping、arping、clockdiff等工具。

#### 项目结构

- `src/bin/ping.rs` - ping命令实现
- `src/ping/` - ping功能核心模块
- `src/common/` - 共享的网络工具函数
- `tests/` - 集成测试

#### 构建

```bash
cargo build --release
```

#### 运行

```bash
# 基本ping命令
sudo ./target/release/utping 127.0.0.1

# 使用自定义pattern
sudo ./target/release/utping -p 1234 -c 3 127.0.0.1
```

#### 测试

运行测试套件：
```bash
cargo test
```

**注意**：部分测试需要：
- sudo权限（用于创建原始socket）
- tcpdump工具（用于网络包验证测试）

测试包括：
- **单元测试**：15个模块内部功能测试
- **集成测试**：41个完整功能测试，验证所有ping选项和行为
- **网络包验证**：1个深度验证测试，确保pattern正确写入ICMP包

#### 特性

- ✅ 完整的ping功能实现
- ✅ IPv4和IPv6支持
- ✅ 自定义pattern支持（包括奇数长度hex字符串）
- ✅ 与原生ping行为完全兼容
- ✅ 详细的错误处理和用户反馈
- ✅ 全面的测试覆盖（41个集成测试 + 1个网络包验证测试）

#### Pattern功能

utping支持与原生ping完全兼容的pattern功能：

```bash
# 标准偶数长度pattern
sudo ./target/release/utping -p abcd 127.0.0.1

# 奇数长度pattern（自动填充处理）
sudo ./target/release/utping -p 123 127.0.0.1   # 变为 1203
sudo ./target/release/utping -p a 127.0.0.1     # 变为 0a

# 单字节pattern
sudo ./target/release/utping -p ff 127.0.0.1
```

#### 代码架构

项目遵循以下设计原则：
- **第一性原理**：从最基础的网络协议开始构建
- **DRY原则**：避免代码重复
- **KISS原则**：保持简单直接
- **SOLID原则**：良好的模块分离和依赖管理
- **YAGNI原则**：不实现不需要的功能

#### 测试架构

- **单元测试**：在各模块内部进行基础功能验证
- **集成测试**：验证完整的命令行工具行为
- **网络包验证**：使用tcpdump验证实际网络包内容
- **并发安全**：网络测试使用全局锁确保串行执行

#### 参与贡献

1. Fork 本仓库
2. 新建 Feat_xxx 分支
3. 提交代码
4. 新建 Pull Request

#### 开源许可证

utiputils在 [GPL-2.0-or-later](LICENSE)下发布。