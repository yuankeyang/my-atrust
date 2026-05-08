# ATrust-ZTNA 项目工程结构

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| 0.2.0-draft | 2026-04-30 | 修复结构性问题：workspace、Cargo依赖版本、CI命令、工具链配置 |

---

## 1. 顶层结构

```
atrusted/
├── SPEC.md                          # 产品设计规范（OpenSpec SDD 基准）
├── Cargo.toml                       # Workspace 根配置
├── rust-toolchain.toml              # 工具链版本（stable + nightly）
├── deny.toml                        # cargo-deny 许可证/漏洞规则
├── openapi.yaml                     # 控制面 REST API 契约
├── policy.proto                     # gRPC 策略同步协议
├── config.schema.json               # 配置 JSON Schema
├── config.example.json              # 配置示例（ajv 验证用）
├── PROJECT_STRUCTURE.md             # 本文档
├── SDD_WORKFLOW.md                  # SDD 流程定义
│
├── trust-core/                      # 核心共享库（Rust）
├── trust-ctl/                       # 控制面服务（Controller）
├── trust-gw/                        # 数据面服务（Gateway）
├── trust-client/                    # 客户端共享逻辑
├── client-desktop/                  # Tauri 桌面端（Windows/macOS/Linux）
├── client-mobile/                   # Flutter 移动端（iOS/Android）
│
├── eBPF/                           # eBPF 内核态程序（唯一源码）
│   ├── interceptor/
│   └── binding-gen/
│
├── .cargo/
│   └── config.toml                  # 跨平台编译 target 配置
│
├── scripts/                        # 构建/部署脚本
├── infra/                          # 基础设施即代码
│   ├── docker/
│   ├── kubernetes/
│   └── terraform/
│
├── .github/
│   └── workflows/
│       ├── pr-check.yml            # PR 检查流水线
│       ├── ci.yml                  # Main 分支 CI
│       ├── contract-drift.yml      # 运行时契约漂移检测
│       └── ebpf-test.yml           # eBPF 内核矩阵测试
│
└── tools/                          # 开发工具链
    ├── spectral-ruleset/            # 自定义 spectral 规则
    └── mock-server/                # 契约 Mock Server
```

---

## 2. trust-core — 核心共享库

> **设计原则**：无 GC、零成本抽象、所有平台共享同一份核心逻辑

```
trust-core/
├── Cargo.toml
├── src/
│   ├── lib.rs                      # 库入口，导出所有模块
│   │
│   ├── auth/                       # 认证模块
│   │   ├── mod.rs
│   │   ├── jwt.rs                  # JWT 签发/校验（使用 jsonwebtoken）
│   │   ├── oauth2.rs               # OAuth2 客户端实现
│   │   ├── totp.rs                # TOTP 验证码校验
│   │   └── gm/                     # 国密模块（SM2/3/4）
│   │       ├── mod.rs
│   │       ├── sm2.rs
│   │       ├── sm3.rs
│   │       └── sm4.rs
│   │
│   ├── policy/                     # 策略引擎
│   │   ├── mod.rs
│   │   ├── engine.rs               # 策略评估引擎
│   │   ├── compiler.rs            # 策略编译（→ eBPF 字节码/JSON）
│   │   ├── cache.rs                # 策略缓存（dashmap + LRU）
│   │   └── types.rs                # 策略类型定义
│   │
│   ├── session/                    # 会话管理
│   │   ├── mod.rs
│   │   ├── manager.rs             # 会话生命周期管理
│   │   ├── heartbeat.rs           # 心跳处理
│   │   └── anomaly.rs             # 异常检测
│   │
│   ├── posture/                    # 设备可信评估
│   │   ├── mod.rs
│   │   ├── collector.rs           # posture 收集器抽象
│   │   ├── assessor.rs            # 风险评分计算
│   │   └── checks/                # 各类检查实现
│   │       ├── mod.rs
│   │       ├── antivirus.rs
│   │       ├── disk_encryption.rs
│   │       └── os_patch.rs
│   │
│   ├── interceptor/                # 流量拦截统一抽象
│   │   ├── mod.rs                 # TrafficInterceptor Trait
│   │   └── fallback.rs            # 纯用户态降级（跨平台）
│   │
│   └── platform/                   # 平台特定实现（独立子 crate）
│       ├── linux/                  # eBPF + iptables
│       ├── windows/                # WFP
│       └── macos/                  # NetworkExtension
│   │
│   ├── spa/                       # SPA 单包授权
│   │   ├── mod.rs
│   │   ├── server.rs              # SPA 网关端
│   │   └── client.rs              # SPA 客户端（TOTP 复用 auth/totp.rs）
│   │
│   ├── tunnel/                    # 隧道模块
│   │   ├── mod.rs
│   │   ├── wireguard.rs           # WireGuard 协议实现
│   │   └── socks5.rs             # SOCKS5 代理
│   │
│   ├── crypto/                    # 密码学工具
│   │   ├── mod.rs
│   │   ├── keys.rs                # 密钥管理（secrecy/zeroize）
│   │   └── cert.rs               # 证书操作（X509, PKCS12）
│   │
│   ├── observability/             # 可观测性
│   │   ├── mod.rs
│   │   ├── tracing.rs            # 结构化日志（tracing）
│   │   ├── metrics.rs           # Prometheus metrics
│   │   └── perf.rs               # perf event 上报
│   │
│   └── config/                   # 配置解析
│       ├── mod.rs
│       ├── loader.rs             # 配置文件加载
│       └── schema.rs             # JSON Schema 校验（使用 schemars）
│
├── proto/                         # 生成的 Protobuf 代码
│   └── policy.rs                  # 由 prost 自动生成
│
├── tests/
│   ├── auth_tests.rs
│   ├── policy_tests.rs
│   └── integration_tests.rs
│
└── fuzz/
    ├── Cargo.toml
    └── fuzz_targets/
        ├── policy_parse.rs        # 策略解析模糊测试
        └── spa_packet.rs          # SPA 包解析模糊测试
```

---

## 3. trust-ctl — 控制面服务

```
trust-ctl/
├── Cargo.toml
├── src/
│   ├── main.rs                    # 入口，axum server
│   ├── app.rs                     # 应用状态（Arc<AppState>）
│   │
│   ├── api/                       # API 层（路由 + handler）
│   │   ├── mod.rs
│   │   ├── v1/
│   │   │   ├── mod.rs
│   │   │   ├── auth.rs            # /auth/* 路由
│   │   │   ├── device.rs         # /devices/* 路由
│   │   │   ├── policy.rs         # /policies/* 路由
│   │   │   ├── session.rs        # /sessions/* 路由
│   │   │   └── admin.rs          # /admin/* 路由
│   │   │
│   │   ├── middleware/
│   │   │   ├── mod.rs
│   │   │   ├── auth.rs            # JWT 校验中间件
│   │   │   ├── ratelimit.rs      # 限流中间件
│   │   │   └── audit.rs          # 审计日志中间件
│   │   │
│   │   └── error.rs              # 统一错误处理（RFC 7807）
│   │
│   ├── service/                   # 业务逻辑层
│   │   ├── mod.rs
│   │   ├── auth_service.rs
│   │   ├── device_service.rs
│   │   ├── policy_service.rs
│   │   ├── session_service.rs
│   │   └── gateway_service.rs
│   │
│   ├── repository/               # 数据访问层
│   │   ├── mod.rs
│   │   ├── user_repo.rs
│   │   ├── device_repo.rs
│   │   ├── policy_repo.rs
│   │   ├── session_repo.rs
│   │   └── audit_repo.rs
│   │
│   ├── grpc/                     # gRPC 服务（策略同步）
│   │   ├── mod.rs
│   │   ├── server.rs             # gRPC Server
│   │   └── policy_sync.rs        # PolicySync 服务实现
│   │
│   └── db/                       # 数据库
│       ├── mod.rs
│       ├── schema.rs             # SQLx 查询定义
│       └── migrations/           # sqlx migrate 迁移
│           ├── 0001_init.sql
│           └── 0002_add_device.sql
│
└── tests/
    ├── api_contract_tests.rs     # 契约对齐测试
    └── service_tests.rs
```

---

## 4. trust-gw — 数据面网关

```
trust-gw/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── app.rs
│   │
│   ├── proxy/                    # 反向代理核心
│   │   ├── mod.rs
│   │   ├── server.rs             # HTTPS 服务器
│   │   ├── upstream.rs           # 上游连接池
│   │   ├── router.rs             # 路径路由
│   │   └── websocket.rs          # WebSocket 支持
│   │
│   ├── spa/                      # SPA 端口（UDP 8883）
│   │   ├── mod.rs
│   │   └── server.rs
│   │
│   ├── interceptor/              # 流量拦截（调用 trust-core）
│   │   ├── mod.rs
│   │   └── manager.rs            # 拦截器生命周期管理
│   │
│   ├── tunnel/                   # 隧道（SOCKS5 → 目标）
│   │   └── mod.rs
│   │
│   ├── policy/                   # 本地策略缓存与热更新
│   │   ├── mod.rs
│   │   └── updater.rs            # 从 Controller 接收策略
│   │
│   └── cli.rs                    # 命令行参数解析
│
├── ebpf/                        # eBPF 产物引用（调用顶层 eBPF/ 编译结果）
│   └── build.sh                  # CO-RE 编译脚本（调用顶层 aya-build）
│
└── tests/
    └── proxy_tests.rs
```

---

## 5. client-desktop — Tauri 桌面端

```
client-desktop/
├── src/
│   ├── main.rs                   # Tauri 入口
│   ├── lib.rs                    # Rust 逻辑导出（薄包装层）
│   │
│   ├── client/                   # trust-core Rust 客户端封装
│   │   ├── mod.rs
│   │   ├── connection.rs         # 连接管理
│   │   └── posture.rs            # 设备 posture 上报
│   │
│   └── ui/                      # 前端 UI（TypeScript/React）
│       ├── App.tsx
│       ├── pages/
│       │   ├── Login.tsx
│       │   ├── Dashboard.tsx
│       │   └── Settings.tsx
│       ├── components/
│       │   └── StatusIndicator.tsx
│       └── i18n/
│
├── package.json
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json           # Tauri v2 配置（唯一）
    └── src/
        └── main.rs
```

> **职责说明**：`client-desktop/src/client/` 仅做 Tauri IPC bridge 的薄包装，不含业务逻辑；业务逻辑在 `trust-client/` crate 中。

---

## 6. client-mobile — Flutter 移动端

```
client-mobile/
├── lib/
│   ├── main.dart
│   ├── core/                     # trust-core Dart FFI 封装
│   │   ├── bridge.dart
│   │   ├── connection.dart
│   │   └── posture.dart
│   │
│   ├── ui/
│   │   ├── app.dart
│   │   ├── pages/
│   │   │   ├── login_page.dart
│   │   │   ├── home_page.dart
│   │   │   └── settings_page.dart
│   │   └── widgets/
│   │       └── connection_status.dart
│   │
│   └── generated/                # OpenAPI Dart 客户端（自动生成）
│       └── api/
│
├── ios/
├── android/
└── pubspec.yaml
```

---

## 7. eBPF 内核态程序

```
eBPF/
├── interceptor/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs
│   │   ├── maps.rs              # LruHashMap / ProgramArray 定义
│   │   ├── cgroup_connect4.rs   # IPv4 连接拦截
│   │   ├── cgroup_connect6.rs   # IPv6 连接拦截
│   │   ├── redir.rs             # 重定向逻辑
│   │   └── logging.rs           # perf event 输出
│   │
│   ├── oteldaemon/               # 用户态 perf event 收集器
│   │   └── src/
│   │       └── main.rs
│   │
│   ├── tests/
│   │   └── integration_tests.rs
│   │
│   └── build.sh                  # aya-build 编译脚本
│
└── binding-gen/                  # C -> Rust BTF bindings 自动生成
    └── src/
        └── lib.rs
```

---

## 8. 依赖版本矩阵

| 组件 | 版本 | 说明 |
|------|------|------|
| Rust | 1.79+ | MSRV (aya 1.0+ 需要)；eBPF 编译用 nightly |
| tokio | 1.x | 异步运行时 |
| axum | 0.7.x | HTTP 框架 |
| sqlx | 0.8.x | 异步数据库 |
| utoipa | 4.x | OpenAPI 生成 |
| aya | 1.0+ | eBPF 框架（需要 nightly 工具链） |
| rustls | 0.22.x | TLS 实现 |
| jsonwebtoken | 9.x | JWT 处理 |
| dashmap | 5.x | 无锁并发 HashMap |
| secrecy | 0.8.x | 内存安全密钥 |
| opentelemetry | 0.22.x | Tracing 后端 |
| redis | 0.25.x | 黑名单/Nonce 缓存 |
| tauri | 2.x | 桌面客户端框架 |
| Flutter | 3.x | 移动端框架 |
| prost | 0.13.x | Protobuf |

> **工具链说明**：项目使用 `rust-toolchain.toml` 区分 stable（用于非 eBPF crate）和 nightly（仅 eBPF 编译）。

---

## 9. CI/CD 流水线

```
GitHub Actions
│
├── [PR] pr-check.yml
│   ├── spectral lint (openapi.yaml)
│   ├── openapi-diff (契约变更校验)
│   ├── protoc --lint (policy.proto)
│   ├── ajv-cli validate (config.schema.json)   # JSON Schema 校验
│   ├── cargo check --all-targets
│   └── cargo test --lib
│
├── [Main] ci.yml
│   ├── cargo build --release
│   ├── cargo test --all
│   ├── cargo audit (漏洞扫描)
│   ├── trivy image scan (容器镜像)
│   ├── cargo-fuzz -- -max_total_time=60 (60s smoke，完整 fuzz 在 nightly cron)
│   └── insta snapshots (策略快照)
│
├── [Contract] contract-drift.yml        # 运行时契约漂移检测
│   ├── Start trust-ctl
│   └── schemathesis run openapi.yaml --checks all
│
├── [eBPF] ebpf-test.yml
│   ├── QEMU 多内核测试 (5.10 / 5.15 / 6.1 / 6.6)
│   ├── bpftool prog load (Verifier 校验)
│   ├── perf test (内核功能测试)
│   └── fallback 测试 (kernel 4.19, no CAP_BPF)
│
└── [Release] release.yml
    ├── 构建各平台发布包
    ├── 生成 SBOM
    └── GitHub Release + CHANGELOG
```
