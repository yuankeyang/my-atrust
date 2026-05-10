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
│   │   └── jwt.rs                 # JWT 验证（支持 HS256/RS256/ES256）
│   │
│   ├── spa.rs                     # SPA 单包授权验证
│   │
│   ├── policy.rs                  # 策略引擎
│   │
│   ├── error.rs                   # 统一错误类型
│   ├── types.rs                   # 共享类型定义
│   │
│   ├── crypto/                    # 密码学工具
│   │   ├── mod.rs
│   │   └── gm.rs                  # 国密模块（SM2/3/4 空实现）
│   │
│   └── telemetry/                 # 可观测性
│       ├── mod.rs
│       └── metrics.rs            # Prometheus metrics
│
├── tests/
│
└── fuzz/
    ├── Cargo.toml
    └── fuzz_targets/
```

---

## 3. trust-ctl — 控制面服务

```
trust-ctl/
├── Cargo.toml
├── build.rs
├── src/
│   ├── main.rs                    # 入口，axum server
│   ├── lib.rs                     # 库入口，导出 api 模块
│   ├── config.rs                  # 配置加载
│   ├── db.rs                      # 数据库模块
│   ├── grpc.rs                    # gRPC 服务
│   ├── service.rs                  # 业务逻辑层
│   │
│   └── api/                       # API 层（路由 + handler）
│       ├── mod.rs
│       └── v1/
│           ├── mod.rs
│           ├── handlers.rs        # 所有 handler
│           └── types.rs           # API 类型定义
│
└── tests/
```

---

## 4. trust-gw — 数据面网关

```
trust-gw/
├── Cargo.toml
├── src/
│   ├── main.rs                   # 入口
│   ├── spa.rs                    # SPA 模块（UDP 端口 8883）
│   ├── proxy.rs                  # 反向代理模块
│   ├── interceptor.rs            # 流量拦截模块
│   └── config.rs                 # 配置模块
│
└── tests/
```

---

## 5. client-desktop — Tauri 桌面端

```
client-desktop/
├── package.json
├── src/
│   └── main.ts                   # 前端入口（TypeScript/React）
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json           # Tauri v2 配置（唯一）
│   └── src/
│       └── main.rs               # Rust 入口
└── src/                          # 前端源码（与 src-tauri 平级）
    ├── App.tsx
    └── pages/
        └── Dashboard.tsx
```

> **注意**：`client-desktop/src/client/` 目录在初始阶段不存在，业务逻辑在 `trust-client/` crate 中。

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
│   │   ├── lib.rs               # 入口（当前为占位符）
│   │   └── bpf.rs               # bpf 模块声明
│   │
│   └── tests/
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
