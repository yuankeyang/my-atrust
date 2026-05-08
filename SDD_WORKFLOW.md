# ATrust-ZTNA OpenSpec SDD 开发流程

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| 0.1.0-draft | 2026-04-30 | 初始草案 |
| 0.2.0-draft | 2026-04-30 | 修正工具链错误（utoipa/proc/proxy 替换）、补充契约漂移检测（Schemathesis）、修正 Spectral 语法、追加 RACI/Getting Started/安全门禁/版本降级策略 |

---

## 1. 概述

本文档定义 ATrust-ZTNA 产品的 **OpenSpec Specification-Driven Development (SDD)** 开发流程。所有代码实现必须以预定义的契约（OpenAPI / Protobuf / JSON Schema）为基准，契约变更优先于代码变更。

### 1.1 SDD 核心原则

| 原则 | 描述 |
|------|------|
| **契约先行 (Contract-First)** | 所有接口在代码实现前必须完成定义和评审 |
| **契约版本化 (Contract Versioning)** | 契约变更必须遵循语义化版本，破坏性变更需 Major 版本升级 |
| **契约漂移检测 (Drift Detection)** | CI 必须自动化检测实现与契约的偏离 |
| **安全内建 (Security by Design)** | 安全需求写入契约，而非事后补充 |
| **跨职能评审 (Cross-Functional Review)** | 契约评审需包含安全、运维、合规人员 |

---

## 2. SDD 阶段映射

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Phase 1   │    │   Phase 2   │    │   Phase 3   │    │   Phase 4   │    │   Phase 5   │
│   Spec      │───▶│   Contract  │───▶│   Skeleton  │───▶│   Impl      │───▶│   Release   │
│   Definition │    │   Generate  │    │   Code Gen  │    │   + Test    │    │   + Monitor │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

---

## 3. Phase 1 — 规范定义 (Spec Definition)

**目标**：产出完整的产品规范和接口契约定义文档。

### 3.1 交付物

| 交付物 | 文件 | 审批人 |
|--------|------|--------|
| 产品设计规范 | `SPEC.md` | 产品负责人 |
| OpenAPI 契约 | `openapi.yaml` | API Owner |
| gRPC 协议 | `policy.proto` | 后端负责人 |
| 配置 Schema | `config.schema.json` | 基础设施负责人 |

### 3.2 规范定义 Checklist

```
[ ] SPEC.md 包含：
    [ ] 产品概述与定位
    [ ] 系统架构图（控制面/数据面/客户端）
    [ ] 安全模型（STRIDE 威胁建模）
    [ ] 合规要求（等保2.0/国密/GDPR）
    [ ] 术语表与缩写定义

[ ] openapi.yaml 通过 spectral 校验：
    $ spectral lint openapi.yaml --fail-severity error
    (error 数量必须为 0，warning 不阻断)

[ ] policy.proto 通过 protoc 校验：
    $ cargo build -p trust-ctl  # build.rs 中自动调用 prost_build
    (禁止 proto 文件有编译错误)

[ ] config.schema.json 通过 JSON Schema 校验：
    $ npx ajv compile -s config.schema.json --spec=draft7
    (编译通过即 Schema 合法，不验证具体数据)
```

### 3.3 评审流程

1. **起草**：API Owner 编写契约初稿
2. **安全评审**：安全工程师审查认证/授权/加密相关字段
3. **跨团队评审**：前端/后端/运维/合规共同参与
4. **定格**：评审通过后，由 **API Owner** 打 `reviewed/v{version}` tag，锁定版本

**Tag 权限规则**：
- `reviewed/*` tag：仅 **API Owner** 有权限 push
- `v{version}` semver tag：仅 **Release Manager** 有权限 push
- Branch Protection：main 分支必须经过 2 人 code review

**锁定后发现问题的紧急变更流程**：
```
1. 创建 hotfix 分支 hotfix/{issue-id}
2. 修复契约文件
3. 必须经过：安全工程师 + API Owner 即时 review（< 2h）
4. 合并后打新的 reviewed tag
5. 同步更新 CHANGELOG 说明紧急修复原因
```

---

## 4. Phase 2 — 契约生成 (Contract Generation)

**目标**：从 Spec 生成类型定义、Mock Server、客户端骨架。

### 4.1 工具链（已修正）

> ⚠️ 以下为修正后的工具链。`utoipa` 是编译时 derive 库（非独立 binary），`protoc --rust_out` 已过时需用 `prost_build`，`openapi-typescript-codegen` 已归档改用 `@hey-api/openapi-ts`。

| 工具 | 用途 | 正确用法 |
|------|------|----------|
| `utoipa` | Rust OpenAPI derive（编译时） | `#[derive(ToSchema)]` + `#[utoipa::path]` 宏 |
| `oapi-codegen` / `openapi-generator` | OpenAPI → Rust 类型（反向生成） | `oapi-codegen --config openapi-codegen.yaml` |
| `@hey-api/openapi-ts` | TS 客户端生成（替代已归档的 openapi-typescript-codegen） | `npx @hey-api/openapi-ts -i openapi.yaml -o ./src/generated` |
| `protoc` + `prost` | Protobuf 代码生成 | 在 `build.rs` 中调用 `prost_build::compile_protos`（**不要**用 `protoc --rust_out`） |
| `schemars` | JSON Schema → Rust 类型 | 编译时 derive（`#[derive(JsonSchema)]`） |
| `prism` (Stoplight) | Mock Server | `npx @stoplight/prism-cli mock openapi.yaml` |
| `ajv-cli` | JSON Schema 校验 | `npx ajv validate -s config.schema.json -d test.json` |

**build.rs 正确写法**（protobuf）：
```rust
// trust-ctl/build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(
        &["proto/policy.proto"],
        &["proto/"],
    )?;
    println!("cargo:rerun-if-changed=proto/policy.proto");
    Ok(())
}
```

**cargo xtask codegen 正确实现**：
```rust
// tools/codegen/src/main.rs
use oapi_codegen::{self, Config};
fn main() {
    oapi_codegen::generate_from_file(
        "openapi.yaml",
        Config::default(),
        "trust-ctl/src/api/generated.rs",
    ).expect("codegen failed");
}
```

### 4.2 生成交付物

```bash
# 1. 生成 Rust 类型定义
cargo xtask codegen

# 2. 生成 TypeScript 客户端
npm run generate:api-client

# 3. 启动 Mock Server
npm run mock:server

# 4. 契约校验
make spec-lint
```

### 4.3 生成的目录结构

```
trust-ctl/src/api/v1/
├── types.rs              # 自动生成的请求/响应类型
├── auth.rs               # 认证接口 handler 桩
├── device.rs             # 设备接口 handler 桩
├── policy.rs             # 策略接口 handler 桩
└── session.rs            # 会话接口 handler 桩

client-desktop/src/generated/
├── api.ts               # TypeScript API 客户端
└── types.ts             # TypeScript 类型定义
```

### 4.4 Phase 2 Checklist

```
[ ] Rust API 类型从 openapi.yaml 100% 覆盖，无手写额外字段
[ ] TypeScript 客户端覆盖所有端点
[ ] Mock Server 启动成功，所有端点返回符合 Schema 的响应
[ ] 代码生成日志无 warning
[ ] 生成后的类型通过 cargo check + tsc --noEmit
```

---

## 5. Phase 3 — 骨架代码生成 (Skeleton Code Generation)

**目标**：生成完整的项目骨架，业务逻辑暂为空实现（stub）。

### 5.1 项目初始化

```bash
# 创建所有子项目
cargo new trust-core --lib
cargo new trust-ctl
cargo new trust-gw
cargo new client-desktop
cargo new client-mobile

# 初始化 Tauri
cd client-desktop && npm create tauri-app@latest

# 初始化 Flutter
flutter create client-mobile
```

### 5.2 骨架生成 Makefile

```makefile
# Makefile
.PHONY: spec-lint gen contract-test build test

spec-lint:  ## 契约校验（spectral + ajv + protoc）
	spectral lint openapi.yaml --fail-severity error
	npx ajv compile -s config.schema.json --spec=draft7
	cd trust-ctl && cargo build --features codegen

gen: spec-lint  ## 代码生成（Rust + TypeScript）
	cargo xtask codegen
	npm run generate:api-client

contract-test: gen  ## 契约对齐测试（Schemathesis）
	cd trust-ctl && cargo test --test contract_tests
	npx playwright test

build:  ## 全量构建
	cargo build --release --workspace
	npm run build --workspace

test:  ## 单元测试
	cargo test --workspace

# 注意：Fuzz 不在 PR CI 里运行，单独跑 nightly fuzz job（见 9.3）
```

### 5.3 Phase 3 Checklist

```
[ ] 所有模块编译通过（cargo check --all-targets）
[ ] 项目目录结构符合 PROJECT_STRUCTURE.md
[ ] Cargo workspace 配置正确
[ ] Git pre-commit 钩子已配置（spectral + cargo check）
[ ] CI 流水线文件已创建（.github/workflows/）
```

---

## 6. Phase 4 — 实现与测试 (Implementation + Test)

**目标**：在契约骨架内实现业务逻辑，通过契约测试。

### 6.1 TDD 流程

```
RED  ──────▶  GREEN  ──────▶  REFACTOR
 │              │               │
 ▼              ▼               ▼
写一个失败的   只写最小代码     清理代码，
契约测试       让测试通过      保持测试绿色
```

### 6.2 测试金字塔

```
              ┌─────────────────┐
              │   E2E Tests     │  ← 使用 mock 外围依赖
              │   (Playwright)  │
              └───────┬─────────┘
                      │
        ┌─────────────┴─────────────┐
        │    Contract Tests         │  ← 核心：验证实现严格匹配契约
        │  (reqwest + OpenAPI)      │
        └─────────────┬─────────────┘
                      │
        ┌─────────────┴─────────────┐
        │    Unit Tests             │  ← trust-core 各模块单元测试
        │   (cargo test)            │
        └─────────────┬─────────────┘
                      │
        ┌─────────────┴─────────────┐
        │    Fuzz Tests              │  ← cargo-fuzz 模糊测试
        │  (policy_parse / spa)      │
        └───────────────────────────┘
```

### 6.3 契约测试（测试真实实现，不是 Mock）

**原则**：契约测试必须对**真实运行的服务器**发请求，验证响应是否严格符合 Schema。对 Mock 的测试没有意义。

**推荐工具**：Schemathesis（基于 OpenAPI Schema 自动生成测试用例）

```bash
# 启动真实服务
cargo run --bin trust-ctl &
# 等待服务就绪
./scripts/wait-for-it.sh localhost:8080 --timeout=30

# 使用 Schemathesis 对所有端点进行属性测试
schemathesis run openapi.yaml \
  --url http://localhost:8080 \
  --checks all \
  --hypothesis-seed 12345 \
  --report-generate卫生 \
  --report-path test-results/
```

**手写契约测试（Rust）**：
```rust
// contract_tests.rs — 对真实服务器发请求，验证响应 Schema
#[tokio::test]
async fn test_auth_token_response_matches_schema() {
    // 启动本地服务（或指向 staging）
    let base_url = std::env::var("TEST_SERVER_URL")
        .unwrap_or_else(|_| "http://localhost:8080".into());

    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}/v1/auth/token", base_url))
        .json(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "test",
            "client_secret": "test-secret"
        }))
        .send()
        .await
        .expect("request failed");

    // 关键：对真实服务器响应做 JSON Schema 校验
    let body = response.json::<serde_json::Value>().await.unwrap();
    let validation_result = jsonschema::validator(
        &config.schema,  // 加载 openapi.yaml 中的 JSON Schema
        &body
    );
    assert!(validation_result.is_ok(), "响应不符合 Schema: {:?}", validation_result.err());
}
```

**Consumer-Driven Contract（可选）**：
- 使用 Pact 或 Pact Rust 定义 consumer 的期望
- Provider CI 验证 Pact 契约是否满足
- 适用于前后端分离团队

```rust
// pact.rs — Consumer 侧定义期望
#[tokio::test]
async fn auth_service_consumer_pact() {
    let pact = Pact::builder()
        .interaction("申请访问令牌", |i| {
            i.given("存在测试用户");
            i.request
                .method("POST")
                .path("/v1/auth/token")
                .body(json!({"grant_type": "password", "username": "test", "password": "test123"}));
            i.response
                .status(200)
                .header("Content-Type", "application/json")
                .body(json!({
                    "access_token": regex::regex(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
                    "token_type": "Bearer",
                    "expires_in": 900
                }));
        })
        .build();

    // 与 Mock 服务器验证
    let mock_server = MockServer::start(&pact);
    // ... 运行测试
}
```

### 6.4 安全测试

> ⚠️ Fuzz 不在 PR CI 里跑（2h 会导致流水线完全卡死），单独见 9.3 Nightly Fuzz Job。

```bash
# 内存安全 — PR CI 用快速 smoke fuzz（30s）
cargo +nightly fuzz run policy_parse_fuzzer -- -max_len=4096 --max_iterations=10000

# 深度模糊测试 — 仅在 nightly/weekly CI 跑
# 见 9.3 nightly-fuzz.yml

# 依赖漏洞扫描
cargo audit
trivy fs . --severity HIGH,CRITICAL
cargo deny check licenses && cargo deny check advisories

# 密钥扫描
trufflehog3 . --no-update || gitleaks detect --source .

# Clippy SAST（含 deny rules）
cargo clippy -- -D warnings \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::todo

# 加密强度基准
cargo run --bin crypto_bench

# 国密合规检查
gm_check config.yaml

# 容器镜像扫描
trivy image my-gateway:latest --severity HIGH,CRITICAL
```

### 6.5 Phase 4 Checklist

```
[ ] 所有 OpenAPI 端点有对应 handler 实现
[ ] 所有 Protobuf 服务有对应 gRPC 实现
[ ] 契约测试覆盖率 100%（每个端点至少一个契约测试）
[ ] cargo test --all 全部通过
[ ] cargo audit 无高危漏洞
[ ] 安全相关字段（JWT / TLS / MFA）有专项测试
[ ] 代码变更通过 code review
```

---

## 7. Phase 5 — 发布与监控 (Release + Monitor)

### 7.1 版本发布

```bash
# 1. 更新版本
# SPEC.md / Cargo.toml / package.json 统一版本号

# 2. 生成 CHANGELOG
git-changelog --from-tag v0.9.0 --to-tag v1.0.0

# 3. 构建发布包
make release

# 4. 生成 SBOM
cargo sbom --workspace --output sbom.json
trivy image -f CycloneDX -o bom.json

# 5. 发布
git tag v1.0.0
git push --tags
gh release create v1.0.0 --notes-file CHANGELOG.md
```

### 7.2 版本兼容矩阵（含降级策略）

**最低兼容版本（MVV — Minimum Version Policy）**：
- 客户端必须容忍控制面/网关**向上一个兼容版本**的响应
- 未知字段必须**宽容忽略**（forward compatibility）
- 灰度升级顺序：控制面 → 网关 → 客户端

| 客户端 \ 控制面 | 1.0.x | 1.1.x（新增字段） | 2.0.x（Breaking） |
|---------------|-------|-------------------|-------------------|
| **1.0.x** | ✅ 完全兼容 | ✅ 容忍新增字段 | ❌ 不兼容，需升级 |
| **1.1.x** | ✅ 向下兼容 | ✅ 完全兼容 | ❌ Breaking |
| **2.0.x** | ✅ 向下兼容 | ✅ 向下兼容 | ✅ 完全兼容 |

**策略格式版本兼容**：
- 策略格式升级时，Controller 同时下发**新旧两种格式**（Transition Window = 7d）
- Gateway 自行判断版本，支持热切换
- 窗口期后 Controller 下发新格式，旧格式自动淘汰

**强制升级触发条件**：
| 触发条件 | 动作 | 通知方式 |
|----------|------|----------|
| 发现关键安全漏洞（CVE） | 24h 内强制升级 | 邮件 + 客户端弹窗 |
| 证书 7 天内过期 | 引导续期 | 客户端站内信 |
| 控制面版本差异 > 1 Major | 禁止登录（安全策略收紧） | 全屏提示 |

**Hotfix 紧急变更流程**（绕过正常评审）：
```
1. 发起 hotfix PR，标题注明 [HOTFIX]
2. 安全工程师 + API Owner 即时 review（< 2h）
3. 合并后自动打 `hotfix/v{version}` tag
4. 触发紧急发布 pipeline（跳过 staging 直接上生产）
5. 事后补全完整评审记录和变更说明
```

### 7.3 监控与告警

```
指标采集 (Prometheus)
├── http_requests_total{endpoint, status}
├── policy_evaluation_duration_seconds
├── active_sessions_total
├── device_posture_score{device_id}
└── interceptor_action_total{action}

告警规则
├── SessionAnomalyAlert: 同一 token 多设备登录
├── PolicyDriftAlert: 实现与契约 Schema 不一致
├── InterceptorDownAlert: eBPF 程序加载失败
└── CertificateExpiryAlert: 证书30天内过期
```

---

## 8. 契约变更管理

### 8.1 变更分类

| 变更类型 | 定义 | 版本影响 |
|----------|------|----------|
| **破坏性变更 (Breaking)** | 删除字段、改变类型、改变语义 | Major +1 |
| **新增 (Additive)** | 新增字段/端点 | Minor +1 |
| **修复 (Fix)** | 修复 Schema 与实现不一致 | Patch +1 |
| **文档 (Docs)** | 仅注释/描述变更 | 无版本变更 |

### 8.2 变更评审流程

```
1. 发起人提交 PR 修改契约文件
2. CI 自动运行：
   - spectral lint（新契约）
   - openapi-diff（旧 vs 新，报告变更类型）
   - 破坏性变更检测
3. 通知相关团队评审
4. 若为破坏性变更：
   - 确认新旧版本兼容性窗口
   - 确认客户端/网关灰度升级策略
5. 合并后自动触发代码重新生成
```

### 8.3 openapi-diff 示例输出

```
$ openapi-diff old.yaml new.yaml

Breaking Changes:
  - DELETE /policies/{policy_id}/publish [Operation]
  - CHANGE property 'action' enum in /policies [Schema]
    Old: [ALLOW, DENY, BLOCK]
    New: [ALLOW, DENY, MFA_REQUIRED, BLOCK]

Compatible Changes:
  + ADD /devices/{device_id}/posture/policy [Operation]
  + ADD property 'risk_score' in DevicePostureReport [Schema]
```

---

## 9. CI/CD 流水线配置

### 9.1 pre-commit 钩子

> ⚠️ pre-commit 可被 `git commit --no-verify` 绕过，**不能**作为唯一质量门禁。必须在 CI 中重复所有检查。

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: spectral-lint
        name: spectral lint
        entry: spectral lint openapi.yaml --fail-severity error
        language: system
        files: openapi.yaml
        pass_filenames: false

      - id: proto-check
        name: protoc check
        entry: protoc --proto_path=. --cpp_out=. proto/*.proto
        language: system
        files: proto/
        pass_filenames: false

      - id: cargo-check
        name: cargo check
        entry: cargo check --all-targets
        language: system
        pass_filenames: false
```

### 9.2 GitHub Actions CI（PR + Main）

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  contract-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install tools
        run: |
          npm install -g @stoplight/spectral@latest
          npx ajv@latest compile -s config.schema.json --spec=draft7
          cargo install cargo-audit cargo-deny
      - name: Spectral lint
        run: spectral lint openapi.yaml --fail-severity error
      - name: JSON Schema compile check
        run: npx ajv compile -s config.schema.json --spec=draft7
      - name: cargo-deny (licenses + advisories)
        run: cargo deny check licenses && cargo deny check advisories
      - name: Audit
        run: cargo audit

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - name: Run unit tests
        run: cargo test --workspace
      - name: Clippy SAST (deny rules)
        run: cargo clippy -- -D warnings \
          -D clippy::unwrap_used \
          -D clippy::expect_used \
          -D clippy::todo
      - name: Build check
        run: cargo build --release --workspace

  contract-drift:
    runs-on: ubuntu-latest
    # ⚠️ 这是核心 SDD 漂移检测，对真实服务发请求验证 Schema 符合性
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - name: Build service
        run: cargo build --release --bin trust-ctl
      - name: Start service
        run: cargo run --bin trust-ctl &
          sleep 5  # 等待启动
      - name: Wait for service
        run: |
          for i in {1..30}; do
            curl -s http://localhost:8080/health && break
            sleep 1
          done
      - name: Schemathesis drift test
        run: |
          pip install schemathesis
          schemathesis run openapi.yaml \
            --url http://localhost:8080 \
            --checks all \
            --hypothesis-seed 12345 \
            --report-path test-results/ \
            || true  # 不阻断，只生成报告
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: schemathesis-report
          path: test-results/

  ebpf-test:
    runs-on: ubuntu-latest
    container:
      image: gravitir/aya-dev:latest
    steps:
      - uses: actions/checkout@v4
      - name: Build eBPF
        run: cargo ebpf build --release
      - name: Verify with bpftool
        run: bpftool prog load target/bpf/interceptor.bpf.o /sys/fs/bpf/test

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Secret scan (gitleaks)
        run: |
          docker run --rm -v $PWD:/repo zricethezav/gitleaks:latest detect \
            --source /repo --no-git --exit-code
      - name: Trivy FS scan
        run: trivy fs . --severity HIGH,CRITICAL --exit-code 1
```

### 9.3 Nightly Fuzz Job（独立运行，不在 PR CI）

```yaml
# .github/workflows/nightly-fuzz.yml
name: Nightly Fuzz

on:
  schedule:
    - cron: '0 2 * * *'  # 每天凌晨 2:00 UTC
  workflow_dispatch:  # 可手动触发

jobs:
  fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 240  # 4 小时超时
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
        with:
          components: rustfuzz
      - name: Run policy parser fuzz
        run: |
          cargo +nightly fuzz run policy_parse_fuzzer \
            -- -max_len=4096 2>&1 | tee fuzz_output.log
      - name: Run SPA packet fuzz
        run: |
          cargo +nightly fuzz run spa_packet_fuzzer \
            -- -max_len=256 2>&1 | tee spa_fuzz_output.log
      - name: Upload corpus
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-corpus
          path: |
            fuzz_output.log
            spa_fuzz_output.log
            cargo fuzzCorpus/
```

---

## 10. 质量门禁总结

> ⚠️ `spectral 0 warning` 会导致流水线频繁失败。正确做法：`--fail-severity error`（阻断 error，warn 记录）。

| 阶段 | 质量门禁 | 工具 | 阻断级别 |
|------|----------|------|----------|
| Spec 定义 | spectral lint 0 error | spectral | **Error** |
| 契约生成 | ajv compile 通过, protoc 通过 | ajv, protoc | **Error** |
| 骨架生成 | cargo check --all-targets 通过 | cargo | **Error** |
| 实现测试 | cargo test 100%, cargo audit 0 高危, clippy deny | cargo, cargo-audit, clippy | **Error** |
| 安全扫描 | trivy 0 HIGH/CRITICAL, gitleaks 0 secrets | trivy, gitleaks | **Error** |
| 发布 | SBOM 生成, CHANGELOG 更新 | cargo-sbom, git-changelog | **Warn** |

**渐进收紧策略**：
- Week 1-4：warn 级别不阻断，允许团队适应
- Week 5+：逐步将 warn 升级为 error
- 安全相关规则（secret 扫描、CVE）：立即设置为 error

---

## 附录 A：spectral 自定义规则集（已修正语法）

> ⚠️ 旧版本规则存在 YAML 语法错误，以下为修正后的正确版本。

```yaml
# .spectral.yaml
extends: [[spectral:oas, recommended]]

rules:
  # 强制安全响应标头（OAS 3.1 compatible）
  security-headers:
    message: "Responses should include security headers (HSTS, X-Content-Type-Options)"
    given: "$.paths..responses"
    severity: warn
    then:
      - if:
          field: headers
        then:
          object:
            properties:
              Strict-Transport-Security:
                type: string
              X-Content-Type-Options:
                type: string

  # 错误响应必须遵循 RFC 7807 Problem Details
  rfc-7807-error-format:
    message: "Error responses (4xx/5xx) must follow RFC 7807 Problem Details"
    given: "$.paths..responses[?(@.status >= 400)]"
    severity: error
    then:
      object:
        properties:
          type:
            type: string
          title:
            type: string
          status:
            type: integer
          detail:
            type: string

  # 端点必须包含 operationId（用于追踪和契约测试）
  operation-id-required:
    message: "Every operation must have an operationId"
    given: "$.paths.*.*"
    severity: error
    then:
      object:
        required: ["operationId"]

  # operationId 必须唯一
  operation-id-unique:
    message: "Every operationId must be unique across the API"
    given: "$.paths.*.*"
    severity: error
    then:
      function: unreferenced
      functionOptions:
        name: operationId
        schemaRoots:
          - "$.paths"

  # 路径参数必须在路径中声明
  path-parameters-declared:
    message: "Path parameters must be declared in the path"
    given: "$.paths[*]"
    severity: error
    then:
      object:
        properties:
          parameters:
            function: pathParametersDeclared

  # 所有认证端点必须标注 security
  security-requirement:
    message: "Protected endpoints must have security requirements"
    given: "$.paths.*.*"
    severity: warn
    then:
      - if:
          properties:
            security: false
          not: true
        then:
          object:
            required: ["security"]

  # description 不得为空（鼓励文档化）
  no-empty-description:
    message: "Operations must have a non-empty description"
    given: "$.paths.*.*"
    severity: warn
    then:
      object:
        properties:
          description:
            minLength: 10
```

**正确用法**：
```bash
# 安装
npm install -g @stoplight/spectral-cli

# 校验（--fail-severity error 仅阻断 error，warn 报告但不失败）
spectral lint openapi.yaml --fail-severity error

# 集成到 CI（只在 error 级别卡死）
spectral lint openapi.yaml --output JSON | \
  jq '[.[] | select(.severity == "error")]'
```

---

## 11. RACI 责任矩阵

**R = Responsible（负责）, A = Accountable（审批）, C = Consulted（咨询）, I = Informed（知会）**

| 阶段 | 产品负责人 | API Owner | 后端工程师 | 前端工程师 | 安全工程师 | 运维工程师 |
|------|-----------|-----------|-----------|-----------|-----------|-----------|
| **Phase 1 规范定义** | A | R | C | I | C | I |
| **Phase 2 契约生成** | I | A | R | C | C | I |
| **Phase 3 骨架生成** | I | A | R | R | I | I |
| **Phase 4 实现测试** | I | C | R | R | C | C |
| **Phase 5 发布监控** | C | C | R | I | A | R |
| **契约变更评审** | A | R | C | C | R | I |
| **安全热修复** | I | C | R | I | A | R |

**权限保护规则**：
- `reviewed` tag：**API Owner** 才能 push
- semver tag：**Release Manager** 才能 push
- Branch protection：main 分支必须经过 **2 人 review** 才能合并
- Hotfix：可绕过部分评审，但**安全工程师 + API Owner** 必须即时 review

---

## 12. Getting Started（本地开发快速启动）

### 12.1 环境准备（首次克隆）

```bash
# 1. 克隆代码
git clone https://github.com/your-org/atrusted.git
cd atrusted

# 2. 安装基础依赖
# Rust (via rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
cargo install cargo-audit cargo-deny cargo-tarpaulin

# Node.js (via nvm)
nvm install 20
npm install -g @stoplight/spectral-cli @hey-api/openapi-ts

# Python (for schemathesis)
pip install schemathesis

# Docker (for local infra)
docker compose up -d postgres redis
```

### 12.2 启动本地服务

```bash
# 启动依赖服务（Postgres + Redis）
docker compose up -d

# 启动 Controller（控制面）
cargo run --bin trust-ctl
# 服务监听 http://localhost:8080

# 启动 Mock Server（前端并行开发用）
npx @stoplight/prism-cli mock openapi.yaml -p 8081
# Mock 监听 http://localhost:8081
```

### 12.3 本地开发命令

```bash
# 契约校验
make spec-lint

# 生成代码
make gen

# 运行测试
make test

# 启动完整栈（所有组件）
docker compose -f docker-compose.dev.yml up -d

# 运行契约漂移测试（需先启动 trust-ctl）
make contract-drift

# 前端热重载开发
cd client-desktop && npm run tauri dev
```

### 12.4 新人 Checklist

```
[ ] 安装上述所有依赖
[ ] 启动 trust-ctl 并访问 http://localhost:8080/docs 查看 API 文档
[ ] 运行 make spec-lint 确认契约校验通过
[ ] 运行 cargo test --workspace 确认所有测试通过
[ ] 阅读 SPEC.md 理解产品架构
[ ] 阅读 trust-core/src/lib.rs 理解核心模块结构
[ ] 提交第一个 PR（即使是文档修复）
```

---

## 附录 B：OpenAPI 与零信任原则映射

| OpenAPI 端点 | 零信任原则 |
|--------------|------------|
| `POST /auth/token` | 持续验证：每次请求需有效 JWT |
| `POST /devices/{id}/posture` | 设备可信评估：每次访问前检查设备状态 |
| `GET /policies/{id}` | 最小权限：策略精确到应用/用户/时间 |
| `POST /sessions/{id}/heartbeat` | 假设已被入侵：持续心跳检测异常 |
| `DELETE /sessions/{id}` | 最短会话：按需撤销，立即生效 |
| `GET /admin/audit-log` | 日志审计：所有操作可追溯 |
