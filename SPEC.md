# ATrust-ZTNA 产品设计规范

| 属性 | 值 |
|------|-----|
| **版本** | 0.3.0-draft |
| **状态** | Draft — 遵循 OpenSpec SDD |
| **最后更新** | 2026-04-30 |

---

## 1. 产品概述

### 1.1 产品定位

**ATrust-ZTNA** 是一款基于**零信任网络访问（Zero Trust Network Access）**原则的企业级安全接入产品。实现"永不信任，始终验证"的核心理念，为企业提供**身份驱动、应用级最小权限、持续安全评估**的统一安全接入平台。

**核心价值主张**：
- 替代传统 VPN，实现应用级安全访问
- 消除网络层隐式信任，以身份和设备状态为访问决策核心
- 统一管理多云、多站点的安全接入策略

### 1.2 设计目标

| 目标 | 描述 | 量化指标 |
|------|------|----------|
| **安全** | 零信任架构，内存安全实现 | CVE 漏洞 < 2/年，GC 停顿 0ms |
| **跨平台** | Linux / Windows / macOS / iOS / Android | 核心逻辑代码复用率 > 85% |
| **高性能** | 数据面低延迟，策略热更新 | p99 延迟 < 5ms，策略更新 < 50µs |
| **可观测** | 全链路追踪，结构化日志 | 日志覆盖率 100%，trace 延迟 < 10ms |
| **合规** | 等保2.0 / 国密 / 数据出境 | 默认 TLS 1.3，可选 SM2/3/4 |

### 1.3 术语表

| 术语 | 定义 |
|------|------|
| **ZTNA** | Zero Trust Network Access，零信任网络访问 |
| **SPA** | Single Packet Authorization，单包授权 |
| **PDP** | Policy Decision Point，策略决策点 |
| **PEP** | Policy Enforcement Point，策略执行点 |
| **SDP** | Software-Defined Perimeter，软件定义边界 |
| **Posture** | 设备可信状态（杀软/补丁/磁盘加密等） |
| **CGW** | ATrust Gateway，网关执行点 |
| **CTL** | ATrust Controller，控制器管理点 |
| **CO-RE** | Compile Once Run Everywhere，eBPF 跨内核兼容技术 |

---

## 2. 系统架构

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        客户端层                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │Windows   │  │ macOS    │  │ Linux    │  │ iOS / Android    │  │
│  │Client    │  │ Client   │  │ Client   │  │ (Flutter)        │  │
│  │(Tauri)  │  │(Tauri)   │  │(Tauri)  │  │                  │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘  │
│       │              │             │                  │            │
│       └──────────────┴─────────────┴──────────────────┘          │
│                              │                                     │
│                     TrafficInterceptor Trait                        │
│                     (跨平台统一抽象层)                               │
└──────────────────────────────┼────────────────────────────────────┘
                               │ mTLS + SPA
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                      控制面 (ATrust Controller)                     │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │
│  │   身份认证     │  │   策略引擎     │  │   会话管理         │  │
│  │  OAuth2/OIDC   │  │  风险评分      │  │  生命周期          │  │
│  │  SAML/LDAP    │  │  设备评估      │  │  异常检测          │  │
│  │  国密SM2      │  │  最小权限      │  │  JWT token        │  │
│  └───────┬────────┘  └───────┬────────┘  └─────────┬──────────┘  │
│          │                   │                    │               │
│          └───────────────────┴────────────────────┘               │
│                              │                                     │
│                    OpenAPI 3.1 REST / gRPC                        │
└──────────────────────────────┼────────────────────────────────────┘
                               │ Protobuf (gRPC)
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                      数据面 (ATrust Gateway)                       │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐  │
│  │   SPA 敲门    │  │   反向代理     │  │   流量拦截         │  │
│  │  TOTP/Cert    │  │  HTTP/S 终结   │  │  Linux eBPF        │  │
│  │  UDP 8883     │  │  WebSocket     │  │  Windows WFP        │  │
│  │               │  │  TLS 1.3      │  │  macOS NE          │  │
│  └────────────────┘  └────────────────┘  └────────────────────┘  │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              安全管理 (secrecy/zeroize)                   │   │
│  │              perf event 异步日志                         │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    受保护资源        │
                    │  企业内网应用        │
                    │  SaaS 服务           │
                    │  数据库/SSH         │
                    └─────────────────────┘
```

### 2.2 组件职责

| 组件 | 职责 | 技术选型 |
|------|------|----------|
| **ATrust Controller** | 管理平面：身份认证、策略决策、会话管理 | `axum` + `sqlx` + `utoipa` |
| **ATrust Gateway** | 数据平面：流量代理、SPA 校验、策略执行 | `tokio` + `hyper` + `rustls` + `wireguard-rs` |
| **ATrust Client** | 终端代理：设备 posture 收集、隧道建立 | `Tauri v2` (桌面) + `Flutter` (移动) |
| **Policy Agent** | 策略执行：跨平台流量拦截 | `aya` (Linux eBPF) / `wfp` (Windows) / `NE` (macOS) |

---

## 3. 控制面设计

### 3.1 身份认证

**支持的认证协议**：
- OAuth 2.0 + PKCE（Web/移动端）
- OpenID Connect 1.0（SSO 集成）
- SAML 2.0（企业 IdP 集成）
- LDAP / Active Directory（内部目录）
- TOTP / HOTP（多因子）
- 证书认证（国密 SM2 / RSA）

**认证流程**：
1. 用户发起访问请求 → Client 申请 JWT
2. Controller 校验凭证 → 结合设备 posture 评分
3. 风险评分通过 → 颁发短期 JWT（15min）+ 刷新令牌（7d）
4. Client 持 JWT 访问网关，网关验证 JWT 有效性

#### 3.1.1 风险评分模型

**动态权重配置**（管理员可运营调整）：
| 维度 | 默认权重 | 可配置 | 说明 |
|------|----------|--------|------|
| 设备指纹 | 25% | 是 | 设备证书、硬件特征 |
| OS 版本/补丁 | 20% | 是 | 是否存在已知漏洞 |
| 杀软状态 | 20% | 是 | 运行状态 + 病毒库日期 |
| 网络位置 | 15% | 是 | 首次登录 vs 常用地点 |
| 认证历史 | 20% | 是 | 失败次数、异常行为 |

**动态阈值扩展**：
- **时间上下文**：凌晨（00:00-06:00）访问自动 +15 风险分
- **UEBA 基线**：行为偏离基线（访问习惯/地理画像）触发渐进式风险加分
- **冷启动期（Baseline Establishment Period）**：新用户/新设备前 14 天为基线建立期，期间：
  - 风险评分使用静态阈值（而非动态偏离检测）
  - 允许访问权限基于初始策略（不过度限制也不过度开放）
  - 14 天后自动切换为 UEBA 动态基线（若数据不足则延长至 21 天）
  - 期间所有行为日志均标记为 `baseline_enrollment=true`，不触发风险告警（仅记录）
- **连续异常**：同一设备 3 次认证失败后，权重动态翻倍

#### 3.1.2 JWT 生命周期与强制失效

**令牌层次**：
| 令牌类型 | 有效期 | 存储 | 刷新方式 |
|----------|--------|------|----------|
| Access Token (JWT) | 15 分钟 | 内存 | 滚动刷新 |
| Refresh Token | 7 天 | OS Keychain | 需重新认证 |
| 设备证书 | 1 年 | Keychain/DPAPI | SCEP 自动续期 |

**JWT 强制失效机制**（核心安全能力）：

```
┌─────────────────────────────────────────────────────────────┐
│                    JWT 校验决策流程                           │
│                                                              │
│  1. Gateway 收到请求 → 提取 JWT Header 中的 kid (Key ID)      │
│  2. 查询 Controller JWKS 端点 /jwks                         │
│  3. 若 kid 不在当前 JWKS 版本：                              │
│     → 触发静默刷新，重新获取最新 JWKS                         │
│     → 重试验证（防止缓存导致新旧 key 冲突）                   │
│  4. 若 kid 在黑名单（Redis SET）：                           │
│     → 拒绝访问，返回 401                                     │
│  5. Gateway 本地缓存 JWT 校验结果 60s（避免频繁查库）        │
└─────────────────────────────────────────────────────────────┘
```

**黑名单设计**：
- **存储**：Redis SET，key = `jwt:revoked:{jti}`，TTL = JWT 原始过期时间
- **触发条件**：
  - 用户主动登出
  - 管理员撤销会话
  - 检测到 token 被盗用
  - 设备被注销
- **性能**：Redis O(1) 查询，支持集群部署

**网关 Grace Period**：
- JWT 即将过期（< 60s）时，Gateway 允许在途请求继续完成（grace period = 60s）
- 防止流量高峰时 token 突然过期导致大量 401
- 超出 grace period 的请求必须刷新 token

**离线场景降级**：
- 离线时使用本地缓存的策略（加密存储，最长 24h 有效）
- 离线超过 24h，客户端必须重新认证
- 离线期间的操作日志本地暂存，联网后异步上报

### 3.2 策略引擎

**策略模型**：
```
Policy = Subject (谁) + Resource (访问什么) + Action (怎么访问) + Conditions (何时/何地)
```

**策略规则示例**：
```yaml
- id: rule-001
  name: "研发部门访问GitLab"
  subject:
    groups: ["engineering"]
  resource:
    - type: application
      id: gitlab.internal
      cidr: ["10.0.1.0/24"]
  action: ALLOW
  conditions:
    device_posture:
      min_score: 70
      required_checks: ["antivirus", "disk_encryption", "os_patch"]
    require_mfa: true
    valid_hours: "09:00-18:00"
```

#### 3.2.1 策略冲突解决规则

**优先级体系**：
1. **显式优先级（Explicit Priority）**：每条规则有 `priority` 字段（整数，**越小优先级越高**）
2. **资源覆盖优先**：同一 Subject 访问同一 Resource，多条规则时高优先级生效
3. **DENY 绝对优先（Dark Prioritization）**：无论优先级如何，`DENY` / `BLOCK` 规则永远先于 `ALLOW` 执行

**冲突解决矩阵**：
| 规则 A | 规则 B | 结果 |
|--------|--------|------|
| DENY | ALLOW | **DENY**（拒绝） |
| MFA_REQUIRED | ALLOW | MFA_REQUIRED |
| MFA_REQUIRED | DENY | **DENY**（高风险时从严） |
| 相同优先级 | 相同 Subject/Resource | 升序 version 覆盖（最后发布的生效） |

**分布式冲突解决**（多 Controller 副本）：
- 使用 **向量时钟（Vector Clock）** 标记策略版本
- Controller 之间同步时，比较向量时钟：
  - 若存在偏序关系 → 采纳最新
  - 若存在并发冲突 → 管理员告警，人工介入或自动采纳更高优先级规则
- 冲突日志完整保留，供审计追溯

#### 3.2.2 策略热更新

**全量推送 + 版本切换（原子性保证）**：

```
Controller                              Gateway
  │                                       │
  │  gRPC PushPolicyBatch(batches=[],     │
  │                  version=v17,         │
  │                  total_count=50)      │
  │  ──────────────────────────────────> │
  │                                       │
  │  [50 条策略，分 5 批推送，每批 version=v17]  │
  │                                       │
  │  Gateway 接收逻辑：                    │
  │  1. 校验批次 version：若 version < 本地   │
  │     当前版本 → 丢弃（过期批次）           │
  │  2. 校验批次序号：若序号不连续 → 拒绝整批  │
  │    （触发重新拉取全量策略）              │
  │  3. 累积所有批次至 count == total_count  │
  │  4. 校验完整性（MD5/SHA-256 校验和）      │
  │  5. 版本向量更新（原子替换 LruHashMap）   │
  │                                       │
  │  <-- ACK(version=v17)                 │
```

**版本切换机制**：
- Controller 为每次策略变更生成全局递增的版本号（Vector Clock：`(controller_id, seq)`）
- Gateway 持有策略时附带版本号，本地替换时保证原子性（RwLock + version check）
- 若推送中途断开：Gateway 保留旧版本策略，拒绝不完整的增量更新，自动触发 Controller 全量拉取
- 若新版本完整性校验失败（校验和不对）：回退旧版本，告警 Controller 重发

**目标**：p99 更新延迟 < 50µs（不含网络传输）

### 3.3 会话管理

- 会话 ID：`session_id = SHA256(user_id + device_id + timestamp + nonce)`
- JWT 有效期：15 分钟（短期访问令牌）
- 刷新令牌有效期：7 天（滚动刷新）
- 会话监控：实时心跳（30s），超时断连
- 异常检测：同一 token 多设备登录、地理位置突变

---

## 4. 数据面设计

### 4.1 SPA 单包授权

**协议流程**：
```
Client                          Gateway
  │                                │
  │  1. UDP SPA 敲门 (端口 8883)   │
  │  ───────────────────────────> │
  │     [TOTP + Nonce + Timestamp]  │
  │                                │
  │  2. 网关校验 (Nonce 去重)      │
  │                                │
  │  3. TCP 握手 + mTLS            │
  │  <─────────────────────────── │
  │                                │
  │  4. HTTP CONNECT (应用代理)    │
  │  ───────────────────────────> │
```

**SPA 重放攻击防护**（必须实现）：
| 防护机制 | 实现方式 |
|----------|----------|
| **Nonce 去重窗口** | Gateway 维护最近 60s 内收到的 Nonce 集合（Redis SET，TTL=60s），重复 Nonce 直接丢弃 |
| **时间戳签名** | 敲门包包含 Unix 时间戳，Gateway 拒绝时间戳偏差 > 30s 的包 |
| **序列号** | 每包带递增序列号，Gateway 记录最大序列号，丢弃旧序列号包 |
| **单次有效性** | 成功敲门的 Nonce 标记为已使用，TTL=5min（覆盖网络重传窗口） |

**敲门包结构**（两条互斥路径，根据认证方式字段选择）：

```
┌────────────────────────────────────────┐
│  Magic (4B) │ Version (1B) │ Mode (1B) │
├────────────────────────────────────────┤
│  Timestamp (8B, Unix ns)              │
├────────────────────────────────────────┤
│  Nonce (16B, random)                  │
├────────────────────────────────────────┤
│  [Path A] TOTP Mode：                   │
│    TOTP Code (8B)                      │
│    HMAC-SHA256(Magic+Timestamp+Nonce+ │ ← 对称密钥（预共享的 Gateway Secret）
│             TOTP, GatewaySecret)        │
├────────────────────────────────────────┤
│  [Path B] 证书模式：                     │
│    Device Cert Signature (64B)         │ ← Ed25519 签名（私钥签名，Gateway 用公钥验证）
│    Device Cert (DER, max 2KB)          │ ← 设备证书，Gateway 用 CA 公钥验证
└────────────────────────────────────────┘
```

**Mode 字段定义**：
| Mode 值 | 含义 | 完整性机制 |
|---------|------|------------|
| `0x01` | TOTP 模式 | HMAC-SHA256(GatewaySecret) — 对称密钥，需预共享 |
| `0x02` | 证书签名模式 | Ed25519/ECDSA 签名 — 非对称，Gateway 用 CA 公钥验证 |

**选择逻辑**：
- 新设备首次注册：走 TOTP 模式（设备尚未获得证书）
- 已有证书的设备：走证书签名模式（抗中继攻击，无 TOTP 步长限制）
- TOTP 步长 30s，允许前后 1 个步长窗口（±30s）
- 敲门成功验证路径 B 后，Gateway 记录设备证书，后续 mTLS 直接使用证书，无需再走 SPA

**安全特性**：
- UDP 敲门包包含 TOTP (30s 步长) + Nonce + 时间戳签名
- 敲门成功前，TCP 端口对扫描工具不可见（端口敲门）
- mTLS 双向证书认证

**SPA 层 DoS 防护**：
- UDP Flood 限流：单 IP 敲门速率限制 10次/秒，超限加入临时黑名单 60s
- 敲门失败率告警：单 IP 连续 5 次敲门失败触发风险告警

### 4.2 反向代理

- **协议支持**：HTTP/1.1、HTTP/2、WebSocket、TLS 1.3
- **上游协议**：HTTP、FastCGI、TCP Socket
- **负载均衡**：轮询、最少连接、IP Hash（仅内部）
- **健康检查**：主动探活 + 被动故障转移

### 4.3 流量拦截（跨平台）

**统一抽象**：`TrafficInterceptor` Trait

```rust
#[async_trait]
pub trait TrafficInterceptor: Send + Sync {
    async fn start(&self) -> Result<(), InterceptorError>;
    async fn apply_policy(&self, rule: PolicyRule) -> Result<(), InterceptorError>;
    fn get_original_dst(&self, local_fd: RawFd) -> Result<SocketAddr, InterceptorError>;
    async fn fallback_to_legacy(&self) -> Result<(), InterceptorError>;
    async fn unload(&self) -> Result<(), InterceptorError>;
}
```

**平台实现矩阵**：

| 平台 | 拦截机制 | 权限要求 | 能力 |
|------|----------|----------|------|
| Linux 5.10+ | eBPF cgroup/connect | CAP_BPF / root | 进程级拦截、策略重写 |
| Linux (降级) | iptables + TPROXY | root | IP+Port 拦截 |
| Windows | WFP Callout Driver | 管理员 + 代码签名 | 内核级拦截 |
| macOS | NetworkExtension | 系统扩展授权 | 沙箱内 L7 拦截 |
| iOS | NEPacketTunnelProvider | MDM / 企业证书 | 隧道模式 |
| Android | VpnService (TUN) | 用户授权弹窗 | L3 路由拦截 |

**降级判断与恢复**：
```
┌─────────────────────────────────────────────────────┐
│              降级决策树                               │
│                                                       │
│  启动拦截器 → 检查内核版本                            │
│    │                                               │
│    ├── 内核 >= 5.10 + 有 CAP_BPF                    │
│    │    → 加载 eBPF 程序                            │
│    │    ├── Verifier 通过 → 正常运行                │
│    │    └── Verifier 拒绝 → 降级到 iptables         │
│    │                                               │
│    └── 无 CAP_BPF / 内核 < 5.10                     │
│         → 降级到 iptables + TPROXY                  │
│                                                       │
│  降级事件自动：                                      │
│  1. 记录降级原因（内核版本/权限/Verifier错误）       │
│  2. 发送监控事件（interceptor_fallback_events_total） │
│  3. 记录安全能力变化（进程级→IP级）                  │
│  4. 触发告警（高风险时）                             │
│                                                       │
│  恢复：下次客户端认证时重新检测，若条件满足则切回 eBPF │
└─────────────────────────────────────────────────────┘
```

**降级后安全能力差异**：
| 能力 | eBPF 模式 | iptables 降级模式 |
|------|-----------|-----------------|
| 进程级身份 | ✅ 完整 | ❌ 仅 IP+Port |
| 策略热更新 | ✅ < 50µs | ⚠️ 需要 iptables-restore |
| 精细重定向 | ✅ bpf_sk_redirect | ❌ REDIRECT/TPROXY |
| SPA 联动 | ✅ 内核级协同 | ⚠️ 用户态代理模式 |

---

## 5. 客户端设计

### 5.1 跨平台架构

```
┌─────────────────────────────────────────────┐
│              ATrust Client (Rust Core)       │
│  ┌──────────────────────────────────────┐   │
│  │           trust-core (共享库)         │   │
│  │  - 认证模块 (OAuth2/JWT/国密)        │   │
│  │  - SPA 客户端                        │   │
│  │  - 策略本地缓存 (LRU + 版本向量)      │   │
│  │  - 日志/遥测                         │   │
│  └──────────────────────────────────────┘   │
│                      │                       │
│         ┌────────────┼────────────┐          │
│         ▼            ▼            ▼          │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐ │
│  │Tauri Win  │  │Tauri macOS│  │Flutter    │ │
│  │  /Linux   │  │           │  │iOS/Android│ │
│  │  UI (TS)  │  │  UI (TS)  │  │  UI       │ │
│  └───────────┘  └───────────┘  └───────────┘ │
└─────────────────────────────────────────────┘
```

### 5.2 设备注册与证书管理

**设备注册流程**（信任链起点）：

```
┌─────────────────────────────────────────────────────────────────┐
│                    设备首次注册 TOFU 引导流程                       │
│                                                               │
│  阶段 1：Bootstrap 凭证分发（管理员操作）                          │
│  ──────────────────────────────────────────────────────────── │
│  方式 A - 带外一次性密码（BYOD / 管理员审批）：                     │
│    管理员在 Controller 后台生成设备注册码（一次性 Token）            │
│    → 通过邮件/企业微信/QR 码发给用户                             │
│    → 用户在客户端输入注册码（或扫描 QR）                          │
│    → 设备持有此 Token 向 Controller 发起注册请求                   │
│                                                               │
│  方式 B - MDM 预注册（企业托管设备）：                            │
│    MDM 服务器通过 DEP/Apple Configurator / Intune 预推送         │
│    设备证书和注册凭证，设备开箱即有受信任身份                       │
│    → 无需用户手动输入注册码                                       │
│                                                               │
│  方式 C - 管理员手动审批（高安全场景）：                           │
│    设备生成密钥对 + 设备指纹，提交注册申请（状态=Pending）          │
│    → 管理员在 Controller UI 审批设备注册                          │
│    → 审批通过后颁发设备证书                                        │
│                                                               │
│  阶段 2：密钥对生成与证书申请                                      │
│  ──────────────────────────────────────────────────────────── │
│  1. 设备生成 RSA-2048 / ECDSA-P256 密钥对（私钥存于 KMS/Keychain）│
│  2. 设备指纹 = SHA-256(硬件序列号 + TPM 公开密钥 + 随机 nonce)     │
│  3. 设备向 Controller 提交 CSR + 设备指纹 + Bootstrap 凭证        │
│  4. Controller 验证凭证后签发设备注册证书（通过 SCEP 或直接签发）   │
│                                                               │
│  阶段 3：证书续期与重注册                                          │
│  ──────────────────────────────────────────────────────────── │
│  已注册设备证书到期前 30 天，Client 自动通过 SCEP/EST 续期         │
│  设备指纹变更（即硬件更换）→ 需要重新走 Bootstrap 流程              │
└─────────────────────────────────────────────────────────────────┘
```

**首次注册安全强度分级**：
| 场景 | 引导方式 | 安全强度 | 说明 |
|------|----------|----------|------|
| 企业托管设备（MDM） | MDM 预置凭证 | 🔴 极高 | 设备在 MDM 管理下，开箱即受信任 |
| BYOD | 注册码邮件/QR | 🟡 中等 | 凭证带时间限制（24h），单次使用 |
| 高安全场景 | 管理员人工审批 | 🟢 最高 | 管理员核验设备信息后审批 |
| 离线/无网场景 | 不支持首次注册 | — | 离线期间可使用已有证书，离线续期需预置 |

**VPN-less 首次注册**：
ZTNA 的核心场景是内网不可达时仍需安全接入。首次注册依赖公网可达的 Controller（端口 443），设备通过 TLS 1.3 客户端证书与 Controller 建立安全通道，Bootstrap 凭证通过外部渠道（邮件/通知）传递，确保即使在不可信网络中也能完成设备认证。

**证书类型**：
- 设备注册证书（1年有效期，SCEP 自动续期）
- 设备认证证书（短周期，30天，用于 mTLS）

**证书吊销**：
   - **首选：OCSP Stapling**（证书持有者预先获取 OCSP 响应，Gateway 直接验证，无需实时查询）
   - **辅障：本地 CRL 缓存**（Gateway 每 1h 刷新 CRL，缓存至本地）
   - **降级路径（证书状态查询）**：
     1. 尝试验证 OCSP Stapling 响应（若证书中含 AIA 扩展）
     2. 若无 Stapling 或验证失败 → 查询本地 CRL 缓存
     3. 若 CRL 缓存过期或不存在 → 实时查询 OCSP（超时 2s）
     4. **超时或查询失败 → 拒绝访问（fail-closed）**，拒绝建立 mTLS 连接
   - **紧急撤销**：管理员可通过 Controller API 立即撤销设备证书（写入 Redis 黑名单，Gateway 实时感知）
   - **设计原则**：绝不因 OCSP 查询超时而放行 —— fail-open 等同于绕过证书吊销检查
```

**多用户共用设备**：
| 场景 | 处理方式 |
|------|----------|
| 个人设备（BYOD） | 设备证书 + 用户账号绑定，独立 posture 评分 |
| 共享设备（医疗/教育） | 设备级 posture + 用户级策略双重检查 |
| 访客设备 | Agentless 模式，浏览器 SSO，无持久证书 |

**策略本地缓存一致性**：
```
┌──────────────────────────────────────────────────┐
│              策略缓存同步流程                      │
│                                                   │
│  1. Controller 下发策略（带 Vector Clock 版本号）  │
│  2. Client 本地存储（SQLite，加密）               │
│  3. Client 比对版本：                             │
│     - 本地版本 < 下发版本 → 更新本地缓存          │
│     - 版本冲突（并发分支）→ 采纳 Controller 版本  │
│  4. 离线缓存有效期：24h（管理员可配置，≤ 72h 硬上限）│ ← 超出 72h 必须重新认证，持续验证原则不可绕过 │
│  5. 离线超期：强制重新认证                        │
│  6. 缓存数据：存储前 AES-256-GCM 加密            │
│     密钥存储于 OS Keychain/DPAPI/Keystore        │
└──────────────────────────────────────────────────┘
```

### 5.3 客户端生命周期

```
启动 → 设备注册 → 身份认证 → 获取策略 → 启动拦截器
  ↓                                                 ↓
卸载 ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ← ←
```

---

## 6. 安全模型

### 6.1 零信任原则映射

| 原则 | 在 ATrust 中的实现 |
|------|-------------------|
| **永不信任，始终验证** | 每次访问均需 JWT 校验 + 设备 posture 评估 |
| **最小权限访问** | 应用级粒度策略，非网段级开放 |
| **微分段** | eBPF/cgroup 隔离每次连接 |
| **持续监控** | 30s 心跳 + 异常行为检测 |
| **假设已被入侵** | 全流量加密、会话追踪、审计日志 |

### 6.2 威胁建模 (STRIDE)

| 威胁类型 | 攻击描述 | 防御措施 |
|----------|----------|----------|
| **Spoofing** | 伪造身份访问 | mTLS 双向证书 + JWT |
| **Tampering** | 篡改策略/配置 | 配置签名 + Schema 校验 |
| **Repudiation** | 否认操作行为 | 不可篡改审计日志 |
| **Information Disclosure** | 敏感数据泄露 | TLS 1.3 + 国密 + DLP |
| **DoS** | 资源耗尽 | 限流 + 熔断 + 降级 |
| **Elevation of Privilege** | 提权攻击 | 最小权限 + 策略审批流 |

### 6.3 密钥管理

| 密钥类型 | 存储方式 | 生命周期 |
|----------|----------|----------|
| **客户端证书** | OS Keychain / DPAPI / KeyStore | 1年，可续期 |
| **TLS 会话密钥** | 内存 (secrecy::Secret) | 会话级 |
| **JWT 签名密钥** | HSM / 云 KMS | 90天轮换 |
| **国密私钥** | 国密KMS | 1年，支持硬件绑定 |

### 6.4 可观测性设计

#### 6.4.1 Metrics（Prometheus）

**控制面指标**：
```
# 认证指标
auth_token_issued_total{grant_type, mfa_used}
auth_token_verify_errors_total{reason}
auth_mfa_attempts_total{result}

# 策略指标
policy_evaluations_total{action, risk_level}
policy_evaluation_duration_seconds{quantile}
active_sessions_total{status}

# 设备指标
device_posture_checks_total{check_type, result}
device_posture_score_histogram{percentile}
```

**数据面指标**：
```
# 网关指标
gateway_spa_challenges_total{result, reason}
gateway_proxy_requests_total{backend, status_code}
gateway_proxy_request_duration_seconds{backend, quantile}
interceptor_actions_total{action, platform}

# 拦截器指标
ebpf_policy_lookup_duration_seconds{quantile}
interceptor_fallback_events_total{mode_from, mode_to}
```

#### 6.4.2 Tracing（W3C TraceContext）

**链路追踪传播格式**：`W3C TraceContext`（`traceparent` + `tracestate` HTTP header）

```
traceparent: 00-{TraceId}-{SpanId}-{TraceFlags}
```

**跨组件 Trace 传播**：
```
Client (生成 TraceId)
  → SPA 请求（UDP 包中携带 TraceContext）
  → Gateway（提取 TraceId，创建 Span）
    → Controller gRPC（继续 Span）
    → 上游服务（HTTP/out）
  → 响应 TraceId 回到 Client
```

**采样策略**：
- 正常流量：10% 采样
- 异常/SPA 失败：100% 采样
- 可配置 Trace ID 前缀过滤

#### 6.4.3 告警规则

| 告警名称 | 条件 | 严重度 | 处理方式 |
|----------|------|--------|----------|
| `JWTAuthFailureRate` | 5min 内 JWT 验证失败率 > 10% | High | 自动封锁源 IP + 通知 SOC |
| `DevicePostureScoreDrop` | 设备 posture 评分 5min 内下降 > 30 | Medium | 触发 re-authentication |
| `SPAChallengeFailureSpike` | 单 IP 10s 内敲门失败 > 5 次 | High | 加入临时黑名单 + 告警 |
| `PolicyDriftDetected` | 实现 Schema 与契约偏离 | Critical | 阻断 CI/CD 发布 |
| `InterceptorDowngrade` | eBPF → iptables 降级事件 | High | 通知运维，确认安全策略降级 |
| `CertificateExpiryWarning` | 证书 30 天内过期 | Low | 自动触发续期流程 |
| `GatewayHighLatency` | p99 延迟 > 500ms 持续 5min | Medium | 自动扩容 + 降级非关键路径 |

#### 6.4.4 审计日志

**日志格式**：JSON（结构化），遵循 CEF（Common Event Format）扩展

```json
{
  "timestamp": "2026-04-30T10:15:30.123Z",
  "version": "1.0",
  "event_type": "SESSION_POLICY_EVALUATION",
  "severity": "INFO",
  "actor": {
    "user_id": "uuid",
    "device_id": "uuid",
    "ip": "203.0.113.45"
  },
  "resource": {
    "type": "application",
    "id": "gitlab.internal",
    "action": "ALLOW"
  },
  "context": {
    "risk_score": 35,
    "mfa_used": true,
    "policy_id": "uuid",
    "gateway_id": "uuid"
  },
  "trace_id": "abc123..."
}
```

**不可篡改保证**：
- 审计日志追加写入（Append-only），不提供删除接口
- **Hash Chain + HMAC 防篡改**：
  - 每小时生成一个新的 hash chain 节点：`HMac-SHA256(hourly_log_batch, chain_key)`
  - `chain_key` 存储于独立HSM/Key Vault（与应用程序密钥分离）
  - 每小时节点保存：`HMAC(prev_hash + current_batch_hash, chain_key)`，而非纯 SHA-256
- **外部存证（可选增强）**：定期将 hash chain root 写入时间戳权威服务（RFC 3161），获取不可抵赖的时间证明
- 支持完整性验证：`verify-hash-chain --from 2026-04-01 --to 2026-04-30`（重放 HMAC 验证）
- 日志保留：默认 1 年（等保要求），可配置延长

### 6.5 供应链安全

**依赖管理**：
| 措施 | 实施方式 |
|------|----------|
| **SBOM 生成** | 每个 Release 自动生成 SPDX 格式 SBOM，随发布包分发 |
| **cargo-audit** | CI 中每次 PR 执行，阻断高危漏洞依赖 |
| **cargo-deny** | 在 ` deny.toml` 中维护允许/禁止的许可证列表和漏洞库 |
| **osv-scanner** | 额外对所有依赖做 OSV（Open Source Vulnerabilities）扫描 |
| **依赖版本锁定** | `Cargo.lock` / `package-lock.json` 必须提交，禁止 `cargo update` 自动升级 |

**eBPF 程序签名验证**：
```
加载 eBPF 程序前：
1. 验证程序签名（CO-RE + BTF 保证可移植性）
2. 使用 bpftool verify 检查 Verifier 日志
3. 白名单校验程序 hash（防止恶意 BPF 注入）
4. 内核版本兼容性矩阵校验
```

**容器镜像安全**：
- 基础镜像：distroless（无 shell，无包管理器）
- 多阶段构建，最终镜像只含运行时必要文件
- Trivy 扫描：阻断已知 CVE 高危漏洞镜像发布

---

## 7. 部署模式

### 7.1 部署拓扑

| 模式 | 适用场景 | 网关部署 |
|------|----------|----------|
| **单机部署** | 小规模 / POC | 单台硬件/VM |
| **主备部署** | 高可用要求 | 双机 + VRRP |
| **多区域分布式** | 全球企业 / 低延迟 | 每区域 2+ 网关 |
| **云原生** | 公有云租户 | K8s Deployment |

### 7.2 网关高可用与会话保持

**会话状态同步**（多网关副本间）：
```
┌──────────┐  gRPC    ┌──────────┐
│ Gateway A│◄────────►│ Gateway B│
│(Active)  │  Session │(Standby) │
│          │  Sync    │          │
└────┬─────┘          └────┬─────┘
     │  mTLS               │  mTLS
     ▼                     ▼
┌─────────────────────────────────────┐
│         Redis Cluster               │
│  Session State │ JWT Blacklist │    │
│  Policy Cache  │ Nonce Dedup  │    │
└─────────────────────────────────────┘
```

**Redis 不可用时的安全策略（Fail-closed）**：
| 功能 | Redis 可用时 | Redis 不可用时 |
|------|-------------|----------------|
| **JWT 黑名单校验** | 实时查询 Redis SET | **拒绝所有新请求**（返回 503），在途 JWT 依赖本地缓存（60s）继续放行，超出 grace period 后拒绝 |
| **Nonce 去重** | Redis SET 校验 | 降级为本地 Bloom Filter（内存有限，仅保证不漏检，不保证零误判），记录降级事件 |
| **Session 状态** | Redis 读写 | 拒绝新建会话，保持现有会话存活（本地状态），阻止新用户登录 |
| **策略缓存** | 正常热更新 | 使用本地缓存策略（版本向量保证），不阻塞已有连接 |

**CAP 取舍策略**：
- 采用 **AP 优先**（Availability + Partition Tolerance）
- 跨地域 Redis Cluster 部署时，接受短暂数据不一致（同步窗口 ≤ 5s）
- 对安全性敏感操作（JWT 黑名单）：写入时强一致（主节点确认后返回）
- 对可用性敏感操作（Nonce 去重）：允许最终一致（副本节点可接受写入）

**Redis 分区时的双写窗口防护**：
若同一 JWT 在两个区域同时被撤销：Gateway 对 JWT 黑名单操作使用 **Redis SET NX**（仅设置一次），避免重复写入冲突。跨区域同步使用向量时钟标记各区域最后更新时间，冲突时以时间戳更早的撤销记录为准（先到先生效）。

**会话保持设计**：
| 场景 | 处理方式 |
|------|----------|
| **WebSocket 长连接** | 用户绑定到固定网关（session_affinity=sticky），切换时先 drain 再迁移 |
| **mTLS Session Resumption** | 使用 SessionTicket（TLS 1.3 Session Ticket）恢复会话，无需完整握手；**STEK（Session Ticket Encryption Key）每 24h 轮换**，历史 Ticket 使用旧密钥仍可解密（grace period = 轮换周期），防止 STEK 泄漏后历史会话被解密影响 Forward Secrecy |
| **TCP 连接** | Gateway 之间不共享 TCP 连接，切换时客户端重连 |
| **会话迁移触发** | 主动线：VRRP 切换时，主网关推送 session 列表到备网关 |

**优雅关闭（Drain）**：
1. 网关接收 SIGTERM
2. 进入 drain 模式：停止接收新连接，保留现有连接
3. 按连接类型差异化处理：
   - **HTTP/1.1 短连接**：30s drain 窗口，强制关闭时发送 RST
   - **WebSocket / HTTP/2 长连接**：发送 GOAWAY 帧（code=0），通知客户端重新建立连接，300s 迁移窗口
   - **mTLS 会话**：通知对端关闭，60s 后强制终止
4. 所有被强制关闭的连接均记录审计日志（reason=`graceful_shutdown_timeout`）
5. 策略：避免业务流量中断，优先给客户端足够的迁移时间

**熔断机制**：
- 限流维度：per-IP / per-User / per-Gateway
- 熔断阈值：5s 内错误率 > 50% → 熔断 30s
- 降级恢复：半开试探（5% 流量），成功则恢复正常

```
Internet ──────┬────── ATrust Gateway ────── 受保护资源
               │              │
               │              │ mTLS / SPA
               ▼              ▼
         ATrust Controller (管理平面)
```

---

## 8. 合规与认证

| 合规标准 | 要求 | 当前状态 |
|----------|------|----------|
| **等保2.0** | 网络安全三级 | 目标：默认支持 |
| **国密认证** | SM2/3/4 | 可选模块 |
| **TLS 1.3** | 传输加密 | 默认启用 |
| **GDPR** | 数据保护 | 日志脱敏支持 |

---

## 9. 参考规范

| 规范 | 描述 |
|------|------|
| **RFC 7807** | Problem Details for HTTP APIs |
| **NIST SP 800-207** | Zero Trust Architecture |
| **CISA ZTNA Guidance** | 云安全联盟 ZTNA 定义 |
| **OpenAPI 3.1** | REST API 契约格式 |
| **gRPC** | Protocol Buffers 3 |
| **JSON Schema Draft-07** | 配置校验规范 |

## 10. 文档变更记录

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| 0.1.0-draft | 2026-04-30 | 初始草案 |
| 0.2.0-draft | 2026-04-30 | 补全 JWT 强制失效机制（黑名单/JWKS 版本）、SPA 重放防护（Nonce 去重）、设备注册流程（SCEP/EST）、策略冲突解决规则、网关 HA 会话保持、可观测性专章（Metrics/Tracing/Alert/Audit）、供应链安全 |
| 0.3.0-draft | 2026-04-30 | 修复 OCSP fail-open 安全漏洞（改为 fail-closed + CRL 降级）、补全设备首次注册 TOFU 引导流程（MDM/注册码/人工审批三条路径）、定义 Redis 不可用时的 fail-closed 策略、SPA 敲门包结构 HMAC/签名路径分离（Mode 字段）、策略热更新原子性（全量版本切换）、离线缓存硬上限 72h、Section 6.5 供应链安全编号归位、UEBA 冷启动期 14 天定义、Hash chain 完整性改用 HMAC-SHA256 + HSM 外部存证、WebSocket drain 差异化超时、SessionTicket 拼写修正 + TLS 1.3 STEK 24h 轮换 |
