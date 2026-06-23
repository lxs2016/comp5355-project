---
name: E2EE Messaging Requirements
overview: Based on the course project spec (comp5355_project.pdf) and the group's preliminary design proposal (preliminary_design_proposal.pdf), this is a comprehensive requirements document for the End-to-End Encrypted Messaging System (Task 1).
todos: []
isProject: false
---

# 端对端加密消息系统 — 完整需求文档

## 1. 项目概述

| 项目 | 说明 |
|------|------|
| 课程 | COMP5355 Cyber and Internet Security 2025/2026 |
| 任务 | Task 1: End-to-End Encrypted Messaging System |
| 核心原则 | 明文仅存在于通信端点；服务器仅处理密文和路由元数据 |

---

## 2. 系统架构

### 2.1 三方组件

```
mermaid
flowchart TD
    subgraph clientA [Alice 客户端 CLI]
        A_keys[本地密钥存储\nIK_sig / IK_dh / SPK / SK]
        A_enc[加密/解密模块\nXChaCha20-Poly1305]
    end

    subgraph relay [中继服务器 FastAPI + SQLite]
        R_reg[用户注册/登录]
        R_keys[公钥存储与分发]
        R_route[消息路由/转发]
    end

    subgraph clientB [Bob 客户端 CLI]
        B_keys[本地密钥存储]
        B_dec[加密/解密模块]
    end

    clientA -->|"注册/登录, 上传公钥包"| relay
    clientB -->|"注册/登录, 上传公钥包"| relay
    clientA -->|"握手初始化 (signed, ephemeral PK)"| relay
    relay -->|"握手转发"| clientB
    clientB -->|"握手响应"| relay
    relay -->|"握手转发"| clientA
    clientA -->|"AEAD 密文 + 元数据"| relay
    relay -->|"路由密文"| clientB
```

### 2.2 技术栈

- **语言**: Python 3.11+
- **密码库**: PyNaCl / `cryptography` 包
- **服务端框架**: FastAPI
- **数据库**: SQLite
- **传输协议**: HTTP（CLI 客户端轮询）
- **接口**: 命令行界面（CLI）

---

## 3. 功能需求

### FR-1 用户注册与密钥对生成（必须实现）

- 用户以用户名 + 密码在中继服务器注册身份
- 客户端本地生成三类密钥对：
  - `IK_sig`：Ed25519 身份签名密钥（用于握手时认证发送方）
  - `IK_dh`：X25519 身份 DH 密钥（静态 DH 贡献）
  - `SPK`：X25519 已签名预密钥（发布到服务器供会话发起使用）
- 客户端将签名的公钥包（`IK_sig_pub`, `IK_dh_pub`, `SPK_pub`, `signature`）上传至服务器
- **私钥绝不离开客户端设备**
- 服务器仅存储公钥材料

### FR-2 认证密钥交换与会话建立（必须实现）

基于 X3DH-lite 协议（Extended Triple Diffie-Hellman 简化版）：

```
mermaid
sequenceDiagram
    participant Alice
    participant Server
    participant Bob

    Alice->>Server: 获取 Bob 的公钥包 (IK_dh_pub, SPK_pub)
    Note over Alice: 生成临时 X25519 密钥 EK
    Note over Alice: 执行多次 DH:\n  DH1 = EK ↔ Bob.IK_dh\n  DH2 = EK ↔ Bob.SPK\n  DH3 = Alice.IK_dh ↔ Bob.SPK
    Note over Alice: SK = HKDF-SHA256(DH1 || DH2 || DH3)
    Note over Alice: 用 IK_sig 签名握手摘要
    Alice->>Server: handshake_init (EK_pub, signature, session_id)
    Server->>Bob: 转发 handshake_init
    Note over Bob: 重建相同 DH 推导 SK
    Note over Bob: 验证 Alice 的 Ed25519 签名
    Bob->>Server: handshake_resp (session_id, ack)
    Server->>Alice: 转发 handshake_resp
    Note over Alice: 销毁 EK 私钥材料（前向保密）
```

### FR-3 在线一对一文本消息收发（必须实现）

- 消息使用 XChaCha20-Poly1305（AEAD）加密
- Associated Data 绑定：`session_id` + `sender` + `recipient` + `direction` + 单调递增序列号（`seq`）
- 服务器仅路由不透明密文信封，不解析明文
- 接收方验证 AEAD tag 及序列号后接受消息，否则拒绝

---

## 4. 非功能需求

### NFR-1 实现范围（明确划定）

| 功能 | 状态 |
|------|------|
| 用户注册与密钥生成 | 必须实现 |
| X3DH-lite 会话建立 | 必须实现 |
| 在线一对一文本消息 | 必须实现 |
| SR1–SR4 安全需求 | 必须实现 |
| 前向保密 SR5（Bonus B1） | 计划实现 |
| 恶意服务器抵抗 SR6（Bonus B2） | 计划实现 |
| 离线存储转发 | **不在范围** |
| 群组消息 | **不在范围** |
| 文件/媒体附件 | **不在范围** |
| 元数据隐藏 | **不在范围** |
| 持续丢包/延迟可用性 | **不在范围** |

### NFR-2 性能与部署

- 系统可在单机多进程、容器或真实网络上运行
- 本地演示必须清晰区分 Sender、Recipient、Relay Server 三个角色

---

## 5. 威胁模型

### 5.1 信任边界

| 实体 | 假设 |
|------|------|
| 端点（Alice / Bob） | 受信任；正确执行协议；保护长期密钥和会话密钥 |
| 中继服务器（基础模型） | Honest-but-curious（A3）：遵守协议但可读取并记录所有经手数据；不得获知明文 |
| 网络 | 完全对抗性：无内置保密性、完整性或真实性 |
| 密码原语 | 来自已验证库（PyNaCl）的标准原语视为安全 |

**明确假设**：客户端到服务器的登录可选用 TLS 保护密码；E2EE 安全性不依赖 TLS。消息保密性和完整性完全在应用层端点之间建立。

### 5.2 攻击者类别

| ID | 攻击者 | 能力 |
|----|--------|------|
| A1 | 被动网络攻击者 | 观察所有流量（密文、大小、时序、地址） |
| A2 | 主动网络攻击者 | A1 + 修改/丢弃/延迟/重排/重放/注入消息；可在建立连接时尝试 MITM |
| A3 | 诚实但好奇的服务器 | 读取所有存储/中继的数据；不主动篡改 |
| A4 (Bonus) | 短暂端点妥协 | 一次性读取设备密钥状态（如手机丢失）；无持续控制 |
| A5 (Bonus) | 恶意服务器 | A3 + 可篡改中继数据或分发虚假公钥 |

### 5.3 允许的信息泄漏

明确允许泄漏：密文长度、消息路由元数据（发送方、接收方、时间戳）、服务器上的公钥材料。明文和会话密钥保留在端点。

---

## 6. 安全需求

| ID | 需求 | 计划机制 |
|----|------|----------|
| SR1 | **保密性** — 消息体仅可被授权用户访问；被动观察者或服务器不得获知明文 | AEAD 加密（XChaCha20-Poly1305）；SK 仅对端点可知 |
| SR2 | **完整性** — 传输中任何修改、替换或伪造必须被接收方以可忽略概率以外检测到 | AEAD 认证标签；拒绝无效密文 |
| SR3 | **发送方真实性** — 接收方必须验证消息来自声称的发送方 | Ed25519 签名握手 + 从认证交换派生 SK |
| SR4 | **重放保护** — 捕获的合法密文不可被重发以触发重复效果 | 单调递增会话序列号；拒绝重复序列号 |
| SR5 (Bonus) | **前向保密** — 长期密钥泄露不影响过去会话密钥 | 每次会话使用临时 DH（EK）；SK 派生后立即销毁 EK 和 SK |
| SR6 (Bonus) | **恶意服务器抵抗** — 服务器篡改密文或分发虚假公钥须被检测 | AEAD + seq 绑定；通过 safety number（SHA-256 对等方身份公钥指纹）带外验证 |

---

## 7. 密码学规格

| 用途 | 算法 |
|------|------|
| 身份签名密钥 | Ed25519 |
| 身份 DH 密钥 & 预密钥 | X25519 |
| 临时 DH 密钥（会话建立） | X25519（每次会话新生成，用后销毁） |
| 会话密钥派生 | HKDF-SHA256（输入：多次 DH 输出拼接） |
| 消息加密 | XChaCha20-Poly1305（AEAD） |
| 安全编号（Bonus B2） | SHA-256 对等方 `IK_dh_pub` 指纹 |
| 密码库 | PyNaCl / `cryptography` |

**禁止**：自行实现任何密码原语（块密码、椭圆曲线算术、哈希函数、AEAD 模式）。

---

## 8. 协议消息流

```
mermaid
sequenceDiagram
    participant Alice as Alice CLI
    participant Server as Relay Server
    participant Bob as Bob CLI

    Note over Alice,Bob: 阶段 0: 注册
    Alice->>Server: POST /register {username, password_hash, key_bundle}
    Bob->>Server: POST /register {username, password_hash, key_bundle}

    Note over Alice,Bob: 阶段 1: 登录
    Alice->>Server: POST /login {username, password}
    Bob->>Server: POST /login {username, password}

    Note over Alice,Bob: 阶段 2: X3DH 会话建立
    Alice->>Server: GET /keys/{bob_username}
    Server-->>Alice: {IK_dh_pub, SPK_pub}
    Note over Alice: 生成 EK, 计算 SK = HKDF(DH1||DH2||DH3)\n销毁 EK 私钥
    Alice->>Server: POST /handshake {session_id, to: bob, EK_pub, signature}
    Server->>Bob: 转发 handshake_init
    Note over Bob: 验证签名, 重建 SK
    Bob->>Server: POST /handshake_ack {session_id}
    Server->>Alice: 转发 handshake_ack

    Note over Alice,Bob: 阶段 3: 加密消息交换
    Alice->>Server: POST /message {session_id, to: bob, ciphertext, seq, ad}
    Server->>Bob: 转发密文信封
    Note over Bob: 验证 AEAD tag, 检查 seq\n解密得到明文
```

---

## 9. 提交要求

### 9.1 代码仓库

- 客户端源码 + 中继服务器源码，分模块组织，命名一致
- **不得提交任何密钥、密码或 token**
- `README.md` 包含：依赖及版本、启动服务器命令、注册用户命令、演示两客户端消息交换的脚本

### 9.2 组报告（PDF）

- 威胁模型声明（信任边界、假设、攻击者类别、范围外设置）
- 协议与密钥管理生命周期描述，含握手和消息流程图
- 针对每类攻击者的防御论证（机制、安全需求映射、局限性）
- 若实现 Bonus，同样论证 A4/A5 的防御

### 9.3 个人报告（PDF）

- 每位成员单独提交，说明个人贡献

---

## 10. 评分标准

| 评分项 | 权重 | 关键检查点 |
|--------|------|-----------|
| 系统设计 & 威胁模型 | 25% | 架构图、消息流图与实现匹配；A1–A3 逐一论证 |
| 密码学正确性 | 25% | 使用已验证库；密钥由 CSPRNG 生成；nonce 不重用；无明文密钥在网络中传输 |
| 有效防御 | 25% | 运行系统实际抵御声明的攻击者；不夸大能力 |
| 代码质量 & 文档 | 25% | 模块化代码；README 完整；演示可运行 |
| Bonus B1 前向保密 | +12% | 临时密钥协议；长期密钥泄露不解密历史会话 |
| Bonus B2 恶意服务器抵抗 | +8% | 带外安全编号验证；服务器篡改可被检测 |

---

## 11. 开发优先级建议

- **P0（核心路径）**: FR-1 用户注册 → FR-2 X3DH 会话建立 → FR-3 消息加密收发
- **P1（安全加固）**: SR1–SR4 全部通过；协议设计文档完成
- **P2（Bonus）**: 前向保密（SR5）+ 安全编号带外验证（SR6）
- **P3（报告）**: 群报告 + 个人报告