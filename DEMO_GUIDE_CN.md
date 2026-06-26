# 端对端加密消息系统 — 项目介绍与演示指南

**课程**：COMP5355 Cyber and Internet Security（2025/2026）  
**语言**：Python 3.11+  
**运行方式**：本机单台电脑，三个终端窗口模拟 Alice、Bob 和 Relay Server

---

## 目录

1. [项目背景与目标](#1-项目背景与目标)
2. [系统架构](#2-系统架构)
3. [核心密码学方案](#3-核心密码学方案)
4. [安全属性与威胁模型](#4-安全属性与威胁模型)
5. [演示前准备](#5-演示前准备)
6. [Presentation 演示脚本（逐步说话稿）](#6-presentation-演示脚本逐步说话稿)
7. [常见问题与应急处理](#7-常见问题与应急处理)

---

## 1. 项目背景与目标

### 1.1 问题定义

传统即时通讯系统（如普通 SMS、早期 Email）中，服务器可以读取所有消息明文。一旦服务器被攻击或运营方"好奇"，用户隐私即告失守。

本项目实现一套**端对端加密（E2EE）一对一消息系统**：

> 消息的明文**只存在于发送方和接收方的设备上**。中继服务器只能看到密文，无法解密，也无法伪造合法消息。

### 1.2 实现范围

| 阶段 | 内容 | 对应评分项 |
|------|------|-----------|
| Phase 0 | 项目脚手架（FastAPI + SQLite） | Criterion 4 |
| Phase 1 | 用户注册 / 登录 / 公钥分发 | Criterion 4 |
| Phase 2 | X3DH-lite 密钥协商（Session Key） | Criterion 1, 2 |
| Phase 3 | XChaCha20-Poly1305 消息加密收发 | Criterion 1, 2, 3 |
| Phase 4 | **Bonus B1** 前向保密（EK 销毁） | +12% |
| Phase 5 | **Bonus B2** Safety Number（恶意服务器抵抗） | +8% |
| Phase 6 | 测试全绿 + 完整文档 | Criterion 4 |

---

## 2. 系统架构

```
┌─────────────────────────────────────────────────────┐
│                   本机（单台电脑）                     │
│                                                     │
│  ┌──────────┐    HTTP/JSON    ┌──────────────────┐  │
│  │  Alice   │◄──────────────►│  Relay Server    │  │
│  │  CLI     │                │  (FastAPI+SQLite) │  │
│  └──────────┘                │                  │  │
│                              │  存储内容：        │  │
│  ┌──────────┐                │  • 用户名+密码哈希  │  │
│  │   Bob    │◄──────────────►│  • 公钥（IK/SPK） │  │
│  │  CLI     │                │  • 密文（CT）      │  │
│  └──────────┘                │  ✗ 不存储明文      │  │
│                              └──────────────────┘  │
│  本地磁盘（~/.e2ee/）                                │
│  • 私钥  identity.json（mode 0o600）                │
│  • 会话密钥 SK（sessions/）                          │
└─────────────────────────────────────────────────────┘
```

### 2.1 目录结构

```
cyber-project/
├── server/
│   ├── main.py        # FastAPI 路由（注册、登录、握手、消息）
│   ├── database.py    # SQLite 初始化与查询
│   ├── models.py      # Pydantic 请求 / 响应模型
│   └── auth.py        # bcrypt 密码哈希 + JWT 鉴权
├── client/
│   ├── cli.py         # 命令行入口（argparse）
│   ├── crypto.py      # 全部密码学操作（PyNaCl）
│   ├── protocol.py    # X3DH 握手 + 消息流程编排
│   ├── storage.py     # 本地身份与会话状态读写
│   └── api.py         # HTTP 客户端封装（httpx）
└── tests/             # 15 个自动化验收测试
```

---

## 3. 核心密码学方案

### 3.1 密钥体系

每个用户在注册时生成三对密钥，**私钥永不离开本地**：

| 密钥 | 类型 | 用途 |
|------|------|------|
| `IK_sig` | Ed25519 签名密钥对 | 签名握手 transcript，证明身份 |
| `IK_dh` | X25519 DH 密钥对 | 长期身份 DH，参与 SK 推导 |
| `SPK` | X25519 DH 密钥对 + Ed25519 签名 | 签名预密钥，服务器存储公开部分 |

### 3.2 X3DH-lite 密钥协商（Phase 2）

Alice 想和 Bob 建立安全会话：

```
Alice 端：
  EK ← 随机生成（临时密钥，用完即毁）
  DH1 = X25519(EK.priv,         Bob.IK_dh.pub)
  DH2 = X25519(EK.priv,         Bob.SPK.pub)
  DH3 = X25519(Alice.IK_dh.priv, Bob.SPK.pub)
  SK  = HKDF-SHA256(DH1 ‖ DH2 ‖ DH3, info="e2ee-chat-v1")
  *** EK 私钥立即销毁（随机覆写 + 置零 + del） ***

Bob 端（镜像计算）：
  DH1 = X25519(Bob.IK_dh.priv,  Alice.EK.pub)
  DH2 = X25519(Bob.SPK.priv,    Alice.EK.pub)
  DH3 = X25519(Bob.SPK.priv,    Alice.IK_dh.pub)
  SK  = HKDF-SHA256(DH1 ‖ DH2 ‖ DH3)
  → 两侧 SK 严格相等
```

服务器只传递 `EK.pub`，不知道 `DH1/DH2/DH3`，无法推导 SK。

### 3.3 消息加密（Phase 3）

```
nonce = random(24 bytes)
AD    = JSON { session_id, sender, recipient, seq }
CT    = XChaCha20-Poly1305.encrypt(key=SK, nonce=nonce, msg=明文, aad=AD)
发送  = nonce ‖ CT（base64）+ AD
```

AEAD 保证：
- **保密性**：没有 SK 无法解密
- **完整性**：任何比特翻转都会导致认证失败
- **绑定性**：AD 中的 seq、sender、session_id 被密码学绑定

### 3.4 前向保密（Phase 4 — Bonus B1）

EK 销毁后，攻击者即使获得 Alice 的长期私钥 `IK_dh.priv`，也只能重算 DH3，**无法重算 DH1 和 DH2**（需要已销毁的 `EK.priv`）。HKDF 输入不完整 → SK 错误 → AEAD 解密失败。

### 3.5 Safety Number（Phase 5 — Bonus B2）

```
safety_number = format(
    SHA-256( sort([Alice.IK_dh_pub, Bob.IK_dh_pub]) )
)
→ 8 组 × 5 位十进制数字（共 40 位）
```

字典序排序保证双方计算结果相同。带外比对（电话 / 当面）可检测服务器的公钥替换攻击。

---

## 4. 安全属性与威胁模型

### 4.1 安全需求

| 编号 | 属性 | 实现机制 |
|------|------|---------|
| SR1 | 机密性 | XChaCha20-Poly1305 AEAD，SK 不过服务器 |
| SR2 | 完整性 | AEAD 认证标签覆盖密文 + AD |
| SR3 | 发送方认证 + 消息绑定 | AD 绑定 sender、session_id、seq；握手 transcript 由 IK_sig 签名 |
| SR4 | 重放保护 | 单调递增序列号，接收方校验 |
| SR5 | 前向保密 | EK 销毁，历史会话密钥不可重建 |
| SR6 | 恶意服务器抵抗 | Safety number 带外比对 |

### 4.2 威胁模型

| 攻击者 | 能力 | 防御 |
|--------|------|------|
| A1 被动网络攻击者 | 监听所有流量 | 全程密文传输，无密钥无法解密 |
| A2 主动网络攻击者 | 注入 / 篡改数据包 | AEAD 标签立即检测篡改 |
| A3 诚实但好奇的服务器 | 读取数据库 | 数据库只有密文 + 公钥，无明文 |
| A4 暂时性端点攻破 | 泄露后读取内存 | EK 已被覆写销毁，SK 可安全留存 |
| A5 恶意服务器 | 替换公钥（MITM） | Safety number 不匹配 → 用户察觉 |

---

## 5. 演示前准备

### 5.1 环境检查

```bash
cd /path/to/cyber-project
source .venv/bin/activate        # 激活虚拟环境
python --version                 # 确认 Python 3.11+
pip show pynacl cryptography     # 确认依赖已安装
```

### 5.2 清理旧数据（每次演示前执行）

```bash
rm -f server/relay.db            # 清空数据库
rm -rf ~/.e2ee/alice ~/.e2ee/bob  # 清空本地密钥
```

### 5.3 打开四个终端（推荐标签式终端）

| 标签 | 用途 |
|------|------|
| **T0 — Server** | 运行 uvicorn relay 服务器 |
| **T1 — Alice** | Alice 的所有操作 |
| **T2 — Bob** | Bob 的所有操作 |
| **T3 — Attacker** | 攻击演示（重放 / 篡改 / 泄露密钥） |

---

## 6. Presentation 演示脚本（逐步说话稿）

### 第 0 步 — 启动服务器（T0）

```bash
uvicorn server.main:app --host 127.0.0.1 --port 8000 --reload
```

> **说话稿**："我们先启动中继服务器。它是一个 FastAPI 服务，使用 SQLite 存储公钥和密文。注意它存储的永远不会是消息明文。"

健康检查：
```bash
curl http://localhost:8000/health
# → {"status":"ok"}
```

---

### 第 1 步 — 注册与登录（演示 Phase 1）

**T1 — Alice：**
```bash
python -m client.cli register --user alice --password alice123
python -m client.cli login    --user alice --password alice123
```

**T2 — Bob：**
```bash
python -m client.cli register --user bob --password bob123
python -m client.cli login    --user bob --password bob123
```

> **说话稿**："注册时，客户端在本地生成三对密钥（Ed25519 签名密钥、X25519 身份 DH 密钥、X25519 签名预密钥），只把**公钥**上传到服务器。私钥存在 `~/.e2ee/` 目录，权限 0600，从不离开本地。密码用 bcrypt 哈希存储，服务器不保存明文密码。"

查看服务器存的公钥：
```bash
python -m client.cli keys --user alice --peer bob
```

> **说话稿**："可以看到服务器返回的是 Bob 的公钥束（`IK_dh_pub`、`SPK_pub`、`SPK_sig`）。服务器就充当一个'公钥目录服务'。"

---

### 第 2 步 — 建立加密会话（演示 Phase 2 — X3DH）

**T1 — Alice 发起握手：**
```bash
python -m client.cli connect --user alice --to bob
```

**T2 — Bob 接受握手：**
```bash
python -m client.cli listen --user bob
```

> **说话稿**："Alice 从服务器取回 Bob 的公钥，在本地做三次 Diffie-Hellman 运算推导会话密钥 SK。临时密钥 EK 的私钥在推导完成后立即被随机覆写并置零销毁——这是前向保密的基础。握手包含 Alice 用自己 Ed25519 密钥签名的 transcript，服务器无法伪造合法握手。Bob 镜像计算，得到与 Alice **完全相同**的 SK，整个过程服务器**从不接触 SK**。"

---

### 第 3 步 — 加密消息收发（演示 Phase 3）

**T1 — Alice 发送消息：**
```bash
python -m client.cli send --user alice --to bob --msg "Hello Bob! This is secret."
```

**T2 — Bob 接收并解密：**
```bash
python -m client.cli recv --user bob
# → [alice] Hello Bob! This is secret.
```

> **说话稿**："Alice 用 SK 和 XChaCha20-Poly1305 AEAD 算法加密消息，同时把 `session_id`、发送方、接收方、序列号 `seq` 作为关联数据（Associated Data）绑定在密文里。Bob 解密时自动验证这些字段，确保消息来自合法会话、且未被篡改。"

**验证服务器只存密文（T0 或 T3）：**
```bash
sqlite3 server/relay.db "SELECT ciphertext FROM messages LIMIT 1;"
```

> **说话稿**："可以看到数据库里存的是 base64 编码的密文，**没有任何明文**。即使服务器被攻破，攻击者拿到的也只是无法解读的密文。"

---

### 第 4 步 — 安全攻击演示

#### 4a — 重放攻击（演示 SR4）

> **说话稿**："我们来演示重放保护。攻击者截获了 Alice 的 seq=1 消息，尝试再次发送。"

运行重放测试：
```bash
pytest tests/test_phase3_acceptance.py::test_replay_rejected -v -s
# → [REJECT] Duplicate or out-of-order seq
```

> **说话稿**："Bob 客户端检测到 seq 号重复，直接拒绝该消息。这防止了攻击者把历史消息重新注入会话。"

#### 4b — 篡改攻击（演示 SR2）

```bash
pytest tests/test_phase3_acceptance.py::test_aead_tampering_rejected -v -s
# → [REJECT] AEAD authentication failed
```

> **说话稿**："攻击者翻转密文中的一个比特，AEAD 认证标签立即失效，解密直接抛出异常，被应用层拦截并报告。"

#### 4c — 伪造消息攻击（演示 SR3）

```bash
pytest tests/test_phase3_acceptance.py::test_unauthorized_post_rejected -v -s
# → HTTP 401/403
```

> **说话稿**："没有合法 JWT token 的请求直接被服务器拒绝，不进入任何业务逻辑。"

---

### 第 5 步 — 前向保密演示（Bonus B1）

```bash
pytest tests/test_security.py::test_leaked_longterm_key_cannot_decrypt -v -s
```

> **说话稿**："这个测试模拟了最坏情形：Alice 的长期身份私钥 `IK_dh` 泄露给攻击者。攻击者利用该私钥只能重算 DH3，但 DH1 和 DH2 需要已被销毁的临时密钥 EK，所以 HKDF 输入残缺，推导出的 SK 与真实 SK 不同，历史密文无法解密。Bob 用真实 SK 依然可以正常解密——这就是前向保密。"

---

### 第 6 步 — 恶意服务器 Safety Number（Bonus B2）

**T1 — Alice 查看 safety number：**
```bash
python -m client.cli safety-number --user alice --peer bob
# → Safety Number: XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX
```

**T2 — Bob 查看 safety number：**
```bash
python -m client.cli safety-number --user bob --peer alice
# → Safety Number: XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX
```

> **说话稿**："两侧输出的 40 位数字完全一致。这个数字是两人 `IK_dh` 公钥的 SHA-256 指纹，字典序排序保证顺序无关。如果恶意服务器替换了 Bob 的公钥，Alice 这边的指纹就会包含攻击者的公钥，两侧数字**不同**，用户通过电话一比对就能发现。"

MITM 检测演示：
```bash
pytest tests/test_phase5_acceptance.py::test_mitm_substitution_detected -v -s
```

> **说话稿**："测试自动模拟服务器替换公钥的场景，两侧 safety number 明显不同，证明攻击**可被检测**。"

---

### 第 7 步 — 运行全套自动化测试（演示代码质量）

```bash
pytest tests/ -v
```

> **说话稿**："最后运行全部 15 个验收测试，覆盖 Phase 2 到 Phase 5 的所有安全属性，全部通过，没有跳过或失败项。"

期望输出：
```
15 passed in ~12s
```

---

## 7. 常见问题与应急处理

### Q1：`Connection refused` — 服务器没启动

```bash
# 确认服务器进程
lsof -i :8000
# 重新启动
uvicorn server.main:app --host 127.0.0.1 --port 8000
```

### Q2：`Login failed: Invalid credentials`

```bash
# 数据库可能是旧数据，重置
rm -f server/relay.db
# 重新注册 alice 和 bob
```

### Q3：`Session not found` — 会话文件丢失

```bash
rm -rf ~/.e2ee/alice ~/.e2ee/bob
# 重新走 register → login → connect/listen 流程
```

### Q4：`ModuleNotFoundError: No module named 'client'`

```bash
# 必须用 -m 模式运行，不能直接 python client/cli.py
python -m client.cli <command>
```

### Q5：测试失败，但单独运行 CLI 正常

```bash
# 测试使用独立数据库和随机用户名，重置数据库后重跑
rm -f server/relay.db
pytest tests/ -v
```

---

## 附录 — CLI 命令速查

```
python -m client.cli <command> [options]

  register      --user USER --password PASS     注册新用户
  login         --user USER --password PASS     登录，获取 JWT
  keys          --user USER --peer PEER         查看对方公钥束
  connect       --user USER --to PEER           发起 X3DH 会话（Alice 侧）
  listen        --user USER                     接受待处理会话（Bob 侧）
  send          --user USER --to PEER --msg MSG 加密发送消息
  recv          --user USER                     拉取并解密消息
  safety-number --user USER --peer PEER         显示 safety number
```
