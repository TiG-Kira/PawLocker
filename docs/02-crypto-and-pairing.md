# 加密体系与配对流程

> 这份文档回答两个问题：**两端怎么加密**、**配对怎么保证不被中间人劫持**。

---

## 1. 算法选型

| 用途 | 算法 | 参数 |
|---|---|---|
| 密钥协商 | ECDH | NIST P-256 (secp256r1) |
| 身份签名 | ECDSA | P-256 + SHA-256，DER 编码签名 |
| 对称加密 | AES-256-GCM | 96-bit 随机 nonce，128-bit tag |
| 密钥派生 | HKDF | SHA-256 |
| 完整性（回执） | HMAC | SHA-256 |
| 随机源 | CSPRNG | `SecureRandom`（Android 侧走 Conscrypt） |

### 为什么是 P-256 而不是 X25519 / Ed25519

1. **AndroidKeyStore 原生支持 P-256**，能把私钥放进 TEE / StrongBox 且不可导出；
   X25519 在 AndroidKeyStore 里至今没有等价支持
2. **JDK 8 起内置 P-256**，Windows 端不需要引入 BouncyCastle —— 少一个依赖就少一处供应链风险
3. Android API 26 全量覆盖，`minSdk` 不用为了密码学往上抬

代价是 P-256 的运算比 X25519 慢一个量级。但我们的调用频率是「一天几次」，
单次差几毫秒完全无所谓。

---

## 2. 密钥体系

三层密钥，生命周期与用途严格分开：

```
┌─────────────────────────────────────────────────────────────────┐
│ ① 身份密钥 IdentityKey（长期，随设备安装存活）                        │
│    · P-256 密钥对，私钥永不导出                                    │
│    · 公钥 = 设备身份。deviceId = SHA-256(pubKey) 前 16 字节         │
│    · 用途：ECDSA 签名（解锁指令）+ ECDH 协商（仅配对时）              │
│                                                                  │
│   Android：API 31+ 用 AndroidKeyStore 原生 EC 密钥（TEE/StrongBox） │
│            API 26–30 用软件密钥 + AndroidKeyStore AES 包裹          │
│   Windows：软件密钥，PKCS#8 经 DPAPI（当前用户作用域）封装落盘        │
└─────────────────────────────────────────────────────────────────┘
                              │ 配对时 ECDH
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ ② 配对数密钥 PairSecret（长期，每对设备一份）                        │
│    · encKey (32B) —— AES-256-GCM 数据加密密钥                     │
│    · macKey (32B) —— HMAC 回执完整性密钥                           │
│    · 派生：HKDF(ECDH共享秘密, salt=SHA256(winPub‖phonePub‖pairingId)) │
└─────────────────────────────────────────────────────────────────┘
                              │ 每条指令
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ ③ 单次 nonce（一次性，12 字节随机）                                 │
│    · 每条解锁指令独立生成，绝不复用                                 │
└─────────────────────────────────────────────────────────────────┘
```

`PairSecret.derive` 把双方公钥和 `pairingId` 一起塞进 salt，好处是：
即使两台不同手机与同一台电脑协商出了相同的共享秘密（理论上不该发生，但防御性编程），
派生出的密钥也不会相同。

---

## 3. 配对流程

### 3.1 带外信任锚

> **电脑屏幕上那 6 位配对码，是整条信任链唯一无法被网络攻击者伪造的东西。**

用户能同时看到电脑屏幕和手机屏幕，这个物理前提就是全部安全性的基础。
其余所有密码学机制，都是为了把这个前提「放大」成一条完整的加密信道。

### 3.2 二维码携带什么

```json
{
  "v": 1,
  "pairingId": "<16 字节随机数的 Base64Url>",
  "code": "428317",
  "computerDeviceId": "...",
  "computerDisplayName": "DESKTOP-KIRA",
  "computerPublicKey": "<65 字节未压缩点>",
  "endpoints": [
    { "kind": "LAN",    "host": "192.168.1.10", "port": 28900 },
    { "kind": "TUNNEL", "host": "frp.example.com", "port": 19898 }
  ],
  "expiresAt": 1730000000000
}
```

编码形式：`pawlocker://pair?d=<Base64Url(JSON)>`

**把配对码放进二维码会不会降低安全性？**
不会。能看到二维码的物理位置（电脑屏幕前）和能看到配对码的物理位置是同一个，
两者泄露风险等价，但扫码体验好得多。

### 3.3 完整时序

```
  电脑端                                                    手机端
    │                                                        │
    │ ① 用户在管理页点「添加手机」                                │
    │    生成 pairingId + 6 位配对码                            │
    │    展示二维码 / 亦可手抄 host:port + 码                    │
    │                                                        │
    │                       ② 扫码 或 手动输入                  │
    │◄───────────────────────────────────────────────────────│
    │                                                        │
    │  ── ClientHello { deviceId, publicKey, nonce } ──────►  │
    │  ◄─ ServerHello { serverTime, pairingOpen,             │
    │                   activePairingId, publicKey, ... } ──  │
    │                                                        │
    │                                        ③ 手机计算：       │
    │              K_code = HKDF(code, salt=pairingId,       │
    │                            info="pairing-protection")  │
    │              confirmTag = HMAC(K_code,                 │
    │                "confirm"‖winPub‖phonePub‖pairingId)    │
    │                                                        │
    │  ◄── PairRequest { pairingId, nonce,                   │
    │        ct = AES-GCM(K_code, nonce, {                   │
    │               phoneDeviceId, phonePublicKey,           │
    │               confirmTag, ... }, aad) } ─────────────  │
    │                                                        │
    │ ④ 电脑解密并校验 confirmTag                                │
    │    ✗ 不匹配 → 回 Error(pairing_code_mismatch)            │
    │    ✓ 匹配 → 回 PairPending，**弹出确认框**                 │
    │                                                        │
    │  ── PairPending ─────────────────────────────────────►  │
    │                                                        │
    │ ⑤ 用户在电脑上点「允许」                                    │
    │    compute S = ECDH(winPriv, phonePub)                 │
    │    derive  encKey / macKey                             │
    │    TrustStore.upsert(手机记录)                           │
    │                                                        │
    │  ── PairResponse { ct = AES-GCM(K_code, nonce, {       │
    │        accepted, windowsPublicKey,                     │
    │        serverConfirmTag, endpoints[] } ) } ──────────► │
    │                                                        │
    │                                        ⑥ 手机校验：       │
    │              AES-GCM 解密成功（证明对方有配对码）           │
    │              serverConfirmTag 匹配（证明公钥未被替换）      │
    │              两者都过 → 才做 ECDH → 存 TrustRecord        │
    │                                                        │
    │ ⑦ 两端各显示同一组 SAS emoji，用户肉眼比对                  │
    │    🐶 🍊 ⚽ 🦄  ←──────── 必须一致 ────────►  🐶 🍊 ⚽ 🦄  │
    │                                                        │
    └── 配对完成，长期密钥建立 ───────────────────────────────────┘
```

### 3.4 为什么这样能防住中间人

| 攻击 | 为什么失败 |
|---|---|
| **窃听** | `PairRequest` / `PairResponse` 的载荷由 `K_code` 加密，没有配对码连内容都读不到 |
| **替换公钥** | `confirmTag` 把 `winPub ‖ phonePub ‖ pairingId` 一起绑进 HMAC，改任何一位都导致对端校验失败 |
| **重放 A 的配对报文到 B 的会话** | `pairingId` 进了 HKDF 的 salt 和 AAD，跨会话直接解密失败 |
| **中继转发（relay）** | 攻击者只能转发密文，拿不到 ECDH 共享秘密；SAS 人眼比对是最后一道闸 |
| **暴力猜配对码** | 电脑端 `AuthThrottle` 单调退避：连续 5 次失败后按 2s → 4s → 8s … 最长 5 分钟封禁；6 位码需要 ~10⁶ 次尝试，在限流下不可行 |
| **会话复用** | 配对会话一次性：`ComputerPairingSession.consumed` 置位后同一会话直接拒绝 |

### 3.5 手动配对路径

用户只在手机上填「主机 + 端口 + 6 位码」。`pairingId` 与电脑公钥从 `ServerHello`
的 `activePairingId` / `publicKey` 字段拿。

**这不会降低安全性**：公钥本来就是公开信息，`pairingId` 也不是信任锚 ——
真正的门槛始终是那 6 位配对码。即使中间人伪造 `ServerHello` 塞进自己的公钥，
它也拿不到配对码，算不出正确的 `confirmTag`，手机端的校验会失败。

---

## 4. 解锁指令流程

### 4.1 报文结构

```json
{
  "t": "unlock",
  "deviceId": "<手机的 deviceId>",
  "counter": 42,
  "requestedAt": 1730000000000,
  "nonce": "<12 字节 Base64Url>",
  "ciphertext": "<AES-GCM 密文 + tag>",
  "signature": "<ECDSA DER 签名>"
}
```

其中：

```
aad         = "1|deviceId|counter|requestedAt|nonce"
signedBytes = aad ‖ ciphertext
ciphertext  = AES-256-GCM(encKey, nonce, {
                 action: "unlock",
                 issuedAt: <ms>,
                 clientDisplayName: "Kira 的 Pixel 8"
              }, aad = aad)
signature   = ECDSA(phoneIdentityPriv, SHA256(signedBytes))
```

### 4.2 三重防护的分工

| 层 | 手段 | 挡住什么 |
|---|---|---|
| **来源认证** | ECDSA-P256 签名（手机**身份私钥**，不是对称密钥） | 冒名顶替、伪造指令 |
| **机密性** | AES-256-GCM（配对时协商的 `encKey`） | 抓包、篡改载荷 |
| **新鲜性** | 时间戳 ±60s + 单调计数器 + nonce 去重 | 重放、录播攻击 |

签名用身份密钥而非对称密钥，是为了让 Windows 端**在解密之前**就能确认
「这条指令确实来自那台已配对的手机」—— 未通过验签的报文不会进入解密环节。

### 4.3 电脑端的校验顺序

```
① 按 deviceId 查信任记录         → 查不到：Error(device_not_trusted)
② 验 ECDSA 签名                  → 失败：  ack(ok=false, bad_signature)
③ 防重放三连：时间窗 / 计数器 / nonce → 失败：  ack(ok=false, replay_detected)
④ AES-GCM 解密                   → 失败：  ack(ok=false, decrypt_failed)
⑤ 执行解锁动作
⑥ 落盘推进后的计数器
⑦ 回 ack（带 HMAC(macKey) 签名）
```

顺序很关键：

- **先验签再解密**（encrypt-then-sign）：未认证的输入不会进解密器，
  掐断了 padding-oracle / 侧信道类攻击的前提
- **先防重放再执行**：计数器只在全部校验通过后才推进，
  被拒绝的报文不会污染状态，攻击者也无法靠发垃圾包把正常手机的计数器顶高
- **最后落盘计数器**：进程重启后从 `TrustRecord.lastCounter` 恢复基线，
  只要落过盘，旧指令就不能复活

### 4.4 回执也要验签

`UnlockAck` 带 `HMAC(macKey, "ack|1|ok|counter|serverTime")`。

手机端必须验。否则内网攻击者可以伪造一个 `{ok: true}` 的回执，
让用户**以为门开了**，但实际上指令根本没被处理 —— 这种「假成功」比明确的失败更危险。

### 4.5 完整时序

```
  手机端                                                      电脑端
    │                                                          │
    │ ① 用户点击「解锁」                                          │
    │                                                          │
    │ ② BiometricPrompt（指纹 / 面容 / 设备 PIN）                 │
    │    ✗ 取消 / 失败 → 流程终止，不发任何报文                     │
    │    ✓ 通过 ↓                                               │
    │                                                          │
    │ ③ counter = lastCounter + 1                               │
    │    nonce = random(12)                                     │
    │    ct = AES-256-GCM(encKey, nonce, payload, aad)          │
    │    sig = ECDSA(phonePriv, aad ‖ ct)                       │
    │                                                          │
    │  ── UnlockRequest ────────────────────────────────────►    │
    │                                                          │
    │                          ④ 查记录 → 验签 → 防重放 → 解密     │
    │                          ⑤ UnlockExecutor.execute()      │
    │                                                          │
    │  ◄─ UnlockAck { ok, counter, serverTime, mac } ────────   │
    │                                                          │
    │ ⑥ verifyAck(macKey, ack)                                  │
    │    ✗ 不匹配 → 提示「回执校验失败，连接可能被劫持」             │
    │    ✓ 匹配 → 更新 lastCounter，提示解锁成功                   │
    │                                                          │
```

---

## 5. 防重放细节

实现在 `core/protocol/ReplayGuard.kt`，纯内存 + 信任列表基线：

```kotlin
fun validate(deviceId, counter, timestampMillis, nonce, now): ReplayFailure?
```

1. **时间窗口**：`|now - timestamp| > 60s` → `ClockSkew`
2. **单调计数器**：`counter <= lastCounter[deviceId]` → `CounterRollback`
3. **nonce 去重**：保留 5 分钟内见过的 nonce（LRU 上限 2048 条）→ `NonceReused`

为什么三个都要？
- 只有时间窗 → 攻击者可以在 60 秒窗口内重放
- 只有计数器 → 手机重装 / 数据损坏导致计数器回滚时会永久锁死
- 只有 nonce → 缓存失效后无法防护

三者叠加后，**任何一条旧报文都无法再次生效**，即使攻击者拿到了完整的抓包记录。

---

## 6. 密钥存储

| 平台 | 存储位置 | 保护机制 |
|---|---|---|
| Android（API 31+） | AndroidKeyStore | 原生 EC 密钥，私钥不可导出，优先 StrongBox，退回 TEE |
| Android（API 26–30） | 应用私有目录 | 软件 P-256 私钥，由 AndroidKeyStore 里一把 TEE 保护的 AES-256-GCM 密钥包裹 |
| Android（信任列表 / 配置） | `filesDir/pawlocker/secure/` | 同一把 AES-256-GCM 包裹密钥加密，格式 `[1B 版本][12B IV][密文+tag]` |
| Windows（身份密钥 / 信任列表 / 配置） | `%APPDATA%\PawLocker\secure\` | DPAPI（当前用户作用域）+ `icacls` 收紧 ACL 到当前用户 |

### 为什么 Android 要分两档

AndroidKeyStore 直到 **API 31** 才支持 `PURPOSE_AGREE`（ECDH 密钥协商）
与 `PURPOSE_SIGN` 共用一把 EC 密钥。低于 31 时强行用原生密钥会导致配对直接失败，
所以退化方案是「软件密钥 + 硬件包裹」—— 安全性依然显著高于明文落盘。

---

## 7. 威胁模型

| 威胁 | 是否防护 | 说明 |
|---|---|---|
| 网络中间人（配对阶段） | ✅ | 6 位配对码 + HMAC 公钥绑定 + SAS 人眼比对 |
| 网络中间人（解锁阶段） | ✅ | ECDSA 签名 + AES-GCM |
| 抓包重放 | ✅ | 时间戳 + 计数器 + nonce |
| 伪造解锁成功回执 | ✅ | 回执带 HMAC |
| 偷走手机 | ✅ | 需要过生物识别才能签名；拿不到生物特征就签不出有效指令 |
| 偷走电脑上的信任列表文件 | ✅ | DPAPI / AndroidKeyStore 包裹，拷走也解不开 |
| 暴力猜配对码 | ✅ | `AuthThrottle` 指数退避封禁 |
| 内网扫描 28900 端口 | ⚠️ 部分 | 限流 + 版本校验 + 未配对直接拒绝；但端口本身可被探测到。建议用防火墙白名单或走虚拟组网 |
| **电脑已被物理控制 / 已 root** | ❌ | 不在威胁模型内。这是任何本地认证方案的共同边界 |
| **恶意软件在本机运行** | ❌ | 同上。DPAPI 保护的是「文件被拷走」，不是「同机进程」 |
| **用户主动交出配对码** | ❌ | 社会工程学无法用密码学解决 |

---

## 8. 传输层为什么不加 TLS

经过权衡后**不加**，理由：

1. 业务载荷已被端到端 AES-256-GCM 保护，密钥来自 ECDH，**不依赖传输层**
2. 主机地址是动态的（内网 IP / frp 域名 / 虚拟组网 IP），自签证书的轮换与固定非常难做
3. 引入 TLS 会让「证书不匹配」变成最常见的用户报错，收益却接近于零

如果部署环境有合规要求，可以在 frp 那一跳单独加 TLS（`transport.tls.enable = true`），
与协议本身不冲突 —— 生成配置里默认就是开的。

---

## 9. 协议报文一览

| 类型 | 方向 | 说明 |
|---|---|---|
| `hello` | 手机 → 电脑 | 握手，带手机公钥与设备信息 |
| `hello.ack` | 电脑 → 手机 | 服务端信息 + `pairingOpen` + `activePairingId` |
| `pair.request` | 手机 → 电脑 | 配对请求，载荷由 `K_code` 加密 |
| `pair.pending` | 电脑 → 手机 | 「已收到，等用户确认」，防止手机超时重试 |
| `pair.response` | 电脑 → 手机 | 配对结果 + 可达地址列表 |
| `unlock` | 手机 → 电脑 | 解锁指令（签名 + 加密 + 防重放） |
| `unlock.ack` | 电脑 → 手机 | 执行结果 + HMAC |
| `ping` / `pong` | 双向 | 保活 |
| `error` | 电脑 → 手机 | 统一错误码，见 `ErrorCodes` |

帧格式：`[4 字节大端长度][JSON]`，单帧上限 64 KiB。

所有二进制字段用 Base64Url 编码进 JSON —— 抓包可读、跨语言实现友好，
代价是约 33% 带宽开销，对几百字节的解锁指令完全可以忽略。
