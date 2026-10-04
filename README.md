# PawLocker

用手机解锁 Windows。手机做生物验证，电脑完成登录。

两端都用 [Miuix](https://github.com/YuKongA/Miuix)（Compose Multiplatform，HyperOS 设计语言）构建。

---

## 它解决什么问题

坐在电脑前，人在，但密码不想打 —— 或者电脑在锁屏，手机在身上。  
PawLocker 让手机变成一把钥匙：**指纹验证通过 → 电脑登录**。

链路是端到端加密的，电脑那边收到指令后要验签、查重放、解密，全过了才动作。

## 仓库结构

```
core/          协议 / 密码学 / 传输层 —— 纯 Kotlin，无 UI 依赖，可单测
  crypto/      P-256 ECDH、ECDSA、AES-256-GCM、HKDF-SHA256、密钥分级加载
  protocol/    报文定义、长度分帧、配对协议、解锁协议、防重放
  config/      配置模型、端点解析、frp 配置生成、解锁策略
  net/         TCP 传输、限流、服务端与客户端
  trust/       信任列表持久化
  platform/    expect/actual：DPAPI、AndroidKeyStore、Windows 注册表

ui/            Miuix 界面层，Android 与 Desktop 共用一套 Composable
  screens/     设备页、详情页、配对页、管理页、设置页、启动向导、登录窗口
  state/       两端的状态机（DeviceSideController / AdminSideController）
  theme/       单一根 MiuixTheme

androidApp/    Android 应用壳
windowsApp/    Windows 桌面应用（jpackage / MSI）

credential-provider/   Windows 凭据提供程序的接口契约（需 MSVC 单独构建）

docs/
  01-architecture.md       总体架构、进程模型、Windows 登录集成三条路径
  02-crypto-and-pairing.md 加密体系与配对流程（含完整时序图）
  03-tunnel-and-ports.md   内网穿透选型与端口配置
  04-interaction.md        两端交互细节
```

## 加密一览

| 用途    | 算法                           |
| ----- | ---------------------------- |
| 密钥协商  | NIST P-256 (secp256r1) ECDH  |
| 指令签名  | ECDSA-SHA256                 |
| 载荷加密  | AES-256-GCM                  |
| 密钥派生  | HKDF-SHA256（RFC 5869）        |
| 二进制编码 | URL-safe Base64（RFC 4648 §5） |

选 P-256 而不是 X25519 / Ed25519 的原因：AndroidKeyStore 原生支持、  
JDK 8+ 内置、Android API 26 起全量覆盖 —— 三端都不需要额外依赖。

**配对防中间人**：6 位配对码是唯一的带外信任锚。  
`confirmTag = HMAC(K_code, "confirm" ‖ winPub ‖ phonePub ‖ pairingId)`  
把双方公钥绑进受配对码保护的 HMAC —— 中间人必须同时伪造公钥和配对码才能通过。  
配对之后两端还会显示同一组 emoji（SAS），供肉眼二次确认。

**解锁三层防护**：

1. ECDSA 签名 —— 来源认证
2. 时间戳 + 单调计数器 + nonce —— 新鲜性，挡重放
3. AES-256-GCM —— 机密性，AAD 覆盖元数据

签名覆盖密文（encrypt-then-sign），AAD 覆盖  
`version | deviceId | counter | requestedAt | nonce`。

详见 [docs/02-crypto-and-pairing.md](docs/02-crypto-and-pairing.md)。

## 内网穿透

电脑端对外暴露 **TCP 9898**，三条通道按优先级依次尝试：

| 优先级 | 通道                             | 适用                |
| --- | ------------------------------ | ----------------- |
| 1   | **局域网直连**                      | 手机和电脑在同一 Wi-Fi    |
| 2   | **虚拟组网**（Tailscale / ZeroTier） | 两头都能装客户端，最省心，推荐   |
| 3   | **frp 反向代理**                   | 有公网服务器；不需要手机装任何东西 |

选 frp 而不是 UPnP 或 Cloudflare Tunnel：  
UPnP 会把这个端口暴露给整个局域网且不少路由器实现有洞；  
Cloudflare Tunnel 需要自有域名且走 HTTP 语义，对裸 TCP 不友好。

frp 的 `frpc.toml` 由程序自动生成，不内置 `frpc.exe` ——  
二进制由用户指定路径，避免把第三方产物打包进仓库。

详见 [docs/03-tunnel-and-ports.md](docs/03-tunnel-and-ports.md)。

## Windows 首次启动

**第一次运行会走一个注册向导**，因为 PawLocker 要在系统层面挂钩子：

| 会改动什么                   | 需要管理员 |
| ----------------------- | ----- |
| 放行监听端口（Windows 防火墙入站规则） | 是     |
| 注册凭据提供程序（可选，真正完成登录）     | 是     |
| 开机自动运行（可选）              | 否     |

每一项都会单独弹 UAC、单独征求同意，**任何一项都可以跳过**。  
跳过不会让程序不可用，只是功能不全，之后随时能在设置页补。

采用「按操作提权」而不是「整个程序以管理员运行」——  
主程序始终是普通用户权限，这是最小权限原则的直接体现。

### 解锁策略

| 策略                    | 能做到什么      | 需要什么                               |
| --------------------- | ---------- | ---------------------------------- |
| `CREDENTIAL_PROVIDER` | **真正完成登录** | `PawLockerProvider.dll`（需 MSVC 构建） |
| `WAKE_ONLY`           | 只点亮显示器     | 无                                  |
| `CUSTOM_COMMAND`      | 执行自定义命令    | 无                                  |
| `DRY_RUN`             | 只记日志，零系统影响 | 无                                  |

后三条开箱即用。

> **为什么锁屏不能直接注入按键**：锁屏界面跑在独立的安全桌面上，  
> 普通进程的 `SendInput` 会被系统丢弃。要真正完成登录，  
> 唯一官方扩展点是 Credential Provider —— 见  
> [credential-provider/README.md](credential-provider/README.md)。

## 构建

需要 JDK 17+（构建期可用更高版本，产物统一为 Java 17 字节码）  
与 Android SDK（compileSdk 37）。

```bash
# Android APK
./gradlew :androidApp:assembleDebug
# → androidApp/build/outputs/apk/debug/androidApp-debug.apk

# Windows MSI
./gradlew :windowsApp:packageMsi
# → windowsApp/build/compose/binaries/main/msi/

# 只编译，不打包
./gradlew :core:compileKotlinDesktop :ui:compileKotlinDesktop :windowsApp:compileKotlin
```

## 文档

- [总体架构](docs/01-architecture.md)
- [加密体系与配对流程](docs/02-crypto-and-pairing.md)
- [内网穿透与端口配置](docs/03-tunnel-and-ports.md)
- [两端交互细节](docs/04-interaction.md)
- [凭据提供程序契约](credential-provider/README.md)

## 状态

工程骨架、core 层、两端界面均已实现并**通过编译**。  
尚未做的：

- Windows 凭据提供程序（`PawLockerProvider.dll`）的原生实现 —— 契约已定，代码待写
- 单元测试（`core` 的密码学与协议部分已按可测试的方式分层）
- 托盘常驻与「关掉窗口仍继续服务」—— 需要把 `LockerServer` 挪进 Windows 服务

## 许可证

[Apache License 2.0](LICENSE)
