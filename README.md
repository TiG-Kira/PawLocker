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

credential-provider/   Windows 凭据提供程序（C++17，需 MSVC 单独构建）
  include/     与 Kotlin 侧共用的契约（CLSID / 事件名 / 管道名 / 凭据块格式）
  src/         ICredentialProvider 实现、具名事件看门狗、命名管道取凭据
  build.bat    vswhere + vcvars64 + cl，不依赖 CMake

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

**解锁四层防护**：

1. ECDSA 签名 —— 来源认证
2. **绑定链核对** —— 目标 Windows 账户必须是本机当前账户
3. 时间戳 + 单调计数器 + nonce —— 新鲜性，挡重放
4. AES-256-GCM —— 机密性，AAD 覆盖元数据

签名覆盖密文（encrypt-then-sign），AAD 覆盖  
`version | deviceId | targetUserSid | counter | requestedAt | nonce`。

### 三元绑定链：设备 + Windows 账户 + 手机

信任链上串着三样东西，**任何一环对不上都不解锁**：

```
[电脑设备] ──── [Windows 账户] ──── [手机设备]
```

少了中间那一环会出这种事：家里电脑上有「Kira」和「孩子」两个账户，  
给「Kira」配对的手机会把「孩子」的账户一起解开 —— 因为信任记录只绑了设备。

账户因此出现在四个地方，层层递进：

| 位置 | 作用 |
| --- | --- |
| HKDF 的 salt | 为账户 A 派生的密钥在**密码学上**解不开账户 B 的指令，不依赖任何一方的自觉检查 |
| `PairingOffer` / `ServerHello` | 手机明确知道自己配的是哪个账户；用户能看到「正在与 书房主机 · Kira（S-1-5-21-…）配对」 |
| `PairRequest` / `PairResponse` | 配对窗口期内账户被切换过就中止，不会记下错绑定 |
| `UnlockRequest.targetUserSid` | 进 AAD 与签名，电脑端拿本机**真实**账户比对；对不上整条拒绝，且**不消耗**防重放计数额度 |

账户标识用 SID（`S-1-5-21-…-RID`，改账户名也不变）而不是账户名；  
极小概率取不到 SID 时退化为 `name:<账户名>`，前缀保证两种形态永远不会意外相等。  
取不到账户名则绑定键为 `name:`，它匹配不上任何正常账户 —— 只会拒绝，不会误开。

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
| 信任 DLL 的代码签名证书（选了凭据提供程序才出现） | 是     |
| 开机自动运行（可选）              | 否     |

每一项都会单独弹 UAC、单独征求同意，**任何一项都可以跳过**。  
跳过不会让程序不可用，只是功能不全，之后随时能在设置页补。

采用「按操作提权」而不是「整个程序以管理员运行」——  
主程序始终是普通用户权限，这是最小权限原则的直接体现。

### 为什么要单独有一步「信任签名证书」

`注册凭据提供程序` 只是往注册表里写了条目，**不等于 Windows 愿意加载它**。  
`LogonUI` 只加载证书受信任的签名组件，而拒绝发生在锁屏进程内部 ——
桌面上不会有任何报错，唯一的现象是「手机点了解锁，电脑没反应」。

所以向导在 DLL 注册好之后会多走两步：

1. **DLL 没签名** → 列出 `credential-provider` 下该敲的命令（签名要用 MSVC 工具链在仓库里做，应用内做不了，所以**不给按钮** —— 给一个点了没用的按钮比不给更糟）；
2. **签了名但证书不受信任** → 把证书信息（主体、指纹、有效期）摊开给用户看，再给一个「信任这张证书」的按钮。

第二点里有几个刻意的设计：

- **不需要用户去找 `.cer` 文件**。证书就嵌在 DLL 的 Authenticode 签名里，直接从 `Get-AuthenticodeSignature` 取出来写进存储。少一步「请找到某个文件」的引导，就少一整类「找错了文件」的问题。
- **写的是 `LocalMachine\Root` + `LocalMachine\TrustedPublisher`**，不是 `CurrentUser`。DLL 由 `LogonUI.exe` 加载，它跑在 SYSTEM 上下文，看不到当前用户的证书存储 —— 只信任给当前用户，在锁屏上依然会失败。
- **信任前先把要信任的对象摆出来**。机器级的证书信任是最不该盲签的东西：此后任何用这张证书签名的程序都会被这台电脑认作可信，而开发证书的私钥就在本机。界面必须让用户看清签的是什么。
- **成败以重新探测的结果判定**，不看提权进程的退出码。退出码只说明「脚本跑完了」，不说明「签名真的通过了校验」。

同一组操作在设置页的「Windows 注册状态」里也有一行（已就绪 / 待处理），可以单独重做或撤销。

> 换成正式发布用的代码签名证书（CA / EV）后，这一步根本不需要 —— 证书由公共 CA 签发，系统天然信任。
> 见 [credential-provider/README.md §6](credential-provider/README.md#6-代码签名)。

### 解锁策略

| 策略                    | 能做到什么      | 需要什么                                          |
| --------------------- | ---------- | --------------------------------------------- |
| `CREDENTIAL_PROVIDER` | **真正完成登录** | `PawLockerProvider.dll`（已实现，需本机用 MSVC 构建一次） |
| `WAKE_ONLY`           | 只点亮显示器     | 无                                             |
| `CUSTOM_COMMAND`      | 执行自定义命令    | 无                                             |
| `DRY_RUN`             | 只记日志，零系统影响 | 无                                             |

后三条开箱即用。

### 凭据是怎么送到锁屏的

DLL 跑在 LogonUI（SYSTEM 上下文）里，解不开 `%APPDATA%` 下那份**用户作用域**的 DPAPI 密文；  
换成机器作用域能让它解开，代价是同机任何进程都能解开 —— 对远程解锁来说不可接受。

所以走**现投**，顺序不能换：

```
1. 主程序 CreateNamedPipe     ← 先把管道挂起来
2. 主程序 SetEvent            ← 再叫醒 DLL
3. DLL CreateFile 连上，取凭据  ← 取到即用，写完立刻清零
```

先建管道再置事件是必须的，反过来会出现「DLL 被叫醒了但管道还不存在」的竞态。  
结果是**磁盘上永远不存在一份机器可解的密码副本**。

> **为什么锁屏不能直接注入按键**：锁屏界面跑在独立的安全桌面上，  
> 普通进程的 `SendInput` 会被系统丢弃。要真正完成登录，  
> 唯一官方扩展点是 Credential Provider —— 见  
> [credential-provider/README.md](credential-provider/README.md)。

## 构建

需要 JDK 17+（构建期可用更高版本，产物统一为 Java 17 字节码）  
与 Android SDK（compileSdk 37）。

```bash
# Android 调试包
./gradlew :androidApp:assembleDebug
# → androidApp/build/outputs/apk/debug/androidApp-debug.apk

# Android 正式包（R8 压缩 + 混淆 + 签名）
./gradlew :androidApp:assembleRelease
# → androidApp/build/outputs/apk/release/androidApp-release.apk

# Windows MSI 安装包
./gradlew :windowsApp:packageMsi
# → windowsApp/build/compose/binaries/main/msi/PawLocker-1.0.0.msi

# 校验打包出的 runtime 真的够用（见下文「Windows MSI 安装包」）
tools/check-runtime-modules.sh

# 只编译，不打包
./gradlew :core:compileKotlinDesktop :ui:compileKotlinDesktop :windowsApp:compileKotlin

# 单元测试（229 个用例）
./gradlew :core:desktopTest
```

### release 包的签名

签名凭据放在 `androidApp/keystore.properties`（**已被 gitignore**），
不要写进 `build.gradle.kts` —— 后者会被提交，密码写进去等于公开。

```bash
cp androidApp/keystore.properties.example androidApp/keystore.properties
# 然后填入 storeFile / storePassword / keyAlias / keyPassword
```

两条刻意的行为约定：

- **没有** `keystore.properties` → 构建照常跑通，产物是 `-unsigned.apk`。
  这样 clone 下来的人与没配密钥的 CI 都能出包。
- **有** `keystore.properties` 但密钥库文件找不到 → 构建**直接失败**。
  不做静默降级：一个「看着正常、其实没签名」的 release 包，
  只有在用户安装时才会暴露问题，代价比构建失败大得多。

签名方案是 v2 + v3（v1 已关）。**v3 别关** —— 它带密钥轮换信息，
是将来万一要换签名密钥时唯一的退路。

签完可以用 Android SDK 的 `apksigner` 核对：

```bash
"$ANDROID_HOME/build-tools/<版本>/apksigner" verify --verbose --print-certs \
    androidApp/build/outputs/apk/release/androidApp-release.apk
```

### Windows MSI 安装包

产物约 64 MB，装完约 126 MB，结构是 `PawLocker.exe` + `app/`（72 个 jar）
+ `runtime/`（jlink 裁剪过的 JRE）。三件容易踩的事：

**WiX 不用自己装，但必须是 3.x。** jpackage 在 Windows 上出 MSI 要靠 WiX 的
`candle.exe` / `light.exe`，Compose 的 `downloadWix` 任务会自己去拉
（本项目落在 `build/wix311`）。注意只认 **WiX 3.x** —— WiX 4/5 只提供 `wix.exe`，
jpackage 不支持，装了也没用。

**`upgradeUuid` 一旦发布就不能改。** Windows Installer 靠它判断「装的是同一产品的
新版本」还是「另一个产品」。改了之后旧版本不再被识别为可升级，用户会看到两个
PawLocker 并存，而且不先卸载旧版直接装新版会**安装失败**。

**图标由脚本生成，不是手工素材。**

```bash
python tools/generate-icons.py
# → windowsApp/icons/pawlocker.ico（7 个尺寸）+ pawlocker-1024.png
```

只依赖 Pillow。图形含义是「肉垫中央挖出钥匙孔」——爪印代表手机侧的口令，
钥匙孔代表要开的那把锁。改形状或配色请改脚本里的常量重跑，
不要直接编辑产出的 `.ico`（下次重跑就覆盖了）。

#### 运行时模块会被 jlink 裁掉，这件事必须验

打包用的 runtime 被 jlink 裁到只剩 7 个模块。而 Gradle 的测试跑在**完整 JDK** 上，
装进 MSI 的应用跑在**裁剪 runtime** 上 —— 两者不等价，差异只在安装后才暴露。

```bash
./gradlew :windowsApp:packageMsi   # 先出包，runtime 才会生成
tools/check-runtime-modules.sh
```

脚本从打包出的 `runtime/release` 里读模块清单，再用 `--limit-modules`
构造出等价条件，把 JNA / ECDH / ECDSA / AES-GCM / HKDF / SecureRandom 跑一遍。
**模块清单是读出来的，不是写死的**，所以不会随 Compose 升级而悄悄失效。

重点盯 `jdk.crypto.ec`：ECDH 与 ECDSA 的实现不在 `java.base` 里，而是
`jdk.crypto.ec` 提供的 Service Provider。它通过 ServiceLoader 加载，
**`jdeps` 静态分析看不见**，所以 Compose 自带的 `checkRuntime` 任务也查不出来。
一旦被裁，`KeyPairGenerator.getInstance("EC")` 会在运行期抛
`NoSuchAlgorithmException` —— 配对整个废掉，且只在安装版复现。

### 凭据提供程序（原生组件）

凭据提供程序是原生组件，走独立的构建脚本（需要 VS 的「使用 C++ 的桌面开发」工作负载）：

```bat
credential-provider\build.bat
rem → credential-provider\build\PawLockerProvider.dll
```

### 代码签名

Windows **不强制**凭据提供程序签名，但未签名的 DLL 会被 WDAC / AppLocker /
Smart App Control 拦在锁屏之外，而且签名是发现「DLL 被替换」的唯一手段。

```bat
credential-provider\sign.bat devcert   rem 造一张自签名开发证书（私钥不可导出）
credential-provider\sign.bat sign      rem SHA256 + RFC3161 时间戳
credential-provider\sign.bat trust     rem 装进 LocalMachine 信任（弹 UAC）
credential-provider\sign.bat verify    rem Successfully verified
```

> 信任必须装在 **`LocalMachine`** 而不是 `CurrentUser`：DLL 跑在 LogonUI，
> 也就是 SYSTEM 上下文，看不到当前用户的证书存储。
> 装错地方的现象是「提权窗口里校验通过、锁屏上依然没磁贴」。

自签名证书只适合自用验证，过不了 SmartScreen；对外分发需要 CA / EV 证书，
用 `sign.bat cert <指纹>` 换证书即可。细节见
[credential-provider/README.md §6](credential-provider/README.md#6-代码签名)。

## 文档

- [总体架构](docs/01-architecture.md)
- [加密体系与配对流程](docs/02-crypto-and-pairing.md)
- [内网穿透与端口配置](docs/03-tunnel-and-ports.md)
- [两端交互细节](docs/04-interaction.md)
- [凭据提供程序契约](credential-provider/README.md)

## 状态

compilable and testable 的部分都已完成并**通过编译与单元测试**：

- core 层：密码学、协议、配对、解锁、防重放、三元绑定链 —— 229 个用例全绿
- 两端界面（Miuix）：设备页、配对页、管理页、设置页、首次启动向导
- **原生凭据提供程序**：能出现在锁屏、挂进 Winlogon 登录流程，收到授权后自动提交
  （`ICredentialProvider` / `ICredentialProviderCredential2` / `ICredentialProviderSetUserArray`）
- 凭据投递通道：命名管道现投，磁盘上不留机器可解副本
- **Windows MSI 安装包**：`packageMsi` 可直接出包，含 7 个尺寸的图标、
  稳定的 `upgradeUuid`、perMachine 安装；打包出的 runtime 已用
  `tools/check-runtime-modules.sh` 验证过模块充分性

尚未做的：

- **真机端到端验证** —— 目前只过了编译器与单元测试，从未在真实锁屏上跑过一轮完整解锁
- **MSI 与 exe 的代码签名** —— 签名工具链已有（`credential-provider/sign.bat`），
  但安装包本身还没签：SmartScreen 会拦，而且 UIAccess 要求可执行文件已签名
- 托盘常驻与「关掉窗口仍继续服务」—— 需要把 `LockerServer` 挪进 Windows 服务
- 凭据提供程序的注册仍走 `reg.exe` + 落盘 `.reg` 文件，待提权路径与其他操作统一
  （见 [credential-provider/README.md §6.4](credential-provider/README.md)）

## 许可证

[Apache License 2.0](LICENSE)
