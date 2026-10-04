# PawLocker 总体架构

> 手机（Android）远程解锁 Windows 电脑。基于内网穿透打通网络，指令端到端加密。

---

## 1. 名词表

| 词 | 含义 |
|---|---|
| **电脑端 / Windows 端** | 被解锁的一方。持有私钥、监听端口、维护信任列表、执行解锁 |
| **手机端 / Android 端** | 发起解锁的一方。持有私钥、做生物识别、发加密指令 |
| **配对** | 双方交换公钥、协商长期共享密钥的过程。**只在电脑已登录且用户在场时进行** |
| **解锁指令** | 手机在通过生物识别后签发的一条加密报文 |
| **信任记录** | 一条配对关系的落盘形式，含对方公钥、共享密钥、计数器基线 |
| **配对码** | 配对时电脑屏幕上显示的 6 位数字，是整条信任链唯一的带外信任锚 |

---

## 2. 仓库结构

```
PawLocker/
├── core/          纯 Kotlin：密码学、协议、传输、配置、信任存储（可单测，不含 UI）
│   ├── commonMain/   协议状态机、HKDF、Base64Url、报文定义、防重放、TCP 抽象
│   ├── androidMain/  AndroidKeyStore 实现、应用私有目录存储、TCP 实现
│   └── desktopMain/  DPAPI 实现、frpc 进程托管、Windows 解锁执行器、TCP 实现
│
├── ui/            Compose Multiplatform + Miuix：两端共用的界面层
│   ├── commonMain/   主题、组件、页面、状态持有者
│   ├── androidMain/  BiometricPrompt、CameraX 扫码、二维码渲染
│   └── desktopMain/  二维码渲染（Skia）、桌面占位实现
│
├── androidApp/    Android 应用壳（Application / MainActivity / Manifest / 资源）
└── windowsApp/    Windows 应用壳（Compose Desktop application / MSI 打包配置）
```

### 为什么这样切

- **core 与 ui 分离**：密码学与协议可以脱离 Compose 单测，也便于将来做安全审计时只审 `core`
- **androidMain / desktopMain 分离**：两端跑的都是 JVM，但**密钥存放方式完全不同**，
  这恰恰是安全模型里最关键的一环，必须显式分开而不是靠 `if (isAndroid)` 糊起来
- **androidApp / windowsApp 只是壳**：真正的逻辑全部在上面两层，壳里只有平台入口与打包配置

---

## 3. 部署形态

```
┌─────────────────────────────┐                ┌─────────────────────────────┐
│        Android 手机          │                │        Windows 电脑          │
│                             │                │                             │
│  ┌───────────────────────┐  │                │  ┌───────────────────────┐  │
│  │ DeviceSideController  │  │                │  │ AdminSideController   │  │
│  │  · 设备列表            │  │                │  │  · 管理页 / 登录窗口    │  │
│  │  · 生物识别门          │  │                │  │  · 配对确认框          │  │
│  └──────────┬────────────┘  │                │  └──────────┬────────────┘  │
│             │               │                │             │               │
│  ┌──────────▼────────────┐  │                │  ┌──────────▼────────────┐  │
│  │     LockerClient      │  │                │  │     LockerServer      │  │
│  │  握手 / 配对 / 解锁     │  │                │  │  监听 9898 / 验签 / 解密 │  │
│  └──────────┬────────────┘  │                │  └──────────┬────────────┘  │
│             │               │                │             │               │
│  ┌──────────▼────────────┐  │   加密 TCP      │  ┌──────────▼────────────┐  │
│  │  IdentityKey (P-256)  │──┼───────────────►│  │  IdentityKey (P-256)  │  │
│  │  AndroidKeyStore      │  │  9898 / 隧道    │  │  DPAPI 保护的 PKCS#8   │  │
│  └───────────────────────┘  │                │  └──────────┬────────────┘  │
│                             │                │             │               │
│  ┌───────────────────────┐  │                │  ┌──────────▼────────────┐  │
│  │ TrustStore（AES 包裹）  │  │                │  │  UnlockExecutor       │  │
│  └───────────────────────┘  │                │  │  CP / 唤醒 / 自定义命令  │  │
└─────────────────────────────┘                │  └───────────────────────┘  │
                                               └─────────────────────────────┘
```

---

## 4. Windows 端进程模型

当前交付是一个 **Compose Desktop 应用**，内部结构：

```
windowsApp:Main
  └─ ComputerApp
       ├─ LockerServer        ← 持有 9898 监听，处理所有网络与密码学
       ├─ AdminSideController ← ServerHooks 实现，把「需要人类介入」的两件事桥接到 UI
       └─ UnlockExecutor      ← 唯一的平台动作执行点
```

### 端口占用与生命周期

服务在管理窗口存活期间运行。关掉窗口 = 停止服务。

要做到「窗口关了也继续服务」，正确的演进方向是：

```
PawLockerService.exe   以 SYSTEM 身份注册为 Windows 服务
   ├─ 持有 9898 端口与 LockerServer
   ├─ 独占访问 DPAPI 加密的信任列表
   └─ 通过本地命名管道接收 UI 的指令

PawLockerUI.exe        普通用户权限
   └─ 通过命名管道读写状态、开关配对窗口
```

拆成服务的好处不只是「关窗口不掉线」：**服务以 SYSTEM 运行才能和锁屏界面
（安全桌面）交互**，这是下一节 Credential Provider 路线的前提。

---

## 5. Windows 登录集成 —— 三条路径

这是整个项目最容易踩坑的地方，先说清楚为什么难：

> Windows 的锁屏界面跑在一个**独立的安全桌面（Winlogon desktop）**上。
> 普通进程（哪怕是管理员）既不能对它发 `SendInput`，也读不到它的窗口。
> 想在锁屏界面上做交互，程序必须以 **UIAccess** 身份运行**并被代码签名**，
> 或者以 **Credential Provider** 的形式由 Winlogon 直接加载。

所以本应用提供三条路径，而不是假装一条能通吃：

### 路径 A：Credential Provider（真正能完成登录）

- **交付物**：`PawLockerProvider.dll`，用 C++ 实现 `ICredentialProvider` /
  `ICredentialProviderCredential`，注册到 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{GUID}`
- **JVM 侧的配合**（本仓库已实现）：
  1. `WindowsCredentialStore` 用 DPAPI 保存「账户 + 密码」
  2. 收到合法解锁指令后，`WindowsUnlockExecutor` 执行
     `OpenEvent(0x0002, false, "Global\\PawLocker.Unlock.<用户名>")` + `SetEvent`
- **DLL 侧的契约**：
  1. 启动时 `CreateEvent(NULL, FALSE, FALSE, L"Global\\PawLocker.Unlock.<用户名>")`
  2. 用户点击 PawLocker 磁贴后 `WaitForSingleObject` 等待该事件（带超时）
  3. 事件置位 → 从 `%APPDATA%\<用户>\PawLocker\secure\windows-credential.json`
     读取并 DPAPI 解密凭据
  4. `SetStringField(CREDUI_USERNAME_FIELD_INDEX, ...)` /
     `SetStringField(CREDUI_PASSWORD_FIELD_INDEX, ...)` 后返回
     `S_OK` 让 LogonUI 提交
- **代价**：需要代码签名证书（EV 证书最好，普通 OV 也行）才能让 Winlogon 加载

### 路径 B：仅唤醒屏幕（零依赖，立即可用）

- `User32.SendInput` 注入一次相对鼠标位移，唤醒显示器 / 退出屏保
- 作用于**用户桌面**，不需要 UIAccess，因此对已登录但息屏的会话有效
- **对已锁屏的会话无效** —— 这是系统边界，不是实现缺陷

### 路径 C：自定义命令（最灵活）

- 收到解锁指令时执行用户配置的命令，`{action}` 会被替换成 `unlock` / `wake` / `lock`
- 适合已经自建了解锁方案、或者接了第三方工具的场景
- 退出码 0 视为成功

> **默认值**：`DRY_RUN`（仅记录日志）。这样首次部署时可以不装任何东西先验证
> 「手机 → 电脑」的完整链路是否打通，确认无误后再切到路径 A。

### 为什么不用「自动输入密码」

市面上有些工具宣称「自动帮你输密码」，本质是：
1. 以 UIAccess 运行 + 代码签名 → 等价于路径 A 的签名门槛
2. 或者通过 `LogonUser` 创建新会话 → 那不是「解锁当前会话」，用户会看到桌面被切走

两条都不是更优解。本仓库选择把边界讲清楚，而不是给一个在锁屏场景下静默失败的实现。

---

## 6. Android 端进程模型

```
androidApp:MainActivity (FragmentActivity)
  └─ PhoneApp
       ├─ 设备列表页（默认页）
       ├─ 设备详情页
       ├─ 配对页（扫码 / 手动）
       └─ 设置页
```

- 单 Activity + 状态驱动导航。屏幕轮转时状态量很小（一个设备列表 + 一个操作进度），
  重新从 `TrustStore` 读一次即可，没有需要跨配置变更保留的复杂中间态
- **`FragmentActivity` 是硬性要求**，`BiometricPrompt` 的构造函数只接受它
- 相机权限**按需申请**：只有进入配对页的扫码模式才申请，不在启动时索取

---

## 7. 状态与线程模型

| 层 | 线程/协程 | 说明 |
|---|---|---|
| Compose UI | Main | 只读状态、派发事件 |
| `*Controller` | Main（通过 `rememberCoroutineScope`） | 持有 `mutableStateOf`，发起异步任务 |
| `LockerServer` / `LockerClient` | `Dispatchers.Default` / `IO` | 网络与密码学运算 |
| `Transport` | `Dispatchers.IO` | 阻塞式 Socket 读写 |

所有网络操作都不在 Main 线程上执行。UI 永远不会被 IO 卡住。

---

## 8. 扩展点

| 想改什么 | 改哪里 |
|---|---|
| 换曲线 / 换密码学后端 | 实现新的 `PlatformCrypto` + `IdentityKey` actual |
| 换内网穿透方案 | 实现新的 `TunnelLauncher`，或直接手动填地址 |
| 换解锁方式 | 实现新的 `UnlockExecutor`，在 `ComputerApp` 的 `createUnlockExecutor` 里注入 |
| 加新的指令类型 | 在 `UnlockAction` 加常量 + `UnlockExecutor` 里处理分支 |
| 换传输层（加 TLS / 换 WebSocket） | 替换 `Transport` 的 actual，协议层无感知 |
