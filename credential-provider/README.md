# PawLocker 凭据提供程序（Credential Provider）

这个目录承载 **Windows 端「真正完成登录」的那块拼图**。

PawLocker 主程序（Kotlin / JVM）**无法**在锁屏界面注入键盘输入 —— 锁屏跑在
独立的安全桌面上，普通进程的 `SendInput` 会被系统丢弃。要真正完成登录，
必须挂进 Winlogon 的登录流程，而唯一的官方扩展点就是 **Credential Provider**。

本目录说明这个组件**必须实现什么**，以便它和已经实现好的 JVM 侧严丝合缝地对接。
本仓库不提供预编译的 `PawLockerProvider.dll` —— 它是需要 MSVC 单独构建的原生产物。

---

## 1. 它要解决的问题

```
[手机] ──加密解锁指令──▶ [PawLocker.exe :9898]
                              │ 验签 / 防重放 / 解密 全部通过
                              │
                              │ SetEvent("Global\PawLocker.Unlock.<用户名>")
                              ▼
                        [PawLockerProvider.dll]  ← 运行在 Winlogon 进程内
                              │ 收到事件，取出本机保存的凭据
                              │ 通过 ICredentialProviderCredential::GetSerialization 提交
                              ▼
                        [Winlogon] ──▶ 完成登录
```

关键分工：

| 环节 | 由谁负责 | 为什么 |
|---|---|---|
| 收指令、验签、防重放、解密 | JVM 侧（`LockerServer`） | 密码学逻辑只在 Kotlin 里写一份，避免两套实现走样 |
| 等待并响应系统登录请求 | CP DLL | 只有它能出现在锁屏界面上 |
| 实际提交凭据 | CP DLL | 只有它能拿到 `GetSerialization` 回调 |

**DLL 里不放任何密码学。** 它只做「收到信号 → 提交凭据」，
这样即使 DLL 被逆向，也拿不到与手机通信的能力。

---

## 2. 硬性契约

这些值必须与 JVM 侧一字不差，否则两端对不上。

### 2.1 具名事件

| 项 | 值 |
|---|---|
| 事件名 | `Global\PawLocker.Unlock.<用户名>` |
| 用户名 | 当前交互式登录的用户名（不含域前缀），即 `%USERNAME%` |
| 对象类型 | 手动重置事件（manual-reset event） |
| 创建方 | **CP DLL 创建**（`CreateEventW` with `CreateEventInitialOwner = FALSE`，安全描述符需允许普通用户 `EVENT_MODIFY_STATE`） |
| 触发方 | JVM 侧 `OpenEventW(EVENT_MODIFY_STATE, ...)` + `SetEvent` |

JVM 侧实现见 `core/src/desktopMain/.../platform/WindowsUnlockExecutor.kt`
（常量 `UNLOCK_EVENT_PREFIX`）。

之所以由 DLL 创建而不是主程序创建：DLL 在 Winlogon 进程里，
主程序可能在用户登录后才启动。事件必须**在锁屏阶段就已经存在**，
否则手机解锁请求会打空。

DLL 创建事件后应立即 `WaitForSingleObject` 并循环
`ResetEvent` → 触发一次凭据提交 → 重新等待。

### 2.2 COM 注册

| 项 | 值 |
|---|---|
| CLSID | `{6F3A1C48-9D2B-4E77-A5C1-8B0E4D7F2315}` |
| 显示名 | `PawLocker` |
| DLL 建议路径 | `C:\Program Files\PawLocker\PawLockerProvider.dll` |
| 线程模型 | `Apartment` |

> CLSID **不可更改**。已注册的机器会按这个 GUID 查找；改动会导致升级后
> 系统找不到自己的凭据提供程序。

注册表结构由 JVM 侧自动写入（见
`core/src/desktopMain/.../platform/WindowsRegistrar.desktop.kt`），
不需要手工 `regedit`：

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6F3A1C48-...}
    @ = "PawLocker"

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6F3A1C48-...}
    @ = "PawLocker 凭据提供程序"
    \InprocServer32
        @ = "C:\Program Files\PawLocker\PawLockerProvider.dll"
        ThreadingModel = "Apartment"
```

### 2.3 需要实现的 COM 接口

最小可用集合（V2 版凭据提供程序）：

- `ICredentialProvider` —— 枚举凭据、响应 `SetUsageScenario` 的 `CPUS_LOGON` / `CPUS_UNLOCK_WORKSTATION`
- `ICredentialProviderCredential`（或 V2）—— 
  - `SetSelected` / `SetDeselected` 控制磁贴状态
  - `GetSerialization` —— **提交凭据的唯一出口**，
    返回 `CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION`，
    其中 `rgbSerialization` 必须是 `KERB_INTERACTIVE_LOGON` 结构
    （`MessageType = KerbInteractiveLogon`），
    `ulAuthenticationPackage` 通过
    `Kerberos!Negotiate2` 或 `Kerberos!Kerberos` 查得
  - `Advise` 拿到 `ICredentialProviderCredentialEvents`，用于异步更新磁贴文字
  - `ReportResult` —— 登录成功/失败回调，在这里决定是保留磁贴还是收起

---

## 3. 必须遵守的安全约束

1. **不落盘明文凭据。** 从内存/DPAPI 取出后，用完立刻 `SecureZeroMemory`。
2. **只在收到事件后提交，不做任何其他触发。** 不要监听网络、不要读文件。
3. **磁贴标记为「需要用户在场」** 时不要用 —— 本场景下用户不在场，
   但这也意味着**手机侧的生物识别必须真的开启**，它是唯一的「人证」环节。
4. **DLL 必须被签名**，否则在启用 Secure Boot 的机器上
   无法进入锁屏界面（Winlogon 只加载受信任的模块）。
5. **不要复制 DLL 到系统目录**。JVM 侧的注册逻辑刻意只写注册表、
   不搬运文件 —— 往系统目录放文件应该是用户的决定。

---

## 4. 凭据从哪来

JVM 侧把 Windows 登录凭据（用户名 + 密码，或 PIN）用 **DPAPI** 加密后存在
`%APPDATA%\PawLocker\` 下，作用域为当前用户。

> **CP DLL 不能直接解密这个文件** —— 它跑在 Winlogon 进程（SYSTEM 上下文），
> 与用户 DPAPI 作用域不互通。

因此实际部署时有两条路：

| 方案 | 说明 | 取舍 |
|---|---|---|
| **A. 由主程序写入共享内存 / 具名管道** | DLL 在收到事件后向主程序索取凭据，主程序解密后经一次性通道交给 DLL | 需要为通道设计好 ACL，且主程序必须在运行 |
| **B. 用机器作用域 DPAPI + 额外加密** | `CRYPTPROTECT_LOCAL_MACHINE`，保护强度依赖附加的密钥派生 | 省事，但 SYSTEM 上下文可读，安全边界更弱 |

推荐 **A**。当前 JVM 侧已实现的是「写入 DPAPI 用户作用域」，
方案 A 的传输通道属于本目录要补的部分。

---

## 5. 构建

需要一个 C++ 工具链（Visual Studio 2022，含「使用 C++ 的桌面开发」工作负载）：

```bat
:: 需自行编写 CMakeLists.txt 或 .vcxproj
cl /LD /EHsc /DUNICODE /D_UNICODE PawLockerProvider.cpp ^
   /link /DEF:PawLockerProvider.def ole32.lib advapi32.lib secur32.lib
```

构建完成后，在 PawLocker 的**首次启动向导**里选择「凭据提供程序」策略，
向导会自动检测 DLL 是否存在、注册状态是否完整，并在你点击时弹 UAC 完成注册。

---

## 6. 与其他解锁策略的关系

PawLocker 提供四条解锁策略（见 `docs/01-architecture.md` §5），
只有本目录对应的策略需要额外的原生产物：

| 策略 | 是否需要 DLL | 能做到什么 |
|---|---|---|
| `CREDENTIAL_PROVIDER` | ✅ 需要 | **真正完成登录** |
| `WAKE_ONLY` | ❌ | 只点亮显示器，不解锁 |
| `CUSTOM_COMMAND` | ❌ | 执行你指定的任意命令 |
| `DRY_RUN` | ❌ | 只记日志，不产生任何系统影响 |

后三条开箱即用。本目录的存在是为了让第 4 条也能用。
