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

## 4. 凭据从哪来 —— 命名管道现投

**这一节是最容易设计错的地方。**

JVM 侧把 Windows 登录凭据用 **DPAPI（当前用户作用域）** 加密存在
`%APPDATA%\PawLocker\secure\windows-credential.json`。这份文件**不能**直接给 DLL 用：

> DLL 跑在 LogonUI 进程（SYSTEM 上下文），与用户 DPAPI 作用域不互通，解不开。

一个看起来更省事的做法是改用 `CRYPTPROTECT_LOCAL_MACHINE`（机器作用域）——
那 DLL 就能解开。但它意味着**同机任何进程都能解开**，磁盘上等于常驻一份
机器可解的密码副本。对「远程解锁」这个场景，这是不可接受的。

所以采用**现投**：

```
   [PawLocker.exe]                                [PawLockerProvider.dll]
        │                                                   │
        │ 1. CreateNamedPipe(                                │
        │      \\.\pipe\PawLocker.Cred.<账户>)               │
        │ 2. SetEvent(Global\PawLocker.Unlock.<账户>) ──────▶ │ 看门狗被唤醒
        │                                                   │ 3. CreateFile(管道)
        │ 4. WriteFile([4字节长度][凭据块])  ◀───────────────┘
        │ 5. 立刻清零内存里的明文副本                          │ 6. 解析 + 校验 SID
        │                                                   │ 7. 提交给 Winlogon
```

关键点：

| 问题 | 处理 |
|---|---|
| 磁盘上会不会留下机器可解的副本 | **不会。** 落盘的始终只有用户作用域的 DPAPI 密文 |
| 是否需要自己配管道 ACL | **不需要。** 命名管道由用户进程创建时，默认 DACL 已含 SYSTEM 与当前用户，LogonUI 天然连得上 |
| 为什么先建管道再置事件 | 反过来会留下「CP 被叫醒但管道还不存在」的竞态窗口 |
| 主程序必须先启动吗 | 必须。但解锁指令本来就是它收的，所以这个前提天然成立 |

### 4.1 凭据块格式（两端必须逐字节一致）

`[4 字节小端总长][载荷]`，载荷为定长头 + 四个 UTF-8 字段：

| 偏移 | 类型 | 含义 |
|---|---|---|
| 0 | DWORD | magic，`'PWLC'` = `0x434C5750` |
| 4 | WORD | 版本，当前 `1` |
| 6 | WORD | 标志，bit0 = 含密码 |
| 8 | DWORD | userName 字节数 |
| 12 | DWORD | domain 字节数 |
| 16 | DWORD | password 字节数 |
| 20 | DWORD | sid 字节数 |
| 24 | … | 四个字段依次排列（UTF-8，无结尾 NUL） |

Kotlin 侧实现在 `core/desktopMain/.../platform/CredentialHandoff.kt`
（`CredentialBlobCodec`）；C 侧在 `include/PawLockerContract.h`。

> 用定长头而不是 JSON，是为了让 C 侧解析只走一趟、没有边界歧义 ——
> 也不必为了一个字符串字段在原生侧手写 JSON 解析器，那是 bug 温床。

### 4.2 密码在交给 LSA 之前的处理

DLL 取到明文密码后，**不是**直接塞进 `KERB_INTERACTIVE_LOGON`，而是先用
**`CredProtectW`**（凭据保护 API）加密：

- 这个 API 的输出仍是一个 NUL 结尾的宽字符串，所以后续量长度仍可用 `wcslen`；
- 解密由 LSA 在正确的登录上下文里完成 —— 这正是「把序列化凭据交给 Winlogon」
  这条链路需要的语义；
- 空密码不送进 `CredProtect`（它要求非空输入），已经是保护态的不重复保护。

> 注意这里**不是** `CryptProtectData`。官方 CredentialProvider 示例用的就是
> `CredProtectW`，且 LOGON 与 UNLOCK 两个场景处理方式相同，也没有域加入检测。

### 4.3 绑定链：任何一环不符都不解锁

「**电脑设备 + Windows 账户 + 手机**」三元绑定，中间那一环尤其容易被漏掉：
一台家用电脑上如果有两个 Windows 账户，只绑设备的话，给 A 账户配的手机会把
B 账户一起解开。所以账户身份被穿在四个位置上：

| 位置 | 作用 |
|---|---|
| HKDF 的 salt | 密码学绑定 —— 为账户 A 派生的密钥解不开账户 B 的指令 |
| `PairingOffer` / `ServerHello` | 让手机明确知道自己在和哪个账户配对 |
| `UnlockRequest.targetUserSid`（进 AAD 与签名） | 「目标账户」成为不可篡改的显式声明 |
| DLL 里的 `SidEquals` 校验 | 密码进入 LSA 之前的最后一道闸门 |

最后一道尤其重要：它比对的是「LogonUI 实际正在为哪个账户解锁」，
比主程序侧的推断更权威。**任一侧的 SID 为空一律判为不等** ——
身份未知时必须拒绝，绝不能因为「两边都空」而静默放行。


---

## 5. 构建

本目录已经包含完整可编译的实现，直接用脚本构建：

```bat
credential-provider\build.bat
```

脚本自己用 `vswhere` 找 Visual Studio、初始化 `vcvars64`、调编译器，
**不依赖 CMake / MSBuild** —— 少一层抽象就少一处「本机能跑、换台机器跑不起来」的差异。

产物：`credential-provider\build\PawLockerProvider.dll`

需要 Visual Studio 的「**使用 C++ 的桌面开发**」工作负载。
编译开了 `/W4 /WX`：这个组件跑在 LogonUI 里，一条被忽略的警告可能就是
下次「用户登不进去」的伏笔，所以警告一律当错误处理。

构建完成后，在 PawLocker 的**首次启动向导**或**设置 — 解锁方式**里选择
「凭据提供程序」，向导会自动检测 DLL 与注册状态，并在你点击时弹 UAC 完成注册。

> ⚠️ **DLL 需要代码签名**才能在启用 Secure Boot 的机器上进入锁屏界面 ——
> Winlogon 只加载受信任的模块。开发和自用环境可以先跳过，
> 但对外分发必须签名。


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
