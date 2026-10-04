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
[手机] ──加密解锁指令──▶ [PawLocker.exe :28900]
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
4. **DLL 应当被签名。** Windows 本身**不强制**凭据提供程序做 Authenticode
   签名 —— 注册表指到哪个 DLL 它就加载哪个。但未签名的 DLL 会被下面这些拦住：

   - **WDAC / AppLocker / Device Guard** 策略（受管机器基本都开）
   - **Smart App Control**（Windows 11 22H2 起默认对新装的未签名二进制生效）
   - 大多数 **EDR** 产品

   签名同时是**发现 DLL 被替换**的唯一手段：`C:\Program Files` 的 ACL
   挡得住普通用户改文件，但挡不住管理员改文件 —— 而 ACL 不是完整性。
   做法见 [§6](#6-代码签名)。
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

> ⚠️ **DLL 应当做代码签名**，见下一节。Windows 不会因为「没签名」就拒绝加载，
> 但在启用了 WDAC / AppLocker / Smart App Control 的机器上会被拦下，
> 而这些策略在受管环境里几乎是默认的。


---

## 6. 代码签名

### 6.1 Windows 到底要不要求签名

**不要求。** 凭据提供程序是普通的 COM 进程内服务器：`HKLM` 下注册表指向
哪个 DLL，LogonUI 就加载哪个。签名与否不影响加载本身。

那为什么还是要签：

| 场景 | 未签名的后果 |
|---|---|
| WDAC / AppLocker / Device Guard | DLL 直接被拒绝加载，锁屏上没有磁贴 |
| Smart App Control（Win11 22H2+） | 同上 |
| EDR / 杀软 | 常见启发式拦截：往 SYSTEM 进程里加载未签名模块 |
| 供应链 | **无法察觉 DLL 被替换** —— `C:\Program Files` 的 ACL 只挡普通用户 |
| 分发 | 用户看到的是一堆「未知发布者」警告 |

所以签名解决的是「**能不能加载**」和「**有没有被换掉**」两件事，
而不是「能不能通信」。

### 6.2 用哪张证书

| 证书 | 能做什么 | 代价 |
|---|---|---|
| 自签名开发证书 | 本机 sign → verify → 加载全流程自测 | 对别人零可信度，过不了 SmartScreen |
| 由 CA 签发的 OV 代码签名证书 | 受管环境里的 WDAC 白名单可以按发布者放行 | 需要实名审核，年费 |
| **EV 代码签名证书** / Azure Trusted Signing | 直接获得 SmartScreen 信誉，无需等待累积 | 更贵，或绑定云订阅 |

自签名证书**永远**过不了 SmartScreen，也不会被别人的 WDAC 策略接受 ——
它只适合自用与开发验证。

### 6.3 本仓库的做法

```bat
rem 1. 造一张开发证书（放进 Cert:\CurrentUser\My，私钥默认不可导出）
credential-provider\sign.bat devcert

rem 2. 签名（/fd SHA256，并用 DigiCert 的 RFC 3161 服务打时间戳）
credential-provider\sign.bat sign

rem 3. 本机信任这张证书 —— 会弹 UAC
credential-provider\sign.bat trust

rem 4. 验证
credential-provider\sign.bat verify
rem → Successfully verified，SHA256 + RFC3161

rem 撤销信任
credential-provider\sign.bat untrust
```

用真实的 CA / EV 证书时，换成按指纹签名即可：

```bat
credential-provider\sign.bat cert <证书指纹>
rem 指纹可用 certutil -user -store My 查看
```

几个不显眼但会咬人的细节：

- **信任必须装在 `LocalMachine`，不是 `CurrentUser`。**
  DLL 跑在 LogonUI 里，也就是 SYSTEM 上下文；SYSTEM 有自己的一套证书存储，
  看不到当前用户的。装错位置的现象是「提权窗口里 `verify` 通过，
  锁屏上依然没有磁贴」。`sign.bat trust` 装的就是 `LocalMachine`。
- **一定要打时间戳。** 证书过期之后，没有时间戳的签名会一起失效；
  有时间戳则签名在证书有效期内永久有效。
- **私钥默认不可导出。** `dev-cert.ps1` 用 `NonExportable` 创建证书 ——
  签名密钥留在证书存储里就够了，没有必要能拷走。
  确实要挪到构建服务器上时，加 `-Exportable` 显式重建。
- **`sign.bat` 与 `dev-cert.ps1` 是纯 ASCII 的。** `cmd.exe` 按 OEM 代码页
  解析批处理文件，PowerShell 5.1 对无 BOM 的 UTF-8 也按 ANSI 处理 ——
  中文注释在 `.kt` 里没问题，在这两个文件里会变成乱码，甚至破坏解析。
- 签名后**不要重新构建**。任何字节改动会让签名失效，`verify` 会报
  「哈希不匹配」。正确的顺序永远是 build → sign → verify。

### 6.4 应用内的等价操作

第 3 步（`sign.bat trust`）在 PawLocker 的**首次启动向导**里有一份等价实现，
不依赖这个目录存在，也不需要用户去 `build\` 里找 `.cer`：

1. DLL 没签名 → 向导列出上面那三条命令。**不给按钮** ——
   签名要用 MSVC 工具链，应用内做不了；给一个点了没用的按钮比不给更糟。
2. 签了名但证书不受信任 → 把证书的**主体、指纹、有效期**摊开，再给「信任这张证书」。
   证书是从 DLL 的签名里现取的（`Get-AuthenticodeSignature`），不是从 `.cer` 文件读的。

两者写的是同一组存储（`LocalMachine\Root` + `LocalMachine\TrustedPublisher`），
效果完全一致，用哪个都行。设置页「Windows 注册状态」里那一行还能单独撤销信任。

实现里有两个从实测踩出来、值得记下来的点：

- **`Get-AuthenticodeSignature` 的 `Status` 不能照字面用。**
  Windows PowerShell 5.1 在「签名没问题、但证书不受信任」时返回的是
  `UnknownError`，**不是** `NotTrusted`。照文档映射会把「缺信任」判成「签名坏了」，
  于是引导用户去重签 —— 而重签一遍还是 `UnknownError`，人就这么卡在循环里。
  正确做法是只用 `Valid` / `NotSigned` 这两个确定取值，其余情况**自己去查证书存储**：
  证书在受信任存储里 → 问题不在信任上；不在 → 就是缺信任。
- **待提权执行的脚本不落盘。** 把脚本写进 `%LOCALAPPDATA%` 再提权执行，
  等于开一个本地提权窗口：任何普通权限进程都能在「写完」和「提权读」之间把它换掉。
  改成把脚本正文内联进命令行 —— 内容在 `CreateProcess` 那一刻就固定，
  而且 Windows 的完整性级别不允许中完整性进程写入高完整性进程的内存。

> 上面第二条只覆盖了本目录新增的信任/撤销操作。
> 凭据提供程序本身的注册仍走 `reg.exe` + 落盘 `.reg` 的老路，有同样的隐患，
> 属于已知待收敛项。


---

## 7. 与其他解锁策略的关系

PawLocker 提供四条解锁策略（见 `docs/01-architecture.md` §5），
只有本目录对应的策略需要额外的原生产物：

| 策略 | 是否需要 DLL | 能做到什么 |
|---|---|---|
| `CREDENTIAL_PROVIDER` | ✅ 需要 | **真正完成登录** |
| `WAKE_ONLY` | ❌ | 只点亮显示器，不解锁 |
| `CUSTOM_COMMAND` | ❌ | 执行你指定的任意命令 |
| `DRY_RUN` | ❌ | 只记日志，不产生任何系统影响 |

后三条开箱即用。本目录的存在是为了让第 4 条也能用。
