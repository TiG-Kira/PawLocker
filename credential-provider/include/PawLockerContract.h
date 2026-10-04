// PawLockerContract.h —— JVM 侧与原生 DLL 侧共用的一份契约。
//
// 这个头文件里的**每一个值**都必须与 Kotlin 侧一字不差，否则两端对不上，
// 而症状会是「手机说解锁成功，电脑毫无反应」这种最难排查的形态。
// 对应的 Kotlin 实现位置逐条列在下面，改动时任一侧都要同步。
//
//  - 事件名 / 管道名  → core/desktopMain/.../platform/WindowsUnlockExecutor.kt
//  - CLSID            → core/desktopMain/.../platform/WindowsRegistrar.desktop.kt
//  - 凭据投递格式      → core/desktopMain/.../platform/CredentialHandoff.kt

#pragma once

#include <windows.h>

namespace pawlocker {

// ——————————————————————————————————————————————————————————————
// COM 身份
// ——————————————————————————————————————————————————————————————

// {6F3A1C48-9D2B-4E77-A5C1-8B0E4D7F2315}
//
// ⚠️ 这个 GUID 一经发布就不能改：已经注册过的机器会按它查找 DLL，
// 改动会导致升级后系统找不到自己的凭据提供程序，用户只能重新注册。
inline constexpr GUID kProviderClsid = {
    0x6F3A1C48, 0x9D2B, 0x4E77, {0xA5, 0xC1, 0x8B, 0x0E, 0x4D, 0x7F, 0x23, 0x15}
};

inline constexpr wchar_t kProviderFriendlyName[] = L"PawLocker";
inline constexpr wchar_t kProviderDescription[] = L"PawLocker 凭据提供程序";

// ——————————————————————————————————————————————————————————————
// 同步对象命名
// ——————————————————————————————————————————————————————————————

// `Global\` 前缀是必须的：DLL 跑在 Winlogon 进程（会话 0/1 的 SYSTEM 上下文），
// 而主程序跑在用户的交互式会话里。只有全局命名空间能让两边看到同一个对象。
inline constexpr wchar_t kEventPrefix[] = L"Global\\PawLocker.Unlock.";
inline constexpr wchar_t kPipePrefix[] = L"\\\\.\\pipe\\PawLocker.Cred.";

// 取不到账户名时的兜底名字。正常情况下用不到，
// 它的存在是为了「账户解析失败」时两端仍可能对上，而不是必然打空。
inline constexpr wchar_t kFallbackUserName[] = L"PawLocker";

// 事件的安全描述符。
//
// 必须显式给交互式用户 EVENT_MODIFY_STATE —— 由 SYSTEM 创建的内核对象
// 默认只把权限给 SYSTEM 与 Administrators，普通用户进程的 OpenEvent 会直接失败。
// 少了这一段，表现就是「手机端报『未检测到 PawLocker 登录组件』」，
// 而组件其实装得好好的。
//   SY = Local System        GA = GENERIC_ALL
//   BA = Builtin Admins      GA = GENERIC_ALL
//   IU = Interactive Users   0x0002 = EVENT_MODIFY_STATE（SetEvent 需要它）
inline constexpr wchar_t kEventSddl[] = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0002;;;IU)";

// ——————————————————————————————————————————————————————————————
// 凭据投递格式
// ——————————————————————————————————————————————————————————————
//
// 为什么不复用 `%APPDATA%` 下那份 DPAPI 文件：那份是**用户作用域**加密的，
// 只有当前用户的 DPAPI 主密钥能解；而 DLL 跑在 SYSTEM 上下文，解不开。
// 于是改成「解锁时由主程序通过命名管道现投」——
// 这样磁盘上永远不会存在一份「机器可解」的密码副本。
//
// 传输分两段：4 字节小端总长 + 载荷；载荷 = 固定头 + 四个 UTF-8 字段。
// 用定长头而不是逐字段长度前缀，是为了让 C 侧解析只走一趟、没有边界歧义。

inline constexpr DWORD kBlobMagic = 0x434C5750;  // 'PWLC'（小端读作 'PWLC'）
inline constexpr WORD kBlobVersion = 1;

inline constexpr WORD kFlagHasPassword = 0x0001;

// 单个字段与整块的上限。防止「连接上的其实是别的东西」把解析器喂爆。
inline constexpr DWORD kMaxFieldBytes = 4096;
inline constexpr DWORD kMaxPayloadBytes = 64 * 1024;

#pragma pack(push, 1)
struct CredentialBlobHeader {
    DWORD magic;         // kBlobMagic
    WORD  version;       // kBlobVersion
    WORD  flags;         // kFlagHasPassword
    DWORD userNameBytes; // 以下四个长度均不含结尾的 NUL
    DWORD domainBytes;
    DWORD passwordBytes;
    DWORD sidBytes;
    // 紧随其后：userNameBytes + domainBytes + passwordBytes + sidBytes 个 UTF-8 字节
};
#pragma pack(pop)

inline constexpr DWORD kBlobHeaderBytes = sizeof(CredentialBlobHeader);

// ——————————————————————————————————————————————————————————————
// 磁贴文案
// ——————————————————————————————————————————————————————————————

inline constexpr wchar_t kStatusIdle[] = L"等待手机确认…";
inline constexpr wchar_t kStatusArmed[] = L"已授权，正在提交登录凭据";
inline constexpr wchar_t kStatusNoCredential[] = L"本机尚未保存登录凭据";
inline constexpr wchar_t kStatusChannelFailed[] = L"无法连接 PawLocker 主程序";
inline constexpr wchar_t kStatusUserMismatch[] = L"凭据绑定的 Windows 账户与当前账户不符";

// 等待主程序连上管道的时间。主程序在 SetEvent 之前就已经把管道挂好，
// 所以这里不需要等很久；给宽一点只是为了兜住调度抖动。
inline constexpr DWORD kChannelTimeoutMillis = 5000;

}  // namespace pawlocker
