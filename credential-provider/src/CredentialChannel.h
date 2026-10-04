// CredentialChannel.h —— 从主程序取回登录凭据。
//
// 通道设计的三条硬约束：
//
//  1. **不做机器作用域落盘。** 磁盘上永远不存在一份「SYSTEM 也能解」的密码副本。
//     凭据只在「手机已授权 → 主程序投递 → DLL 取出」这个窗口内存在于内存与管道里。
//  2. **单向、单次。** DLL 只读不写，一次解锁读一次，读完主程序即关闭管道。
//  3. **永不信任管道内容。** 结构、长度、SID 全部重新校验；任何一项不对就整体拒绝。
//
// 为什么管道权限不用自己设：命名管道的默认 DACL 已经包含 SYSTEM
// （管道由用户进程创建，其令牌默认 DACL 里有 SYSTEM 与本用户），
// 所以 LogonUI（SYSTEM）天然能连上，不需要额外配置 SDDL ——
// 也就少了一处可能配错的地方。

#pragma once

#include <windows.h>

#include <string>

namespace pawlocker {

// 一次成功取回的凭据。析构时清零密码。
struct ResolvedCredential {
    std::wstring userName;
    std::wstring domain;
    std::wstring password;
    std::wstring sid;

    ~ResolvedCredential() { Wipe(); }
    ResolvedCredential() = default;
    ResolvedCredential(const ResolvedCredential&) = delete;
    ResolvedCredential& operator=(const ResolvedCredential&) = delete;

    // 不依赖编译器优化：用 SecureZeroMemory 保证密码不被留在栈或堆上
    void Wipe();
};

enum class ChannelStatus {
    Ok,
    /// 管道不存在 —— 主程序没在运行，或者还没开始投递
    NoProvider,
    ConnectFailed,
    ReadFailed,
    /// 结构不合法（magic / 版本 / 长度 / UTF-8 解码失败）
    Malformed,
};

// 从 `\\.\pipe\PawLocker.Cred.<userName>` 取一份凭据。
// detail 用于把失败原因写进磁贴文案与日志。
ChannelStatus FetchCredential(
    const std::wstring& userName,
    ResolvedCredential* out,
    std::wstring* detail);

}  // namespace pawlocker
