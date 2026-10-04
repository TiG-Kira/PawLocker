// Provider.h —— 凭据提供程序与凭据磁贴。
//
// ## 数据流
//
// ```
//   [手机] ──加密指令──▶ [PawLocker.exe]
//                            │ 验签 / 账户绑定 / 防重放 / 解密 全部通过
//                            │ 1. 先建好命名管道
//                            │ 2. SetEvent("Global\PawLocker.Unlock.<账户>")
//                            ▼
//                      [本 DLL · 看门狗线程]
//                            │ 收到事件 → 置 armed → CredentialsChanged()
//                            ▼
//                      [LogonUI] 重新枚举 → 自动选中 → 调 GetSerialization
//                            │
//                            │ 3. 连管道取凭据（一次性）
//                            │ 4. 校验 SID == 本次要解锁的账户
//                            │ 5. 打包 KERB_INTERACTIVE_UNLOCK_LOGON
//                            ▼
//                      [Winlogon / LSA] ──▶ 完成登录
// ```
//
// 注意：密码学**一点都没有**进这个 DLL。它只做「等信号 → 取凭据 → 校验账户 → 上交」，
// 所以即使被人逆向，也拿不到与手机通信的能力。

#pragma once

#include <windows.h>

#include <credentialprovider.h>

#include <memory>
#include <string>

namespace pawlocker {

// 磁贴上的三个字段。顺序即 LogonUI 的渲染顺序。
enum PawLockerField {
    PFI_LABEL = 0,   // 大标题
    PFI_STATUS = 1,  // 状态行（会随解锁流程变化）
    PFI_HINT = 2,    // 说明行
    PFI_COUNT = 3,
};

// 阻塞在等待上是不可接受的 —— LogonUI 卡住就等于用户无法登录。
// 所有状态都在这一处集中管理，且全部访问都在临界区内。
struct SharedState {
    CRITICAL_SECTION lock = {};
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario = CPUS_INVALID;

    // 本次要解锁 / 登录的账户（事件与管道名用它）
    std::wstring accountName;
    // 该账户的 SID。绑定链的最后一道校验就靠它。
    std::wstring accountSid;

    // 是否已收到手机授权
    bool armed = false;
    // 是否已经尝试过取凭据（避免重复连管道）
    bool channelAttempted = false;

    std::wstring status;
    std::wstring hint;

    SharedState() {
        InitializeCriticalSection(&lock);
        status = L"等待手机确认…";
        hint = L"在手机上点击「解锁」并完成生物识别";
    }
    ~SharedState() { DeleteCriticalSection(&lock); }
    SharedState(const SharedState&) = delete;
    SharedState& operator=(const SharedState&) = delete;
};

class Provider;

// 磁贴本体。实现 V2 接口 —— 只有 V2 才能通过 GetUserSid 把自己
// 挂到「当前登录用户」名下，从而出现在锁屏界面上（而不是变成「其他用户」）。
class Credential : public ICredentialProviderCredential2 {
public:
    Credential(std::shared_ptr<SharedState> state);

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // ICredentialProviderCredential
    STDMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override;
    STDMETHODIMP UnAdvise() override;
    STDMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    STDMETHODIMP SetDeselected() override;
    STDMETHODIMP GetFieldState(
        DWORD dwFieldID,
        CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;
    STDMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz) override;
    STDMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp) override;
    STDMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel) override;
    STDMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo) override;
    STDMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) override;
    STDMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem) override;
    STDMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz) override;
    STDMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked) override;
    STDMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) override;
    STDMETHODIMP CommandLinkClicked(DWORD dwFieldID) override;
    STDMETHODIMP GetSerialization(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;
    STDMETHODIMP ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) override;

    // ICredentialProviderCredential2
    STDMETHODIMP GetUserSid(PWSTR* ppszSid) override;

private:
    ~Credential();

    LONG _ref = 1;
    std::shared_ptr<SharedState> _state;
    ICredentialProviderCredentialEvents* _events = nullptr;

    // 只在 LogonUI 线程调用 —— 事件回调不允许跨线程调
    void UpdateStatusField(PCWSTR text);
};

class Provider : public ICredentialProvider, public ICredentialProviderSetUserArray {
public:
    Provider();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // ICredentialProvider
    STDMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) override;
    STDMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;
    STDMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) override;
    STDMETHODIMP UnAdvise() override;
    STDMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount) override;
    STDMETHODIMP GetFieldDescriptorAt(
        DWORD dwIndex,
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;
    STDMETHODIMP GetCredentialCount(
        DWORD* pdwCount,
        DWORD* pdwDefault,
        BOOL* pbAutoLogonWithDefault) override;
    STDMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) override;

    // ICredentialProviderSetUserArray
    STDMETHODIMP SetUserArray(ICredentialProviderUserArray* users) override;

private:
    ~Provider();

    // 解析「本次要解锁哪个 Windows 账户」—— 绑定链的中间一环
    void ResolveTargetUser();

    bool StartWatchdog();
    void StopWatchdog();
    static DWORD WINAPI WatchdogProc(LPVOID param);

    LONG _ref = 1;
    CRITICAL_SECTION _lock = {};
    std::shared_ptr<SharedState> _state;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _scenario = CPUS_INVALID;

    ICredentialProviderUserArray* _userArray = nullptr;      // 弱引用（LogonUI 持有）
    Credential* _credential = nullptr;

    ICredentialProviderEvents* _providerEvents = nullptr;
    UINT_PTR _adviseContext = 0;

    HANDLE _unlockEvent = nullptr;
    HANDLE _stopEvent = nullptr;
    HANDLE _watchdog = nullptr;
};

// —— 供 Credential 复用的工具 ——

// 用 CredProtect 保护密码。
//
// 为什么是 CredProtect 而不是 CryptProtectData：CredProtect 的输出可以被
// LSA 在正确的登录上下文里解回明文，这正是「把序列化凭据交给 Winlogon」
// 这条链路需要的语义。官方 CredentialProvider 示例用的也是它。
//
// 两个容易踩的点：
//  - 输出**仍是 NUL 结尾的宽字符串**，所以后续可以正常用 wcslen 量长度
//  - 空密码不能送进来（CredProtect 要求非空输入），原样返回即可
HRESULT ProtectPasswordForSerialization(
    const std::wstring& password,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
    std::wstring* out);

// 查 Negotiate 认证包 ID。失败返回 false。
bool LookupNegotiateAuthPackage(ULONG* packageId);

// 按官方约定打包：单块 CoTaskMemAlloc，UNICODE_STRING.Buffer 存**相对偏移**。
// LogonId 留零 —— 由 Winlogon 自己填，这是文档化的行为。
HRESULT PackKerbInteractiveUnlockLogon(
    const std::wstring& domain,
    const std::wstring& userName,
    const std::wstring& protectedPassword,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
    BYTE** packed,
    DWORD* packedBytes);

// SID 比较。任一侧为空一律判为不等 —— 拿不到身份就必须拒绝，不能默认放行。
bool SidEquals(const std::wstring& left, const std::wstring& right);

}  // namespace pawlocker
