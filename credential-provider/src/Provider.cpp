#include "Provider.h"

#include "CredentialChannel.h"
#include "PawLockerContract.h"
#include "Trace.h"

#include <ntsecapi.h>
#include <sddl.h>
#include <shlwapi.h>
#include <wincred.h>
#include <wtsapi32.h>

#include <string.h>
#include <wchar.h>

#include <new>
#include <vector>

namespace pawlocker {
namespace {

// ntstatus.h 与 windows.h 里的 winerror.h 不能同时包含（会重定义 STATUS_*），
// 而我们只需要这两个值，直接按定义写死，省掉一整套 `WIN32_NO_STATUS` 的写法。
constexpr NTSTATUS kStatusLogonFailure = static_cast<NTSTATUS>(0xC000006D);
constexpr NTSTATUS kStatusWrongPassword = static_cast<NTSTATUS>(0xC000006A);

// NEGOSSP_NAME_A 在部分 SDK 版本里不随 ntsecapi.h 暴露出来，
// 直接写它的字面值 —— 这个字符串是 LSA 的公开契约，不会变。
constexpr char kNegotiatePackageName[] = "Negotiate";

// ——————————————————————————————————————————————————————————————
// 小工具
// ——————————————————————————————————————————————————————————————

// 按官方示例的做法分配字段描述符：结构体与标签各一次 CoTaskMemAlloc，
// LogonUI 负责用 CoTaskMemFree 释放。
HRESULT AllocFieldDescriptor(
    DWORD fieldId,
    CREDENTIAL_PROVIDER_FIELD_TYPE type,
    PCWSTR label,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** out) {
    if (!out) return E_POINTER;
    *out = nullptr;

    auto* descriptor = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
        CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (!descriptor) return E_OUTOFMEMORY;

    descriptor->dwFieldID = fieldId;
    descriptor->cpft = type;
    descriptor->guidFieldType = GUID_NULL;
    descriptor->pszLabel = nullptr;

    HRESULT hr = label ? SHStrDupW(label, &descriptor->pszLabel) : S_OK;
    if (FAILED(hr)) {
        CoTaskMemFree(descriptor);
        return hr;
    }

    *out = descriptor;
    return S_OK;
}

// LSA_STRING 没有公开的初始化函数，官方示例自带一个
void InitLsaString(LSA_STRING* target, const char* source) {
    if (!target || !source) return;
    const size_t length = strlen(source);
    target->Length = static_cast<USHORT>(length);
    target->MaximumLength = static_cast<USHORT>(length + sizeof(char));
    target->Buffer = const_cast<char*>(source);
}

// CredProtect 的输出仍是 NUL 结尾宽字符串，按官方示例用 wcslen 量。
size_t ProtectedLength(const wchar_t* text) {
    return text ? wcslen(text) : 0;
}

std::wstring CurrentAccountNameFromConsoleSession() {
    const DWORD session = WTSGetActiveConsoleSessionId();
    if (session == 0xFFFFFFFF) return std::wstring();

    LPWSTR name = nullptr;
    DWORD bytes = 0;
    if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, WTSUserName, &name, &bytes) &&
        name != nullptr && *name != L'\0') {
        std::wstring result(name);
        WTSFreeMemory(name);
        return result;
    }
    if (name) WTSFreeMemory(name);
    return std::wstring();
}

}  // namespace

// ——————————————————————————————————————————————————————————————
// 工具函数实现
// ——————————————————————————————————————————————————————————————

bool SidEquals(const std::wstring& left, const std::wstring& right) {
    // 任一侧为空一律判为不等。
    //
    // 这是整个绑定链里最容易写错、后果最严重的一处：如果写成
    // 「两边都空 → 相等」，那么当账户解析失败时，校验会被静默跳过，
    // 绑定链直接失效。宁可拒绝一次合法的解锁，也不能默认放行。
    if (left.empty() || right.empty()) return false;
    return _wcsicmp(left.c_str(), right.c_str()) == 0;
}

bool LookupNegotiateAuthPackage(ULONG* packageId) {
    if (!packageId) return false;

    HANDLE lsa = nullptr;
    if (LsaConnectUntrusted(&lsa) < 0) {
        Trace(L"LsaConnectUntrusted 失败");
        return false;
    }

    LSA_STRING name = {};
    InitLsaString(&name, kNegotiatePackageName);

    ULONG id = 0;
    const NTSTATUS status = LsaLookupAuthenticationPackage(lsa, &name, &id);
    LsaDeregisterLogonProcess(lsa);

    if (status < 0) {
        Trace(L"LsaLookupAuthenticationPackage(Negotiate) 失败，NTSTATUS=0x%08X", status);
        return false;
    }
    *packageId = id;
    return true;
}

HRESULT ProtectPasswordForSerialization(
    const std::wstring& password,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
    std::wstring* out) {
    if (!out) return E_POINTER;
    out->clear();

    // 空密码不需要保护 —— CredProtect 要求非空输入
    if (password.empty()) return S_OK;

    // CredUI 场景不加密：调用方未必能处理加密后的密码。
    // 本提供程序只支持登录与解锁，这条分支是防御性写法。
    if (scenario == CPUS_CREDUI) {
        *out = password;
        return S_OK;
    }

    // 已经保护过就不要再保护一次。
    // 经终端服务连接进来时，SetSerialization 可能已经带着加密后的密码。
    PWSTR mutablePassword = const_cast<PWSTR>(password.c_str());
    CRED_PROTECTION_TYPE type = CredUnprotected;
    if (CredIsProtectedW(mutablePassword, &type) && type != CredUnprotected) {
        *out = password;
        return S_OK;
    }

    // 两次调用：先探测需要的字符数，再真正加密
    DWORD needed = 0;
    if (!CredProtectW(FALSE, mutablePassword, static_cast<DWORD>(password.size() + 1),
                      nullptr, &needed, nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER || needed == 0) {
            Trace(L"CredProtect 探测长度失败，Win32=%u", error);
            return HRESULT_FROM_WIN32(error);
        }
    }
    if (needed == 0) return E_FAIL;

    std::vector<wchar_t> buffer(static_cast<size_t>(needed), L'\0');
    DWORD written = needed;
    if (!CredProtectW(FALSE, mutablePassword, static_cast<DWORD>(password.size() + 1),
                      buffer.data(), &written, nullptr)) {
        const DWORD error = GetLastError();
        Trace(L"CredProtect 加密失败，Win32=%u", error);
        SecureZeroMemory(buffer.data(), buffer.size() * sizeof(wchar_t));
        return HRESULT_FROM_WIN32(error);
    }

    out->assign(buffer.data(), ProtectedLength(buffer.data()));
    SecureZeroMemory(buffer.data(), buffer.size() * sizeof(wchar_t));
    return S_OK;
}

HRESULT PackKerbInteractiveUnlockLogon(
    const std::wstring& domain,
    const std::wstring& userName,
    const std::wstring& protectedPassword,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario,
    BYTE** packed,
    DWORD* packedBytes) {
    if (!packed || !packedBytes) return E_POINTER;
    *packed = nullptr;
    *packedBytes = 0;

    KERB_LOGON_SUBMIT_TYPE messageType = KerbInteractiveLogon;
    switch (scenario) {
        case CPUS_UNLOCK_WORKSTATION:
            messageType = KerbWorkstationUnlockLogon;
            break;
        case CPUS_LOGON:
            messageType = KerbInteractiveLogon;
            break;
        default:
            return E_INVALIDARG;
    }

    // 三个字符串都按 NUL 结尾量长度（CredProtect 的输出也不例外）
    auto init = [](const std::wstring& text, UNICODE_STRING* target) -> bool {
        if (text.size() > (0xFFFFu / sizeof(wchar_t))) return false;
        target->Length = static_cast<USHORT>(text.size() * sizeof(wchar_t));
        target->MaximumLength = target->Length;
        target->Buffer = const_cast<PWSTR>(text.c_str());
        return true;
    };

    KERB_INTERACTIVE_UNLOCK_LOGON staging = {};
    KERB_INTERACTIVE_LOGON* stagingLogon = &staging.Logon;
    if (!init(domain, &stagingLogon->LogonDomainName)) return E_INVALIDARG;
    if (!init(userName, &stagingLogon->UserName)) return E_INVALIDARG;
    if (!init(protectedPassword, &stagingLogon->Password)) return E_INVALIDARG;
    stagingLogon->MessageType = messageType;

    // 单块分配：结构体 + 三个字符串。LogonId 留零 —— 由 Winlogon 填。
    const DWORD total = static_cast<DWORD>(sizeof(staging)) +
        stagingLogon->LogonDomainName.Length +
        stagingLogon->UserName.Length +
        stagingLogon->Password.Length;

    auto* output = static_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(CoTaskMemAlloc(total));
    if (!output) return E_OUTOFMEMORY;
    ZeroMemory(output, sizeof(*output));

    BYTE* cursor = reinterpret_cast<BYTE*>(output) + sizeof(*output);
    const BYTE* base = reinterpret_cast<const BYTE*>(output);
    KERB_INTERACTIVE_LOGON* target = &output->Logon;
    target->MessageType = stagingLogon->MessageType;

    const UNICODE_STRING* sources[3] = {
        &stagingLogon->LogonDomainName, &stagingLogon->UserName, &stagingLogon->Password};
    UNICODE_STRING* targets[3] = {
        &target->LogonDomainName, &target->UserName, &target->Password};

    for (int index = 0; index < 3; ++index) {
        targets[index]->Length = sources[index]->Length;
        targets[index]->MaximumLength = sources[index]->Length;
        memcpy(cursor, sources[index]->Buffer, sources[index]->Length);
        // 关键：LSA 消费的是 packed 形式，Buffer 存的是**相对偏移**而不是指针。
        // 写成真实指针会在跨进程传递时立刻失效。
        targets[index]->Buffer = reinterpret_cast<PWSTR>(cursor - base);
        cursor += sources[index]->Length;
    }

    *packed = reinterpret_cast<BYTE*>(output);
    *packedBytes = total;
    return S_OK;
}

// ——————————————————————————————————————————————————————————————
// Credential
// ——————————————————————————————————————————————————————————————

Credential::Credential(std::shared_ptr<SharedState> state) : _state(std::move(state)) {}

Credential::~Credential() {
    if (_events) _events->Release();
}

STDMETHODIMP Credential::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_ICredentialProviderCredential)) {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
    } else if (IsEqualIID(riid, IID_ICredentialProviderCredential2)) {
        *ppv = static_cast<ICredentialProviderCredential2*>(this);
    } else {
        return E_NOINTERFACE;
    }
    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) Credential::AddRef() {
    return static_cast<ULONG>(InterlockedIncrement(&_ref));
}

STDMETHODIMP_(ULONG) Credential::Release() {
    const LONG remaining = InterlockedDecrement(&_ref);
    if (remaining == 0) delete this;
    return static_cast<ULONG>(remaining);
}

STDMETHODIMP Credential::Advise(ICredentialProviderCredentialEvents* events) {
    if (_events) {
        _events->Release();
        _events = nullptr;
    }
    _events = events;
    if (_events) _events->AddRef();
    return S_OK;
}

STDMETHODIMP Credential::UnAdvise() {
    if (_events) {
        _events->Release();
        _events = nullptr;
    }
    return S_OK;
}

void Credential::UpdateStatusField(PCWSTR text) {
    // 只在 LogonUI 线程调用 —— 字段更新回调不允许跨线程
    if (_events && text) {
        _events->SetFieldString(this, PFI_STATUS, text);
    }
}

STDMETHODIMP Credential::SetSelected(BOOL* pbAutoLogon) {
    if (!pbAutoLogon) return E_POINTER;

    auto state = _state;
    bool armed = false;
    if (state) {
        EnterCriticalSection(&state->lock);
        armed = state->armed;
        LeaveCriticalSection(&state->lock);
    }

    // 已经收到手机授权 → 让 LogonUI 立刻提交，用户不需要再点一下
    *pbAutoLogon = armed ? TRUE : FALSE;
    return S_OK;
}

STDMETHODIMP Credential::SetDeselected() {
    return S_OK;
}

STDMETHODIMP Credential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) {
    if (!pcpfs || !pcpfis) return E_POINTER;
    if (dwFieldID >= PFI_COUNT) return E_INVALIDARG;

    // 三个字段在选中与未选中状态下都显示 —— 磁贴本身要能一眼看懂
    *pcpfs = static_cast<CREDENTIAL_PROVIDER_FIELD_STATE>(
        CPFS_DISPLAY_IN_SELECTED_TILE | CPFS_DISPLAY_IN_DESELECTED_TILE);
    *pcpfis = CPFIS_NONE;
    return S_OK;
}

STDMETHODIMP Credential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz) {
    if (!ppwsz) return E_POINTER;
    *ppwsz = nullptr;

    auto state = _state;
    if (!state) return E_UNEXPECTED;

    std::wstring text;
    EnterCriticalSection(&state->lock);
    switch (dwFieldID) {
        case PFI_LABEL:
            text = kProviderFriendlyName;
            break;
        case PFI_STATUS:
            text = state->status;
            break;
        case PFI_HINT:
            text = state->hint;
            break;
        default:
            LeaveCriticalSection(&state->lock);
            return E_INVALIDARG;
    }
    LeaveCriticalSection(&state->lock);

    return SHStrDupW(text.c_str(), ppwsz);
}

STDMETHODIMP Credential::GetBitmapValue(DWORD, HBITMAP*) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::GetSubmitButtonValue(DWORD, DWORD*) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::SetStringValue(DWORD, PCWSTR) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::SetCheckboxValue(DWORD, BOOL) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::SetComboBoxSelectedValue(DWORD, DWORD) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::CommandLinkClicked(DWORD) {
    return E_NOTIMPL;
}

STDMETHODIMP Credential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {
    if (!pcpgsr || !pcpcs || !ppwszOptionalStatusText || !pcpsiOptionalStatusIcon) {
        return E_POINTER;
    }

    // 默认「没有凭据，而且这条凭据还没走完」—— 语义上就是「继续等」
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    auto state = _state;
    if (!state) return E_UNEXPECTED;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario;
    bool armed;
    std::wstring accountName;
    std::wstring accountSid;
    EnterCriticalSection(&state->lock);
    scenario = state->scenario;
    armed = state->armed;
    accountName = state->accountName;
    accountSid = state->accountSid;
    if (!armed) state->status = kStatusIdle;
    LeaveCriticalSection(&state->lock);

    // ① 还没收到手机授权。用户手动点磁贴也不该放行 ——
    //    「本机有人在键盘前」不能替代「手机持有人已完成生物识别」。
    if (!armed) {
        UpdateStatusField(kStatusIdle);
        return S_OK;
    }

    // ② 连管道取凭据
    ResolvedCredential credential;
    std::wstring detail;
    const ChannelStatus status = FetchCredential(accountName, &credential, &detail);

    auto fail = [&](PCWSTR text, PCWSTR logLine) -> HRESULT {
        EnterCriticalSection(&state->lock);
        state->status = text;
        state->hint = detail;
        LeaveCriticalSection(&state->lock);
        UpdateStatusField(text);
        Trace(L"%s（%s）", logLine, detail.c_str());
        // 取不到凭据属于「本轮结束」，让 LogonUI 收起等待动画、
        // 把选择权交回用户，而不是卡在转圈上
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_OK;
    };

    switch (status) {
        case ChannelStatus::NoProvider:
        case ChannelStatus::ConnectFailed:
            return fail(kStatusChannelFailed, L"无法连接凭据通道");
        case ChannelStatus::ReadFailed:
        case ChannelStatus::Malformed:
            return fail(kStatusChannelFailed, L"凭据通道内容异常");
        case ChannelStatus::Ok:
            break;
    }

    // ③ 绑定链最后一环：凭据声明的账户必须就是本次要解锁的账户。
    //
    //    在主程序里已经查过一次，这里再查一次不是冗余 ——
    //    这是密码进入 LSA 之前的最后一道闸门，而且此处掌握的是
    //    「LogonUI 实际正在为哪个账户解锁」，比主程序侧的推断更权威。
    if (!SidEquals(credential.sid, accountSid)) {
        credential.Wipe();
        return fail(kStatusUserMismatch, L"凭据绑定的账户与当前解锁账户不符，已拒绝");
    }

    // ④ 保护密码，然后按官方约定打包
    std::wstring protectedPassword;
    HRESULT hr = ProtectPasswordForSerialization(credential.password, scenario, &protectedPassword);
    if (FAILED(hr)) {
        credential.Wipe();
        return fail(kStatusChannelFailed, L"密码保护失败");
    }

    BYTE* packed = nullptr;
    DWORD packedBytes = 0;
    hr = PackKerbInteractiveUnlockLogon(
        credential.domain, credential.userName, protectedPassword, scenario, &packed, &packedBytes);
    credential.Wipe();

    if (FAILED(hr) || packed == nullptr || packedBytes == 0) {
        if (packed) CoTaskMemFree(packed);
        return fail(kStatusChannelFailed, L"构造登录凭据失败");
    }

    ULONG authPackage = 0;
    if (!LookupNegotiateAuthPackage(&authPackage)) {
        CoTaskMemFree(packed);
        return fail(kStatusChannelFailed, L"查询 Negotiate 认证包失败");
    }

    pcpcs->ulAuthenticationPackage = authPackage;
    pcpcs->clsidCredentialProvider = kProviderClsid;
    pcpcs->rgbSerialization = packed;
    pcpcs->cbSerialization = packedBytes;

    {
        EnterCriticalSection(&state->lock);
        state->status = L"正在提交登录凭据…";
        state->hint = L"若停留在本界面，请改用密码登录";
        LeaveCriticalSection(&state->lock);
    }

    Trace(L"已提交登录凭据：账户=%s，长度=%u", credential.userName.c_str(), packedBytes);
    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    return S_OK;
}

STDMETHODIMP Credential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon) {
    if (!ppwszOptionalStatusText || !pcpsiOptionalStatusIcon) return E_POINTER;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    // 失败时把原因写进磁贴，免得用户只看到「用户名或密码错误」而不知道
    // 是 PawLocker 这条路径出了问题。
    if (ntsStatus != 0) {
        const wchar_t* text =
            (ntsStatus == kStatusLogonFailure || ntsStatus == kStatusWrongPassword)
                ? L"PawLocker 提交的凭据被拒绝，请检查保存的密码是否正确"
                : L"PawLocker 提交的凭据未被接受，请改用密码登录";
        SHStrDupW(text, ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;

        if (_events) {
            _events->SetFieldString(this, PFI_STATUS, text);
        }
        Trace(L"登录被拒：ntsStatus=0x%08X，sub=0x%08X", ntsStatus, ntsSubstatus);
    }

    auto state = _state;
    if (state) {
        EnterCriticalSection(&state->lock);
        // 一轮结束，收回归属：下一次解锁必须重新等一遍手机授权
        state->armed = false;
        state->channelAttempted = false;
        LeaveCriticalSection(&state->lock);
    }
    return S_OK;
}

STDMETHODIMP Credential::GetUserSid(PWSTR* ppszSid) {
    if (!ppszSid) return E_POINTER;
    *ppszSid = nullptr;

    // 返回当前解锁用户的 SID，LogonUI 才会把这个磁贴挂在锁屏界面上，
    // 而不是当成「其他用户」。这是「出现在锁屏」的关键一步。
    auto state = _state;
    if (!state) return E_UNEXPECTED;

    std::wstring sid;
    EnterCriticalSection(&state->lock);
    sid = state->accountSid;
    LeaveCriticalSection(&state->lock);

    if (sid.empty()) return E_FAIL;
    return SHStrDupW(sid.c_str(), ppszSid);
}

// ——————————————————————————————————————————————————————————————
// Provider
// ——————————————————————————————————————————————————————————————

Provider::Provider() {
    InitializeCriticalSection(&_lock);
    _state = std::make_shared<SharedState>();
}

Provider::~Provider() {
    StopWatchdog();

    if (_unlockEvent) CloseHandle(_unlockEvent);
    if (_stopEvent) CloseHandle(_stopEvent);
    if (_credential) _credential->Release();
    if (_providerEvents) _providerEvents->Release();
    if (_userArray) _userArray->Release();

    DeleteCriticalSection(&_lock);
}

STDMETHODIMP Provider::QueryInterface(REFIID riid, void** ppv) {
    if (!ppv) return E_POINTER;
    *ppv = nullptr;

    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_ICredentialProvider)) {
        *ppv = static_cast<ICredentialProvider*>(this);
    } else if (IsEqualIID(riid, IID_ICredentialProviderSetUserArray)) {
        *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
    } else {
        return E_NOINTERFACE;
    }
    AddRef();
    return S_OK;
}

STDMETHODIMP_(ULONG) Provider::AddRef() {
    return static_cast<ULONG>(InterlockedIncrement(&_ref));
}

STDMETHODIMP_(ULONG) Provider::Release() {
    const LONG remaining = InterlockedDecrement(&_ref);
    if (remaining == 0) delete this;
    return static_cast<ULONG>(remaining);
}

STDMETHODIMP Provider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD) {
    // 只支持登录与解锁。
    // 不支持场景返回 E_INVALIDARG 是文档化的做法 —— 这样 LogonUI 会干净地
    // 跳过我们，而不是留一个点了没反应的磁贴。
    if (cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION) {
        return E_INVALIDARG;
    }

    _scenario = cpus;
    if (_state) {
        EnterCriticalSection(&_state->lock);
        _state->scenario = cpus;
        _state->status = kStatusIdle;
        LeaveCriticalSection(&_state->lock);
    }

    // 解锁场景可以直接从控制台会话拿到账户，不必等 SetUserArray ——
    // 这一步让「磁贴出现在锁屏上」不依赖用户数组是否送达。
    if (cpus == CPUS_UNLOCK_WORKSTATION) {
        ResolveTargetUser();
    }
    return S_OK;
}

STDMETHODIMP Provider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) {
    // 本提供程序不是默认凭据，不会接到自动登录的序列化数据。
    return E_NOTIMPL;
}

STDMETHODIMP Provider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext) {
    EnterCriticalSection(&_lock);
    if (_providerEvents) _providerEvents->Release();
    _providerEvents = pcpe;
    if (_providerEvents) _providerEvents->AddRef();
    _adviseContext = upAdviseContext;
    LeaveCriticalSection(&_lock);

    if (!pcpe) {
        StopWatchdog();
        return S_OK;
    }

    // 到这里 LogonUI 已经把用户数组给过来了，账户信息齐了
    ResolveTargetUser();
    if (!StartWatchdog()) {
        Trace(L"看门狗启动失败，本轮解锁将无法自动响应");
    }
    return S_OK;
}

STDMETHODIMP Provider::UnAdvise() {
    EnterCriticalSection(&_lock);
    if (_providerEvents) {
        _providerEvents->Release();
        _providerEvents = nullptr;
    }
    _adviseContext = 0;
    LeaveCriticalSection(&_lock);

    StopWatchdog();
    return S_OK;
}

STDMETHODIMP Provider::GetFieldDescriptorCount(DWORD* pdwCount) {
    if (!pdwCount) return E_POINTER;
    *pdwCount = PFI_COUNT;
    return S_OK;
}

STDMETHODIMP Provider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    if (!ppcpfd) return E_POINTER;
    *ppcpfd = nullptr;

    switch (dwIndex) {
        case PFI_LABEL:
            return AllocFieldDescriptor(PFI_LABEL, CPFT_LARGE_TEXT, kProviderFriendlyName, ppcpfd);
        case PFI_STATUS:
            return AllocFieldDescriptor(PFI_STATUS, CPFT_SMALL_TEXT, L"状态", ppcpfd);
        case PFI_HINT:
            return AllocFieldDescriptor(PFI_HINT, CPFT_SMALL_TEXT, L"说明", ppcpfd);
        default:
            return E_INVALIDARG;
    }
}

STDMETHODIMP Provider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault) {
    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault) return E_POINTER;

    const bool supported = (_scenario == CPUS_LOGON || _scenario == CPUS_UNLOCK_WORKSTATION);
    *pdwCount = supported ? 1 : 0;
    *pdwDefault = supported ? 0 : CREDENTIAL_PROVIDER_NO_DEFAULT;

    // 这一条就是「手机一授权，电脑自动登录」的开关：
    // 收到解锁信号后返回 TRUE，LogonUI 会自动提交默认凭据，用户不必再点一下。
    bool armed = false;
    if (_state) {
        EnterCriticalSection(&_state->lock);
        armed = _state->armed;
        LeaveCriticalSection(&_state->lock);
    }
    *pbAutoLogonWithDefault = (supported && armed) ? TRUE : FALSE;
    return S_OK;
}

STDMETHODIMP Provider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) {
    if (!ppcpc) return E_POINTER;
    *ppcpc = nullptr;

    if (dwIndex != 0) return E_INVALIDARG;
    if (_scenario != CPUS_LOGON && _scenario != CPUS_UNLOCK_WORKSTATION) return E_INVALIDARG;

    EnterCriticalSection(&_lock);
    if (!_credential) {
        _credential = new (std::nothrow) Credential(_state);
    }
    Credential* credential = _credential;
    if (credential) credential->AddRef();
    LeaveCriticalSection(&_lock);

    if (!credential) return E_OUTOFMEMORY;
    *ppcpc = static_cast<ICredentialProviderCredential*>(credential);
    return S_OK;
}

STDMETHODIMP Provider::SetUserArray(ICredentialProviderUserArray* users) {
    EnterCriticalSection(&_lock);
    if (_userArray) _userArray->Release();
    _userArray = users;
    if (_userArray) _userArray->AddRef();
    LeaveCriticalSection(&_lock);

    ResolveTargetUser();
    return S_OK;
}

void Provider::ResolveTargetUser() {
    std::wstring accountName;
    std::wstring sidString;

    // ① 最权威：LogonUI 给的用户数组
    ICredentialProviderUserArray* users = nullptr;
    EnterCriticalSection(&_lock);
    users = _userArray;
    if (users) users->AddRef();
    LeaveCriticalSection(&_lock);

    if (users) {
        DWORD count = 0;
        if (SUCCEEDED(users->GetCount(&count)) && count > 0) {
            ICredentialProviderUser* user = nullptr;
            if (SUCCEEDED(users->GetAt(0, &user)) && user) {
                // 注意：这个 GetSid 返回的是 SID 的**字符串**形式（S-1-5-21-…），
                // 不是 PSID。要反查账户名得先转回二进制形式。
                LPWSTR sidText = nullptr;
                if (SUCCEEDED(user->GetSid(&sidText)) && sidText) {
                    sidString = sidText;
                    CoTaskMemFree(sidText);

                    PSID sid = nullptr;
                    if (ConvertStringSidToSidW(sidString.c_str(), &sid) && sid) {
                        wchar_t name[256] = {};
                        DWORD nameChars = ARRAYSIZE(name);
                        wchar_t domain[256] = {};
                        DWORD domainChars = ARRAYSIZE(domain);
                        SID_NAME_USE use = SidTypeUnknown;
                        if (LookupAccountSidW(nullptr, sid, name, &nameChars,
                                              domain, &domainChars, &use)) {
                            accountName = name;
                        }
                        LocalFree(sid);
                    }
                }
                user->Release();
            }
        }
        users->Release();
    }

    // ② 退路：控制台会话的登录用户名。解锁场景下这是最准的来源，
    //    而且与主程序侧 `System.getProperty("user.name")` 语义一致。
    if (accountName.empty()) {
        accountName = CurrentAccountNameFromConsoleSession();
    }

    // ③ 由账户名反查 SID
    if (sidString.empty() && !accountName.empty()) {
        BYTE sidBuffer[SECURITY_MAX_SID_SIZE] = {};
        DWORD sidBytes = ARRAYSIZE(sidBuffer);
        wchar_t domain[256] = {};
        DWORD domainChars = ARRAYSIZE(domain);
        SID_NAME_USE use = SidTypeUnknown;
        if (LookupAccountNameW(nullptr, accountName.c_str(), sidBuffer, &sidBytes,
                               domain, &domainChars, &use)) {
            LPWSTR text = nullptr;
            if (ConvertSidToStringSidW(sidBuffer, &text)) {
                sidString = text;
                LocalFree(text);
            }
        }
    }

    // ④ 全都拿不到：保留兜底名字，SID 留空。
    //    SID 为空会让绑定校验必然失败 —— 这是刻意的 fail-closed：
    //    宁可拒绝一次解锁，也不能在身份未知的情况下把密码交出去。
    if (accountName.empty()) {
        accountName = kFallbackUserName;
        Trace(L"警告：无法确定当前 Windows 账户，绑定校验将一律拒绝");
    }

    LUID ignored = {};
    EnterCriticalSection(&_state->lock);
    const bool changed = (_state->accountName != accountName) || (_state->accountSid != sidString);
    _state->accountName = accountName;
    _state->accountSid = sidString;
    LeaveCriticalSection(&_state->lock);

    if (changed) {
        Trace(L"目标账户解析完成：%s（SID %s）", accountName.c_str(),
              sidString.empty() ? L"<未知>" : sidString.c_str());
    }
}

bool Provider::StartWatchdog() {
    StopWatchdog();

    {
        EnterCriticalSection(&_state->lock);
        // 新一轮开始，归属清零。上一次解锁的授权绝不能被这一轮继承 ——
        // 否则「解锁过一次」就等于「之后永久免授权」。
        _state->armed = false;
        _state->channelAttempted = false;
        _state->status = kStatusIdle;
        _state->hint = L"在手机上点击「解锁」并完成生物识别";
        LeaveCriticalSection(&_state->lock);
    }

    std::wstring accountName;
    EnterCriticalSection(&_state->lock);
    accountName = _state->accountName;
    LeaveCriticalSection(&_state->lock);

    if (accountName.empty()) {
        Trace(L"账户未知，跳过看门狗启动");
        return false;
    }

    const std::wstring eventName = std::wstring(kEventPrefix) + accountName;

    // 显式指定安全描述符：SYSTEM 创建的内核对象默认不给交互式用户
    // EVENT_MODIFY_STATE，主程序的 OpenEvent 会直接失败。
    SECURITY_ATTRIBUTES attributes = {};
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kEventSddl, SDDL_REVISION_1, &descriptor, nullptr)) {
        attributes.nLength = sizeof(attributes);
        attributes.lpSecurityDescriptor = descriptor;
        attributes.bInheritHandle = FALSE;
    }

    // 手动重置事件：主程序置位后由我们显式 ResetEvent 收回，
    // 避免「一次信号被消费两次」或者「信号在重置前就丢了」
    _unlockEvent = CreateEventW(
        attributes.lpSecurityDescriptor ? &attributes : nullptr,
        TRUE, FALSE, eventName.c_str());
    if (descriptor) LocalFree(descriptor);

    if (!_unlockEvent) {
        Trace(L"创建解锁事件失败：%s，Win32=%u", eventName.c_str(), GetLastError());
        return false;
    }

    _stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!_stopEvent) {
        Trace(L"创建停止事件失败，Win32=%u", GetLastError());
        CloseHandle(_unlockEvent);
        _unlockEvent = nullptr;
        return false;
    }

    _watchdog = CreateThread(nullptr, 0, &Provider::WatchdogProc, this, 0, nullptr);
    if (!_watchdog) {
        Trace(L"创建看门狗线程失败，Win32=%u", GetLastError());
        CloseHandle(_stopEvent);
        CloseHandle(_unlockEvent);
        _stopEvent = nullptr;
        _unlockEvent = nullptr;
        return false;
    }

    Trace(L"看门狗已就绪，监听 %s", eventName.c_str());
    return true;
}

void Provider::StopWatchdog() {
    if (_stopEvent) SetEvent(_stopEvent);

    if (_watchdog) {
        // 等待线程真正退出：DllCanUnloadNow 要靠它保证没有悬空线程
        WaitForSingleObject(_watchdog, 3000);
        CloseHandle(_watchdog);
        _watchdog = nullptr;
    }
    if (_stopEvent) {
        CloseHandle(_stopEvent);
        _stopEvent = nullptr;
    }
    if (_unlockEvent) {
        CloseHandle(_unlockEvent);
        _unlockEvent = nullptr;
    }
}

DWORD WINAPI Provider::WatchdogProc(LPVOID param) {
    auto* self = static_cast<Provider*>(param);
    if (!self) return 0;

    // 线程期间保活：这样 Provider 不会在线程还在跑的时候被析构
    self->AddRef();

    HANDLE handles[2] = {self->_unlockEvent, self->_stopEvent};
    for (;;) {
        const DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

        // 被要求停止
        if (wait == WAIT_OBJECT_0 + 1) break;
        // 事件句柄失效（例如另一条路径已经关掉了它）
        if (wait != WAIT_OBJECT_0) break;

        ResetEvent(self->_unlockEvent);

        {
            auto state = self->_state;
            EnterCriticalSection(&state->lock);
            state->armed = true;
            state->status = kStatusArmed;
            state->hint = L"已在手机上完成生物识别，正在登录";
            LeaveCriticalSection(&state->lock);
        }
        Trace(L"收到解锁信号，已置为已授权");

        // 通知 LogonUI 重新枚举：
        // 配合 GetCredentialCount 的 pbAutoLogonWithDefault 完成自动提交。
        // 这一步是「不用点鼠标就能登录」的关键，也是 Windows 上唯一
        // 官方支持的免交互提交路径。
        ICredentialProviderEvents* events = nullptr;
        UINT_PTR context = 0;
        EnterCriticalSection(&self->_lock);
        events = self->_providerEvents;
        if (events) events->AddRef();
        context = self->_adviseContext;
        LeaveCriticalSection(&self->_lock);

        if (events) {
            events->CredentialsChanged(context);
            events->Release();
        } else {
            Trace(L"没有可用的 LogonUI 事件接口，自动提交可能不会触发");
        }
    }

    self->Release();
    return 0;
}

}  // namespace pawlocker
