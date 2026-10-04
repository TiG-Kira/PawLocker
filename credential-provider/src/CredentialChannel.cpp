#include "CredentialChannel.h"

#include "PawLockerContract.h"
#include "Trace.h"

#include <vector>

namespace pawlocker {
namespace {

// 读完整个句柄，直到对端关闭或读满。命名管道是流式的，
// 单次 ReadFile 不保证拿到全部字节 —— 这是最容易被忽略、
// 又只在「数据稍微大一点」时才复现的一类 bug。
bool ReadAll(HANDLE pipe, BYTE* buffer, DWORD total, std::wstring* detail) {
    DWORD received = 0;
    while (received < total) {
        DWORD chunk = 0;
        if (!ReadFile(pipe, buffer + received, total - received, &chunk, nullptr)) {
            DWORD error = GetLastError();
            // 对端已关闭但数据已读满，属于正常收尾
            if (error == ERROR_BROKEN_PIPE && received == total) return true;
            if (detail) {
                wchar_t text[128] = {};
                wsprintfW(text, L"ReadFile 失败（Win32 %u），已读 %u/%u", error, received, total);
                *detail = text;
            }
            return false;
        }
        if (chunk == 0) {
            if (detail) *detail = L"对端提前关闭了管道";
            return false;
        }
        received += chunk;
    }
    return true;
}

bool DecodeUtf8(const BYTE* bytes, DWORD count, std::wstring* out) {
    if (count == 0) {
        out->clear();
        return true;
    }
    int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(bytes),
                                    static_cast<int>(count), nullptr, 0);
    if (chars <= 0) return false;

    std::vector<wchar_t> buffer(static_cast<size_t>(chars));
    int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(bytes),
                                      static_cast<int>(count), buffer.data(), chars);
    if (written <= 0) return false;

    out->assign(buffer.data(), static_cast<size_t>(written));
    SecureZeroMemory(buffer.data(), buffer.size() * sizeof(wchar_t));
    return true;
}

}  // namespace

void ResolvedCredential::Wipe() {
    if (!password.empty()) {
        SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
    }
    password.clear();
    userName.clear();
    domain.clear();
    sid.clear();
}

ChannelStatus FetchCredential(
    const std::wstring& userName,
    ResolvedCredential* out,
    std::wstring* detail) {
    if (out == nullptr) return ChannelStatus::Malformed;

    const std::wstring name = userName.empty()
        ? std::wstring(kFallbackUserName)
        : userName;
    std::wstring pipeName = kPipePrefix;
    pipeName += name;

    // 主程序先建管道再置事件，所以到这里管道通常已经在了。
    // 仍然等一下是为了兜住「事件与管道之间的调度间隙」。
    if (!WaitNamedPipeW(pipeName.c_str(), kChannelTimeoutMillis)) {
        const DWORD error = GetLastError();
        if (detail) {
            *detail = (error == ERROR_FILE_NOT_FOUND)
                ? L"主程序没有在监听凭据通道（可能未运行，或解锁策略不是凭据提供程序）"
                : L"等待凭据通道超时";
        }
        return ChannelStatus::NoProvider;
    }

    HANDLE pipe = CreateFileW(
        pipeName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        if (detail) *detail = L"打开凭据通道失败";
        return ChannelStatus::ConnectFailed;
    }

    ChannelStatus status = ChannelStatus::Malformed;
    std::vector<BYTE> payload;

    do {
        // ① 4 字节小端总长
        BYTE lengthBytes[sizeof(DWORD)] = {};
        if (!ReadAll(pipe, lengthBytes, sizeof(lengthBytes), detail)) {
            status = ChannelStatus::ReadFailed;
            break;
        }
        DWORD payloadBytes = 0;
        memcpy(&payloadBytes, lengthBytes, sizeof(payloadBytes));

        if (payloadBytes < kBlobHeaderBytes || payloadBytes > kMaxPayloadBytes) {
            if (detail) *detail = L"凭据通道返回了不合法长度";
            break;
        }

        // ② 载荷
        payload.assign(payloadBytes, 0);
        if (!ReadAll(pipe, payload.data(), payloadBytes, detail)) {
            status = ChannelStatus::ReadFailed;
            break;
        }

        CredentialBlobHeader header = {};
        memcpy(&header, payload.data(), kBlobHeaderBytes);

        if (header.magic != kBlobMagic) {
            if (detail) *detail = L"凭据通道 magic 不匹配";
            break;
        }
        if (header.version != kBlobVersion) {
            if (detail) *detail = L"凭据通道版本不匹配";
            break;
        }
        if ((header.flags & kFlagHasPassword) == 0) {
            if (detail) *detail = L"凭据里没有密码";
            break;
        }

        const DWORD fields[4] = {
            header.userNameBytes, header.domainBytes, header.passwordBytes, header.sidBytes};
        DWORD sum = 0;
        for (DWORD each : fields) {
            if (each > kMaxFieldBytes) {
                sum = 0xFFFFFFFF;
                break;
            }
            sum += each;
        }
        if (sum > payloadBytes || kBlobHeaderBytes + sum != payloadBytes) {
            if (detail) *detail = L"凭据字段长度不自洽";
            break;
        }

        const BYTE* cursor = payload.data() + kBlobHeaderBytes;
        if (!DecodeUtf8(cursor, header.userNameBytes, &out->userName)) break;
        cursor += header.userNameBytes;
        if (!DecodeUtf8(cursor, header.domainBytes, &out->domain)) break;
        cursor += header.domainBytes;
        if (!DecodeUtf8(cursor, header.passwordBytes, &out->password)) break;
        cursor += header.passwordBytes;
        if (!DecodeUtf8(cursor, header.sidBytes, &out->sid)) break;

        if (out->userName.empty() || out->password.empty()) {
            if (detail) *detail = L"凭据里的用户名或密码为空";
            break;
        }

        status = ChannelStatus::Ok;
    } while (false);

    // 立刻清零本地副本，做完就走
    if (!payload.empty()) {
        SecureZeroMemory(payload.data(), payload.size());
    }
    FlushFileBuffers(pipe);
    CloseHandle(pipe);

    if (status != ChannelStatus::Ok) {
        out->Wipe();
    } else {
        Trace(L"已从凭据通道取回账户 %s（域 %s）", out->userName.c_str(), out->domain.c_str());
    }
    return status;
}

}  // namespace pawlocker
