#include "Trace.h"
#include "PawLockerContract.h"

#include <strsafe.h>

#include <cstdarg>
#include <cstdio>

namespace pawlocker {
namespace {

constexpr wchar_t kLogDir[] = L"C:\\ProgramData\\PawLocker";
constexpr wchar_t kLogFile[] = L"provider.log";
constexpr DWORD kMaxLogBytes = 2u * 1024u * 1024u;

CRITICAL_SECTION g_logLock;
bool g_logLockReady = false;
bool g_logLockInitTried = false;

void EnsureInit() {
    if (g_logLockReady || g_logLockInitTried) return;
    g_logLockInitTried = true;
    // 延迟初始化：DllMain 里做这件事有加载器锁死锁的风险
    __try {
        InitializeCriticalSection(&g_logLock);
        g_logLockReady = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_logLockReady = false;
    }
}

void AppendFile(const wchar_t* line) {
    CreateDirectoryW(kLogDir, nullptr);

    wchar_t path[MAX_PATH] = {};
    lstrcpynW(path, kLogDir, MAX_PATH);
    lstrcatW(path, L"\\");
    lstrcatW(path, kLogFile);

    // 超过上限就重头写。日志不是数据，不需要保留历史。
    WIN32_FILE_ATTRIBUTE_DATA attrs = {};
    if (GetFileAttributesExW(path, GetFileExInfoStandard, &attrs)) {
        ULARGE_INTEGER size = {};
        size.LowPart = attrs.nFileSizeLow;
        size.HighPart = attrs.nFileSizeHigh;
        if (size.QuadPart > kMaxLogBytes) {
            DeleteFileW(path);
        }
    }

    HANDLE file = CreateFileW(
        path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME st = {};
    GetLocalTime(&st);

    wchar_t stamped[2048] = {};
    int written = wsprintfW(
        stamped, L"[%04u-%02u-%02u %02u:%02u:%02u] %s\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, line);

    if (written > 0) {
        DWORD bytes = static_cast<DWORD>(written) * sizeof(wchar_t);
        DWORD done = 0;
        WriteFile(file, stamped, bytes, &done, nullptr);
    }
    CloseHandle(file);
}

}  // namespace

void Trace(const wchar_t* format, ...) {
    wchar_t body[1600] = {};
    va_list args;
    va_start(args, format);
    // 用 _vsnwprintf_s 而不是 StringCchVPrintf：不需要额外头文件，行为也够用
    _vsnwprintf_s(body, _TRUNCATE, format, args);
    va_end(args);

    OutputDebugStringW(L"PawLocker: ");
    OutputDebugStringW(body);
    OutputDebugStringW(L"\n");

    EnsureInit();
    if (!g_logLockReady) {
        // 连临界区都没建起来就不要再碰文件了，避免把一个可恢复的问题变成崩溃
        AppendFile(body);
        return;
    }

    __try {
        EnterCriticalSection(&g_logLock);
        AppendFile(body);
        LeaveCriticalSection(&g_logLock);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // 日志写失败绝不能影响登录流程
        LeaveCriticalSection(&g_logLock);
    }
}

bool TraceFilePath(wchar_t* buffer, DWORD cchBuffer) {
    if (buffer == nullptr || cchBuffer == 0) return false;
    return SUCCEEDED(StringCchPrintfW(buffer, cchBuffer, L"%s\\%s", kLogDir, kLogFile));
}

}  // namespace pawlocker
