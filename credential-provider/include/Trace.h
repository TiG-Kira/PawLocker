// Trace.h —— 极简日志。
//
// 这个 DLL 跑在 LogonUI 进程里。它一旦抛出异常或死锁，用户**就登不进系统了** ——
// 没有桌面、没有任务管理器、没有救援入口。所以这里的原则是：
// 日志通道本身绝不允许成为故障点，任何一步失败都静默吞掉。

#pragma once

#include <windows.h>

namespace pawlocker {

// 格式化输出一行日志，同时写到 %ProgramData%\PawLocker\provider.log 与调试器。
// 绝不抛异常、绝不阻塞在不可控的外部资源上。
void Trace(const wchar_t* format, ...);

// 日志文件路径（供注册向导展示「日志在哪」）。
bool TraceFilePath(wchar_t* buffer, DWORD cchBuffer);

}  // namespace pawlocker
