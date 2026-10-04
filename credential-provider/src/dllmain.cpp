// dllmain.cpp —— 进程内 COM 服务器的入口与类工厂。
//
// 唯一的导出是 DllGetClassObject / DllCanUnloadNow（见 PawLockerProvider.def）。
//
// 一个必须守住的纪律：**DllMain 里什么都不能做。**
// 加载器锁下做任何实质工作（创建线程、加载 DLL、等待同步对象）都可能死锁，
// 而这里的死锁意味着用户登不进系统。所以 DllMain 只记一个实例句柄。

#include <windows.h>

#include <new>

#include "PawLockerContract.h"
#include "Provider.h"
#include "Trace.h"

namespace {

HINSTANCE g_instance = nullptr;

// 存活的对象数。DllCanUnloadNow 靠它决定 DLL 能否被卸载。
volatile LONG g_objectCount = 0;

void IncrementObjectCount() {
    InterlockedIncrement(&g_objectCount);
}

void DecrementObjectCount() {
    InterlockedDecrement(&g_objectCount);
}

class ClassFactory : public IClassFactory {
public:
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (ppv == nullptr) return E_POINTER;
        *ppv = nullptr;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&_ref));
    }

    STDMETHODIMP_(ULONG) Release() override {
        const LONG remaining = InterlockedDecrement(&_ref);
        if (remaining == 0) delete this;
        return static_cast<ULONG>(remaining);
    }

    STDMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** ppv) override {
        if (ppv == nullptr) return E_POINTER;
        *ppv = nullptr;

        // 不支持聚合：凭据提供程序从来不需要它，实现反而多一处出错面
        if (outer != nullptr) return CLASS_E_NOAGGREGATION;

        auto* provider = new (std::nothrow) pawlocker::Provider();
        if (provider == nullptr) return E_OUTOFMEMORY;

        const HRESULT hr = provider->QueryInterface(riid, ppv);
        provider->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL lock) override {
        if (lock) {
            IncrementObjectCount();
        } else {
            DecrementObjectCount();
        }
        return S_OK;
    }

private:
    LONG _ref = 1;
};

}  // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_instance = instance;
        // 我们不需要线程创建/销毁通知，关掉可以省下可观的加载开销
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** ppv) {
    if (ppv == nullptr) return E_POINTER;
    *ppv = nullptr;

    if (!IsEqualCLSID(clsid, pawlocker::kProviderClsid)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    auto* factory = new (std::nothrow) ClassFactory();
    if (factory == nullptr) return E_OUTOFMEMORY;

    const HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

extern "C" HRESULT WINAPI DllCanUnloadNow() {
    return (g_objectCount == 0) ? S_OK : S_FALSE;
}
