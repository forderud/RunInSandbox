#include "Resource.h"
#include "TestControl_h.h"
#include "TestControl_i.c"
#include "ComSupport.hpp"
#include <psapi.h>

#ifdef _WINDLL
class TestControlModule : public ATL::CAtlDllModuleT<TestControlModule> {
public:
    DECLARE_LIBID(LIBID_TestControl)
    DECLARE_REGISTRY_APPID_RESOURCEID(IDR_AppID, "{264FBADA-8FEF-44B7-801E-B728A1749B5A}")
};

#else

class TestControlModule : public ATL::CAtlExeModuleT<TestControlModule> {
public:
    TestControlModule() {
        //MessageBox(NULL, L"TestControl init", L"Debugging aid", MB_OK);
    }

    DECLARE_LIBID(LIBID_TestControl)
    DECLARE_REGISTRY_APPID_RESOURCEID(IDR_AppID, "{264FBADA-8FEF-44B7-801E-B728A1749B5A}")
};
#endif

TestControlModule _AtlModule;


#ifdef _WINDLL
// DLL Entry Point
extern "C" BOOL WINAPI DllMain(HINSTANCE /*hInstance*/, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
#if 0
        // break dllhost.exe until debugger is attached
        HANDLE process = GetCurrentProcess();
        TCHAR filename[MAX_PATH] = {};
        GetProcessImageFileName(process, filename, MAX_PATH);
        if (std::string(filename).find("dllhost.exe") != std::string::npos) {
            while (!IsDebuggerPresent())
                Sleep(200);
        }
#endif
    }

    return _AtlModule.DllMain(dwReason, lpReserved);
}

// Used to determine whether the DLL can be unloaded by OLE.
STDAPI DllCanUnloadNow() {
    return _AtlModule.DllCanUnloadNow();
}

// Returns a class factory to create an object of the requested type.
_Check_return_
STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID* ppv) {
    return _AtlModule.DllGetClassObject(rclsid, riid, ppv);
}

// DllRegisterServer - Adds entries to the system registry.
STDAPI DllRegisterServer() {
    // registers object, typelib and all interfaces in typelib
    return _AtlModule.DllRegisterServer();
}

// DllUnregisterServer - Removes entries from the system registry.
STDAPI DllUnregisterServer() {
    return _AtlModule.DllUnregisterServer();
}

// DllInstall - Adds/Removes entries to the system registry per user per machine.
STDAPI DllInstall(BOOL bInstall, _In_opt_  LPCWSTR pszCmdLine) {
    static const wchar_t szUserSwitch[] = L"user";

    if (pszCmdLine != NULL) {
        if (_wcsnicmp(pszCmdLine, szUserSwitch, _countof(szUserSwitch)) == 0)
            ATL::AtlSetPerUserRegistration(true);
    }

    HRESULT hr = E_FAIL;
    if (bInstall) {
        hr = DllRegisterServer();
        if (FAILED(hr))
            DllUnregisterServer();
    } else {
        hr = DllUnregisterServer();
    }

    return hr;
}

#else

// EXE Entry Point (console subsystem)
int wmain(int /*argc*/, wchar_t * /*argv*/[]) {
    return _AtlModule.WinMain(SW_SHOWDEFAULT);
}
// EXE Entry Point (windows subsystem)
int wWinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, LPTSTR /*lpCmdLine*/, int nShowCmd/*=SW_SHOWDEFAULT*/) {
    return _AtlModule.WinMain(nShowCmd);
}
#endif
