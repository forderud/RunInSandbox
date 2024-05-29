#include "Resource.h"
#include "TestControl_h.h"
#include "TestControl_i.c"
#include "ComSupport.hpp"
#include <psapi.h>


class TestControlModule : public ATL::CAtlExeModuleT<TestControlModule> {
public:
    TestControlModule() {
        //MessageBox(NULL, L"TestControl init", L"Debugging aid", MB_OK);
    }

    DECLARE_LIBID(LIBID_TestControl)
    DECLARE_REGISTRY_APPID_RESOURCEID(IDR_AppID, "{264FBADA-8FEF-44B7-801E-B728A1749B5A}")

    HRESULT InitializeSecurity() {
        // Disable COM security to allow any client to connect.
        // WARNING: Enables non-admin clients to connect to a server running with admin privileges.
        HRESULT hr = CoInitializeSecurity(nullptr, -1/*auto*/, nullptr, NULL/*reserved*/,
            RPC_C_AUTHN_LEVEL_DEFAULT, ///< 
            RPC_C_IMP_LEVEL_IDENTIFY,  ///< allow server to identify but not impersonate client
            nullptr, EOAC_NONE/*capabilities*/, NULL/*reserved*/);
        return hr;
    }
};

TestControlModule _AtlModule;



// EXE Entry Point
int wWinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, wchar_t* /*lpCmdLine*/, int nShowCmd/*=SW_SHOWDEFAULT*/) {
    // initialize COM early for programmatic COM security
    _AtlModule.InitializeCom();
    HRESULT hr = _AtlModule.InitializeSecurity();
    if (FAILED(hr))
        abort();

    return _AtlModule.WinMain(nShowCmd);
}
