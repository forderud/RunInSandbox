#include "Resource.h"
#include "TestControl_h.h"
#include "TestControl_i.c"
#include "ComSupport.hpp"
#include <psapi.h>
#include <Shlobj.h>


class TestControlModule : public ATL::CAtlExeModuleT<TestControlModule> {
public:
    TestControlModule() {
        //MessageBox(NULL, L"TestControl init", L"Debugging aid", MB_OK);
    }

    DECLARE_LIBID(LIBID_TestControl)
};

TestControlModule _AtlModule;


// EXE Entry Point
int wWinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, wchar_t* /*lpCmdLine*/, int nShowCmd/*=SW_SHOWDEFAULT*/) {
    // initialize COM early for programmatic COM security
    _AtlModule.InitializeCom();

    // Disable COM security to allow any client to connect.
    // WARNING: Enables non-admin clients to connect to a server running with admin privileges.
    HRESULT hr = CoInitializeSecurity(nullptr, -1/*auto*/, nullptr, NULL/*reserved*/,
        RPC_C_AUTHN_LEVEL_DEFAULT, ///< 
        RPC_C_IMP_LEVEL_IDENTIFY,  ///< allow server to identify but not impersonate client
        nullptr, EOAC_NONE/*capabilities*/, NULL/*reserved*/);
    if (FAILED(hr))
        abort();

    // prevent type lib registration from failing when not running as admin
    if(!IsUserAnAdmin())
        AtlSetPerUserRegistration(true);

    // register type libraries (needed for interface mashalling)
    hr = _AtlModule.RegisterServer(true);
    if (FAILED(hr))
        abort();

    return _AtlModule.WinMain(nShowCmd);
}
