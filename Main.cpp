#include <iostream>
#include <stdexcept>
#include <comdef.h> // for _com_error
#include <atlbase.h>


/** Translate COM HRESULT failure into exceptions. */
static void CHECK(HRESULT hr) {
    if (FAILED(hr)) {
        _com_error err(hr);
        const wchar_t * msg = err.ErrorMessage(); // weak ptr.
        abort();
    }
}


int wmain(int argc, wchar_t *argv[]) {
    if (argc < 3) {
        std::cerr << "Too few arguments\n.";
        std::cerr << "Usage: ComImpersonation.exe <ProgID> <username> <password>" << std::endl;
        return -1;
    }

    // initialize multi-threaded COM apartment
    CHECK(CoInitializeEx(NULL, COINIT_MULTITHREADED));

    // impersonate a different user
    CHandle user_token;
    {
        if (!LogonUser(argv[2]/*user*/, L""/*domain*/, argv[3]/*passwd*/, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &user_token.m_h)) {
            auto err = GetLastError(); abort();
        }
        if (!ImpersonateLoggedOnUser(user_token)) {
            auto err = GetLastError(); abort();
        }
    }

    // attempt to disable COM security
    CHECK(CoInitializeSecurity(nullptr, -1/*auto*/, nullptr, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_STATIC_CLOAKING, NULL));

    // create COM object in a separate process
    CComPtr<IUnknown> obj;
    DWORD class_context = CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING; // | CLSCTX_ENABLE_AAA;
#ifdef DEBUG_COM_ACTIVATION
    // open Event Viewer, "Windows Logs" -> "System" log to see details on failures
    CLSID clsid = {};
    CHECK(CLSIDFromProgID(argv[1], &clsid));
    CComPtr<IClassFactory> cf;
    CHECK(CoGetClassObject(clsid, class_context, NULL, IID_IClassFactory, (void**)&cf));
    CHECK(cf->CreateInstance(nullptr, IID_IUnknown, (void**)&obj));
#else
    CHECK(obj.CoCreateInstance(argv[1], nullptr, class_context));
#endif
    std::cout << "Object created" << std::endl;
}
