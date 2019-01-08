#include <iostream>
#include <atlbase.h>


CComPtr<IUnknown> CoCreateAsUser (wchar_t* progid, wchar_t* user, wchar_t* passwd) {
    // impersonate a different user
    CHandle user_token;
    if (!LogonUser(user, L""/*domain*/, passwd, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &user_token.m_h)) {
        auto err = GetLastError(); abort();
    }
    if (!ImpersonateLoggedOnUser(user_token)) {
        auto err = GetLastError(); abort();
    }

    // attempt to disable COM security and enable cloaking
    HRESULT hr = CoInitializeSecurity(nullptr, -1/*auto*/, nullptr, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_STATIC_CLOAKING, NULL);
    if (FAILED(hr))
        abort();

    // create COM object in a separate process (fails with 0x80080005: Server execution failed)
    CComPtr<IUnknown> obj;
#ifdef DEBUG_COM_ACTIVATION
    // open Event Viewer, "Windows Logs" -> "System" log to see details on failures
    CLSID clsid = {};
    CLSIDFromProgID(progid, &clsid);
    CComPtr<IClassFactory> cf;
    hr = CoGetClassObject(clsid, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING, NULL, IID_IClassFactory, (void**)&cf);
    if (FAILED(hr))
        abort();
    hr = cf->CreateInstance(nullptr, IID_IUnknown, (void**)&obj);
    if (FAILED(hr))
        abort();
#else
    hr = obj.CoCreateInstance(progid, nullptr, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING);
    if (FAILED(hr))
        abort();
#endif

    // undo impersonation
    if (!RevertToSelf()) {
        auto err = GetLastError(); abort();
    }

    return obj;
}


int wmain (int argc, wchar_t *argv[]) {
    if (argc < 4) {
        std::cerr << "Too few arguments\n.";
        std::cerr << "Usage: ComImpersonation.exe <ProgID> <username> <password>" << std::endl;
        return -1;
    }

    // initialize multi-threaded COM apartment
    if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
        abort();

    CComPtr<IUnknown> obj = CoCreateAsUser(argv[1], argv[2], argv[3]);
    std::cout << "Object created" << std::endl;
}
