#include <iostream>
#include <atlbase.h>
//#define DEBUG_COM_ACTIVATION


/** Attempt to create a COM server that runds through a specific user account.
    WARNING: Does not seem to work. The process is launched with the correct user, but crashes immediately. Might be caused by incorrect env. vars. inherited from the parent process.
    REF: https://stackoverflow.com/questions/54076028/dcom-registration-timeout-when-attempting-to-start-a-com-server-through-a-differ */
CComPtr<IUnknown> CoCreateAsUser1 (wchar_t* progid, wchar_t* user, wchar_t* passwd) {
    // impersonate a different user
    CHandle user_token;
    if (!LogonUser(user, L""/*domain*/, passwd, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &user_token.m_h)) {
        auto err = GetLastError(); abort();
    }
    if (!ImpersonateLoggedOnUser(user_token)) {
        auto err = GetLastError(); abort();
    }

    // create COM object in a separate process (fails with 0x80080005: Server execution failed)
    CComPtr<IUnknown> obj;
#ifdef DEBUG_COM_ACTIVATION
    // open Event Viewer, "Windows Logs" -> "System" log to see details on failures
    CLSID clsid = {};
    CLSIDFromProgID(progid, &clsid);
    CComPtr<IClassFactory> cf;
    HRESULT hr = CoGetClassObject(clsid, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING, NULL, IID_IClassFactory, (void**)&cf);
    if (FAILED(hr))
        abort();
    hr = cf->CreateInstance(nullptr, IID_IUnknown, (void**)&obj);
    if (FAILED(hr))
        abort();
#else
    HRESULT hr = obj.CoCreateInstance(progid, nullptr, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING);
    if (FAILED(hr))
        abort();
#endif

    // undo impersonation
    if (!RevertToSelf()) {
        auto err = GetLastError(); abort();
    }

    return obj;
}


/** Attempt to create a COM server that runds through a specific user account.
    WARNING: Does not seem to work. Fails silently and instead launches with the current user.
    REF: https://stackoverflow.com/questions/10589440/cocreateinstanceex-returns-s-ok-with-invalid-credentials-on-win2003/54135347#54135347 */
CComPtr<IUnknown> CoCreateAsUser2 (wchar_t* progid, wchar_t* user, wchar_t* passwd) {
    CLSID clsid = {};
    CLSIDFromProgID(progid, &clsid);

    CComPtr<IUnknown> obj;
    {
#pragma warning(push)
#pragma warning(disable: 4996) // _wgetenv: This function or variable may be unsafe. Consider using _wdupenv_s instead.
        std::wstring computername = _wgetenv(L"COMPUTERNAME");
#pragma warning(pop)
        std::wstring domain = L"";

        COAUTHIDENTITY id = {};
        id.User = (USHORT*)user;
        id.UserLength = (ULONG)wcslen(user);
        id.Domain = (USHORT*)domain.c_str();
        id.DomainLength = (ULONG)domain.length();
        id.Password = (USHORT*)passwd;
        id.PasswordLength = (ULONG)wcslen(passwd);
        id.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        COAUTHINFO ai = {};
        ai.dwAuthnSvc = RPC_C_AUTHN_WINNT; // RPC_C_AUTHN_DEFAULT;
        ai.dwAuthzSvc = RPC_C_AUTHZ_NONE;
        ai.pwszServerPrincName = nullptr; // (WCHAR*)computername.c_str();
        ai.dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT; //RPC_C_AUTHN_LEVEL_CALL;
        ai.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        ai.pAuthIdentityData = &id;
        ai.dwCapabilities = EOAC_NONE; // EOAC_STATIC_CLOAKING;

        COSERVERINFO si = {};
        si.pAuthInfo = &ai;
        si.pwszName = (WCHAR*)computername.c_str();

#ifdef DEBUG_COM_ACTIVATION
        CComPtr<IClassFactory> cf;
        HRESULT hr = CoGetClassObject(clsid, CLSCTX_REMOTE_SERVER, &si, IID_IClassFactory, (void**)&cf);
        if (FAILED(hr))
            abort();
        hr = cf->CreateInstance(nullptr, IID_IUnknown, (void**)&obj);
        if (FAILED(hr))
            abort();
#else
        MULTI_QI mqi = { &IID_IUnknown, nullptr, E_FAIL };
        HRESULT hr = CoCreateInstanceEx(clsid, nullptr, CLSCTX_REMOTE_SERVER /*| CLSCTX_ENABLE_CLOAKING | CLSCTX_ENABLE_AAA*/, &si, 1, &mqi);
        if (FAILED(hr))
            abort();
        obj.Attach(mqi.pItf);
#endif
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

#if 0
    // attempt to disable COM security and enable cloaking
    HRESULT hr = CoInitializeSecurity(nullptr, -1/*auto*/, nullptr, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE /*EOAC_STATIC_CLOAKING*/, NULL);
    if (FAILED(hr))
        abort();
#endif

    //CComPtr<IUnknown> obj = CoCreateAsUser1(argv[1], argv[2], argv[3]);
    CComPtr<IUnknown> obj = CoCreateAsUser2(argv[1], argv[2], argv[3]);
    std::cout << "COM object created" << std::endl;
}
