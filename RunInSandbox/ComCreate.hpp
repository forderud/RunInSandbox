#pragma once
#include "Sandboxing.hpp"
#include "ProcCreate.hpp"
#include <atlbase.h>
#include "../TestControl/ComSupport.hpp"
#define DEBUG_COM_ACTIVATION


/** Attempt to create a COM server that runds through a specific user account.
    NOTICE: Non-admin users need to be granted local DCOM "launch" and "activation" permission to the DCOM object to prevent E_ACCESSDENIED (General access denied error). Unfortunately, creation still fails with CO_E_SERVER_EXEC_FAILURE.

    WARNING: Does not seem to work. The process is launched with the correct user, but crashes immediately. Might be caused by incorrect env. vars. inherited from the parent process.
    REF: https://stackoverflow.com/questions/54076028/dcom-registration-timeout-when-attempting-to-start-a-com-server-through-a-differ */
CComPtr<IUnknown> CoCreateAsUser_impersonate (CLSID clsid, IntegrityLevel mode, wchar_t* user, wchar_t* passwd) {
    std::unique_ptr<ImpersonateThread> impersonate;
    if (mode != IntegrityLevel::AppContainer) {
        // impersonate a different user
        impersonate.reset(new ImpersonateThread(user, passwd, mode));
    } else {
        // launch process in an AppContainer process.
        ProcessHandles token = ProcCreate(L"C:\\Dev\\RunInSandbox\\x64\\Debug\\TestControl.exe", IntegrityLevel::AppContainer, 0, nullptr);
        // impersonate the process thread
        impersonate.reset(new ImpersonateThread(std::move(token.thread), IMPERSONATE_ANONYMOUS));
    }

    CComPtr<IUnknown> obj;
    // create COM object in a separate process
#ifdef DEBUG_COM_ACTIVATION
    // open Event Viewer, "Windows Logs" -> "System" log to see details on failures
    CComPtr<IClassFactory> cf;
    HRESULT hr = CoGetClassObject(clsid, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING, NULL, IID_IClassFactory, (void**)&cf);
    CHECK(hr);
    hr = cf->CreateInstance(nullptr, IID_IUnknown, (void**)&obj);
    CHECK(hr);
#else
    HRESULT hr = obj.CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING);
    CHECK(hr);
#endif

    return obj;
}


/** Attempt to create a COM server that runds through a specific user account.
    WARNING: Does not seem to work. Fails silently and instead launches with the current user.
    REF: https://stackoverflow.com/questions/10589440/cocreateinstanceex-returns-s-ok-with-invalid-credentials-on-win2003/54135347#54135347 */
CComPtr<IUnknown> CoCreateAsUser_dcom(CLSID clsid, wchar_t* user, wchar_t* passwd) {
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
        CHECK(hr);
        hr = cf->CreateInstance(nullptr, IID_IUnknown, (void**)&obj);
        CHECK(hr);
#else
        MULTI_QI mqi = { &IID_IUnknown, nullptr, E_FAIL };
        HRESULT hr = CoCreateInstanceEx(clsid, nullptr, CLSCTX_REMOTE_SERVER /*| CLSCTX_ENABLE_CLOAKING | CLSCTX_ENABLE_AAA*/, &si, 1, &mqi);
        CHECK(hr);
        obj.Attach(mqi.pItf);
#endif
    }

    return obj;
}


/** Create a AppID and elevation-enabled COM server in a admin process.
    REF: https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker */
template <typename T>
static CComPtr<T> CoCreateInstanceAsAdmin (HWND window, const IID & classId) {
    std::wstring name;
    name.resize(39);
    CHECK(::StringFromGUID2(classId, const_cast<wchar_t*>(name.data()), static_cast<int>(name.size())));
    name = L"Elevation:Administrator!new:" + name;

    BIND_OPTS3 options = {};
    options.cbStruct = sizeof(options);
    options.hwnd = window;
    options.dwClassContext = CLSCTX_LOCAL_SERVER;

    CComPtr<T> obj;
    CHECK(::CoGetObject(name.c_str(), &options, __uuidof(T), reinterpret_cast<void**>(&obj)));
    return obj;
}


/** Try to set a an attribute on an automation-compatible COM server. */
static bool SetComAttribute(CComPtr<IUnknown> & obj, CComBSTR name, CComVariant value) {
    CComPtr<IDispatch> obj_disp;
    if (FAILED(obj.QueryInterface(&obj_disp)))
        return false;

    // lookup attribute ID
    DISPID dispid = 0;
    if (FAILED(obj_disp->GetIDsOfNames(IID_NULL, &name, 1, LOCALE_USER_DEFAULT, &dispid)))
        return false;

    // prepare arguments
    DISPPARAMS params = {};
    DISPID type = DISPID_PROPERTYPUT;
    {
        params.cArgs = 1;
        params.rgvarg = &value;
        params.cNamedArgs = 1;
        params.rgdispidNamedArgs = &type;
    }

    // invoke call
    HRESULT hr = obj_disp->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYPUT, &params, NULL, NULL, NULL);
    return SUCCEEDED(hr);
}
