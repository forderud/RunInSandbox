#pragma once
#include "Sandboxing.hpp"
#include "ProcCreate.hpp"
#include <atlbase.h>
#include "../TestControl/ComSupport.hpp"
#define DEBUG_COM_ACTIVATION

enum MODE {
    MODE_PLAIN,
    MODE_LOW_INTEGRITY,
    MODE_APP_CONTAINER,
};

/** Attempt to create a COM server that runds through a specific user account.
    NOTICE: Non-admin users need to be granted local DCOM "launch" and "activation" permission to the DCOM object to prevent E_ACCESSDENIED (General access denied error). Unfortunately, creation still fails with CO_E_SERVER_EXEC_FAILURE.

    WARNING: Does not seem to work. The process is launched with the correct user, but crashes immediately. Might be caused by incorrect env. vars. inherited from the parent process.
    REF: https://stackoverflow.com/questions/54076028/dcom-registration-timeout-when-attempting-to-start-a-com-server-through-a-differ */
CComPtr<IUnknown> CoCreateAsUser_impersonate (CLSID clsid, MODE mode, wchar_t* user, wchar_t* passwd) {
    std::unique_ptr<ImpersonateThread> impersonate;
    if (mode < MODE_APP_CONTAINER) {
        // impersonate a different user
        impersonate.reset(new ImpersonateThread(user, passwd, mode == MODE_LOW_INTEGRITY));
    } else {
        // impersonate an AppContainer
#if 0
        // WARNING: Does not work. CoCreateInstance will fail with E_OUTOFMEMORY
        AppContainerWrap ac;
        SECURITY_CAPABILITIES sec_cap = ac.SecCap();
        std::vector<HANDLE> saved_handles;
        HandleWrap base_token;
        HandleWrap ac_token = CreateLowBoxToken(base_token, TokenImpersonation, sec_cap, saved_handles);
        impersonate.reset(new ImpersonateThread(std::move(ac_token), IMPERSONATE_USER));
#else
        // launch notepad in an AppContainer process.
        // This is really overkill, since we only need the thread token
        ProcessHandles token = ProcCreate_AppContainer(L"C:\\Windows\\System32\\notepad.exe", false);

        // impersonate the notepad thread
        // WARNING: AppContainer property is _not_ propagated when calling CoCreateInstance
        impersonate.reset(new ImpersonateThread(std::move(token.thread), IMPERSONATE_ANONYMOUS));
#endif
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
