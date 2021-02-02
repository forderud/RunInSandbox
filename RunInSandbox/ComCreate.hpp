#pragma once
#include "Sandboxing.hpp"
#include "ProcCreate.hpp"
#include <atlbase.h>
#include "../TestControl/ComSupport.hpp"
#define DEBUG_COM_ACTIVATION


std::wstring GetLocalServerPath (CLSID clsid, REGSAM bitness) {
    // build registry path
    CComBSTR reg_path(L"CLSID\\");
    reg_path.Append(clsid);
    reg_path.Append(L"\\LocalServer32");

    // extract COM class
    CRegKey cls_reg;
    if (cls_reg.Open(HKEY_CLASSES_ROOT, reg_path, KEY_READ | bitness) != ERROR_SUCCESS)
        return L"";

    ULONG    exe_path_len = 0;
    if (cls_reg.QueryStringValue(nullptr, nullptr, &exe_path_len) != ERROR_SUCCESS)
        return L"";

    std::wstring exe_path(exe_path_len, L'\0');
    if (cls_reg.QueryStringValue(nullptr, const_cast<wchar_t*>(exe_path.data()), &exe_path_len) != ERROR_SUCCESS)
        return L"";
    exe_path.resize(exe_path_len-1); // remove extra zero-termination

    if (exe_path[0] == '"')
        exe_path = exe_path.substr(1, exe_path.size()-2); // remove quotes

    return exe_path;
}


/** Attempt to create a COM server that runds through a specific user account.
    AppContainer problem:
      Process is created but CoGetClassObject activation gives E_ACCESSDENIED (The machine-default permission settings do not grant Local Activation permission for the COM Server) */
CComPtr<IUnknown> CoCreateAsUser_impersonate (CLSID clsid, IntegrityLevel mode, wchar_t* user, wchar_t* passwd) {
    std::unique_ptr<ImpersonateThread> impersonate;
    bool explicit_process_create = (mode == IntegrityLevel::AppContainer);
    if (explicit_process_create) {
        // launch COM server process manually
        std::wstring exe_path = GetLocalServerPath(clsid, /*same bitness as client*/0);
        if (exe_path.empty())
            exe_path = GetLocalServerPath(clsid, KEY_WOW64_32KEY); // fallback to 32bit part of registry

        HandleWrap proc = ProcCreate(exe_path.c_str(), mode, {L"-Embedding"}); // mimic how svchost passes "-Embedding" argument
        // impersonate the process thread
        impersonate.reset(new ImpersonateThread(proc));
    } else {
        // impersonate a different integrity (or user)
        impersonate.reset(new ImpersonateThread(mode, user, passwd));
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
static HRESULT CoCreateInstanceElevated (HWND window, const IID & classId, T ** result) {
    if (!result)
        return E_INVALIDARG;
    if (*result)
        return E_INVALIDARG;

    std::wstring name;
    name.resize(39);
    HRESULT hr = ::StringFromGUID2(classId, const_cast<wchar_t*>(name.data()), static_cast<int>(name.size()));
    if (FAILED(hr))
        return hr;
    name = L"Elevation:Administrator!new:" + name;

    std::wcout << L"CoGetObject: " << name << L'\n';

    BIND_OPTS3 options = {};
    options.cbStruct = sizeof(options);
    options.hwnd = window;
    options.dwClassContext = CLSCTX_LOCAL_SERVER;

    return ::CoGetObject(name.c_str(), &options, __uuidof(T), reinterpret_cast<void**>(result));
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
