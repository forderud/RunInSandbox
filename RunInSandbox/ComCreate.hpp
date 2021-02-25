#pragma once
#include "Sandboxing.hpp"
#include "ProcCreate.hpp"
#include <atlbase.h>
#include <tuple>
#include "../TestControl/ComSupport.hpp"
#define DEBUG_COM_ACTIVATION

/** Returns the COM EXE path and AppID GIUD string. */
static std::tuple<std::wstring,std::wstring> GetLocalServerPath (CLSID clsid, REGSAM bitness = 0/*same bitness as client*/) {
    // build registry path
    CComBSTR clsid_path(L"CLSID\\");
    clsid_path.Append(clsid);

    std::wstring exe_path;
    {
        CComBSTR local_server_path = clsid_path;
        local_server_path.Append(L"\\LocalServer32");

        // extract COM class
        CRegKey cls_reg;
        if (cls_reg.Open(HKEY_CLASSES_ROOT, local_server_path, KEY_READ | bitness) != ERROR_SUCCESS)
            return {L"", L""};

        ULONG exe_path_len = 0;
        if (cls_reg.QueryStringValue(nullptr, nullptr, &exe_path_len) != ERROR_SUCCESS)
            return {L"", L""};

        exe_path.resize(exe_path_len, L'\0');
        if (cls_reg.QueryStringValue(nullptr, const_cast<wchar_t*>(exe_path.data()), &exe_path_len) != ERROR_SUCCESS)
            return {L"", L""};
        exe_path.resize(exe_path_len - 1); // remove extra zero-termination

        if (exe_path[0] == '"')
            exe_path = exe_path.substr(1, exe_path.size() - 2); // remove quotes

        // remove "/automation" (or other) argument if present
        size_t idx = exe_path.find(L" /");
        if (idx != exe_path.npos)
            exe_path = exe_path.substr(0, idx);
    }

    std::wstring app_id;
    if (!exe_path.empty()){
        // extract COM class
        CRegKey cls_reg;
        if (cls_reg.Open(HKEY_CLASSES_ROOT, clsid_path, KEY_READ | bitness) != ERROR_SUCCESS)
            abort();

        ULONG app_id_len = 0;
        if (cls_reg.QueryStringValue(L"AppID", nullptr, &app_id_len) != ERROR_SUCCESS)
            abort();

        app_id.resize(app_id_len, L'\0');
        if (cls_reg.QueryStringValue(L"AppID", const_cast<wchar_t*>(app_id.data()), &app_id_len) != ERROR_SUCCESS)
            abort();
        app_id.resize(app_id_len - 1); // remove extra zero-termination
    }

    if (exe_path.empty() && (bitness == 0))
        std::tie(exe_path, app_id) = GetLocalServerPath(clsid, KEY_WOW64_32KEY); // fallback to 32bit part of registry

    return std::tie(exe_path,app_id);
}


static void GrantAppContainerPermissions(std::wstring exe_path, std::wstring app_id) {
    SidWrap ac_sid;
    WIN32_CHECK(ConvertStringSidToSid(L"S-1-15-2-1", &ac_sid)); // ALL_APP_PACKAGES

    // Grant ALL_APPLICATION_PACKAGES read&execute permissions to the EXE
    DWORD err = MakePathAppContainer(ac_sid, exe_path.c_str(), GENERIC_READ | GENERIC_EXECUTE);
    if (err != ERROR_SUCCESS) {
        // ignore errors for now
    }


    CComBSTR appid_path(L"AppID\\");
    appid_path.Append(app_id.c_str());

    CRegKey appid_reg;
    if (appid_reg.Open(HKEY_CLASSES_ROOT, appid_path, KEY_READ | KEY_WRITE) != ERROR_SUCCESS)
        abort();

    // TODO: Update AppID LaunchPermission registry key to grant ALL_APPLICATION_PACKAGES local activation permission
    std::vector<uint8_t> acl;
    //appid_reg.SetBinaryValue(L"LaunchPermission", acl.data(), (ULONG)acl.size());
}


/** Attempt to create a COM server that runds through a specific user account.
    AppContainer problem:
      Process is created but CoGetClassObject activation gives E_ACCESSDENIED (The machine-default permission settings do not grant Local Activation permission for the COM Server) */
CComPtr<IUnknown> CoCreateAsUser_impersonate (CLSID clsid, IntegrityLevel mode) {
    std::unique_ptr<ImpersonateThread> impersonate;
    bool explicit_process_create = (mode == IntegrityLevel::AppContainer);
    if (explicit_process_create) {
        // launch COM server process manually
        std::wstring exe_path;
        std::wstring app_id;
        std::tie(exe_path, app_id) = GetLocalServerPath(clsid);

        GrantAppContainerPermissions(exe_path, app_id);

        HandleWrap proc = ProcCreate(exe_path.c_str(), mode, {L"-Embedding"}); // mimic how svchost passes "-Embedding" argument
        // impersonate the process thread
        impersonate.reset(new ImpersonateThread(proc));
    } else {
        // impersonate a different integrity (or user)
        impersonate.reset(new ImpersonateThread(mode));
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
