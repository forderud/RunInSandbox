#include <Shlobj.h>
#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"


static bool IsProcessElevated () {
#if 1
    // Determine the integrity level for a process.
    // Based on https://github.com/chromium/chromium/blob/master/base/process/process_info_win.cc */
    HANDLE process_token = GetCurrentProcessToken();
    DWORD token_info_length = 0;
    if (GetTokenInformation(process_token, TokenIntegrityLevel, NULL, 0, &token_info_length))
        abort();

    std::vector<char> token_info_buf(token_info_length);
    auto* token_info = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(token_info_buf.data());
    if (!GetTokenInformation(process_token, TokenIntegrityLevel, token_info, token_info_length, &token_info_length))
        abort();

    DWORD integrity_level = *GetSidSubAuthority(token_info->Label.Sid, *GetSidSubAuthorityCount(token_info->Label.Sid)-1);
    return (integrity_level >= SECURITY_MANDATORY_HIGH_RID);
#else
    // TODO: Seem to always return true if the parent process is elevated
    HandleWrap token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        abort();

    TOKEN_ELEVATION elevation = {};
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &cbSize))
        abort();

    return elevation.TokenIsElevated;
#endif
}


TestControl::TestControl(){
}

TestControl::~TestControl() {
}

HRESULT STDMETHODCALLTYPE TestControl::Add(int a, int b, int * sum) {
    *sum = a + b;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE TestControl::IsElevated (/*out*/BOOL * is_elevated) {
    *is_elevated = IsProcessElevated();
    return S_OK;
}

HRESULT STDMETHODCALLTYPE TestControl::CreateInstance (BOOL elevated, /*in*/CLSID clsid, /*out*/IUnknown ** obj) {
    if (!obj)
        return E_INVALIDARG;

    if (elevated) {
        return CoCreateInstanceElevated<IUnknown>(NULL, clsid, obj);
    } else {
        CComPtr<IUnknown> res;
        HRESULT hr = res.CoCreateInstance(clsid);
        if (FAILED(hr))
            return hr;

        *obj = res.Detach();
        return S_OK;
    }
}
