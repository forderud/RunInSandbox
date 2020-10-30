#include <Shlobj.h>
#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"


HRESULT STDMETHODCALLTYPE TestControl::IsElevated (/*out*/BOOL * is_elevated) {
    HandleWrap token;
    if (!OpenProcessToken(GetCurrentProcess( ), TOKEN_QUERY, &token))
        return E_ACCESSDENIED;

    TOKEN_ELEVATION elevation = {};
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &cbSize))
        return E_ACCESSDENIED;

    *is_elevated = elevation.TokenIsElevated;
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
