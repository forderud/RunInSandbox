#include <Shlobj.h>
#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"


static bool IsProcessElevated () {
    // TODO: Seem to always return true if the parent process is elevated
    HandleWrap token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        abort();

    TOKEN_ELEVATION elevation = {};
    DWORD ret_len = 0;
    if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &ret_len))
        abort();

    {
        TOKEN_ELEVATION_TYPE elevation_type = {};
        ret_len = 0;
        if (!GetTokenInformation(token, TokenElevationType, &elevation_type, sizeof(elevation_type), &ret_len))
            abort();

        if (elevation.TokenIsElevated)
            assert(elevation_type == TokenElevationTypeFull);
    }

    return elevation.TokenIsElevated;
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
    IntegrityLevel proc_integrity = ImpersonateThread::GetProcessLevel();

    *is_elevated = (proc_integrity >= IntegrityLevel::High);
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
