#include <Shlobj.h>
#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"


TestControl::TestControl(){
}

TestControl::~TestControl() {
}

HRESULT STDMETHODCALLTYPE TestControl::Add(int a, int b, int * sum) {
    *sum = a + b;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE TestControl::IsElevated (/*out*/BOOL * is_elevated, /*out*/BOOL * high_integrity) {
    *is_elevated = ImpersonateThread::IsProcessElevated();

    IntegrityLevel proc_integrity = ImpersonateThread::GetProcessLevel();
    *high_integrity = (proc_integrity >= IntegrityLevel::High);

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
