#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"


HRESULT STDMETHODCALLTYPE TestControl::CreateInstance (BOOL elevated, /*in*/BSTR progid, /*out*/IUnknown ** obj) {
    if (!progid || !obj)
        return E_INVALIDARG;

    if (elevated) {
        CLSID clsid = {};
        HRESULT hr = CLSIDFromProgID(progid, &clsid);
        if (FAILED(hr))
            return hr;

        return CoCreateInstanceElevated<IUnknown>(NULL, clsid, obj);
    } else {
        CComPtr<IUnknown> res;
        HRESULT hr = res.CoCreateInstance(progid);
        if (FAILED(hr))
            return hr;

        *obj = res.Detach();
        return S_OK;
    }
}
