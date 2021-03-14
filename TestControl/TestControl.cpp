#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"
#include "Socket.hpp"


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


HRESULT STDMETHODCALLTYPE TestControl::TestNetworkConnection (/*in*/BSTR host, USHORT port, /*out*/BOOL * can_access) {
    *can_access = false; // assume no connectivity by default

    try {
        SocketWrap sock;
        *can_access = sock.TryToConnect(ToAscii(host), port);
    } catch (const std::exception & ) {
        return E_FAIL;
    }

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

HRESULT STDMETHODCALLTYPE TestControl::TestCallback(IUnknown * obj) {
    if (!obj)
        return E_INVALIDARG;

    // cast callback pointer
    CComPtr<ICallbackTest> tmp;
    HRESULT hr = obj->QueryInterface(&tmp);
    if (FAILED(hr))
        return E_INVALIDARG;

    // invoke callback
    return tmp->Ping();
}

HRESULT STDMETHODCALLTYPE TestControl::MoveMouseCursor(int x_pos, int y_pos) {
    // will fail without WINSTA_WRITEATTRIBUTES access
    BOOL ok = SetCursorPos(x_pos, y_pos);
    if (!ok) {
        DWORD err = GetLastError();
        // TODO: Figure out why err==0 here
        return E_ACCESSDENIED;
    }
    return S_OK;
}
