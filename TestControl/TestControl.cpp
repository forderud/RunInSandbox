#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"
#include "Socket.hpp"
#include <atlwin.h>


TestControl::TestControl(){
}

TestControl::~TestControl() {
}

HRESULT STDMETHODCALLTYPE TestControl::Add(int a, int b, int * sum) {
    *sum = a + b;
    return S_OK;
}


HRESULT STDMETHODCALLTYPE TestControl::PerformAdminTask() {
    IntegrityLevel proc_integrity = ImpersonateThread::GetProcessLevel();
    if (proc_integrity < IntegrityLevel::High)
        return E_ACCESSDENIED;

    // TODO: Perform some task requiring admin privileves
    return S_OK;
}


HRESULT STDMETHODCALLTYPE TestControl::IsElevated (/*out*/BOOL * is_elevated, /*out*/BOOL * is_high_il) {
    *is_elevated = ImpersonateThread::IsProcessElevated();

    IntegrityLevel proc_integrity = ImpersonateThread::GetProcessLevel();
    *is_high_il = (proc_integrity >= IntegrityLevel::High);

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
    CWindow wnd;
    {
        // create window to receive cursor events
        RECT rect = { 0, 0, 200, 200 };
        wnd.Create(L"Button", /*parent*/NULL, rect, L"window", WS_OVERLAPPEDWINDOW);
        wnd.ShowWindow(SW_SHOW);
        // move window to foreground, so that it starts receiving events
        BOOL ok = SetForegroundWindow(wnd); // assume host have called CoAllowSetForegroundWindow first
        assert(ok);
    }

    // will fail if the foreground window is running at higher IL than this process (UIPI limitation)
    BOOL ok = SetCursorPos(x_pos, y_pos);
    if (!ok) {
        DWORD err = GetLastError();
        // TODO: Figure out why err==0 here
        return E_ACCESSDENIED;
    }

    return S_OK;
}
