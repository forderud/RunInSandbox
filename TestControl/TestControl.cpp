#include "TestControl.hpp"
#include "../RunInSandbox/ComCreate.hpp"
#include "Socket.hpp"
#include <atlwin.h>
#include <future>


TestControl::TestControl(){
}

TestControl::~TestControl() {
}

HRESULT TestControl::IsElevated (/*out*/VARIANT_BOOL * is_elevated, /*out*/VARIANT_BOOL * is_high_il) {
    *is_elevated = ImpersonateThread::IsProcessElevated();

    IntegrityLevel proc_integrity = ImpersonateThread::GetProcessLevel();
    *is_high_il = (proc_integrity >= IntegrityLevel::High);

    return S_OK;
}

HRESULT TestControl::GetUsername(/*out*/BSTR* username) {
    WCHAR buffer[128] = {};
    auto buf_len = (DWORD)std::size(buffer);
    GetUserNameW(buffer, &buf_len);

    CComBSTR result(buffer);
    *username = result.Detach();
    return S_OK;
}


HRESULT TestControl::Add(int a, int b, int * sum) {
    *sum = a + b;
    return S_OK;
}


HRESULT TestControl::PerformAdminTask() {
    IntegrityLevel proc_integrity = ImpersonateThread::GetProcessLevel();
    if (proc_integrity < IntegrityLevel::High)
        return E_ACCESSDENIED;

    // TODO: Perform some task requiring admin privileves
    return S_OK;
}


HRESULT TestControl::TestNetworkConnection (/*in*/BSTR host, USHORT port, /*out*/VARIANT_BOOL * can_access) {
    *can_access = false; // assume no connectivity by default

    try {
        SocketWrap sock;
        *can_access = sock.TryToConnect(ToAscii(host), port);
    } catch (const std::exception & ) {
        return E_FAIL;
    }

    return S_OK;
}


HRESULT TestControl::CreateInstance (VARIANT_BOOL elevated, /*in*/CLSID clsid, /*out*/IUnknown ** obj) {
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

HRESULT TestControl::TestCallback(IUnknown * obj) {
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


HRESULT TestControl::MoveMouseCursor(VARIANT_BOOL threaded, int x_pos, int y_pos) {
    auto create_window_and_move_cursor = [x_pos, y_pos]() -> HRESULT {
        // create independent window to receive cursor events
        CWindow wnd;
        {
            RECT rect = { 0, 0, 200, 200 };
            wnd.Create(L"Button", /*parent*/NULL, rect, L"MoveMouseCursor", WS_OVERLAPPEDWINDOW);
            wnd.ShowWindow(SW_SHOW);
        }

        // move window to foreground, so that it starts receiving events
        {
            // bring window to the front & activate it
            BOOL ok = BringWindowToTop(wnd);
            assert(ok);
            // verify that window is activated
            HWND active_wnd = GetActiveWindow();
            assert(wnd == active_wnd);

            ok = SetForegroundWindow(wnd); // assume host have called CoAllowSetForegroundWindow first
            assert(ok);

            HWND foreground_wnd = GetForegroundWindow();
            if (foreground_wnd != wnd) {
                // SetForegroundWindow failed silently due to UIPI limitation
                DWORD err = GetLastError(); // TODO: Figure out why err==0 here
                return E_ACCESSDENIED;
            }
        }

        // will fail if the foreground window is running at higher IL than this process (UIPI limitation)
        BOOL ok = SetCursorPos(x_pos, y_pos);
        if (!ok) {
            DWORD err = GetLastError(); // TODO: Figure out why err==0 here
            return E_ACCESSDENIED;
        }

        return S_OK;
    };

    if (threaded)
        return std::async(create_window_and_move_cursor).get(); // run in separate thread
    else
        return create_window_and_move_cursor(); // run in current thread
}


HRESULT TestControl::GetWindow(/*out*/HWND* result) {
    // create dummy window that will be used for establishing a parent-child UI relationship with the parent process
    CWindow wnd;
    {
        RECT rect = { 200, 0, 400, 200 };
        wnd.Create(L"Button", /*parent*/NULL, rect, L"Child window", WS_OVERLAPPEDWINDOW);
        wnd.ShowWindow(SW_SHOW);
    }

    *result = wnd;
    return S_OK;
}
