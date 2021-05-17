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

/** Window Station switching RAII wrapper. */
class WindowStation {
public:
    WindowStation(const wchar_t* name) {
        prev_winsta = GetProcessWindowStation();
        assert(prev_winsta);

        ACCESS_MASK access = WINSTA_ACCESSCLIPBOARD |WINSTA_ACCESSGLOBALATOMS |WINSTA_CREATEDESKTOP |WINSTA_ENUMDESKTOPS |WINSTA_ENUMERATE |WINSTA_EXITWINDOWS |WINSTA_READATTRIBUTES |WINSTA_READSCREEN |WINSTA_WRITEATTRIBUTES;
        cur_winsta = OpenWindowStationW(name, false, access);
        assert(cur_winsta);

        BOOL ok = SetProcessWindowStation(cur_winsta);
        assert(ok);
    }

    ~WindowStation() {
        // switch back to prev. window station
        SetProcessWindowStation(prev_winsta);

        if (cur_winsta)
            CloseWindowStation(cur_winsta);
    }
private:
    HWINSTA prev_winsta = nullptr; ///< weak ptr. don't need to close
    HWINSTA cur_winsta = nullptr;
};

/** Desktop switching RAII wrapper. */
class Desktop {
public:
    Desktop(const wchar_t* name) {
        prev_desk = GetThreadDesktop(GetCurrentThreadId());
        assert(prev_desk);

        ACCESS_MASK access = DESKTOP_CREATEMENU |DESKTOP_CREATEWINDOW |DESKTOP_ENUMERATE |DESKTOP_HOOKCONTROL |DESKTOP_JOURNALPLAYBACK |DESKTOP_JOURNALRECORD |DESKTOP_READOBJECTS |DESKTOP_SWITCHDESKTOP |DESKTOP_WRITEOBJECTS;
        cur_desk = OpenDesktopW(name, NULL, false, access);
        assert(cur_desk);

        BOOL ok = SetThreadDesktop(cur_desk);
        assert(ok);
    }
    ~Desktop() {
        // switch back to prev. desktop
        SetThreadDesktop(prev_desk);

        if (cur_desk)
            CloseDesktop(cur_desk);
    }
private:
    HDESK prev_desk = nullptr; ///< weak ptr. don't need to close
    HDESK cur_desk = nullptr;
};

HRESULT STDMETHODCALLTYPE TestControl::MoveMouseCursor(int x_pos, int y_pos) {
#if 0
    // This does NOT fix failing SetCursorPos in medium IL if the parent process is high IL
    // switch to window station "Winsta0"
    WindowStation winsta(L"Winsta0");
    // switch to desktop "default"
    Desktop desk(L"default");
#endif

    // will fail without WINSTA_WRITEATTRIBUTES access
    BOOL ok = SetCursorPos(x_pos, y_pos);
    if (!ok) {
        DWORD err = GetLastError();
        // TODO: Figure out why err==0 here
        return E_ACCESSDENIED;
    }
    return S_OK;
}
