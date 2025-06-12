#include <conio.h>
#include <iostream>
#include <thread>
#include <Shlobj.h>
#include <atlbase.h>
#include <atlcom.h>
#include <atlwin.h>
#include <wincred.h>
#pragma comment(lib, "Credui.lib")
#include "ComCreate.hpp"
#include "ProcCreate.hpp"
#include "../TestControl/TestControl_h.h"


/** COM callback test class. */
class ATL_NO_VTABLE CallbackTest : 
    public CComObjectRootEx<CComMultiThreadModel>,
    public CComCoClass<CallbackTest>, // no registry entries
    public ICallbackTest {
public:
    HRESULT Ping () override {
        std::wcout << L"  Callback received.\n";
        return S_OK;
    }

    BEGIN_COM_MAP(CallbackTest)
        COM_INTERFACE_ENTRY(ICallbackTest)
    END_COM_MAP()
};


/** Dummy class for enabling OLE drag-and-drop. Not used for anything. */
class DropTarget : 
    public CComObjectRootEx<CComSingleThreadModel>,
    public CComCoClass<DropTarget>, // no registry entries
    public IDropTarget {
public:
    HRESULT DragEnter(IDataObject* /*pDataObj*/, DWORD /*grfKeyState*/, POINTL /*pt*/, DWORD* /*pdwEffect*/) override {
        return E_NOTIMPL;
    }
    HRESULT DragOver(DWORD /*grfKeyState*/, POINTL /*pt*/, DWORD* /*pdwEffect*/) override {
        return E_NOTIMPL;
    }
    HRESULT DragLeave() override {
        return E_NOTIMPL;
    }
    HRESULT Drop(IDataObject* /*pDataObj*/, DWORD /*grfKeyState*/, POINTL /*pt*/, DWORD* /*pdwEffect*/) override {
        return E_NOTIMPL;
    }

    BEGIN_COM_MAP(DropTarget)
        COM_INTERFACE_ENTRY(IDropTarget)
    END_COM_MAP()
};

class RunInSandboxModule: public ATL::CAtlExeModuleT<RunInSandboxModule> {
};

RunInSandboxModule _AtlModule;


static void ComTests (CLSID clsid, IntegrityLevel mode, bool break_at_startup, bool grant_appcontainer_permissions, HWND wnd) {
    CComPtr<IUnknown> obj;
    if ((mode == IntegrityLevel::High) && !ImpersonateThread::IsProcessElevated()) {
        // launch "COM Elevation Moniker"-compatible COM class in elevated process
        // example COM class for testing: HNetCfg.FwOpenPort
        CHECK(CoCreateInstanceElevated<IUnknown>(0, clsid, &obj));
        std::wcout << L"COM server sucessfully created in elevated process.\n";
    } else {
        obj = CoCreateAsUser_impersonate(clsid, mode, break_at_startup, grant_appcontainer_permissions);
    }

    // allow COM server to set foreground window (needed to escape UIPI limitations)
    HRESULT hr = CoAllowSetForegroundWindow(obj, NULL);
    if (FAILED(hr))
        std::wcout << L"WARNING: CoAllowSetForegroundWindow failed. This might occur if the server is running in a background process.\n";

    // try to add two numbers
    CComPtr<ITestInterface> test;
    obj.QueryInterface(&test);
    if (test) {
        int sum = 0;
        CHECK(test->Add(2, 3, &sum));

        std::wcout << L"Add(2, 3) returned " << sum << L".\n";
        assert(sum == 2 + 3);

        VARIANT_BOOL is_elevated = false, is_high_il = false;
        CHECK(test->IsElevated(&is_elevated, &is_high_il));
        std::wcout << L"IsElevated: " << (is_elevated ? L"true" : L"false") << L"\n";
        std::wcout << L"IsHighIL: " << (is_high_il ? L"true" : L"false") << L"\n";

        CComBSTR username;
        CHECK(test->GetUsername(&username));
        std::wcout << L"Username: " << username.m_str << L"\n";

        {
            // fails for AppContainers if host is elevated
            std::wcout << L"Testing COM callback...\n";
            auto cb = CreateLocalInstance<CallbackTest>();
            CHECK(test->TestCallback(cb));
            std::wcout << L"[success]\n";
        }

        {
            std::wcout << L"Testing if admin task succeeds...\n";
            hr = test->PerformAdminTask();
            if (SUCCEEDED(hr))
                std::wcout << L"[success]\n";
            else
                std::wcout << L"[failed]\n";
        }

        if (mode >= IntegrityLevel::Medium) {
            bool reproduce_uipi_child_wnd_issue = true;
            if (reproduce_uipi_child_wnd_issue) {
                // Request child window from sandboxed COM/OLE process
                CComPtr<IOleWindow> win_test;
                test.QueryInterface(&win_test);
                HWND child_wnd = {};
                CHECK(win_test->GetWindow(&child_wnd));

                // Attach child to (invisible) parent window to simulate OLE embedding. This triggers UIPI SetForegroundWindow blocking that also affect unrelated windows.
                auto winStyle = GetWindowLongPtrW(child_wnd, GWL_STYLE);
                winStyle &= ~WS_CAPTION; // Remove title bar
                winStyle |= WS_CHILD;    // Convert to child window. Trigger UIPI blocking when used together with SetParent.
                SetWindowLongPtrW(child_wnd, GWL_STYLE, winStyle);
                SetParent(child_wnd, wnd); // Trigger UIPI blocking when used together with WS_CHILD
            }

            // Fails in medium IL if host is elevated despite the window being in foreground.
            std::wcout << L"Moving mouse cursor to top-left corner...\n";
            hr = test->MoveMouseCursor(false, 0, 0);
            if (FAILED(hr)) {
                _com_error err(hr);
                std::wcout << L"[FAILED] " << err.ErrorMessage() << std::endl;
            } else {
                std::wcout << L"[success]\n";
            }
        }

#if 0
        BOOL has_network = false;
        CComBSTR host = L"1.1.1.1"; // cloudflare
        test->TestNetworkConnection(host, 80, &has_network);
        std::wcout << L"HasNetwork: " << (has_network ? L"true" : L"false") << L"\n";
#endif
#if 0
        // try to create child object in elevated process
        // WARNING: Doesn't trigger UAC elevation if launched from a medium-integrity process that was launched from an elevated process
        std::wcout << L"Creating child COM object in " << ToString(IntegrityLevel::High).c_str() << L"...\n";
        CComPtr<IUnknown> child;
        CHECK(test->CreateInstance(true, clsid, &child));
        CComPtr<ITestInterface> child_test;
        child_test = child;
        is_elevated = false, is_high_il = false;
        CHECK(child_test->IsElevated(&is_elevated, &is_high_il));
        std::wcout << L"Child IsElevated: " << (is_elevated ? L"true" : L"false") << L"\n";
        std::wcout << L"Child IsHighIL: " << (is_high_il ? L"true" : L"false") << L"\n";
#endif
    }

    // try to make window visible
    SetComAttribute(obj, L"Visible", true);

    Sleep(2000); // wait 2sec to keep the child process alive a bit

    // signal that main thread should quit
    PostMessage(wnd, WM_QUIT, 0, 0);
}


int wmain (int argc, wchar_t *argv[]) {
    if (argc < 2) {
        std::wcerr << L"Too few arguments\n.";
        std::wcerr << L"Usage: RunInSandbox.exe [ac|li|mi|hi] [-g] [-b] ProgID\n";
        std::wcerr << L"Usage: RunInSandbox.exe [ac|li|mi|hi] [-b] ExePath|URL <arguments>\n";
        return -1;
    }

    std::wcout << "Host is running in " << ToString(ImpersonateThread::GetProcessLevel()) << L".\n";

    int arg_idx = 1;
    IntegrityLevel mode = FromString(argv[arg_idx]);
    if (mode != IntegrityLevel::Default)
        arg_idx++;

    // check for -g and -b arguments
    bool break_at_startup = false;
    bool grant_appcontainer_permissions = false;
    while (arg_idx < argc) {
        if (std::wstring(argv[arg_idx]) == L"-g") {
            grant_appcontainer_permissions = true;
        } else if (std::wstring(argv[arg_idx]) == L"-b") {
            break_at_startup = true;
        } else {
            break;
        }
        arg_idx++;
    }

    // check if next argument is a COM class ProgID
    CLSID clsid = {};
    std::wstring progid = argv[arg_idx];
    bool progid_provided = SUCCEEDED(CLSIDFromProgID(progid.c_str(), &clsid));
    bool url_provided = std::wstring(argv[arg_idx]).substr(0, 4) == L"http";
    arg_idx++;

    if (progid_provided) {
        // initialize single-threaded COM apartment with OLE support
        OleInitialize(NULL);
        HWND wnd = FindWindowEx(HWND_MESSAGE, NULL, NULL, NULL); // invisible message-only window for COM apartment

        // adjust COM security to allow OLE drag-and-drop
        HRESULT hr = CoInitializeSecurity(nullptr, -1/*auto*/, nullptr, NULL/*reserved*/,
            RPC_C_AUTHN_LEVEL_DEFAULT, ///< 
            RPC_C_IMP_LEVEL_IDENTIFY,  ///< allow server to identify but not impersonate client
            nullptr, EOAC_NONE/*capabilities*/, NULL/*reserved*/);
        if (FAILED(hr))
            abort();

        {
            std::wcout << L"Enabling OLE drag-and-drop.\n";
            // Triggers 0x80070005 "Access is denied" exception in AppContainer process if this process is elevated (high integrity level) unless COM security is tweaked
            auto drop_target = CreateLocalInstance<DropTarget>();
            CHECK(RegisterDragDrop(wnd, drop_target));
        }

        std::wcout << L"Creating COM object " << progid << L" in " << ToString(mode).c_str() << L"...\n";
        // perform COM calls from main thread (STA)
        ComTests(clsid, mode, break_at_startup, grant_appcontainer_permissions, wnd);
    } else if (url_provided) {
        std::wcout << L"Opening URL " << progid << " in default browser\n";
        if (ImpersonateThread::GetProcessLevel() == IntegrityLevel::Low)
            std::wcout << L"WARNING: Does not seem to work in low-integrity!\n";

        int ret = (int)reinterpret_cast<INT_PTR>(ShellExecuteW(NULL, NULL, progid.c_str(), NULL, NULL, SW_SHOWNORMAL));
        if (ret <= 32) {
            std::wcout << L"ShellExecute failed with code " << ret << std::endl;
            return ret;
        }
    } else {
        std::wcout << L"Starting executable " << progid << L" in " << ToString(mode).c_str() << L"...\n";
        std::vector<std::wstring> args;
        for (; arg_idx < argc; ++arg_idx)
            args.push_back(argv[arg_idx]);

        StartupInfoWrap si;

        std::unique_ptr<AppContainerWrap> ac;
        SECURITY_CAPABILITIES sec_cap = {}; // need to outlive CreateProcess
        if (mode == IntegrityLevel::AppContainer) {
            // create new AppContainer process, based on STARTUPINFO
            ac.reset(new AppContainerWrap(L"RunInSandbox.AppContainer", L"RunInSandbox.AppContainer", true/*network*/));

            sec_cap = ac->SecCap(); // need to outlive CreateProcess
            si.SetSecurity(&sec_cap);

            mode = IntegrityLevel::Default; // avoid double-impersonation
        }

        ProcessHandles proc = CreateSuspendedProcess(si, progid.c_str(), mode, args);

        if (proc.thrd.IsValid() && break_at_startup) {
            std::wcout << L"Process created in suspended mode. You can now attach a debugger for investigation of startup problems.\nPress any key to continue." << std::endl;
            std::wcin.get();
        }

        if (proc.thrd.IsValid()) {
            // awake process
            DWORD prev_sleep_cnt = ResumeThread(proc.thrd.Get());
            assert(prev_sleep_cnt == 1); prev_sleep_cnt;
        }
    }

    std::wcout << L"[done]" << std::endl;
}
