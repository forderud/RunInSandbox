#include <conio.h>
#include <iostream>
#include <Shlobj.h>
#include <atlbase.h>
#include <atlcom.h>
#include <wincred.h>
#pragma comment(lib, "Credui.lib")
#include "ComCreate.hpp"
#include "ProcCreate.hpp"
#include "../TestControl/TestControl_h.h"



/** Enable launch/activation requests from all LOW IL clients.
*   WARNING: Does not seem to work!
    REF: https://docs.microsoft.com/nb-no/windows/win32/com/the-com-elevation-moniker */
static void SetLaunchActPermissions(const wchar_t* app_id) {
    // open registry path
    CComBSTR reg_path(L"AppID\\");
    reg_path.Append(app_id);

    CRegKey appid_reg;
    if (appid_reg.Open(HKEY_CLASSES_ROOT, reg_path, KEY_READ | KEY_WRITE) != ERROR_SUCCESS)
        abort();

    // Allow World Local Launch/Activation permissions. Label the SD for LOW IL Execute UP
    // REF: https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
    // REF: https://docs.microsoft.com/en-us/windows/win32/com/access-control-lists-for-com
    PSECURITY_DESCRIPTOR low_integrity_sd = nullptr;
    std::wstring low_int_access = L"O:BA";// Owner: Built-in administrators (BA)
    low_int_access += L"G:BA";            // Group: Built-in administrators (BA)
    low_int_access += L"D:(A;;0xb;;;WD)"; // DACL: (ace_type=Allow (A); ace_flags=; rights=ACTIVATE_LOCAL | EXECUTE_LOCAL | EXECUTE (0xb); object_guid=; inherit_object_guid=; account_sid=Everyone (WD))
    low_int_access += L"(A;;0xb;;;S-1-15-2-1)"; // (ace_type=Allow (A); ace_flags=; rights=ACTIVATE_LOCAL | EXECUTE_LOCAL | EXECUTE (0xb); object_guid=; inherit_object_guid=; account_sid=ALL_APP_PACKAGES (S-1-15-2-1))
    low_int_access += L"S:(ML;;NX;;;LW)"; // SACL:(ace_type=Mandatory Label (ML); ace_flags=; rights=No Execute Up (NX); object_guid=; inherit_object_guid=; account_sid=Low mandatory level (LW))
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(low_int_access.c_str(), SDDL_REVISION_1, &low_integrity_sd, NULL))
        abort();

    // Set launch/activation permissions
    // REF: https://docs.microsoft.com/en-us/windows/win32/com/launchpermission
    DWORD dwLen = GetSecurityDescriptorLength(low_integrity_sd);
    LONG lResult = RegSetValueExW(appid_reg, L"LaunchPermission", 0/*reserved*/, REG_BINARY, (BYTE*)low_integrity_sd, dwLen);
    if (lResult != ERROR_SUCCESS)
        abort();

    LocalFree(low_integrity_sd);
};


int wmain (int argc, wchar_t *argv[]) {
#if 0
    SetLaunchActPermissions(L"{264FBADA-8FEF-44B7-801E-B728A1749B5A}");
#endif

    if (argc < 2) {
        std::wcerr << L"Too few arguments\n.";
        std::wcerr << L"Usage: RunInSandbox.exe [ac|li|mi|hi] ProgID\n";
        std::wcerr << L"Usage: RunInSandbox.exe [ac|li|mi|hi] ExePath|URL\n";
        return -1;
    }

    int arg_idx = 1;
    IntegrityLevel mode = FromString(argv[arg_idx]);
    if (mode != IntegrityLevel::Default)
        arg_idx++;

    // check if 1st argument is a COM class ProgID
    CLSID clsid = {};
    std::wstring progid = argv[arg_idx];
    bool progid_provided = SUCCEEDED(CLSIDFromProgID(progid.c_str(), &clsid));
    bool url_provided = std::wstring(argv[arg_idx]).substr(0, 4) == L"http";

    if (progid_provided) {
        // initialize multi-threaded COM apartment
        if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
            abort();

        std::wcout << L"Creating COM object " << progid << L" in " << ToString(mode).c_str() << L"...\n";

        CComPtr<IUnknown> obj;
        if ((mode == IntegrityLevel::High) && !IsUserAnAdmin()) {
            // launch "COM Elevation Moniker"-compatible COM class in elevated process
            // example COM class for testing: HNetCfg.FwOpenPort
            CHECK(CoCreateInstanceElevated<IUnknown>(0, clsid, &obj));
            std::wcout << L"COM server sucessfully created in elevated process.\n";
        } else {
            arg_idx++;
            obj = CoCreateAsUser_impersonate(clsid, mode);
        }

        // try to add two numbers
        CComPtr<ISimpleCalculator> calc;
        obj.QueryInterface(&calc);
        if (calc) {
            int sum = 0;
            CHECK(calc->Add(2, 3, &sum));

            std::wcout << L"Add(2, 3) returned " << sum << L".\n";
            assert(sum == 2 + 3);

            BOOL is_elevated = false, high_integrity = false;
            CHECK(calc->IsElevated(&is_elevated, &high_integrity));
            std::wcout << L"IsElevated: " << (is_elevated ? L"true" : L"false") << L"\n";
            std::wcout << L"HighIntegrity: " << (high_integrity ? L"true" : L"false") << L"\n";

#if 0
            BOOL has_network = false;
            CComBSTR host = L"1.1.1.1"; // cloudflare
            calc->TestNetworkConnection(host, 80, &has_network);
            std::wcout << L"HasNetwork: " << (has_network ? L"true" : L"false") << L"\n";
#endif
#if 0
            // try to create child object in elevated process
            // WARNING: Doesn't trigger UAC elevation if launched from a medium-integrity process that was launched from an elevated process
            std::wcout << L"Creating child COM object " << progid << L" in " << ToString(IntegrityLevel::High).c_str() << L"...\n";
            CComPtr<IUnknown> child;
            CHECK(calc->CreateInstance(true, clsid, &child));
            CComPtr<ISimpleCalculator> child_calc;
            child_calc = child;
            is_elevated = false, high_integrity = false;
            CHECK(child_calc->IsElevated(&is_elevated, &high_integrity));
            std::wcout << L"Child IsElevated: " << (is_elevated ? L"true" : L"false") << L"\n";
            std::wcout << L"Child HighIntegrity: " << (high_integrity ? L"true" : L"false") << L"\n";
#endif
        }

        // try to make window visible
        SetComAttribute(obj, L"Visible", true);

        Sleep(2000); // wait 2sec to keep the child process alive a bit
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
        arg_idx++;
        std::vector<std::wstring> args;
        for (; arg_idx < argc; ++arg_idx)
            args.push_back(argv[arg_idx]);

        ProcCreate(progid.c_str(), mode, args);
    }

    std::wcout << L"[done]" << std::endl;
}
