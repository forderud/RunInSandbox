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


int wmain (int argc, wchar_t *argv[]) {
    if (argc < 2) {
        std::wcerr << L"Too few arguments\n.";
        std::wcerr << L"Usage: RunInSandbox.exe [ac|li] ProgID [username] [password]\n";
        std::wcerr << L"Usage: RunInSandbox.exe [ac|li] ExePath\n";
        return -1;
    }

    int arg_idx = 1;
    IntegrityLevel mode = FromString(argv[arg_idx]);
    if (mode != IntegrityLevel::Default)
        arg_idx++;

    // check if 1st argument is a COM class ProgID
    CLSID clsid = {};
    bool progid_provided = SUCCEEDED(CLSIDFromProgID(argv[arg_idx], &clsid));

    if (progid_provided) {
        // initialize multi-threaded COM apartment
        if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
            abort();

    #if 0
        // attempt to disable COM security and enable cloaking
        HRESULT hr = CoInitializeSecurity(nullptr, -1/*auto*/, nullptr, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE /*EOAC_STATIC_CLOAKING*/, NULL);
        if (FAILED(hr))
            abort();
    #endif

        std::wcout << L"Creating COM object " << argv[arg_idx];
        std::wcout << L" in " << ToString(mode).c_str() << L"...\n";

        if ((mode == IntegrityLevel::High) && !IsUserAnAdmin()) {
            // launch "COM Elevation Moniker"-compatible COM class in elevated process
            // example COM class for testing: HNetCfg.FwOpenPort
            CComPtr<IUnknown> a = CoCreateInstanceAsAdmin<IUnknown>(0, clsid);
            std::wcout << L"COM server sucessfully created in elevated process.\n";
            return 0;
        }

        arg_idx++;
        wchar_t* user = (argc > arg_idx) ? argv[arg_idx++] : nullptr;
        wchar_t* pw   = (argc > arg_idx) ? argv[arg_idx++] : nullptr;
        CComPtr<IUnknown> obj = CoCreateAsUser_impersonate(clsid, mode, user, pw);
        //CComPtr<IUnknown> obj = CoCreateAsUser_dcom(clsid, user, pw);

        // try to add two numbers
        CComPtr< ISimpleCalculator> calc;
        obj.QueryInterface(&calc);
        if (calc) {
            int sum = 0;
            CHECK(calc->Add(2, 3, &sum));

            std::wcout << L"Add(2, 3) returned " << sum << L".\n";
            assert(sum == 2 + 3);
        }

        // try to make window visible
        SetComAttribute(obj, L"Visible", true);
    } else {
        std::wcout << L"Starting executable " << argv[arg_idx];
        std::wcout << L" in " << ToString(mode).c_str() << L"...\n";

        std::unique_ptr<ImpersonateThread> admin_imp;
        if ((mode == IntegrityLevel::High) && !IsUserAnAdmin()) {
            //std::wcout << L"WARNING: Admin priveledges not detected. Some operations might fail.\n";

            CREDUI_INFOW credui = {};
            credui.cbSize = sizeof(credui);
            credui.pszMessageText = L"Please enter admin password";
            credui.pszCaptionText = L"Administrator privileges required";

            ULONG authPackage = 0;
            void  *outAuthBuf = nullptr;
            ULONG outAuthSize = 0;  
            BOOL save = false;  

            DWORD res = CredUIPromptForWindowsCredentialsW(&credui, /*auth err*/0, &authPackage, /*authBuff*/nullptr, /*auth buf size*/0, &outAuthBuf, &outAuthSize, &save, CREDUIWIN_GENERIC);
            if (res != ERROR_SUCCESS) {
                std::wcerr << L"ERROR: Authentication dialog canceled.\n";
                return -1;
            }

            WCHAR username[CREDUI_MAX_USERNAME_LENGTH + 1] = {};
            DWORD username_len = _countof(username);
            WCHAR password[CREDUI_MAX_PASSWORD_LENGTH + 1] = {};
            DWORD password_len = _countof(password);
            WCHAR domain[CRED_MAX_DOMAIN_TARGET_NAME_LENGTH + 1] = {};
            DWORD domain_len = 0;
            // Attempt to decrypt the user's password
            BOOL ok = CredUnPackAuthenticationBuffer(CRED_PACK_PROTECTED_CREDENTIALS, outAuthBuf, outAuthSize, username, &username_len, domain, &domain_len, password, &password_len);
            if (!ok) {
                std::wcerr << L"ERROR: Unable to retrieve credentials.\n";
                return -1;
            }

            admin_imp.reset(new ImpersonateThread(username, password, IntegrityLevel::Default));
            std::wcout << L"User credentials successfully impersonated.\n";

            SecureZeroMemory(password, sizeof(password));
            SecureZeroMemory(outAuthBuf, outAuthSize);
            CoTaskMemFree(outAuthBuf);
        }

        int extra_args = argc - arg_idx - 1;
        ProcCreate(argv[arg_idx], mode, extra_args, extra_args > 0 ? &argv[arg_idx+1] : nullptr);
    }

    std::wcout << L"[done]" << std::endl;
}
