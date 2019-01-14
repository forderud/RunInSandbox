#include <iostream>
#include <Shlobj.h>
#include "ComCreate.hpp"
#include "ProcCreate.hpp"


int wmain (int argc, wchar_t *argv[]) {
    if (!IsUserAnAdmin()) {
        std::wcerr << L"ERROR: Admin priveledges not detected. Failing early, since some functionality might not work.\n";
        return -2;
    }

    if (argc < 2) {
        std::wcerr << L"Too few arguments\n.";
        std::wcerr << L"Usage: RunInSandbox.exe ProgID  [username] [password]\n";
        std::wcerr << L"Usage: RunInSandbox.exe ExePath [username] [password]\n";
        return -1;
    }

    // check if 1st argument is a COM class ProgID
    CLSID clsid = {};
    bool progid_provided = SUCCEEDED(CLSIDFromProgID(argv[1], &clsid));

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

        std::wcout << L"Creating COM object " << argv[1] << L" in low-integrity...\n";
        wchar_t* user = (argc >= 3) ? argv[2] : nullptr;
        wchar_t* pw   = (argc >= 4) ? argv[3] : nullptr;
        CComPtr<IUnknown> obj1 = CoCreateAsUser_impersonate(clsid, user, pw, true);
        //CComPtr<IUnknown> obj2 = CoCreateAsUser_dcom(clsid, user, pw);

    } else {
        std::wcout << L"Starting executable " << argv[1] << L" in AppContainer...\n";
        ProcCreate(argv[1]);
    }
    std::wcout << L"[done]" << std::endl;
}
