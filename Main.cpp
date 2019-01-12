#include <iostream>
#include "CoCreateAsUser.hpp"
#include "ProcCreate.hpp"


int wmain (int argc, wchar_t *argv[]) {
    if (argc < 2) {
        std::wcerr << L"Too few arguments\n.";
        std::wcerr << L"Usage: ComImpersonation.exe <ProgID>  <username> <password>\n";
        std::wcerr << L"Usage: ComImpersonation.exe <ExePath> [<username> <password>]\n";
        return -1;
    }

    // check if 1st argument is a COM class ProgID
    CLSID clsid = {};
    bool progid_provided = SUCCEEDED(CLSIDFromProgID(argv[1], &clsid));

    if (progid_provided) {
        if (argc < 4) {
            std::wcerr << L"ERROR: username and password arguments missing\n.";
            return -1;
        }

        // initialize multi-threaded COM apartment
        if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
            abort();

    #if 0
        // attempt to disable COM security and enable cloaking
        HRESULT hr = CoInitializeSecurity(nullptr, -1/*auto*/, nullptr, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE /*EOAC_STATIC_CLOAKING*/, NULL);
        if (FAILED(hr))
            abort();
    #endif

        std::wcout << L"Creating COM object " << argv[1] << L"...\n";
        //CComPtr<IUnknown> obj1 = CoCreateAsUser_impersonate(clsid, argv[2], argv[3]);
        CComPtr<IUnknown> obj2 = CoCreateAsUser_dcom(clsid, argv[2], argv[3]);
    } else {
        std::wcout << L"Starting executable " << argv[1] << L"...\n";
        ProcCreate(argv[1]);
    }
    std::wcout << L"[done]" << std::endl;
}
