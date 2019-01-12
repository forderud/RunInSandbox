#include <iostream>
#include "CoCreateAsUser.hpp"


int wmain (int argc, wchar_t *argv[]) {
    if (argc < 4) {
        std::cerr << "Too few arguments\n.";
        std::cerr << "Usage: ComImpersonation.exe <ProgID> <username> <password>" << std::endl;
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

    //CComPtr<IUnknown> obj = CoCreateAsUser_impersonate(argv[1], argv[2], argv[3]);
    CComPtr<IUnknown> obj = CoCreateAsUser_dcom(argv[1], argv[2], argv[3]);
    std::cout << "COM object created" << std::endl;
}
