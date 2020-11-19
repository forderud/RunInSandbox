#include <iostream>
#include <string>
#include "../RunInSandbox/Sandboxing.hpp"


int wmain(int argc, wchar_t *argv[]) {
    if (argc < 3) {
        std::wcout << L"Utility to make filesystem paths writable from low-integrity processes.\n";
        std::wcout << L"Usage: GrantAccess [ac|li] <path>\n";
        return 1;
    }

    std::wstring mode = argv[1];
    std::wstring path = argv[2];

    if (mode == L"li") {
        std::wcout << L"Making path low-integrity: " << path << std::endl;
        DWORD err = MakePathLowIntegrity(path.c_str());
        if (err != ERROR_SUCCESS) {
            _com_error error(err);
            std::wcerr << L"ERROR: " << error.ErrorMessage() << L" (" << err << L")" << std::endl;
            return -2;
        }
    } else if (mode == L"ac") {
        std::wcout << L"Making path accible by AppContainers: " << path << std::endl;
        SidWrap sid;
        WIN32_CHECK(ConvertStringSidToSid(L"S-1-15-2-1", &sid)); // ALL_APP_PACKAGES
        DWORD err = MakePathAppContainer(sid, path.c_str());
        if (err != ERROR_SUCCESS) {
            _com_error error(err);
            std::wcerr << L"ERROR: " << error.ErrorMessage() << L" (" << err << L")" << std::endl;
            return -2;
        }
    } else {
        std::wcerr << L"ERROR: Unknown mode " << mode << std::endl;
        return -2;
    }

    std::wcout << L"Success." << std::endl;
    return 0; // success
}
