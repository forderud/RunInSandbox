#include <Windows.h>
#include <userenv.h>
#include <iostream>
#include "../RunInSandbox/Sandboxing.hpp"

#pragma comment(lib, "Userenv.lib") // for DeriveAppContainerSidFromAppContainerName


int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Compute the SID for a given AppContainer.\n");
        wprintf(L"USAGE: AppContainerSid.exe <AppContainer-name>\n");
        return -1;
    }
    
    std::wstring appContainer = argv[1];

    // DOC: https://devblogs.microsoft.com/oldnewthing/20220502-00/?p=106550
    SidWrap sid;
    HRESULT hr = DeriveAppContainerSidFromAppContainerName(appContainer.c_str(), &sid);
    if (FAILED(hr)) {
        _com_error err(hr);
        wprintf(L"ERROR: Unable to convert AppContainer SID (%s).\n", err.ErrorMessage());
        return -2;
    }

    // convert SID to string representation in "S-1-15-2-x1-x2-x3-x4-x5-x6-x7" format,
    // where x1-x7 are the first 28 bytes of the SHA256 hash of the lowercase app name.
    LocalWrap<wchar_t*> sid_str;
    BOOL ok = ConvertSidToStringSidW(sid, &sid_str);
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"ERROR: Unable to convert AppContainer SID to string (%u).\n", err);
        return -3;
    }

    wprintf(L"%s\n", (wchar_t*)sid_str);
    return 0;
}
