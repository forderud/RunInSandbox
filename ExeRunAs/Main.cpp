#include <iostream>
#include <Shlobj.h> // for IsUserAnAdmin


int wmain (int argc, wchar_t* argv[]) {
    if (!IsUserAnAdmin()) {
        wprintf(L"ERROR: Admin privileges required.\n");
        return -1;
    }

    if (argc < 2) {
        wprintf(L"USAGE: ExeRunAs.exe [UserName] <command>\n");
        wprintf(L"Examples:\n");
        wprintf(L"  LocalService account: ExeRunAs.exe LocalService cmd.exe\n");
        return 1;
    }

    wprintf(L"Not yet implemented.\n");
}
