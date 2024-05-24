#include "RunAs.hpp"
#include <iostream>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wprintf(L"USAGE: ComRunAs.exe <AppID> <UserName> <Password>\n");
        return 1;
    }

    WCHAR* appid = argv[1];
    WCHAR* username = argv[2];
    WCHAR* password = nullptr;
    if (argc >= 4)
        password = argv[3]; // optional

    wprintf(L"Configuring COM server with AppID %s to run with user %s.\n", appid, username);

    auto res = SetRunAsAccount(appid, username, password);

    wprintf(L"INFO: Please ensure that the %s account have filesystem permission to run the COM server.\n", username);

    return res;
}
