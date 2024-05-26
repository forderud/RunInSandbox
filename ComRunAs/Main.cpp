#include "ComRunAs.hpp"
#include <iostream>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        wprintf(L"USAGE: ComRunAs.exe <AppID> <UserName> [Password]\n");
        wprintf(L"Examples:\n");
        wprintf(L"  ComRunAs.exe {99999999-9999-9999-9999-00AA00BBF7C7} \"nt authority\\localservice\"\n");
        wprintf(L"  ComRunAs.exe {99999999-9999-9999-9999-00AA00BBF7C7} MyAccount MyPassword\n");
        return 1;
    }

    WCHAR* appid = argv[1];
    WCHAR* username = argv[2];
    WCHAR* password = nullptr;
    if (argc >= 4)
        password = argv[3]; // optional

    wprintf(L"Configuring COM server with AppID %s to run with user %s.\n", appid, username);

    ComRunAs runas;
    DWORD res = runas.Open(appid);
    if (res != ERROR_SUCCESS) {
        wprintf(L"ERROR: Unable to open AppID %s registry key (%d).", appid, res);
        return res;
    }

    res = runas.Assign(username, password);
    if (res != ERROR_SUCCESS) {
        wprintf(L"ERROR: Unable to assign RunAs account (%d).", res);
        return res;
    }

    wprintf(L"INFO: Please ensure that the %s account have filesystem permission to run the COM server.\n", username);

    return res;
}
