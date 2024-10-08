#include "ComRunAs.hpp"
#include <Shlobj.h> // for IsUserAnAdmin
#include <iostream>

int wmain(int argc, wchar_t* argv[]) {
    if (!IsUserAnAdmin()) {
        wprintf(L"ERROR: Admin privileges required.\n");
        return -1;
    }

    if (argc < 2) {
        wprintf(L"USAGE: ComRunAs.exe <AppID> [UserName] [Password]\n");
        wprintf(L"Examples:\n");
        wprintf(L"  Launching user (default): ComRunAs.exe {99999999-9999-9999-9999-00AA00BBF7C7}\n");
        wprintf(L"  LocalService account    : ComRunAs.exe {99999999-9999-9999-9999-00AA00BBF7C7} \"NT AUTHORITY\\LocalService\"\n");
        wprintf(L"  Other account           : ComRunAs.exe {99999999-9999-9999-9999-00AA00BBF7C7} MyAccount MyPassword\n");
        return 1;
    }

    WCHAR* appid = argv[1];
    WCHAR* username = nullptr;
    if (argc >= 3)
        username = argv[2]; //optional
    WCHAR* password = nullptr;
    if (argc >= 4)
        password = argv[3]; // optional

    ComRunAs runas;
    DWORD res = runas.Open(appid);
    if (res != ERROR_SUCCESS) {
        wprintf(L"ERROR: Unable to open AppID %s registry key (%d).", appid, res);
        return res;
    }

    if (username) {
        wprintf(L"Configuring COM server with AppID %s to run with user %s.\n", appid, username);

        res = runas.Set(username, password);
        if (res != ERROR_SUCCESS) {
            wprintf(L"ERROR: Unable to assign RunAs account (%d).", res);
            return res;
        }

        wprintf(L"INFO: Please ensure that the %s account have filesystem permission to run the COM server.\n", username);
    } else {
        res = runas.Remove();
        if (res != ERROR_SUCCESS) {
            wprintf(L"ERROR: Unable to delete RunAs (%d).", res);
            return res;
        }
    }

    return res;
}
