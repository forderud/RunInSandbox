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

    const wchar_t* username = argv[1];
    const wchar_t* domain = nullptr;
    const wchar_t* password = nullptr;
    DWORD logonFlags = 0;
    const wchar_t* appName = argv[2];
    wchar_t* cmdLine = argv[2];
    DWORD createFlags = 0;
    void* env = nullptr;
    const wchar_t* curDir = nullptr;

    STARTUPINFOW si{
        .cb = sizeof(si)
    };
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessWithLogonW(username, domain, password, logonFlags, appName, cmdLine, createFlags, env, curDir, &si, &pi);
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"ERROR: CreateProcessWithLogon failed with err=%u\n", err);
        return err;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    wprintf(L"SUCCESS: Process created.\n");
}
