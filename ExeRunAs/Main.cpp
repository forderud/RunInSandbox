#include <iostream>
#include <comdef.h> // for _com_error
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
    DWORD logonFlags = 0; // LOGON_WITH_PROFILE
    const wchar_t* appName = argv[2];
    wchar_t* cmdLine = argv[2];
    DWORD createFlags = 0;
    void* env = nullptr;
    const wchar_t* curDir = nullptr; // same as parent process

    STARTUPINFOW si{
        .cb = sizeof(si)
    };
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessWithLogonW(username, domain, password, logonFlags, appName, cmdLine, createFlags, env, curDir, &si, &pi);
    if (!ok) {
        _com_error err(GetLastError());
        wprintf(L"ERROR: CreateProcessWithLogon failed with %s (err=%u)\n", err.ErrorMessage(), err.Error());
        return err.Error();
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    wprintf(L"SUCCESS: Process created.\n");
}
