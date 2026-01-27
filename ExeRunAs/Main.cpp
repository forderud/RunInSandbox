#include <iostream>
#include <cassert>
#include <comdef.h> // for _com_error
#include <Shlobj.h> // for IsUserAnAdmin


int wmain (int argc, wchar_t* argv[]) {
    if (!IsUserAnAdmin()) {
        wprintf(L"ERROR: Admin privileges required.\n");
        return -1;
    }

    if (argc < 4) {
        wprintf(L"USAGE: ExeRunAs.exe [UserName] [Password] <command>\n");
        //wprintf(L"Examples:\n");
        //wprintf(L"  LocalService account: ExeRunAs.exe AUTHORITY\\LocalService cmd.exe\n");
        return 1;
    }

    const wchar_t* username = argv[1];
    const wchar_t* domain = nullptr; // L".";
    const wchar_t* password = argv[2];
    DWORD logonFlags = LOGON_WITH_PROFILE; // confirmed to populate HKEY_CURRENT_USER
    const wchar_t* appName = argv[3];
    wchar_t* cmdLine = argv[3];
    DWORD creationFlags = 0;
    void* env = nullptr;
    const wchar_t* curDir = nullptr; // same as parent process

    STARTUPINFOW si{
        .cb = sizeof(si)
    };
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessWithLogonW(username, domain, password, logonFlags, appName, cmdLine, creationFlags, env, curDir, &si, &pi);
    if (!ok) {
        _com_error err(GetLastError());
        wprintf(L"ERROR: CreateProcessWithLogon failed with %s (err=%u)\n", err.ErrorMessage(), err.Error());
        return err.Error();
    }
    wprintf(L"SUCCESS: Process created.\n");

    wprintf(L"Waiting for process to terminate...\n");
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    ok = GetExitCodeProcess(pi.hProcess, &exitCode);
    assert(ok);

    wprintf(L"Process terminated with exit code %u.\n", exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}
