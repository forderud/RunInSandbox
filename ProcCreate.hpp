#pragma once
#include "Sandboxing.hpp"


class StartupInfoWrap {
public:
    StartupInfoWrap() {
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);

        const DWORD attr_count = 1;
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, attr_count, 0, &attr_size);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
        WIN32_CHECK(InitializeProcThreadAttributeList(si.lpAttributeList, attr_count, 0, &attr_size));
        
    }

    void Update(SECURITY_CAPABILITIES & sc) {
        WIN32_CHECK(UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), NULL, NULL));
    }

    ~StartupInfoWrap() {
        if (si.lpAttributeList) {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            si.lpAttributeList = nullptr;
        }
    }

    STARTUPINFOEX* operator& () {
        return &si;
    }

private:
    STARTUPINFOEX si = {};
};


static HandleWrap ProcCreate(const wchar_t * exe_path, bool token_based) {
    AppContainerWrap ac;
    SECURITY_CAPABILITIES sec_cap = ac.SecCap();
    StartupInfoWrap si;

    PROCESS_INFORMATION pi = {};
    if (!token_based) {
        // create new AppContainer process, based on STARTUPINFO
        // This seem to work correctly
        si.Update(sec_cap);
        WIN32_CHECK(CreateProcess(exe_path, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi));
    } else {
        // create new AppContainer process, based on "LowBox" token
        std::vector<HANDLE> saved_handles;
        HandleWrap base_token;
        HandleWrap ac_token = CreateLowBoxToken(base_token, TokenPrimary, sec_cap, saved_handles);

        // WARNING: Process is created without any error, but crashes immediately afterwards
        WIN32_CHECK(CreateProcessAsUser(ac_token, exe_path, nullptr, nullptr/*proc.attr*/, nullptr/*thread attr*/, FALSE, EXTENDED_STARTUPINFO_PRESENT, nullptr/*env*/, nullptr/*cur-dir*/, (STARTUPINFO*)&si, &pi));
        //WIN32_CHECK(CreateProcessWithTokenW(ac_token, 0 /*LOGON_WITH_PROFILE*/, exe_path, nullptr, 0/*flags*/, nullptr /*env*/, nullptr /*cur-dir*/, nullptr, &pi));
    }

    // wait for process to initialize
    if (WaitForInputIdle(pi.hProcess, INFINITE))
        WIN32_CHECK(0);

    WIN32_CHECK(CloseHandle(pi.hProcess));

    HandleWrap retval;
    retval = std::move(pi.hThread);
    return retval;
}
