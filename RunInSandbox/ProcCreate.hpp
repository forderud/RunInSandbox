#pragma once
#include "Sandboxing.hpp"


class StartupInfoWrap {
public:
    StartupInfoWrap() {
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);

        const DWORD attr_count = 1; // only SECURITY_CAPABILITIES
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, attr_count, 0, /*out*/&attr_size);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
        WIN32_CHECK(InitializeProcThreadAttributeList(si.lpAttributeList, attr_count, 0, &attr_size));
    }

    void Update(SECURITY_CAPABILITIES & sc) {
        WIN32_CHECK(UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), NULL, NULL));
    }

    ~StartupInfoWrap() {
        if (si.lpAttributeList) {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            WIN32_CHECK(HeapFree(GetProcessHeap(), 0, si.lpAttributeList));
            si.lpAttributeList = nullptr;
        }
    }

    STARTUPINFOEX* operator& () {
        return &si;
    }

private:
    STARTUPINFOEX si = {};
};


struct ProcessHandles {
    HandleWrap process;
    HandleWrap thread;
};


/** Launch a new process within an AppContainer. */
static ProcessHandles ProcCreate(const wchar_t * exe_path, IntegrityLevel mode, int argc, wchar_t *argv[]) {
    PROCESS_INFORMATION pi = {};
    StartupInfoWrap si;

    std::wstring arguments = exe_path;
    // append extra arguments
    for (int i = 0; i < argc; ++i) {
        arguments += L" ";
        arguments += argv[i];
    }

    if (mode == IntegrityLevel::Low) {
        ImpersonateThread low_int(nullptr, nullptr, IntegrityLevel::Low);
        WIN32_CHECK(CreateProcessAsUser(low_int.m_token, exe_path, const_cast<wchar_t*>(arguments.data()), nullptr/*proc.attr*/, nullptr/*thread attr*/, FALSE, EXTENDED_STARTUPINFO_PRESENT, nullptr/*env*/, nullptr/*cur-dir*/, (STARTUPINFO*)&si, &pi));
    } else {
        AppContainerWrap ac;
        SECURITY_CAPABILITIES sec_cap = ac.SecCap();

        const bool token_based = false;
        if (!token_based) {
            // create new AppContainer process, based on STARTUPINFO
            // This seem to work correctly
            si.Update(sec_cap);

            auto cmdline = std::wstring() + L'"' + exe_path + L'"';
#if 0
            // mimic how svchost passes "-Embedding" argument
            cmdline += L" -Embedding";
#endif
            WIN32_CHECK(CreateProcess(nullptr, const_cast<wchar_t*>(cmdline.c_str()), NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi));
        } else {
            // create new AppContainer process, based on "LowBox" token
            std::vector<HANDLE> saved_handles;
            HandleWrap base_token;
            HandleWrap ac_token = CreateLowBoxToken(base_token, TokenPrimary, sec_cap, saved_handles);

            // WARNING: Process is created without any error, but crashes immediately afterwards
            WIN32_CHECK(CreateProcessAsUser(ac_token, exe_path, nullptr, nullptr/*proc.attr*/, nullptr/*thread attr*/, FALSE, EXTENDED_STARTUPINFO_PRESENT, nullptr/*env*/, nullptr/*cur-dir*/, (STARTUPINFO*)&si, &pi));
            //WIN32_CHECK(CreateProcessWithTokenW(ac_token, 0 /*LOGON_WITH_PROFILE*/, exe_path, nullptr, 0/*flags*/, nullptr /*env*/, nullptr /*cur-dir*/, nullptr, &pi));
        }
    }

    // wait for process to initialize
    // ignore failure if process is not a GUI app
    WaitForInputIdle(pi.hProcess, INFINITE);

    // wait a bit more (WaitForInputIdle doesn't seem to be sufficient)
    Sleep(200);

    // return process & thread handle
    ProcessHandles handles;
    handles.process = std::move(pi.hProcess);
    handles.thread = std::move(pi.hThread);
    return handles;
}
