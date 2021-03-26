#pragma once
#include <Shlobj.h>
#include "Sandboxing.hpp"


/** RAII wrapper OF STARTUPINFOEX. */
class StartupInfoWrap {
public:
    StartupInfoWrap() {
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);

        const DWORD attr_count = 2; // SECURITY_CAPABILITIES & PARENT_PROCESS
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(NULL, attr_count, /*reserved*/0, /*out*/&attr_size);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)new BYTE[attr_size]();
        WIN32_CHECK(InitializeProcThreadAttributeList(si.lpAttributeList, attr_count, /*reserved*/0, &attr_size));
    }

    void SetSecurity(SECURITY_CAPABILITIES* sc) {
        WIN32_CHECK(UpdateProcThreadAttribute(si.lpAttributeList, /*reserved*/0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, sc, sizeof(SECURITY_CAPABILITIES), /*reserved*/NULL, /*reserved*/NULL));
    }

    void SetParent(HANDLE* process) {
        WIN32_CHECK(UpdateProcThreadAttribute(si.lpAttributeList, /*reserved*/0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, process, sizeof(HANDLE), /*reserved*/NULL, /*reserved*/NULL));
    }

    ~StartupInfoWrap() {
        if (si.lpAttributeList) {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            delete [] (BYTE*)si.lpAttributeList;
            si.lpAttributeList = nullptr;
        }
    }

    STARTUPINFOEX* operator& () {
        return &si;
    }

    StartupInfoWrap(const StartupInfoWrap&) = delete;
    StartupInfoWrap& operator=(const StartupInfoWrap&) = delete;

private:
    STARTUPINFOEX si = {};
};

/** RAII wrapper OF PROCESS_INFORMATION. */
class ProcessInfoWrap {
public:
    ProcessInfoWrap() {
    }

    ~ProcessInfoWrap() {
        if (pi.hThread) {
            WIN32_CHECK(CloseHandle(pi.hThread));
            pi.hThread = nullptr;
            pi.dwThreadId = 0;
        }
        if (pi.hProcess) {
            WIN32_CHECK(CloseHandle(pi.hProcess));
            pi.hProcess = nullptr;
            pi.dwProcessId = 0;
        }
    }

    PROCESS_INFORMATION* operator& () {
        return &pi;
    }
    PROCESS_INFORMATION* operator->() {
        return &pi;
    }

    ProcessInfoWrap(const ProcessInfoWrap&) = delete;
    ProcessInfoWrap& operator=(const ProcessInfoWrap&) = delete;

private:
    PROCESS_INFORMATION pi = {};
};


static bool IsCMD (std::wstring path) {
    for (size_t i = 0; i < path.size(); ++i)
        path[i] = towlower(path[i]);

    return path.substr(0, 23) == L"c:\\windows\\system32\\cmd";
}


/** Launch a new process within an AppContainer. */
static void ProcCreate(const wchar_t * exe_path, IntegrityLevel mode, const std::vector<std::wstring>& arguments) {
    std::wstring cmdline = L"\"" + std::wstring(exe_path) + L"\"";
    // append arguments
    for (const auto & arg : arguments) {
        cmdline += L" " + arg;
    }

    ProcessInfoWrap pi;
    StartupInfoWrap si;

    constexpr BOOL INHERIT_HANDLES = FALSE;
    DWORD creation_flags = EXTENDED_STARTUPINFO_PRESENT;
    if (IsCMD(exe_path))
        creation_flags |= CREATE_NEW_CONSOLE; // required for starting cmd.exe

    if ((mode == IntegrityLevel::High) && !ImpersonateThread::IsProcessElevated()) {
        // request UAC elevation
        SHELLEXECUTEINFOW info = {};
        info.cbSize = sizeof(info);
        info.fMask = 0;
        info.hwnd = NULL;
        info.lpVerb = L"runas";
        info.lpFile = exe_path;
        info.lpParameters = L"";
        info.nShow = SW_NORMAL;
        WIN32_CHECK(::ShellExecuteExW(&info));
        std::wcout << L"Successfully created elevated process.\n";
        return;
    } else if (mode == IntegrityLevel::Medium) {
        HandleWrap parent_proc; // lifetime tied to "si"
        if (ImpersonateThread::IsProcessElevated()) {
            // use explorer.exe as parent process to escape existing UAC elevation
            // REF: https://devblogs.microsoft.com/oldnewthing/20190425-00/?p=102443
            parent_proc = ImpersonateThread::GetShellProc();
            si.SetParent(&parent_proc);
            std::wcout << L"Using explorer as parent process to escape elevation.\n";
        }

        // processes are created with medium integrity as default, regardless of UAC settings
        WIN32_CHECK(CreateProcess(exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, INHERIT_HANDLES, creation_flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));
    } else if (mode == IntegrityLevel::AppContainer) {
        AppContainerWrap ac(L"RunInSandbox.AppContainer", L"RunInSandbox.AppContainer");
        SECURITY_CAPABILITIES sec_cap = ac.SecCap();

        // create new AppContainer process, based on STARTUPINFO
        si.SetSecurity(&sec_cap);

        WIN32_CHECK(CreateProcess(exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, INHERIT_HANDLES, creation_flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));
    } else {
        ImpersonateThread low_int(mode);
        std::wcout << L"Impersonation succeeded.\n";
        WIN32_CHECK(CreateProcessAsUser(low_int.m_token, exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, INHERIT_HANDLES, creation_flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));
    }
}


/** Create and kill an AppContainer process, just to get a process handle that can later be impersonated. */
static HandleWrap CreateAndKillAppContainerProcess (AppContainerWrap & ac, const wchar_t * exe_path) {
    StartupInfoWrap si;
    {
        SECURITY_CAPABILITIES sec_cap = ac.SecCap();
        si.SetSecurity(&sec_cap);
    }

    // create new AppContainer process in suspended state
    std::wstring cmdline = L"\"" + std::wstring(exe_path) + L"\"";
    ProcessInfoWrap pi;
    WIN32_CHECK(CreateProcess(exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, /*INHERIT_HANDLES*/FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));

    // Kill process since we're only interested in the handle for now.
    // The COM runtime will later recreate the process when calling CoCreateInstance.
    WIN32_CHECK(TerminateProcess(pi->hProcess, 0));

    // return process handle
    HandleWrap proc;
    std::swap(*&proc, pi->hProcess);
    return proc;
}
