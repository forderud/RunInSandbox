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

private:
    PROCESS_INFORMATION pi = {};
};


static bool IsCMD (std::wstring path) {
    for (size_t i = 0; i < path.size(); ++i)
        path[i] = towlower(path[i]);

    return path.substr(0, 23) == L"c:\\windows\\system32\\cmd";
}


/** Launch a new process within an AppContainer. */
static HandleWrap ProcCreate(const wchar_t * exe_path, IntegrityLevel mode, bool add_embedding, const std::vector<std::wstring>& arguments) {
    std::wstring cmdline = L"\"" + std::wstring(exe_path) + L"\"";
    if (add_embedding) {
        cmdline += L" -Embedding"; // mimic how svchost passes "-Embedding" argument
    } else {
        // append extra arguments
        for (const auto & arg : arguments) {
            cmdline += L" ";
            cmdline += arg;
        }
    }

    ProcessInfoWrap pi;
    StartupInfoWrap si;

    constexpr BOOL INHERIT_HANDLES = FALSE;
    DWORD creation_flags = EXTENDED_STARTUPINFO_PRESENT;
    if (IsCMD(exe_path))
        creation_flags |= CREATE_NEW_CONSOLE; // required for starting cmd.exe

    if ((mode == IntegrityLevel::High) && !IsUserAnAdmin()) {
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
        return {};
    } else if (mode == IntegrityLevel::Medium) {
        HandleWrap parent_proc; // lifetime tied to "si"
        if (ImpersonateThread::IsProcessElevated()) {
            // use explorer.exe as parent process to escape existing UAC elevation
            // REF: https://devblogs.microsoft.com/oldnewthing/20190425-00/?p=102443
            DWORD pid = {};
            WIN32_CHECK(GetWindowThreadProcessId(GetShellWindow(), &pid));
            parent_proc = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid);
            assert(parent_proc);
            si.SetParent(&parent_proc);
            std::wcout << L"Using explorer as parent process to escape elevation.\n";
        }

        // processes are created with medium integrity as default, regardless of UAC settings
        WIN32_CHECK(CreateProcess(exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, INHERIT_HANDLES, creation_flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));
    } else if (mode == IntegrityLevel::AppContainer) {
        AppContainerWrap ac;
        SECURITY_CAPABILITIES sec_cap = ac.SecCap();

        // create new AppContainer process, based on STARTUPINFO
        si.SetSecurity(&sec_cap);

        WIN32_CHECK(CreateProcess(exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, INHERIT_HANDLES, creation_flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));
    } else {
        ImpersonateThread low_int(nullptr, nullptr, mode);
        std::wcout << L"Impersonation succeeded.\n";
        WIN32_CHECK(CreateProcessAsUser(low_int.m_token, exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, INHERIT_HANDLES, creation_flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));
    }

    // wait for process to initialize
    // CoCreateInstance will fail with REGDB_E_CLASSNOTREG until the AppContainer process has called CoRegisterClassObject
    // TODO: Either call CoCreateInstance in a loop or have some sort of synchronization mechanism
    // ignore failure if process is not a GUI app
    WaitForInputIdle(pi->hProcess, INFINITE);

    // wait a bit more (WaitForInputIdle doesn't seem to be sufficient)
    Sleep(200);

    // return process handle
    HandleWrap proc;
    std::swap(*&proc, pi->hProcess);
    return proc;
}
