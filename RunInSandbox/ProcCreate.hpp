#pragma once
#include <Shlobj.h>


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

struct ProcessHandles {
    HandleWrap proc; // process handle
    HandleWrap thrd; // main thread handle
};

static bool IsCMD (std::wstring path) {
    for (size_t i = 0; i < path.size(); ++i)
        path[i] = towlower(path[i]);

    return path.substr(0, 23) == L"c:\\windows\\system32\\cmd";
}


/** Launch a new suspended process. */
static ProcessHandles CreateSuspendedProcess(StartupInfoWrap & si, const wchar_t * exe_path, IntegrityLevel mode, const std::vector<std::wstring>& arguments) {
    std::wstring cmdline = L"\"" + std::wstring(exe_path) + L"\"";
    // append arguments
    for (const auto & arg : arguments)
        cmdline += L" " + arg;

    ProcessInfoWrap pi;

    constexpr BOOL INHERIT_HANDLES = FALSE;
    DWORD creation_flags = EXTENDED_STARTUPINFO_PRESENT
                         | CREATE_SUSPENDED; // suspended state without any running threads
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
        return ProcessHandles();
    } else {
        HandleWrap parent_proc; // lifetime tied to "si"
        if ((mode <= IntegrityLevel::Medium) && ImpersonateThread::IsProcessElevated()) {
            // use explorer.exe as parent process to escape existing UAC elevation
            // REF: https://devblogs.microsoft.com/oldnewthing/20190425-00/?p=102443
            parent_proc = ImpersonateThread::GetShellProc();
            si.SetParent(parent_proc.GetAddressOf());
            std::wcout << L"Using explorer as parent process to escape elevation.\n";
        }

        if (mode != IntegrityLevel::Default) {
            // impersonate desired integrity level
            ImpersonateThread low_int(mode, GetCurrentProcess());
            std::wcout << L"Impersonation succeeded.\n";
            WIN32_CHECK(CreateProcessAsUserW(low_int.m_token.Get(), exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, INHERIT_HANDLES, creation_flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));
        } else {
            // use STARTUPINFO to determine integrity level
            WIN32_CHECK(CreateProcessW(exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, INHERIT_HANDLES, creation_flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));
        }
    }

    // return process & thread handle
    ProcessHandles proc;
    std::swap(*proc.proc.GetAddressOf(), pi->hProcess);
    std::swap(*proc.thrd.GetAddressOf(), pi->hThread);
    return proc;
}

/** Create an suspended AppContainer process and return the process handle. */
static ProcessHandles CreateSuspendedAppContainerProcess(AppContainerWrap& ac, const wchar_t* exe_path, const std::vector<std::wstring>& arguments) {
    std::wstring cmdline = L"\"" + std::wstring(exe_path) + L"\"";
    // append arguments
    for (const auto& arg : arguments)
        cmdline += L" " + arg;

    StartupInfoWrap si;
    SECURITY_CAPABILITIES sec_cap = ac.SecCap(); // need to outlive CreateProcess
    si.SetSecurity(&sec_cap);

    DWORD flags = EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED; // suspended state without any running threads

    // create new AppContainer process
    ProcessInfoWrap pi;
    WIN32_CHECK(CreateProcessW(exe_path, const_cast<wchar_t*>(cmdline.data()), /*proc.attr*/nullptr, /*thread attr*/nullptr, /*INHERIT_HANDLES*/FALSE, flags, /*env*/nullptr, /*cur-dir*/nullptr, (STARTUPINFO*)&si, &pi));

    // return process & thread handle
    ProcessHandles proc;
    std::swap(*proc.proc.GetAddressOf(), pi->hProcess);
    std::swap(*proc.thrd.GetAddressOf(), pi->hThread);
    return proc;
}
