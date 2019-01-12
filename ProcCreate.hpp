#pragma once
#include "AppContainer.hpp"


class StartupInfoWrap {
public:
    StartupInfoWrap(SECURITY_CAPABILITIES sc) {
        si.StartupInfo.cb = sizeof(STARTUPINFOEX);

        const DWORD attr_count = 1;
        size_t attr_size = 0;
        InitializeProcThreadAttributeList(NULL, attr_count, 0, &attr_size);
        si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
        if (!InitializeProcThreadAttributeList(si.lpAttributeList, attr_count, 0, &attr_size))
            abort();
        
        if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), NULL, NULL))
            abort();
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
    STARTUPINFOEX* operator -> () {
        return &si;
    }

private:
    STARTUPINFOEX si = {};
};


static void ProcCreate(wchar_t * exe_path) {
    AppContainerWrap ac;
    StartupInfoWrap si(ac.SecCap());

    PROCESS_INFORMATION pi = {};
    if (!CreateProcess(exe_path, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi)) {
        auto err = GetLastError();
        abort();
    }
}
