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

    void Update(SECURITY_CAPABILITIES sc) {
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


static void ProcCreate(wchar_t * exe_path) {
    AppContainerWrap ac;
    StartupInfoWrap si;
    si.Update(ac.SecCap());

    PROCESS_INFORMATION pi = {};
    WIN32_CHECK(CreateProcess(exe_path, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi));
}
