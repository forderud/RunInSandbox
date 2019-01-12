#pragma once
#include <vector>
#include <Windows.h>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")


class AppContainerContext {
public:
    AppContainerContext() {
        MakeWellKnownSIDAttributes();
        
        const wchar_t PROFILE_NAME[] = L"ComImpersonation.AppContainer";
        const wchar_t DISPLAY_NAME[] = L"ComImpersonation.AppContainer";
        const wchar_t DESCRIPTION[] = L"ComImpersonation AppContainer";

        // delete existing (if present)
        HRESULT hr = DeleteAppContainerProfile(PROFILE_NAME);

        if (FAILED(CreateAppContainerProfile(PROFILE_NAME, DISPLAY_NAME, DESCRIPTION,
            m_capabilities.empty() ? nullptr : m_capabilities.data(), (DWORD)m_capabilities.size(), &m_sid)))
            abort();
    }

    ~AppContainerContext() {
        if (m_sid)
            FreeSid(m_sid);
        
        for (auto &c : m_capabilities) {
            if (c.Sid) {
                HeapFree(GetProcessHeap(), 0, c.Sid);
            }
        }
    }

    PSID Sid() const {
        return m_sid;
    }

    std::vector<SID_AND_ATTRIBUTES> & Capabilities() {
        return m_capabilities;
    }

private:
    void MakeWellKnownSIDAttributes() {
        const WELL_KNOWN_SID_TYPE capabilities[] = {
            WinCapabilityInternetClientSid,
            WinCapabilityInternetClientServerSid,
            WinCapabilityPrivateNetworkClientServerSid,
            WinCapabilityPicturesLibrarySid,
            WinCapabilityVideosLibrarySid,
            WinCapabilityMusicLibrarySid,
            WinCapabilityDocumentsLibrarySid,
            WinCapabilitySharedUserCertificatesSid,
            WinCapabilityEnterpriseAuthenticationSid,
            WinCapabilityRemovableStorageSid,
        };

        for (auto c : capabilities) {
            PSID sid = HeapAlloc(GetProcessHeap(), 0, SECURITY_MAX_SID_SIZE);
            if (sid == nullptr)
                abort();
            
            DWORD sidListSize = SECURITY_MAX_SID_SIZE;
            if (!CreateWellKnownSid(c, NULL, sid, &sidListSize))
                abort();

            if (!IsWellKnownSid(sid, c)) {
                HeapFree(GetProcessHeap(), 0, sid);
                continue;
            }

            m_capabilities.push_back({ sid, SE_GROUP_ENABLED });
        }
    }

    PSID                            m_sid = nullptr;
    std::vector<SID_AND_ATTRIBUTES> m_capabilities;
};


class StartupInfoWrap {
public:
    StartupInfoWrap() {
        info.StartupInfo.cb = sizeof(STARTUPINFOEX);

        const DWORD attr_count = 1;
        SIZE_T cbAttributeListSize = 0;
        InitializeProcThreadAttributeList(NULL, attr_count, 0, &cbAttributeListSize);
        info.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
        if (!InitializeProcThreadAttributeList(info.lpAttributeList, attr_count, 0, &cbAttributeListSize))
            abort();
    }

    ~StartupInfoWrap() {
        if (info.lpAttributeList) {
            DeleteProcThreadAttributeList(info.lpAttributeList);
            info.lpAttributeList = nullptr;
        }
    }

    STARTUPINFOEX* operator& () {
        return &info;
    }
    STARTUPINFOEX* operator -> () {
        return &info;
    }

private:
    STARTUPINFOEX info = {};
};


static void ProcCreate(wchar_t * exe_path) {
    AppContainerContext ac;

    SECURITY_CAPABILITIES sc = {};
    sc.AppContainerSid = ac.Sid();
    if (!ac.Capabilities().empty())
        sc.Capabilities = ac.Capabilities().data();
    sc.CapabilityCount = static_cast<DWORD>(ac.Capabilities().size());

    StartupInfoWrap si;
    if (!UpdateProcThreadAttribute(si->lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), NULL, NULL))
        abort();

    PROCESS_INFORMATION pi = {};
    if (!CreateProcess(exe_path, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi)) {
        auto err = GetLastError();
        abort();
    }
}
