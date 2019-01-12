#pragma once
#include <vector>
#include <Windows.h>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")

#define APPCONTAINER_PROFILE_NAME L"ComImpersonation.AppContainer"
#define APPCONTAINER_PROFILE_DISPLAYNAME L"ComImpersonation.AppContainer"
#define APPCONTAINER_PROFILE_DESCRIPTION L"ComImpersonation AppContainer"

class AppContainerContext {
public:
    AppContainerContext() {
    }

    ~AppContainerContext() {
        if (m_appContainerSid)
            FreeSid(m_appContainerSid);
        
        for (auto &c : m_capabilities) {
            if (c.Sid) {
                HeapFree(GetProcessHeap(), 0, c.Sid);
            }
        }
    }

    bool AppContainerContextInitialize() {
        if (!MakeWellKnownSIDAttributes())
            return false;
        
        HRESULT hr = DeleteAppContainerProfile(APPCONTAINER_PROFILE_NAME);

        if (FAILED(CreateAppContainerProfile(
            APPCONTAINER_PROFILE_NAME, APPCONTAINER_PROFILE_DISPLAYNAME,
            APPCONTAINER_PROFILE_DESCRIPTION,
            m_capabilities.empty() ? nullptr : m_capabilities.data(),
            (DWORD)m_capabilities.size(), &m_appContainerSid)))
            return false;
        
        return true;
    }
    PSID GetAppContainerSid() const {
        return m_appContainerSid;
    }
    std::vector<SID_AND_ATTRIBUTES> & Capabilities() {
        return m_capabilities;
    }

private:
    bool MakeWellKnownSIDAttributes() {
        const WELL_KNOWN_SID_TYPE capabilitiyTypeList[] = {
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
        for (auto c : capabilitiyTypeList) {
            PSID sid = HeapAlloc(GetProcessHeap(), 0, SECURITY_MAX_SID_SIZE);
            if (sid == nullptr) {
                return false;
            }
            DWORD sidListSize = SECURITY_MAX_SID_SIZE;
            if (::CreateWellKnownSid(c, NULL, sid, &sidListSize) == FALSE) {
                HeapFree(GetProcessHeap(), 0, sid);
                continue;
            }
            if (::IsWellKnownSid(sid, c) == FALSE) {
                HeapFree(GetProcessHeap(), 0, sid);
                continue;
            }
            SID_AND_ATTRIBUTES attr = {};
            attr.Sid = sid;
            attr.Attributes = SE_GROUP_ENABLED;
            m_capabilities.push_back(attr);
        }
        return true;
    }

    PSID                            m_appContainerSid = nullptr;
    std::vector<SID_AND_ATTRIBUTES> m_capabilities;
};


class StartupInfoWrap {
public:
    StartupInfoWrap() {
        info.StartupInfo.cb = sizeof(STARTUPINFOEX);

        SIZE_T cbAttributeListSize = 0;
        InitializeProcThreadAttributeList(NULL, 3, 0, &cbAttributeListSize);
        info.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
        if (!InitializeProcThreadAttributeList(info.lpAttributeList, 3, 0, &cbAttributeListSize))
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
    ac.AppContainerContextInitialize();

    StartupInfoWrap si;

    SECURITY_CAPABILITIES sc = {};
    sc.AppContainerSid = ac.GetAppContainerSid();
    sc.Capabilities = ac.Capabilities().empty() ? NULL : ac.Capabilities().data();
    sc.CapabilityCount = static_cast<DWORD>(ac.Capabilities().size());
    if (!UpdateProcThreadAttribute(si->lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), NULL, NULL)) {
        DeleteProcThreadAttributeList(si->lpAttributeList);
        abort();
    }

    PROCESS_INFORMATION pi = {};
    if (!CreateProcess(exe_path, NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (STARTUPINFO*)&si, &pi)) {
        auto err = GetLastError();
        abort();
    }
}
