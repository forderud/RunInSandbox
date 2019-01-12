#pragma once
#include <vector>
#include <Windows.h>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")


/** RAII class for encapsulating AppContainer configuration. */
class AppContainerWrap {
public:
    AppContainerWrap() {
        AddWellKnownCapabilities();

        const wchar_t PROFILE_NAME[] = L"ComImpersonation.AppContainer";
        const wchar_t DISPLAY_NAME[] = L"ComImpersonation.AppContainer";
        const wchar_t DESCRIPTION[] = L"ComImpersonation AppContainer";

        // delete existing (if present)
        HRESULT hr = DeleteAppContainerProfile(PROFILE_NAME);

        if (FAILED(CreateAppContainerProfile(PROFILE_NAME, DISPLAY_NAME, DESCRIPTION,
            m_capabilities.empty() ? nullptr : m_capabilities.data(), (DWORD)m_capabilities.size(), &m_sid)))
            abort();
    }

    ~AppContainerWrap() {
        if (m_sid) {
            FreeSid(m_sid);
            m_sid = nullptr;
        }

        for (auto &c : m_capabilities) {
            if (c.Sid) {
                HeapFree(GetProcessHeap(), 0, c.Sid);
                c.Sid = nullptr;
            }
        }
    }

    /** Returns a non-owning security capability struct. */
    SECURITY_CAPABILITIES SecCap() {
        SECURITY_CAPABILITIES sc = {};
        sc.AppContainerSid = m_sid;
        if (m_capabilities.size() > 0)
            sc.Capabilities = m_capabilities.data();
        sc.CapabilityCount = static_cast<DWORD>(m_capabilities.size());
        return sc;
    }

private:
    void AddWellKnownCapabilities() {
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
