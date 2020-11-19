#pragma once
#include <cassert>
#include <vector>
#include <Windows.h>
#include <comdef.h>
#include <versionhelpers.h>
#include <aclapi.h> // for SE_FILE_OBJECT
#include <sddl.h> // for SDDL_REVISION_1
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")
#include <Winternl.h>


static void WIN32_CHECK(BOOL res, DWORD whitelisted_err = ERROR_SUCCESS) {
    if (res)
        return;

    DWORD code = GetLastError();
    if (code == whitelisted_err)
        return;

    _com_error error(code);
    std::wcout << L"ERROR: " << error.ErrorMessage() << std::endl;
    abort();
}


class HandleWrap {
public:
    HandleWrap() {
    }

    HandleWrap(const HandleWrap & other) = delete;

    HandleWrap(HandleWrap && other) {
        std::swap(handle, other.handle);
    }

    ~HandleWrap() {
        if (handle) {
            WIN32_CHECK(CloseHandle(handle));
            handle = nullptr;
        }
    }

    HandleWrap& operator = (HandleWrap && other) {
        HandleWrap::~HandleWrap();
        new(this) HandleWrap(std::move(other));
        return *this;
    }
    HandleWrap& operator = (HANDLE other) {
        HandleWrap::~HandleWrap();
        new(this) HandleWrap();
        handle = other;
        return *this;
    }

    operator HANDLE () {
        return handle;
    }
    HANDLE* operator & () {
        return &handle;
    }

private:
    HANDLE handle = nullptr;
};
static_assert(sizeof(HandleWrap) == sizeof(HANDLE), "HandleWrap size mismatch");


class SidWrap {
public:
    SidWrap() {
    }
    ~SidWrap() {
        if (sid) {
            FreeSid(sid);
            sid = nullptr;
        }
    }

    void Allocate(DWORD size) {
        SidWrap::~SidWrap();
        new(this) SidWrap();
        sid = LocalAlloc(LPTR, size);
    }

    operator PSID () {
        return sid;
    }
    PSID* operator & () {
        return &sid;
    }

protected:
    PSID sid = nullptr;
};
static_assert(sizeof(SidWrap) == sizeof(PSID), "SidWrap size mismatch");


/** RAII class for encapsulating AppContainer configuration. */
class AppContainerWrap {
public:
    AppContainerWrap() {
        // https://docs.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations
        const WELL_KNOWN_SID_TYPE capabilities[] = {
            WinCapabilityInternetClientSid, // confirmed to enable client sockets
#if 0
            WinCapabilityInternetClientServerSid,
            WinCapabilityPrivateNetworkClientServerSid,
            WinCapabilityPicturesLibrarySid,
            WinCapabilityVideosLibrarySid,
            WinCapabilityMusicLibrarySid,
            WinCapabilityDocumentsLibrarySid,
            WinCapabilitySharedUserCertificatesSid,
            WinCapabilityEnterpriseAuthenticationSid,
            WinCapabilityRemovableStorageSid,
#endif
        };
        for (auto cap : capabilities) {
            AddCapability(cap);
        }
        const wchar_t PROFILE_NAME[] = L"RunInSandbox.AppContainer";
        const wchar_t DISPLAY_NAME[] = L"RunInSandbox.AppContainer";
        const wchar_t DESCRIPTION[] = L"RunInSandbox AppContainer";

        // delete existing (if present)
        HRESULT hr = DeleteAppContainerProfile(PROFILE_NAME);
        hr;

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
                FreeSid(c.Sid);
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

    void AddCapability(WELL_KNOWN_SID_TYPE capability) {
        PSID sid = LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
        if (sid == nullptr)
            abort();

        DWORD sidListSize = SECURITY_MAX_SID_SIZE;
        WIN32_CHECK(CreateWellKnownSid(capability, NULL, sid, &sidListSize));

        m_capabilities.push_back({ sid, SE_GROUP_ENABLED });
    }

private:
    PSID                            m_sid = nullptr;
    std::vector<SID_AND_ATTRIBUTES> m_capabilities;
};


enum class IntegrityLevel {
    Default = 0,
    AppContainer = 1,            ///< dummy value to ease impl.
    Untrusted = WinUntrustedLabelSid,///< same as ConvertStringSidToSid("S-1-16-0",..)
    Low       = WinLowLabelSid,    ///< same as ConvertStringSidToSid("S-1-16-4096",..)
    Medium    = WinMediumLabelSid, ///< same as ConvertStringSidToSid("S-1-16-8192",..)
    High      = WinHighLabelSid,   ///< same as ConvertStringSidToSid("S-1-16-12288",..)
};

static std::wstring ToString (IntegrityLevel integrity) {
    switch (integrity) {
    case IntegrityLevel::Default:      return L"default";
    case IntegrityLevel::AppContainer: return L"AppContainer";
    case IntegrityLevel::Low:          return L"low integrity";
    case IntegrityLevel::Medium:       return L"medium integrity";
    case IntegrityLevel::High:         return L"high integrity";
    }

    abort(); // never reached
}

static IntegrityLevel FromString (std::wstring arg) {
    if (arg == L"ac") {
        return IntegrityLevel::AppContainer;
    } else if (arg == L"li") {
        return IntegrityLevel::Low;
    } else if (arg == L"mi") {
        return IntegrityLevel::Medium;
    } else if (arg == L"hi") {
        return IntegrityLevel::High;
    }

    return IntegrityLevel::Default;
}

/** Tag a folder path as writable by low-integrity processes.
By default, only %USER PROFILE%\AppData\LocalLow is writable.
Based on "Designing Applications to Run at a Low Integrity Level" https://msdn.microsoft.com/en-us/library/bb625960.aspx */
static DWORD MakePathLowIntegrity(std::wstring path) {
    ACL * sacl = nullptr; // system access control list (weak ptr.)
    PSECURITY_DESCRIPTOR SD = nullptr;
    {
        // initialize "low integrity" System Access Control List (SACL)
        // Security Descriptor String interpretation: (based on sddl.h)
        // SACL:(ace_type=Integrity label; ace_flags=; rights=SDDL_NO_WRITE_UP; object_guid=; inherit_object_guid=; account_sid=Low mandatory level)
        WIN32_CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;LW)", SDDL_REVISION_1, &SD, NULL));
        BOOL sacl_present = FALSE;
        BOOL sacl_defaulted = FALSE;
        WIN32_CHECK(GetSecurityDescriptorSacl(SD, &sacl_present, &sacl, &sacl_defaulted));
    }

    // apply "low integrity" SACL
    DWORD ret = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.data()), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, /*owner*/NULL, /*group*/NULL, /*Dacl*/NULL, sacl);
    LocalFree(SD);
    if (ret == ERROR_SUCCESS)
        return ret; // success

                    // ERROR_FILE_NOT_FOUND ///< 2
                    // ERROR_ACCESS_DENIED  ///< 5
    return ret; // failure
}


/** RAII class for temporarily impersonating users & integrity levels for the current thread.
    Intended to be used together with CLSCTX_ENABLE_CLOAKING when creating COM objects. */
struct ImpersonateThread {
    ImpersonateThread(const wchar_t* user, const wchar_t* passwd, IntegrityLevel integrity) {
        if (user && passwd) {
            // impersonate a different user
            WIN32_CHECK(LogonUser(user, L""/*domain*/, passwd, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &m_token));

            // load associated user profile (doesn't work for current user)
            m_profile.dwSize = sizeof(m_profile);
            m_profile.lpUserName = const_cast<wchar_t*>(user);
            //WIN32_CHECK(LoadUserProfile(m_token, &m_profile));
        } else {
            // current user
            HandleWrap cur_token;
            WIN32_CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &cur_token));
            WIN32_CHECK(DuplicateTokenEx(cur_token, 0, NULL, SecurityImpersonation, TokenPrimary, &m_token));
        }

        if (integrity != IntegrityLevel::Default)
            ApplyIntegrity(integrity);

        WIN32_CHECK(ImpersonateLoggedOnUser(m_token)); // change current thread integrity
    }

    ImpersonateThread(HandleWrap & handle) {
        HandleWrap cur_token;
        WIN32_CHECK(OpenProcessToken(handle, TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &cur_token));
        WIN32_CHECK(DuplicateTokenEx(cur_token, 0, NULL, SecurityImpersonation, TokenPrimary, &m_token));

        WIN32_CHECK(ImpersonateLoggedOnUser(m_token)); // change current thread integrity
    }

    ~ImpersonateThread() {
        if (m_profile.lpUserName) {
            // TODO: Defer profile unloading
            //WIN32_CHECK(UnloadUserProfile(m_token, &m_profile));
        }

        WIN32_CHECK(RevertToSelf());
    }

    /** Create a low-integrity token associated with the current user.
        Based on "Designing Applications to Run at a Low Integrity Level" https://msdn.microsoft.com/en-us/library/bb625960.aspx */
    void ApplyIntegrity(IntegrityLevel integrity) {
        assert(integrity != IntegrityLevel::AppContainer);

        SidWrap li_sid;
        {
            DWORD sid_size = SECURITY_MAX_SID_SIZE;
            li_sid.Allocate(sid_size);
            WIN32_CHECK(CreateWellKnownSid(static_cast<WELL_KNOWN_SID_TYPE>(integrity), nullptr, li_sid, &sid_size));
        }

        // reduce process integrity level
        TOKEN_MANDATORY_LABEL TIL = {};
        TIL.Label.Attributes = SE_GROUP_INTEGRITY;
        TIL.Label.Sid = li_sid;
        WIN32_CHECK(SetTokenInformation(m_token, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(li_sid)));
    }

    /** Determine the integrity level for a process.
    Based on https://github.com/chromium/chromium/blob/master/base/process/process_info_win.cc */
    static IntegrityLevel GetProcessLevel(HANDLE process_token = GetCurrentProcessToken()) {
        DWORD token_info_length = 0;
        if (GetTokenInformation(process_token, TokenIntegrityLevel, NULL, 0, &token_info_length))
            abort();

        std::vector<char> token_info_buf(token_info_length);
        auto* token_info = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(token_info_buf.data());
        if (!GetTokenInformation(process_token, TokenIntegrityLevel, token_info, token_info_length, &token_info_length))
            abort();

        DWORD integrity_level = *GetSidSubAuthority(token_info->Label.Sid, *GetSidSubAuthorityCount(token_info->Label.Sid) - 1);

        if (integrity_level < SECURITY_MANDATORY_LOW_RID)
            return IntegrityLevel::Untrusted;
        if (integrity_level < SECURITY_MANDATORY_MEDIUM_RID)
            return IntegrityLevel::Low;
        else if (integrity_level < SECURITY_MANDATORY_HIGH_RID)
            return IntegrityLevel::Medium;
        else
            return IntegrityLevel::High;
    }

    /** Check if a process is "elevated".
        Please note that elevated processes might still run under medium or low integrity, so this is _not_ a reliable way of checking for administrative privileges. */
    static bool IsProcessElevated (HANDLE process = GetCurrentProcess()) {
        HandleWrap token;
        if (!OpenProcessToken(process, TOKEN_QUERY, &token))
            abort();

        TOKEN_ELEVATION elevation = {};
        DWORD ret_len = 0;
        if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &ret_len))
            abort();

        {
            TOKEN_ELEVATION_TYPE elevation_type = {};
            ret_len = 0;
            if (!GetTokenInformation(token, TokenElevationType, &elevation_type, sizeof(elevation_type), &ret_len))
                abort();

            if (elevation.TokenIsElevated)
                assert(elevation_type == TokenElevationTypeFull);
        }

        return elevation.TokenIsElevated;
    }

    HandleWrap  m_token;
    PROFILEINFO m_profile = {};
};
