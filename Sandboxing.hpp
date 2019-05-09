#pragma once
#include <cassert>
#include <vector>
#include <Windows.h>
#include <comdef.h>
#include <versionhelpers.h>
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
    const TCHAR * msg_ptr = error.ErrorMessage();
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

    HandleWrap& operator = (HANDLE && other) {
        HandleWrap::~HandleWrap();
        std::swap(handle, other);
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
        AddWellKnownCapabilities();

        const wchar_t PROFILE_NAME[] = L"RunInSandbox.AppContainer";
        const wchar_t DISPLAY_NAME[] = L"RunInSandbox.AppContainer";
        const wchar_t DESCRIPTION[] = L"RunInSandbox AppContainer";

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

        for (auto cap : capabilities) {
            PSID sid = LocalAlloc(LPTR, SECURITY_MAX_SID_SIZE);
            if (sid == nullptr)
                abort();

            DWORD sidListSize = SECURITY_MAX_SID_SIZE;
            WIN32_CHECK(CreateWellKnownSid(cap, NULL, sid, &sidListSize));

            m_capabilities.push_back({ sid, SE_GROUP_ENABLED });
        }
    }

    PSID                            m_sid = nullptr;
    std::vector<SID_AND_ATTRIBUTES> m_capabilities;
};

enum IMPERSONATE_MOE {
    IMPERSONATE_USER,
    IMPERSONATE_ANONYMOUS,
};

/** RAII class for temporarily impersonating users & integrity levels for the current thread.
    Intended to be used together with CLSCTX_ENABLE_CLOAKING when creating COM objects. */
struct ImpersonateUser {
    ImpersonateUser(wchar_t* user, wchar_t* passwd, bool low_integrity) {
        if (user && passwd) {
            // impersonate a different user
            WIN32_CHECK(LogonUser(user, L""/*domain*/, passwd, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &m_token));
        } else {
            // current user
            HandleWrap cur_token;
            WIN32_CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &cur_token));
            WIN32_CHECK(DuplicateTokenEx(cur_token, 0, NULL, SecurityImpersonation, TokenPrimary, &m_token));
        }

        if (low_integrity)
            ApplyLowIntegrity();

        WIN32_CHECK(ImpersonateLoggedOnUser(m_token)); // change current thread integrity
    }

    ImpersonateUser(HandleWrap && token, IMPERSONATE_MOE mode) : m_token(std::move(token)) {
        if (mode == IMPERSONATE_USER)
            WIN32_CHECK(ImpersonateLoggedOnUser(m_token)); // change current thread integrity
        else
            WIN32_CHECK(ImpersonateAnonymousToken(m_token)); // change current thread integrity
    }

    ~ImpersonateUser() {
        WIN32_CHECK(RevertToSelf());
    }

    /** Create a low-integrity token associated with the current user.
        Based on "Designing Applications to Run at a Low Integrity Level" https://msdn.microsoft.com/en-us/library/bb625960.aspx */
    void ApplyLowIntegrity() {
        SidWrap li_sid;
        {
            // low integrity SID - same as ConvertStringSidToSid("S-1-16-4096",..)
            DWORD sid_size = SECURITY_MAX_SID_SIZE;
            li_sid.Allocate(sid_size);
            WIN32_CHECK(CreateWellKnownSid(WinLowLabelSid, nullptr, li_sid, &sid_size));
        }

        // reduce process integrity level
        TOKEN_MANDATORY_LABEL TIL = {};
        TIL.Label.Attributes = SE_GROUP_INTEGRITY;
        TIL.Label.Sid = li_sid;
        WIN32_CHECK(SetTokenInformation(m_token, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(li_sid)));

    }

    HandleWrap m_token;
};


/** Copied from https://github.com/chromium/chromium/blob/master/sandbox/win/src/nt_internals.h */
typedef NTSTATUS(WINAPI* NtCreateLowBoxToken)(
    OUT PHANDLE token,
    IN HANDLE original_handle,
    IN ACCESS_MASK access,
    IN POBJECT_ATTRIBUTES object_attribute,
    IN PSID appcontainer_sid,
    IN DWORD capabilityCount,
    IN PSID_AND_ATTRIBUTES capabilities,
    IN DWORD handle_count,
    IN PHANDLE handles);


/** Create AppContainer "LowBox" token for security impersonation.
    WARNING: Does not work yet!
    Based on https://github.com/chromium/chromium/blob/master/sandbox/win/src/restricted_token_utils.cc */
HandleWrap CreateLowBoxToken(HandleWrap& base_token, TOKEN_TYPE token_type, SECURITY_CAPABILITIES &sec_cap, std::vector<HANDLE>& saved_handles) {
    // get NtCreateLowBoxToken function pointer (not ref-counted)
    auto CreateLowBoxToken_fn = reinterpret_cast<NtCreateLowBoxToken>(GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateLowBoxToken"));

    if (!base_token)
        WIN32_CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &base_token));

    OBJECT_ATTRIBUTES obj_attr = {};
    InitializeObjectAttributes(&obj_attr, nullptr, 0, nullptr, nullptr);

    HandleWrap token_lowbox;
    NTSTATUS status = CreateLowBoxToken_fn(&token_lowbox, base_token, TOKEN_ALL_ACCESS, &obj_attr, sec_cap.AppContainerSid, sec_cap.CapabilityCount, sec_cap.Capabilities, (DWORD)saved_handles.size(), saved_handles.data());
    if (!NT_SUCCESS(status)) {
        _com_error error(HRESULT_FROM_NT(status));
        abort();
    }
    if (token_lowbox == 0 || token_lowbox == INVALID_HANDLE_VALUE)
        throw std::runtime_error("CreateLowBoxToken returned invalid token ");

    // Default from NtCreateLowBoxToken is a Primary token.
    if (token_type == TokenPrimary)
        return token_lowbox;

    HandleWrap token_for_sd;
    WIN32_CHECK(DuplicateTokenEx(token_lowbox, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &token_for_sd));

    // Copy security descriptor from primary token as the new object will have DACL from the current token's default DACL.
    {
        DWORD length_needed = 0;
        WIN32_CHECK(GetKernelObjectSecurity(token_lowbox, DACL_SECURITY_INFORMATION, nullptr, 0, &length_needed), ERROR_INSUFFICIENT_BUFFER);
        std::vector<unsigned char> sec_desc_buffer(length_needed);
        WIN32_CHECK(GetKernelObjectSecurity(token_lowbox, DACL_SECURITY_INFORMATION, reinterpret_cast<PSECURITY_DESCRIPTOR>(sec_desc_buffer.data()), length_needed, &length_needed));

        WIN32_CHECK(SetKernelObjectSecurity(token_for_sd, DACL_SECURITY_INFORMATION, reinterpret_cast<PSECURITY_DESCRIPTOR>(sec_desc_buffer.data())));
    }

    return token_for_sd;
}
