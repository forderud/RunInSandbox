#pragma once
#include <cassert>
#include <vector>
#include <Windows.h>
#include <atlbase.h>
#include <comdef.h>
#include <versionhelpers.h>
#include <aclapi.h> // for SE_FILE_OBJECT
#include <sddl.h> // for SDDL_REVISION_1
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")
#include <Winternl.h>


static void WIN32_CHECK(BOOL res) {
    if (res)
        return;

    DWORD code = GetLastError();

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


/** RAII wrapper of Win32 Security IDentifier (SID) handles. */
class SidWrap {
public:
    SidWrap() {
    }
    ~SidWrap() {
        Clear();
    }

    void Clear() {
        if (sid) {
            FreeSid(sid);
            sid = nullptr;
        }
    }

    void Create(WELL_KNOWN_SID_TYPE type) {
        assert(!sid);

        DWORD sid_size = SECURITY_MAX_SID_SIZE;
        sid = LocalAlloc(LPTR, sid_size);
        WIN32_CHECK(CreateWellKnownSid(type, nullptr, sid, &sid_size));
    }

    operator PSID () {
        return sid;
    }
    PSID* operator & () {
        return &sid;
    }

protected:
    SidWrap (const SidWrap &) = delete;
    SidWrap& operator = (const SidWrap &) = delete;

    PSID sid = nullptr;
};
static_assert(sizeof(SidWrap) == sizeof(PSID), "SidWrap size mismatch");


/** RAII wrapper of Win32 API objects allocated with LocalAlloc. */
template <class T>
class LocalWrap {
public:
    LocalWrap() {
    }
    ~LocalWrap() {
        if (obj) {
            LocalFree(obj);
            obj = nullptr;
        }
    }

    operator T () {
        return obj;
    }
    T* operator & () {
        return &obj;
    }

private:
    LocalWrap(const LocalWrap &) = delete;
    LocalWrap& operator = (const LocalWrap &) = delete;

    T obj = nullptr;
};


/** RAII class for encapsulating AppContainer configuration. */
class AppContainerWrap {
public:
    AppContainerWrap(const wchar_t * name, const wchar_t * desc) {
        // https://docs.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations
        // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type
        const WELL_KNOWN_SID_TYPE capabilities[] = {
            WinCapabilityInternetClientSid, // confirmed to enable client sockets
#if 0
            WinCapabilityRemovableStorageSid, // have been unable to get this to work (see https://github.com/M2Team/Privexec/issues/31 for more info)
            WinCapabilityInternetClientServerSid,
            WinCapabilityPrivateNetworkClientServerSid,
            WinCapabilityPicturesLibrarySid,
            WinCapabilityVideosLibrarySid,
            WinCapabilityMusicLibrarySid,
            WinCapabilityDocumentsLibrarySid,
            WinCapabilitySharedUserCertificatesSid,
            WinCapabilityEnterpriseAuthenticationSid,
#endif
        };
        for (auto cap : capabilities)
            AddCapability(cap);

        // delete existing (if present)
        Delete(name);

        Create(name, desc);
    }

    ~AppContainerWrap() {
        for (auto &c : m_capabilities) {
            if (c.Sid) {
                free(c.Sid);
                c.Sid = nullptr;
            }
        }
    }

    void Create(const wchar_t * name, const wchar_t * desc) {
        assert(!m_sid);

        // try to create new container
        HRESULT hr = CreateAppContainerProfile(name, name, desc, m_capabilities.empty() ? nullptr : m_capabilities.data(), (DWORD)m_capabilities.size(), &m_sid);
        if (HRESULT_CODE(hr) == ERROR_ALREADY_EXISTS) {
            // fallback to opening existing container
            hr = DeriveAppContainerSidFromAppContainerName(name, &m_sid);
        }
        if (FAILED(hr))
            abort();
    }

    void Delete(const wchar_t * name) {
        assert(!m_sid);
        HRESULT hr = DeleteAppContainerProfile(name);
        hr; // ignore error
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
        PSID sid = malloc(SECURITY_MAX_SID_SIZE); // freed in destructor
        DWORD sidListSize = SECURITY_MAX_SID_SIZE;
        WIN32_CHECK(CreateWellKnownSid(capability, NULL, sid, &sidListSize));

        m_capabilities.push_back({ sid, SE_GROUP_ENABLED });
    }

private:
    SidWrap                         m_sid;
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


class Permissions {
public:
    /** Tag a folder path as writable by low-integrity processes.
        By default, only %USER PROFILE%\AppData\LocalLow is writable.
        Based on "Designing Applications to Run at a Low Integrity Level" https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v%3dmsdn.10)
        Equivalent to "icacls.exe  <path> /setintegritylevel Low"

    Limitations when running under medium integrity (e.g. from a non-admin command prompt):
    * Will fail if only the "Administrators" group have full access to the path, even if the current user is a member of that group.
    * Requires either the current user or the "Users" group to be granted full access to the path. */
    static DWORD MakePathLowIntegrity(const wchar_t * path) {
        ACL * sacl = nullptr; // system access control list (weak ptr.)
        LocalWrap<PSECURITY_DESCRIPTOR> SD; // must outlive SetNamedSecurityInfo to avoid sporadic failures
        {
            // initialize "low integrity" System Access Control List (SACL)
            // Security Descriptor String interpretation: (based on sddl.h)
            // SACL:(ace_type=Mandatory integrity Label (ML); ace_flags=; rights=SDDL_NO_WRITE_UP (NW); object_guid=; inherit_object_guid=; account_sid=Low mandatory level (LW))
            WIN32_CHECK(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;LW)", SDDL_REVISION_1, &SD, NULL));
            BOOL sacl_present = FALSE;
            BOOL sacl_defaulted = FALSE;
            WIN32_CHECK(GetSecurityDescriptorSacl(SD, &sacl_present, &sacl, &sacl_defaulted));
        }

        // apply "low integrity" SACL
        DWORD ret = SetNamedSecurityInfoW(const_cast<wchar_t*>(path), SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, /*owner*/NULL, /*group*/NULL, /*Dacl*/NULL, sacl);
        return ret; // ERROR_SUCCESS on success
    }


    /** Make file/folder accessible from a given AppContainer.
        Based on https://github.com/zodiacon/RunAppContainer/blob/master/RunAppContainer/RunAppContainerDlg.cpp */
    static DWORD MakePathAppContainer(const wchar_t * ac_str_sid, const wchar_t * path, ACCESS_MASK accessMask) {
        // convert string SID to binary
        SidWrap ac_sid;
        WIN32_CHECK(ConvertStringSidToSid(ac_str_sid, &ac_sid));

        EXPLICIT_ACCESSW access = {};
        {
            access.grfAccessPermissions = accessMask;
            access.grfAccessMode = GRANT_ACCESS;
            access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
            access.Trustee.pMultipleTrustee = nullptr;
            access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
            access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            access.Trustee.ptstrName = (wchar_t*)*&ac_sid;
        }

        ACL * prevAcl = nullptr; // weak ptr.
        DWORD status = GetNamedSecurityInfoW(const_cast<wchar_t*>(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, /*DACL*/&prevAcl, nullptr, nullptr);
        if (status != ERROR_SUCCESS)
            return status;

        LocalWrap<ACL*> newAcl; // owning ptr.
        status = SetEntriesInAclW(1, &access, prevAcl, &newAcl);
        if (status != ERROR_SUCCESS)
            return status;

        status = SetNamedSecurityInfoW(const_cast<wchar_t*>(path), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, /*DACL*/newAcl, nullptr);
        return status; // ERROR_SUCCESS on success
    }


    /** Enable DCOM launch & activation requests for a given AppContainer SID.
        TODO: Append ACL instead of replacing it. */
    static LSTATUS EnableLaunchActPermission (const wchar_t* ac_str_sid, const wchar_t* app_id) {
        // Allow World Local Launch/Activation permissions. Label the SD for LOW IL Execute UP
        // REF: https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
        // REF: https://docs.microsoft.com/en-us/windows/win32/com/access-control-lists-for-com
        std::wstring ac_access = L"O:BA";// Owner: Built-in administrators (BA)
        ac_access += L"G:BA";            // Group: Built-in administrators (BA)
        ac_access += L"D:(A;;0xb;;;WD)"; // DACL: (ace_type=Allow (A); ace_flags=; rights=ACTIVATE_LOCAL | EXECUTE_LOCAL | EXECUTE (0xb); object_guid=; inherit_object_guid=; account_sid=Everyone (WD))
        ac_access += L"(A;;0xb;;;";
        ac_access +=             ac_str_sid;
        ac_access +=                     L")"; // (ace_type=Allow (A); ace_flags=; rights=ACTIVATE_LOCAL | EXECUTE_LOCAL | EXECUTE (0xb); object_guid=; inherit_object_guid=; account_sid=ac_str_sid)
        ac_access += L"S:(ML;;NX;;;LW)"; // SACL:(ace_type=Mandatory Label (ML); ace_flags=; rights=No Execute Up (NX); object_guid=; inherit_object_guid=; account_sid=Low mandatory level (LW))
        LocalWrap<PSECURITY_DESCRIPTOR> ac_sd;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(ac_access.c_str(), SDDL_REVISION_1, &ac_sd, NULL))
            abort();

        // open registry path
        CComBSTR reg_path(L"AppID\\");
        reg_path.Append(app_id);

        CRegKey appid_reg;
        if (appid_reg.Open(HKEY_CLASSES_ROOT, reg_path, KEY_READ | KEY_WRITE) != ERROR_SUCCESS)
            abort();

        // Set AppID LaunchPermission registry key to grant appContainer local launch & activation permission
        // REF: https://docs.microsoft.com/en-us/windows/win32/com/launchpermission
        DWORD dwLen = GetSecurityDescriptorLength(ac_sd);
        LSTATUS lResult = appid_reg.SetBinaryValue(L"LaunchPermission", (BYTE*)*&ac_sd, dwLen);
        return lResult;
    }
};


/** RAII class for temporarily impersonating users & integrity levels for the current thread.
    Intended to be used together with CLSCTX_ENABLE_CLOAKING when creating COM objects. */
struct ImpersonateThread {
    ImpersonateThread(IntegrityLevel integrity) {
        {
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
        WIN32_CHECK(RevertToSelf());
    }

    /** Adjust integrity level for the impersonation token.
        Based on "Designing Applications to Run at a Low Integrity Level" https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v%3dmsdn.10) */
    void ApplyIntegrity(IntegrityLevel integrity) {
        assert(integrity != IntegrityLevel::AppContainer);

        SidWrap impersonation_sid;
        impersonation_sid.Create(static_cast<WELL_KNOWN_SID_TYPE>(integrity));

        // reduce process integrity level
        TOKEN_MANDATORY_LABEL TIL = {};
        TIL.Label.Attributes = SE_GROUP_INTEGRITY;
        TIL.Label.Sid = impersonation_sid;
        WIN32_CHECK(SetTokenInformation(m_token, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(impersonation_sid)));
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
};

class RegQuery {
public:
    /** Get EXE path for a COM class. Input is on "{hex-guid}" format. Returns empty string if the COM class is DLL-based and on failure. */
    static std::wstring GetExePath (const std::wstring & clsid, REGSAM bitness = 0/*same bitness as client*/) {
        // extract COM class
        std::wstring reg_path = L"CLSID\\" + clsid + L"\\LocalServer32";

        CRegKey cls_reg;
        if (cls_reg.Open(HKEY_CLASSES_ROOT, reg_path.c_str(), KEY_READ | bitness) != ERROR_SUCCESS)
            return L""; // unknown CLSID

        ULONG exe_path_len = 0;
        if (cls_reg.QueryStringValue(nullptr, nullptr, &exe_path_len) != ERROR_SUCCESS)
            return L""; // unknown key

        std::wstring exe_path(exe_path_len, L'\0');
        if (cls_reg.QueryStringValue(nullptr, const_cast<wchar_t*>(exe_path.data()), &exe_path_len) != ERROR_SUCCESS)
            abort(); // should never happen
        exe_path.resize(exe_path_len - 1); // remove extra zero-termination

        if (exe_path[0] == '"') {
            // remove quotes and "/automation" or "-activex" arguments
            exe_path = exe_path.substr(1); // remove begin quote

            size_t idx = exe_path.find('"');
            if (idx == exe_path.npos)
                return L""; // malformed quoting
            exe_path = exe_path.substr(0, idx); // remove end quote and arguments
        }

        return exe_path;
    }

    /** Get AppID GUID for a COM class. Both input & output is on "{hex-guid}" format. Returns empty string on failure. */
    static std::wstring GetAppID (const std::wstring & clsid, REGSAM bitness = 0/*same bitness as client*/) {
        // extract COM class
        std::wstring reg_path = L"CLSID\\" + clsid;

        CRegKey cls_reg;
        if (cls_reg.Open(HKEY_CLASSES_ROOT, reg_path.c_str(), KEY_READ | bitness) != ERROR_SUCCESS)
            return L""; // unknown CLSID

        ULONG app_id_len = 0;
        if (cls_reg.QueryStringValue(L"AppID", nullptr, &app_id_len) != ERROR_SUCCESS)
            return L""; // AppID missing

        std::wstring app_id(app_id_len, L'\0');
        if (cls_reg.QueryStringValue(L"AppID", const_cast<wchar_t*>(app_id.data()), &app_id_len) != ERROR_SUCCESS)
            abort(); // should never happen
        app_id.resize(app_id_len - 1); // remove extra zero-termination
        return app_id;
    }
};
