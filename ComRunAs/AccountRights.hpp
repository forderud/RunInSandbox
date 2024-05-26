#pragma once
#include "Util.hpp"
#include <string>
#include <vector>


// Code based on https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/com/fundamentals/dcom/dcomperm

/** Set and query the account right for a given user.
* Current values can be inspected opening gpedit.msc and navigating to "Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment" */
class AccountRights {
public:
    AccountRights() {
    }
    ~AccountRights() {
    }

    DWORD Open(const std::wstring& username) {
        LSA_OBJECT_ATTRIBUTES objectAttributes = {};
        DWORD res = LsaOpenPolicy(NULL, &objectAttributes, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &m_policy);
        res = LsaNtStatusToWinError(res);
        if (res != ERROR_SUCCESS)
            return res;

        res = GetPrincipalSID(username, m_sidPrincipal);
        return res;
    }

    bool HasRight(const WCHAR privilege[]) {
        LSA_UNICODE_STRING* rights = nullptr;
        ULONG count = 0;
        NTSTATUS res = LsaEnumerateAccountRights(m_policy, m_sidPrincipal.data(), &rights, &count);
        if (res != STATUS_SUCCESS)
            return false;

        bool foundMatch = false;
        for (size_t i = 0; i < count; ++i) {
            if (_wcsicmp(privilege, rights[i].Buffer) == 0) {
                foundMatch = true;
                break;
            }
        }

        LsaFreeMemory(rights);
        return foundMatch;
    }

    DWORD Set(const WCHAR privilege[]) {
        LSA_UNICODE_STRING lsaPrivilegeString = {};
        lsaPrivilegeString.Length = (USHORT)(wcslen(privilege) * sizeof(WCHAR)); // exclude null-termination
        lsaPrivilegeString.MaximumLength = lsaPrivilegeString.Length + sizeof(WCHAR); // include null-termination
        lsaPrivilegeString.Buffer = const_cast<WCHAR*>(privilege);

        DWORD res = LsaAddAccountRights(m_policy, m_sidPrincipal.data(), &lsaPrivilegeString, 1);
        res = LsaNtStatusToWinError(res);
        return res;
    }

private:
    /*---------------------------------------------------------------------------*\
     * NAME: GetPrincipalSID                                                     *
     * --------------------------------------------------------------------------*
     * DESCRIPTION: Creates a SID for the supplied principal.                    *
    \*---------------------------------------------------------------------------*/
    static DWORD GetPrincipalSID(const std::wstring& username, /*out*/std::vector<BYTE>& pSid)
    {
        // first check for known in-built SID
        if (ConstructWellKnownSID(username, /*out*/pSid))
            return ERROR_SUCCESS;

        TCHAR tszRefDomain[256] = { 0 };
        DWORD cbRefDomain = 255;
        SID_NAME_USE snu;
        DWORD cbSid = 0;
        LookupAccountNameW(NULL, username.c_str(), (PSID)pSid.data(), &cbSid, tszRefDomain, &cbRefDomain, &snu);

        DWORD dwReturnValue = GetLastError();
        if (dwReturnValue != ERROR_INSUFFICIENT_BUFFER)
            return dwReturnValue;

        dwReturnValue = ERROR_SUCCESS;

        pSid.resize(cbSid);
        cbRefDomain = 255;

        if (!LookupAccountNameW(NULL, username.c_str(), (PSID)pSid.data(), &cbSid, tszRefDomain, &cbRefDomain, &snu)) {
            dwReturnValue = GetLastError();
            return dwReturnValue;
        }

        return dwReturnValue;
    }


    /*---------------------------------------------------------------------------*\
     * NAME: ConstructWellKnownSID                                               *
     * --------------------------------------------------------------------------*
     * DESCRIPTION: This method converts some designated well-known identities   *
     * to a SID.                                                                 *
    \*---------------------------------------------------------------------------*/
    static BOOL ConstructWellKnownSID(const std::wstring& username, /*out*/std::vector<BYTE>& pSid)
    {
        // Look for well-known English names
        DWORD dwSubAuthority = 0;
        BOOL fUseWorldAuth = FALSE;
        if (_wcsicmp(username.c_str(), L"Administrators") == 0) {
            dwSubAuthority = DOMAIN_ALIAS_RID_ADMINS;
        }
        else if (_wcsicmp(username.c_str(), L"Power Users") == 0) {
            dwSubAuthority = DOMAIN_ALIAS_RID_POWER_USERS;
        }
        else if (_wcsicmp(username.c_str(), L"Everyone") == 0) {
            dwSubAuthority = SECURITY_WORLD_RID;
            fUseWorldAuth = TRUE;
        }
        else if (_wcsicmp(username.c_str(), L"System") == 0) {
            dwSubAuthority = SECURITY_LOCAL_SYSTEM_RID;
        }
        else if (_wcsicmp(username.c_str(), L"Self") == 0) {
            dwSubAuthority = SECURITY_PRINCIPAL_SELF_RID;
        }
        else if (_wcsicmp(username.c_str(), L"Anonymous") == 0) {
            dwSubAuthority = SECURITY_ANONYMOUS_LOGON_RID;
        }
        else if (_wcsicmp(username.c_str(), L"Interactive") == 0) {
            dwSubAuthority = SECURITY_INTERACTIVE_RID;
        }
        else {
            return FALSE;
        }

        PSID psidTemp = NULL;
        SID_IDENTIFIER_AUTHORITY SidAuthorityNT = SECURITY_NT_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY SidAuthorityWorld = SECURITY_WORLD_SID_AUTHORITY;
        if (dwSubAuthority == DOMAIN_ALIAS_RID_ADMINS || dwSubAuthority == DOMAIN_ALIAS_RID_POWER_USERS) {
            if (!AllocateAndInitializeSid(
                &SidAuthorityNT,
                2,
                SECURITY_BUILTIN_DOMAIN_RID,
                dwSubAuthority,
                0, 0, 0, 0, 0, 0,
                &psidTemp
            )) return FALSE;
        }
        else {
            if (!AllocateAndInitializeSid(
                fUseWorldAuth ? &SidAuthorityWorld : &SidAuthorityNT,
                1,
                dwSubAuthority,
                0, 0, 0, 0, 0, 0, 0,
                &psidTemp
            )) return FALSE;

        }

        if (!IsValidSid(psidTemp))
            return FALSE;

        BOOL fRetVal = FALSE;
        DWORD cbSid = GetLengthSid(psidTemp);
        pSid.resize(cbSid); // assign output buffer
        if (!CopySid(cbSid, pSid.data(), psidTemp)) {
            pSid.clear();
        }
        else {
            fRetVal = TRUE;
        }
        FreeSid(psidTemp);

        return fRetVal;
    }

    LsaWrap           m_policy;
    std::vector<BYTE> m_sidPrincipal; // PSID buffer
};
