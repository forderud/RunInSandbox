#pragma once
#include <Windows.h>
#include <lsalookup.h>
#include <strsafe.h>
#include <subauth.h>
#define _NTDEF_
#include <ntsecapi.h>
#include <atlbase.h> // CRegKey
#include <string>


/** LSA_HANDLE RAII wrapper */
class LsaWrap {
public:
    LsaWrap() {
    }
    ~LsaWrap() {
        if (obj) {
            LsaClose(obj);
            obj = nullptr;
        }
    }

    operator LSA_HANDLE () {
        return obj;
    }
    LSA_HANDLE* operator & () {
        return &obj;
    }

private:
    LsaWrap(const LsaWrap&) = delete;
    LsaWrap& operator = (const LsaWrap&) = delete;

    LSA_HANDLE obj = nullptr;
};

// Code based on https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/com/fundamentals/dcom/dcomperm

DWORD SetRunAsPassword(const std::wstring AppID, const std::wstring username, const std::wstring password);
DWORD SetAccountRights(const std::wstring username, const WCHAR tszPrivilege[]);
DWORD GetPrincipalSID(const std::wstring username, /*out*/PSID* pSid);
BOOL ConstructWellKnownSID(const std::wstring tszPrincipal, /*out*/PSID* pSid);


DWORD SetRunAsAccount(const std::wstring AppID, const std::wstring username, const std::wstring password)
{
    const size_t SIZE_NAME_BUFFER = 256;
    WCHAR tszKeyName[SIZE_NAME_BUFFER] = { 0 };
    swprintf_s(tszKeyName, RTL_NUMBER_OF(tszKeyName), L"APPID\\%s", AppID.c_str());

    CRegKey hkeyRegistry;
    DWORD dwReturnValue = hkeyRegistry.Open(HKEY_CLASSES_ROOT, tszKeyName, KEY_ALL_ACCESS);
    if (dwReturnValue != ERROR_SUCCESS) {
        wprintf(L"ERROR: Cannot open AppID registry key (%d).", dwReturnValue);
        return dwReturnValue;
    }

    if (_wcsicmp(username.c_str(), L"LAUNCHING USER") == 0) {
        // default case so delete "RunAs" value 
        dwReturnValue = hkeyRegistry.DeleteValue(L"RunAs");

        if (dwReturnValue == ERROR_FILE_NOT_FOUND) {
            dwReturnValue = ERROR_SUCCESS;
        } else if (dwReturnValue != ERROR_SUCCESS) {
            wprintf(L"ERROR: Cannot remove RunAs registry value (%d).", dwReturnValue);
            return dwReturnValue;
        }
    } else {
        // TODO: Skip password also for "nt authority\localservice" & "nt authority\networkservice"

        if (_wcsicmp(username.c_str(), L"INTERACTIVE USER") == 0) {
            // password not needed
        } else {
            // password needed
            dwReturnValue = SetRunAsPassword(AppID, username, password);
            if (dwReturnValue != ERROR_SUCCESS) {
                wprintf(L"ERROR: Cannot set RunAs password (%d).", dwReturnValue);
                return dwReturnValue;
            }
        }

        dwReturnValue = hkeyRegistry.SetStringValue(L"RunAs", username.c_str());
        if (dwReturnValue != ERROR_SUCCESS) {
            wprintf(L"ERROR: Cannot set RunAs registry value (%d).", dwReturnValue);
            return dwReturnValue;
        }
    }

    return ERROR_SUCCESS;
}

/*---------------------------------------------------------------------------*\
 * NAME: SetRunAsPassword                                                    *
 * --------------------------------------------------------------------------*
 * DESCRIPTION: Sets the RunAs password for an AppID. Note that if you       *
 * have specified the RunAs named value to "Interactive User" you do not     *
 * need to set the RunAs password.                                           *
 * --------------------------------------------------------------------------*
 *  ARGUMENTS:                                                               *
 *                                                                           *
 *  tszAppID - The Application ID you wish to modify                         *
 *  (e.g. "{99999999-9999-9999-9999-00AA00BBF7C7}")                          *
 *                                                                           *
 *  username - Name of the principal you have specified in the RunAs     *
 *  named value under the AppID registry key                                 *
 *                                                                           *
 *  tszPassword - Password of the user you have specified in the RunAs       *
 *  named value under the AppID registry key.                                *
 * --------------------------------------------------------------------------*
 *  RETURNS: WIN32 Error Code                                                *
\*---------------------------------------------------------------------------*/
DWORD SetRunAsPassword(const std::wstring AppID, const std::wstring username, const std::wstring password)
{
    // TODO: Check if password is valid

    const size_t GUIDSTR_MAX = 38;
    WCHAR wszKey[4 + GUIDSTR_MAX + 1] = { 0 };
    WCHAR wszAppID[GUIDSTR_MAX + 1] = { 0 };
    WCHAR wszPassword[256] = { 0 };

    StringCchCopyW(wszAppID, RTL_NUMBER_OF(wszAppID), AppID.c_str());
    StringCchCopyW(wszPassword, RTL_NUMBER_OF(wszPassword), password.c_str());

    StringCchCopyW(wszKey, RTL_NUMBER_OF(wszKey), L"SCM:");
    StringCchCatW(wszKey, RTL_NUMBER_OF(wszKey), wszAppID);

    LSA_UNICODE_STRING  lsaKeyString = {};
    lsaKeyString.Length = (USHORT)((wcslen(wszKey) + 1) * sizeof(WCHAR));
    lsaKeyString.MaximumLength = sizeof(wszKey);
    lsaKeyString.Buffer = wszKey;

    LSA_UNICODE_STRING lsaPasswordString = {};
    lsaPasswordString.Length = (USHORT)((wcslen(wszPassword) + 1) * sizeof(WCHAR));
    lsaPasswordString.Buffer = wszPassword;
    lsaPasswordString.MaximumLength = lsaPasswordString.Length;

    // Open the local security policy
    LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
    objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

    LsaWrap hPolicy;
    DWORD dwReturnValue = LsaOpenPolicy(NULL, &objectAttributes, POLICY_CREATE_SECRET, &hPolicy);
    dwReturnValue = LsaNtStatusToWinError(dwReturnValue);
    if (dwReturnValue != ERROR_SUCCESS)
        return dwReturnValue;

    // Store the user's password
    dwReturnValue = LsaStorePrivateData(hPolicy, &lsaKeyString, &lsaPasswordString);
    dwReturnValue = LsaNtStatusToWinError(dwReturnValue);
    if (dwReturnValue != ERROR_SUCCESS)
        return dwReturnValue;


    dwReturnValue = SetAccountRights(username, L"SeBatchLogonRight");
    return dwReturnValue;
}


/*---------------------------------------------------------------------------*\
 * NAME: SetAccountRights                                                    *
 * --------------------------------------------------------------------------*
 * DESCRIPTION: Sets the account right for a given user.                     *
\*---------------------------------------------------------------------------*/
DWORD SetAccountRights(const std::wstring username, const WCHAR tszPrivilege[])
{
    PSID               psidPrincipal = NULL;
    LSA_UNICODE_STRING lsaPrivilegeString = {};

    WCHAR wszPrivilege[256] = { 0 };
    StringCchCopy(wszPrivilege, RTL_NUMBER_OF(wszPrivilege), tszPrivilege);

    LSA_OBJECT_ATTRIBUTES objectAttributes = {};
    LsaWrap hPolicy;
    DWORD dwReturnValue = LsaOpenPolicy(NULL, &objectAttributes, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &hPolicy);
    dwReturnValue = LsaNtStatusToWinError(dwReturnValue);
    if (dwReturnValue != ERROR_SUCCESS)
        goto CLEANUP;

    dwReturnValue = GetPrincipalSID(username, &psidPrincipal);
    if (dwReturnValue != ERROR_SUCCESS)
        goto CLEANUP;

    lsaPrivilegeString.Length = (USHORT)(wcslen(wszPrivilege) * sizeof(WCHAR));
    lsaPrivilegeString.MaximumLength = (USHORT)(lsaPrivilegeString.Length + sizeof(WCHAR));
    lsaPrivilegeString.Buffer = wszPrivilege;

    dwReturnValue = LsaAddAccountRights(hPolicy, psidPrincipal, &lsaPrivilegeString, 1);
    dwReturnValue = LsaNtStatusToWinError(dwReturnValue);
    if (dwReturnValue != ERROR_SUCCESS)
        goto CLEANUP;

CLEANUP:
    if (psidPrincipal)
        free(psidPrincipal);

    return dwReturnValue;
}

/*---------------------------------------------------------------------------*\
 * NAME: GetPrincipalSID                                                     *
 * --------------------------------------------------------------------------*
 * DESCRIPTION: Creates a SID for the supplied principal.                    *
\*---------------------------------------------------------------------------*/
DWORD GetPrincipalSID(const std::wstring username, /*out*/PSID* pSid)
{
    if (ConstructWellKnownSID(username, /*out*/pSid))
        return ERROR_SUCCESS;

    TCHAR        tszRefDomain[256] = { 0 };
    DWORD        cbRefDomain = 255;
    SID_NAME_USE snu;
    DWORD cbSid = 0;
    LookupAccountNameW(NULL, username.c_str(), *pSid, &cbSid, tszRefDomain, &cbRefDomain, &snu);

    DWORD dwReturnValue = GetLastError();
    if (dwReturnValue != ERROR_INSUFFICIENT_BUFFER)
        return dwReturnValue;

    dwReturnValue = ERROR_SUCCESS;

    *pSid = (PSID)malloc(cbSid);
    if (!pSid) {
        dwReturnValue = ERROR_OUTOFMEMORY;
        return dwReturnValue;
    }

    cbRefDomain = 255;

    if (!LookupAccountNameW(NULL, username.c_str(), *pSid, &cbSid, tszRefDomain, &cbRefDomain, &snu)) {
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
BOOL ConstructWellKnownSID(const std::wstring tszPrincipal, /*out*/PSID* pSid)
{
    // Look for well-known English names
    DWORD dwSubAuthority = 0;
    BOOL fUseWorldAuth = FALSE;
    if (_wcsicmp(tszPrincipal.c_str(), L"Administrators") == 0) {
        dwSubAuthority = DOMAIN_ALIAS_RID_ADMINS;
    } else if (_wcsicmp(tszPrincipal.c_str(), L"Power Users") == 0) {
        dwSubAuthority = DOMAIN_ALIAS_RID_POWER_USERS;
    } else if (_wcsicmp(tszPrincipal.c_str(), L"Everyone") == 0) {
        dwSubAuthority = SECURITY_WORLD_RID;
        fUseWorldAuth = TRUE;
    } else if (_wcsicmp(tszPrincipal.c_str(), L"System") == 0) {
        dwSubAuthority = SECURITY_LOCAL_SYSTEM_RID;
    } else if (_wcsicmp(tszPrincipal.c_str(), L"Self") == 0) {
        dwSubAuthority = SECURITY_PRINCIPAL_SELF_RID;
    } else if (_wcsicmp(tszPrincipal.c_str(), L"Anonymous") == 0) {
        dwSubAuthority = SECURITY_ANONYMOUS_LOGON_RID;
    } else if (_wcsicmp(tszPrincipal.c_str(), L"Interactive") == 0) {
        dwSubAuthority = SECURITY_INTERACTIVE_RID;
    } else {
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
    } else {
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
    *pSid = (PSID)malloc(cbSid); // assign output buffer
    if (!CopySid(cbSid, *pSid, psidTemp)) {
        free(*pSid);
        *pSid = NULL;
    } else {
        fRetVal = TRUE;
    }
    FreeSid(psidTemp);

    return fRetVal;
}
