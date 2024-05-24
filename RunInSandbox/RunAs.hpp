#pragma once
#include <Windows.h>
#include <lsalookup.h>
#include <strsafe.h>
#define _NTDEF_
#include <ntsecapi.h>

// Code based on https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/com/fundamentals/dcom/dcomperm

#define GUIDSTR_MAX 38

DWORD SetAccountRights(LPTSTR tszUser, const wchar_t* tszPrivilege);
DWORD GetPrincipalSID(LPTSTR tszPrincipal, PSID* pSid);
BOOL ConstructWellKnownSID(LPTSTR tszPrincipal, PSID* pSid);

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
 *  tszPrincipal - Name of the principal you have specified in the RunAs     *
 *  named value under the AppID registry key                                 *
 *                                                                           *
 *  tszPassword - Password of the user you have specified in the RunAs       *
 *  named value under the AppID registry key.                                *
 * --------------------------------------------------------------------------*
 *  RETURNS: WIN32 Error Code                                                *
\*---------------------------------------------------------------------------*/
DWORD SetRunAsPassword(LPTSTR tszAppID, LPTSTR tszPrincipal, LPTSTR tszPassword)
{
    WCHAR                 wszKey[4 + GUIDSTR_MAX + 1] = { 0 };
    WCHAR                 wszAppID[GUIDSTR_MAX + 1] = { 0 };
    WCHAR                 wszPassword[256] = { 0 };

    StringCchCopy(wszAppID, RTL_NUMBER_OF(wszAppID), tszAppID);
    StringCchCopy(wszPassword, RTL_NUMBER_OF(wszPassword), tszPassword);

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

    HANDLE hPolicy = NULL;
    DWORD dwReturnValue = LsaOpenPolicy(NULL, &objectAttributes, POLICY_CREATE_SECRET, &hPolicy);

    dwReturnValue = LsaNtStatusToWinError(dwReturnValue);

    if (dwReturnValue != ERROR_SUCCESS)
        goto CLEANUP;

    // Store the user's password
    dwReturnValue = LsaStorePrivateData(hPolicy, &lsaKeyString, &lsaPasswordString);

    dwReturnValue = LsaNtStatusToWinError(dwReturnValue);

    if (dwReturnValue != ERROR_SUCCESS)
        goto CLEANUP;


    dwReturnValue = SetAccountRights(tszPrincipal, _T("SeBatchLogonRight"));
    if (dwReturnValue != ERROR_SUCCESS)
        goto CLEANUP;

CLEANUP:
    if (hPolicy)
        LsaClose(hPolicy);

    return dwReturnValue;
}


/*---------------------------------------------------------------------------*\
 * NAME: SetAccountRights                                                    *
 * --------------------------------------------------------------------------*
 * DESCRIPTION: Sets the account right for a given user.                     *
\*---------------------------------------------------------------------------*/
DWORD SetAccountRights(LPTSTR tszUser, const wchar_t* tszPrivilege)
{
    PSID               psidPrincipal = NULL;
    LSA_UNICODE_STRING lsaPrivilegeString = {};

    WCHAR wszPrivilege[256] = { 0 };
    StringCchCopy(wszPrivilege, RTL_NUMBER_OF(wszPrivilege), tszPrivilege);

    LSA_OBJECT_ATTRIBUTES objectAttributes = {};
    LSA_HANDLE            hPolicy = NULL;
    DWORD dwReturnValue = LsaOpenPolicy(NULL, &objectAttributes, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &hPolicy);
    dwReturnValue = LsaNtStatusToWinError(dwReturnValue);

    if (dwReturnValue != ERROR_SUCCESS)
        goto CLEANUP;

    dwReturnValue = GetPrincipalSID(tszUser, &psidPrincipal);
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
    if (hPolicy)
        LsaClose(hPolicy);

    return dwReturnValue;
}

/*---------------------------------------------------------------------------*\
 * NAME: GetPrincipalSID                                                     *
 * --------------------------------------------------------------------------*
 * DESCRIPTION: Creates a SID for the supplied principal.                    *
\*---------------------------------------------------------------------------*/
DWORD GetPrincipalSID(LPTSTR tszPrincipal, PSID* pSid)
{
    DWORD cbSid = 0;
    cbRefDomain = 255;

    if (ConstructWellKnownSID(tszPrincipal, pSid))
        return ERROR_SUCCESS;

    TCHAR        tszRefDomain[256] = { 0 };
    DWORD        cbRefDomain = 0;
    SID_NAME_USE snu;
    LookupAccountName(NULL, tszPrincipal, *pSid, &cbSid, tszRefDomain, &cbRefDomain, &snu);

    DWORD dwReturnValue = GetLastError();
    if (dwReturnValue != ERROR_INSUFFICIENT_BUFFER) goto CLEANUP;

    dwReturnValue = ERROR_SUCCESS;

    *pSid = (PSID)malloc(cbSid);
    if (!pSid) {
        dwReturnValue = ERROR_OUTOFMEMORY;
        goto CLEANUP;
    }

    cbRefDomain = 255;

    if (!LookupAccountName(NULL, tszPrincipal, *pSid, &cbSid, tszRefDomain, &cbRefDomain, &snu)) {
        dwReturnValue = GetLastError();
        goto CLEANUP;
    }

CLEANUP:
    return dwReturnValue;
}


/*---------------------------------------------------------------------------*\
 * NAME: ConstructWellKnownSID                                               *
 * --------------------------------------------------------------------------*
 * DESCRIPTION: This method converts some designated well-known identities   *
 * to a SID.                                                                 *
\*---------------------------------------------------------------------------*/
BOOL ConstructWellKnownSID(LPTSTR tszPrincipal, PSID* pSid)
{
    BOOL fRetVal = FALSE;
    PSID psidTemp = NULL;
    BOOL fUseWorldAuth = FALSE;

    SID_IDENTIFIER_AUTHORITY SidAuthorityNT = SECURITY_NT_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SidAuthorityWorld = SECURITY_WORLD_SID_AUTHORITY;

    DWORD dwSubAuthority;

    // Look for well-known English names
    if (_tcsicmp(tszPrincipal, _T("Administrators")) == 0) {
        dwSubAuthority = DOMAIN_ALIAS_RID_ADMINS;
    } else if (_tcsicmp(tszPrincipal, _T("Power Users")) == 0) {
        dwSubAuthority = DOMAIN_ALIAS_RID_POWER_USERS;
    } else if (_tcsicmp(tszPrincipal, _T("Everyone")) == 0) {
        dwSubAuthority = SECURITY_WORLD_RID;
        fUseWorldAuth = TRUE;
    } else if (_tcsicmp(tszPrincipal, _T("System")) == 0) {
        dwSubAuthority = SECURITY_LOCAL_SYSTEM_RID;
    } else if (_tcsicmp(tszPrincipal, _T("Self")) == 0) {
        dwSubAuthority = SECURITY_PRINCIPAL_SELF_RID;
    } else if (_tcsicmp(tszPrincipal, _T("Anonymous")) == 0) {
        dwSubAuthority = SECURITY_ANONYMOUS_LOGON_RID;
    } else if (_tcsicmp(tszPrincipal, _T("Interactive")) == 0) {
        dwSubAuthority = SECURITY_INTERACTIVE_RID;
    } else {
        return FALSE;
    }

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

    if (IsValidSid(psidTemp)) {
        DWORD cbSid = GetLengthSid(psidTemp);
        *pSid = (PSID)malloc(cbSid);
        if (pSid) {
            if (!CopySid(cbSid, *pSid, psidTemp)) {
                free(*pSid);
                *pSid = NULL;
            } else {
                fRetVal = TRUE;
            }
        }
        FreeSid(psidTemp);
    }

    return fRetVal;
}
