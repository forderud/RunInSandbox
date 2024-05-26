#pragma once
#include "Util.hpp"
#include <string>
#include <tuple>
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

        std::tie(res, m_sidPrincipal) = GetPrincipalSID(username);
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
    static std::tuple<DWORD, std::vector<BYTE>> GetPrincipalSID(const std::wstring& username)
    {
        TCHAR tszRefDomain[256] = { 0 };
        DWORD cbRefDomain = 255;
        SID_NAME_USE snu;
        DWORD cbSid = 0;
        LookupAccountNameW(NULL, username.c_str(), nullptr, &cbSid, tszRefDomain, &cbRefDomain, &snu);

        DWORD res = GetLastError();
        if (res != ERROR_INSUFFICIENT_BUFFER)
            return {res, {}};

        res = ERROR_SUCCESS;

        std::vector<BYTE> sid;
        sid.resize(cbSid);
        cbRefDomain = 255;

        if (!LookupAccountNameW(NULL, username.c_str(), (PSID)sid.data(), &cbSid, tszRefDomain, &cbRefDomain, &snu)) {
            res = GetLastError();
            return {res, {}};
        }

        return {res, sid};
    }

    LsaWrap           m_policy;
    std::vector<BYTE> m_sidPrincipal; // PSID buffer
};
