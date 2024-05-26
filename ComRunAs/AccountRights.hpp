#pragma once
#include "Util.hpp"
#include <string>
#include <tuple>
#include <vector>


// Code based on https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/com/fundamentals/dcom/dcomperm

/** Query and set account rights for a given user.
* Current values can be inspected with "whoami /priv" from an admin command-prompt or by
* opening gpedit.msc and navigating to "Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment" */
class AccountRights {
public:
    DWORD Open(const std::wstring& username) {
        LSA_OBJECT_ATTRIBUTES objectAttributes = {};
        DWORD res = LsaOpenPolicy(NULL, &objectAttributes, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &m_policy);
        res = LsaNtStatusToWinError(res);
        if (res != ERROR_SUCCESS)
            return res;

        std::tie(res, m_user_sid) = GetPrincipalSID(username);
        return res;
    }

    bool HasRight(const WCHAR privilege[]) {
        LSA_UNICODE_STRING* rights = nullptr;
        ULONG count = 0;
        NTSTATUS res = LsaEnumerateAccountRights(m_policy, m_user_sid.data(), &rights, &count);
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

        DWORD res = LsaAddAccountRights(m_policy, m_user_sid.data(), &lsaPrivilegeString, 1);
        res = LsaNtStatusToWinError(res);
        return res;
    }

private:
    /** Get security identifier (SID) associated with a given user account. */
    static std::tuple<DWORD, std::vector<BYTE>> GetPrincipalSID(const std::wstring& username) {
        WCHAR RefDomain[256] = {};
        DWORD RefDomainLen = (DWORD)std::size(RefDomain);
        SID_NAME_USE snu = {};
        DWORD cbSid = 0;
        LookupAccountNameW(NULL, username.c_str(), nullptr, &cbSid, RefDomain, &RefDomainLen, &snu);
        DWORD res = GetLastError();
        if (res != ERROR_INSUFFICIENT_BUFFER)
            return {res, {}};

        res = ERROR_SUCCESS;
        std::vector<BYTE> sid;
        sid.resize(cbSid);
        RefDomainLen = (DWORD)std::size(RefDomain);;
        if (!LookupAccountNameW(NULL, username.c_str(), (PSID)sid.data(), &cbSid, RefDomain, &RefDomainLen, &snu)) {
            res = GetLastError();
            return {res, {}};
        }

        return {res, sid};
    }

    LsaWrap           m_policy;
    std::vector<BYTE> m_user_sid; // PSID buffer
};
