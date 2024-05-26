#pragma once
#include "AccountRights.hpp"
#include <strsafe.h>
#include <atlbase.h> // CRegKey


/** Utility class for configuring which user account to run COM servers through.
*   Will modify the AppID\RunAs registry key as documented on https://learn.microsoft.com/en-us/windows/win32/com/runas */
class ComRunAs {
public:
    DWORD Open (const std::wstring AppID) {
        m_appid = AppID;

        std::wstring tszKeyName = L"APPID\\" + AppID;
        DWORD res = m_reg.Open(HKEY_CLASSES_ROOT, tszKeyName.c_str(), KEY_ALL_ACCESS);
        return res;
    }

    DWORD Assign(const std::wstring username, /*optional*/const WCHAR* password) {
        DWORD res = ERROR_SUCCESS;
        if (_wcsicmp(username.c_str(), L"Launching User") == 0) { // https://learn.microsoft.com/en-us/windows/win32/com/launching-user
            // default case so delete "RunAs" value 
            res = m_reg.DeleteValue(L"RunAs");

            if (res == ERROR_FILE_NOT_FOUND) {
                res = ERROR_SUCCESS;
            } else if (res != ERROR_SUCCESS) {
                wprintf(L"ERROR: Cannot remove RunAs registry value (%d).\n", res);
                return res;
            }
        } else {
            // check if account require password
            bool passwordRequired = true;
            for (const WCHAR* account : s_PasswordlessAccounts) {
                if (_wcsicmp(username.c_str(), account) == 0) {
                    passwordRequired = false;
                    break;
                }
            }

            if (passwordRequired) {
                if (!password) {
                    wprintf(L"ERROR: Password missing for user %s.\n", username.c_str());
                    return ERROR_INVALID_PASSWORD;
                }

                res = SetRunAsPassword(m_appid, password);
                if (res != ERROR_SUCCESS) {
                    wprintf(L"ERROR: Cannot set RunAs password (%d).\n", res);
                    return res;
                }

                // Grant user "Log on as a batch job" rights
                // This is not enabled by default for manually created acounts
                AccountRights ar;
                res = ar.Open(username);
                if (res != ERROR_SUCCESS) {
                    wprintf(L"ERROR: Unknown user %s (%d).\n", username.c_str(), res);
                    return res;
                }

                if (ar.HasRight(L"SeBatchLogonRight")) {
                    wprintf(L"INFO: User %s already has SeBatchLogonRight.\n", username.c_str());
                } else {
                    wprintf(L"INFO: Setting SeBatchLogonRight for user %s.\n", username.c_str());
                    res = ar.Set(L"SeBatchLogonRight");
                    if (res != ERROR_SUCCESS) {
                        wprintf(L"ERROR: Unable to grant SeBatchLogonRight (%d).\n", res);
                        return res;
                    }
                }
            }

            res = m_reg.SetStringValue(L"RunAs", username.c_str());
            if (res != ERROR_SUCCESS) {
                wprintf(L"ERROR: Unable to set RunAs registry value (%d).\n", res);
                return res;
            }
        }

        return ERROR_SUCCESS;
    }

private:
     /* Sets the RunAs password for an AppID.
       Based on https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/com/fundamentals/dcom/dcomperm 
       Arguments:    
       * AppID - The Application ID you wish to modify (e.g. "{99999999-9999-9999-9999-00AA00BBF7C7}")
       * password - Password of the user you have specified in the RunAs named value under the AppID registry key. */
    static DWORD SetRunAsPassword(const std::wstring& AppID, const std::wstring& password) {
        std::wstring key = L"SCM:" + AppID;
        LSA_UNICODE_STRING KeyString = {};
        KeyString.Length = (USHORT)(key.length() + 1) * sizeof(WCHAR); // include null-termination (not according to spec but seem to be required for admin accounts)
        KeyString.MaximumLength = KeyString.Length;                    // include null-termination
        KeyString.Buffer = key.data();

        LSA_UNICODE_STRING PasswordString = {};
        PasswordString.Length = (USHORT)(password.length() + 1) * sizeof(WCHAR); // include null-termination (not according to spec but seem to be required for admin accounts)
        PasswordString.MaximumLength = PasswordString.Length;                    // include null-termination
        PasswordString.Buffer = const_cast<WCHAR*>(password.data());

        // Open the local security policy
        LSA_OBJECT_ATTRIBUTES objectAttributes = {};
        objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

        LsaWrap hPolicy;
        DWORD res = LsaOpenPolicy(NULL, &objectAttributes, POLICY_CREATE_SECRET, &hPolicy);
        res = LsaNtStatusToWinError(res);
        if (res != ERROR_SUCCESS)
            return res;

        // Store the user's password
        res = LsaStorePrivateData(hPolicy, &KeyString, &PasswordString);
        res = LsaNtStatusToWinError(res);
        return res;
    }

    std::wstring m_appid;
    CRegKey      m_reg;

    static inline const WCHAR* s_PasswordlessAccounts[] = {
        L"Interactive User",             ///< https://learn.microsoft.com/en-us/windows/win32/com/interactive-user
        L"nt authority\\localservice",   ///< https://learn.microsoft.com/en-us/windows/win32/services/localservice-account
        L"nt authority\\networkservice", ///< https://learn.microsoft.com/en-us/windows/win32/services/networkservice-account
        L"nt authority\\system",         ///< https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account
    };
};
