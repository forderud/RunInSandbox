#pragma once
#include "AccountRights.hpp"
#include <strsafe.h>
#include <atlbase.h> // CRegKey


// Code based on https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/com/fundamentals/dcom/dcomperm


class ComRunAs {
public:
    ComRunAs() {
    }
    ~ComRunAs() {
    }

    DWORD Open (const std::wstring AppID) {
        m_AppID = AppID;

        std::wstring tszKeyName = L"APPID\\" + AppID;
        DWORD dwReturnValue = m_reg.Open(HKEY_CLASSES_ROOT, tszKeyName.c_str(), KEY_ALL_ACCESS);
        return dwReturnValue;
    }


    DWORD Assign(const std::wstring username, const std::wstring password) {
        DWORD dwReturnValue;
        if (_wcsicmp(username.c_str(), L"LAUNCHING USER") == 0) {
            // default case so delete "RunAs" value 
            dwReturnValue = m_reg.DeleteValue(L"RunAs");

            if (dwReturnValue == ERROR_FILE_NOT_FOUND) {
                dwReturnValue = ERROR_SUCCESS;
            }
            else if (dwReturnValue != ERROR_SUCCESS) {
                wprintf(L"ERROR: Cannot remove RunAs registry value (%d).\n", dwReturnValue);
                return dwReturnValue;
            }
        }
        else {
            // TODO: Skip password also for "nt authority\localservice" & "nt authority\networkservice"

            if (_wcsicmp(username.c_str(), L"INTERACTIVE USER") == 0) {
                // password not needed
            }
            else {
                // password needed
                dwReturnValue = SetRunAsPassword(m_AppID, password);
                if (dwReturnValue != ERROR_SUCCESS) {
                    wprintf(L"ERROR: Cannot set RunAs password (%d).\n", dwReturnValue);
                    return dwReturnValue;
                }

                // Grant user "Log on as a batch job" rights
                // This is not enabled by default for manually created acounts
                // TOOD: Check if user already has this right
                dwReturnValue = SetAccountRights(username, L"SeBatchLogonRight");
                if (dwReturnValue != ERROR_SUCCESS) {
                    wprintf(L"ERROR: Unable to grant SeBatchLogonRight (%d).\n", dwReturnValue);
                    return dwReturnValue;
                }
            }

            dwReturnValue = m_reg.SetStringValue(L"RunAs", username.c_str());
            if (dwReturnValue != ERROR_SUCCESS) {
                wprintf(L"ERROR: Cannot set RunAs registry value (%d).\n", dwReturnValue);
                return dwReturnValue;
            }
        }

        return ERROR_SUCCESS;
    }

private:
    /*---------------------------------------------------------------------------*\
     * NAME: SetRunAsPassword                                                    *
     * --------------------------------------------------------------------------*
     * DESCRIPTION: Sets the RunAs password for an AppID. Note that if you       *
     * have specified the RunAs named value to "Interactive User" you do not     *
     * need to set the RunAs password.                                           *
     * --------------------------------------------------------------------------*
     *  ARGUMENTS:                                                               *
     *                                                                           *
     *  AppID - The Application ID you wish to modify                            *
     *  (e.g. "{99999999-9999-9999-9999-00AA00BBF7C7}")                          *
     *                                                                           *
     *  password - Password of the user you have specified in the RunAs          *
     *  named value under the AppID registry key.                                *
     * --------------------------------------------------------------------------*
     *  RETURNS: WIN32 Error Code                                                *
    \*---------------------------------------------------------------------------*/
    static DWORD SetRunAsPassword(const std::wstring& AppID, const std::wstring& password)
    {
        std::wstring key = L"SCM:" + AppID;
        LSA_UNICODE_STRING lsaKeyString = {};
        lsaKeyString.Length = (USHORT)(key.length() + 1) * sizeof(WCHAR); // include null-termination (not according to spec but seem to be required for admin accounts)
        lsaKeyString.MaximumLength = lsaKeyString.Length;               // include null-termination
        lsaKeyString.Buffer = key.data();

        LSA_UNICODE_STRING lsaPasswordString = {};
        lsaPasswordString.Length = (USHORT)(password.length() + 1) * sizeof(WCHAR); // include null-termination (not according to spec but seem to be required for admin accounts)
        lsaPasswordString.MaximumLength = lsaPasswordString.Length;               // include null-termination
        lsaPasswordString.Buffer = const_cast<WCHAR*>(password.data());

        // Open the local security policy
        LSA_OBJECT_ATTRIBUTES objectAttributes = {};
        objectAttributes.Length = sizeof(LSA_OBJECT_ATTRIBUTES);

        LsaWrap hPolicy;
        DWORD dwReturnValue = LsaOpenPolicy(NULL, &objectAttributes, POLICY_CREATE_SECRET, &hPolicy);
        dwReturnValue = LsaNtStatusToWinError(dwReturnValue);
        if (dwReturnValue != ERROR_SUCCESS)
            return dwReturnValue;

        // Store the user's password
        dwReturnValue = LsaStorePrivateData(hPolicy, &lsaKeyString, &lsaPasswordString);
        dwReturnValue = LsaNtStatusToWinError(dwReturnValue);
        return dwReturnValue;
    }

    std::wstring m_AppID;
    CRegKey      m_reg;
};
