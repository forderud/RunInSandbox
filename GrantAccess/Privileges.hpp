#pragma once


struct Privilege {
    enum State {
        Missing,
        Enabled,
        Disabled,
    };

    const wchar_t* ToString() const {
        switch (state) {
        case Missing: return L"missing";
        case Enabled: return L"enabled";
        case Disabled: return L"disabled";
        default:
            abort();
        }
    }

    Privilege(HANDLE token, const wchar_t* privName) : token(token) {
        BOOL ok = LookupPrivilegeValueW(nullptr, privName, &value);
        assert(ok);

        // detect if privilege is enabled
        std::vector<BYTE> privilegesBuffer(1024, (BYTE)0);
        {
            DWORD privilegesLength = 0;
            ok = GetTokenInformation(token, TokenPrivileges, privilegesBuffer.data(), (DWORD)privilegesBuffer.size(), &privilegesLength);
            assert(ok);
            privilegesBuffer.resize(privilegesLength);
        }
        auto* tp = (TOKEN_PRIVILEGES*)privilegesBuffer.data();

        //wprintf(L"  Privilege count: %u.\n", tp->PrivilegeCount);
        for (size_t i = 0; i < tp->PrivilegeCount; i++) {
            const LUID_AND_ATTRIBUTES entry = tp->Privileges[i];
            bool match = (value.LowPart == entry.Luid.LowPart) && (value.HighPart == entry.Luid.HighPart);
            if (!match)
                continue;

            if (entry.Attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT))
                state = Enabled;
            else
                state = Disabled;
        }
    }

    void Modify(State s) {
        // https://learn.microsoft.com/nb-no/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
        TOKEN_PRIVILEGES tp = {
            .PrivilegeCount = 1,
        };
        tp.Privileges[0] = {
            .Luid = value,
            .Attributes = (s == Enabled) ? (DWORD)SE_PRIVILEGE_ENABLED : 0,
        };

        if (!AdjustTokenPrivileges(token, /*disableAll*/false, &tp, 0, nullptr, nullptr)) {
            DWORD err = GetLastError();
            wprintf(L"ERROR: AdjustTokenPrivileges failed (%u)\n", err);
            abort();
        }

        state = s;
    }

private:
    HANDLE token = 0;
public:
    LUID  value{};
    State state = Missing;
};

bool CheckPrivileges(HANDLE token) {
    {
        TOKEN_TYPE tokenType = {};
        DWORD tokenLen = 0;
        if (!GetTokenInformation(token, TokenType, &tokenType, sizeof(tokenType), &tokenLen))
            abort();

        wprintf(L"  TokenType: %s\n", (tokenType == TokenPrimary) ? L"Primary" : L"Impersonation");
    }

    Privilege Impersonate(token, SE_IMPERSONATE_NAME); // required by CreateProcessWithToken
    wprintf(L"  SE_IMPERSONATE_NAME privilege %s\n", Impersonate.ToString());

    return true;
}


/** Alternative to GetCurrentProcessToken() with more privileges. */
HANDLE GetCurrentProcessTokenEx() {
    HANDLE procToken = 0;
    if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &procToken))
        abort();

    // copy token to avoid ERROR_TOKEN_ALREADY_IN_USE
    HANDLE token = 0;
    if (!DuplicateTokenEx(procToken, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &token))
        abort();
    return token;
}
