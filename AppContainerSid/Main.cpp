#include <Windows.h>
#include <userenv.h>
#include <iostream>
#include "../RunInSandbox/Sandboxing.hpp"

#pragma comment(lib, "Userenv.lib") // for DeriveAppContainerSidFromAppContainerName


/** Alternative implementation of the DeriveAppContainerSidFromAppContainerName algorithm. */
void AlternativeAppContainerSID_impl(std::wstring appContainerName) {
    // convert name to lowercase
    for (auto& elm : appContainerName)
        elm = (wchar_t)std::tolower(elm);

    HCRYPTPROV cryptProv = 0;
    if (!CryptAcquireContext(&cryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        abort();

    HCRYPTHASH hashObj = 0;
    if (!CryptCreateHash(cryptProv, CALG_SHA_256, 0, 0, &hashObj))
        abort();

    if (!CryptHashData(hashObj, (BYTE*)appContainerName.c_str(), 2*(DWORD)appContainerName.size(), 0))
        abort();

    uint32_t hash[8] = {};
    DWORD hashSize = sizeof(hash);
    if (!CryptGetHashParam(hashObj, HP_HASHVAL, (BYTE*)hash, &hashSize, 0))
        abort();

    CryptDestroyHash(hashObj);
    CryptReleaseContext(cryptProv, 0);

    // print AppContainer SID
    wprintf(L"S-1-15-2");
    for (size_t i = 0; i < 8-1; i++)
        wprintf(L"-%u", hash[i]);
    wprintf(L"\n");
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Compute the SID for a given AppContainer.\n");
        wprintf(L"USAGE: AppContainerSid.exe <AppContainer-name>\n");
        return -1;
    }
    
    std::wstring appContainer = argv[1];

#if 1
    // DOC: https://devblogs.microsoft.com/oldnewthing/20220502-00/?p=106550
    SidWrap sid;
    HRESULT hr = DeriveAppContainerSidFromAppContainerName(appContainer.c_str(), &sid);
    if (FAILED(hr)) {
        _com_error err(hr);
        wprintf(L"ERROR: Unable to convert AppContainer SID (%s).\n", err.ErrorMessage());
        return -2;
    }

    // convert SID to string representation in "S-1-15-2-x1-x2-x3-x4-x5-x6-x7" format,
    // where x1-x7 are the first 28 bytes of the SHA256 hash of the lowercase app name.
    LocalWrap<wchar_t*> sid_str;
    BOOL ok = ConvertSidToStringSidW(sid, &sid_str);
    if (!ok) {
        DWORD err = GetLastError();
        wprintf(L"ERROR: Unable to convert AppContainer SID to string (%u).\n", err);
        return -3;
    }

    wprintf(L"%s\n", (wchar_t*)sid_str);
#else
    AlternativeAppContainerSID_impl(appContainer);
#endif
    return 0;
}
