#include <iostream>
#include <stdexcept>
#include <comdef.h> // for _com_error
#include <atlbase.h>


/** Translate COM HRESULT failure into exceptions. */
static void CHECK(HRESULT hr) {
    if (FAILED(hr)) {
        _com_error err(hr);
#ifdef _UNICODE
        const wchar_t * msg = err.ErrorMessage(); // weak ptr.
        abort();
#else
        const char * msg = err.ErrorMessage(); // weak ptr.
        abort();
#endif
    }
}

/** RAII class for COM initialization. */
class ComInitialize {
public:
    ComInitialize(COINIT apartment /*= COINIT_MULTITHREADED*/) : m_initialized(false) {
        // REF: https://msdn.microsoft.com/en-us/library/windows/desktop/ms695279.aspx
        HRESULT hr = CoInitializeEx(NULL, apartment);
        if (SUCCEEDED(hr))
            m_initialized = true;
    }

    ~ComInitialize() {
        if (m_initialized)
            CoUninitialize();
    }

private:
    bool m_initialized; ///< must uninitialize in dtor
};


/** Customization point for adjusting COM security settings. Might be needed for user impersonation. */
struct ComSecurity {
    ComSecurity() {
        CoInitialize(nullptr);

        SECURITY_DESCRIPTOR * sec_desc = nullptr;
        SOLE_AUTHENTICATION_LIST auth_list = {};
        CHECK(CoInitializeSecurity(sec_desc, -1 /*auto*/, nullptr, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, &auth_list, EOAC_STATIC_CLOAKING, NULL));
    }
    ~ComSecurity() {

    }
};


/** RAII class for impersonating a different user. */
class ImpersonateUser {
public:
    ImpersonateUser(std::wstring username, std::wstring password) {
        const wchar_t domain[] = L""; // default domain
        if (!LogonUser(username.c_str(), domain, password.c_str(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &m_user_token.m_h)) {
            auto err = GetLastError();
            abort();
        }
        if (!ImpersonateLoggedOnUser(m_user_token)) {
            auto err = GetLastError();
            abort();
        }
    }
    ~ImpersonateUser() {
        if (m_user_token) {
            if (!RevertToSelf()) {
                auto err = GetLastError();
                abort();
            }
        }
    }
private:
    CHandle m_user_token;
};


int wmain(int argc, wchar_t *argv[]) {
    if (argc < 3) {
        std::cerr << "Too few arguments\n.";
        std::cerr << "Usage  : ComImpersonation.exe <ProgID> <username> <password>" << std::endl;
        return -1;
    }

    ComInitialize com(COINIT_MULTITHREADED);
    //ImpersonateUser impersonate(argv[2], argv[3]);
    //ComSecurity   com_security;

    // create COM object in a separate process
    CComPtr<IUnknown> obj;
    {
        DWORD class_context = CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING; // | CLSCTX_ENABLE_AAA;
        wchar_t *progId = argv[1]; // e.g. "Excel.Application"
#ifdef DEBUG_COM_ACTIVATION
        // open Event Viewer, "Windows Logs" -> "System" log to see details on failures
        CLSID clsid = {};
        CHECK(CLSIDFromProgID(progId, &clsid));
        CComPtr<IClassFactory> cf;
        CHECK(CoGetClassObject(clsid, class_context, NULL, IID_IClassFactory, (void**)&cf));
        CHECK(cf->CreateInstance(nullptr, IID_IUnknown, (void**)&obj));
#else
        CHECK(obj.CoCreateInstance(progId, nullptr, class_context));
#endif
        std::cout << "Object created" << std::endl;
    }
}
