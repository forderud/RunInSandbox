#include "TestControl.hpp"
#include <Shlobj.h>
#include "../RunInSandbox/ComCreate.hpp"

#pragma comment (lib, "Ws2_32.lib")


TestControl::TestControl(){
}

TestControl::~TestControl() {
}

HRESULT STDMETHODCALLTYPE TestControl::Add(int a, int b, int * sum) {
    *sum = a + b;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE TestControl::IsElevated (/*out*/BOOL * is_elevated, /*out*/BOOL * high_integrity) {
    *is_elevated = ImpersonateThread::IsProcessElevated();

    IntegrityLevel proc_integrity = ImpersonateThread::GetProcessLevel();
    *high_integrity = (proc_integrity >= IntegrityLevel::High);

    return S_OK;
}


class SocketWrap {
public:
    SocketWrap() {
        WSADATA init_data = {};
        WSAStartup(MAKEWORD(2, 2), &init_data);

        m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(m_sock == INVALID_SOCKET) {
            //printf("Failed to create socket, error code: %d\n", WSAGetLastError());
            throw std::runtime_error("Failed to create socket");
        }
    }

    ~SocketWrap() {
        if (m_sock == INVALID_SOCKET)
            return;

        int res = closesocket(m_sock);
        if (res)
            std::terminate();
        m_sock = INVALID_SOCKET;

        res = WSACleanup();
        if (res == SOCKET_ERROR)
            std::terminate();
    }

    bool TryToConnect (const std::string& host, const uint16_t port) {
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(host.c_str());
        addr.sin_port = htons(port);

        if(connect(m_sock, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            if(WSAGetLastError() == WSAEACCES)
                ; // Connection blocked
            else
                ; // Connection unsuccessful but not blocked

            return false;
        }

        return true;
    }

private:
    SOCKET m_sock = INVALID_SOCKET;
};


HRESULT STDMETHODCALLTYPE TestControl::TestNetworkConnection (/*in*/BSTR host, USHORT port, /*out*/BOOL * can_access) {
    *can_access = false; // assume no connectivity by default

    try {
        SocketWrap sock;
        *can_access = sock.TryToConnect(ToAscii(host), port);
    } catch (const std::exception & ) {
        return E_FAIL;
    }

    return S_OK;
}


HRESULT STDMETHODCALLTYPE TestControl::CreateInstance (BOOL elevated, /*in*/CLSID clsid, /*out*/IUnknown ** obj) {
    if (!obj)
        return E_INVALIDARG;

    if (elevated) {
        return CoCreateInstanceElevated<IUnknown>(NULL, clsid, obj);
    } else {
        CComPtr<IUnknown> res;
        HRESULT hr = res.CoCreateInstance(clsid);
        if (FAILED(hr))
            return hr;

        *obj = res.Detach();
        return S_OK;
    }
}
